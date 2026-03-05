package gnocker

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/crypto/ssh"
)

// Protocol specification:
// Version   # 1 byte
// Timestamp # 8 bytes
// Rand      # 32 bytes
// PubKeyID  # 32 bytes (SHA256 fingerprint format)
// SignLen   # 3 bytes
// Signature # SignLen
// Signature is everything from Version to Rand included
// Big endian is used

const VER_LEN = 1
const TS_LEN = 8
const RAND_LEN = 32
const PUBKEYID_LEN = 32
const HDR_LEN = VER_LEN + TS_LEN + RAND_LEN + PUBKEYID_LEN

const TS_HALF_WINDOW = 5 // Half the value of the timestamp window the server accepts, in seconds

func intTo3ByteBigEndian(v int) []byte {
	buf := make([]byte, 3)
	buf[0] = byte((v >> 16) & 0xff)
	buf[1] = byte((v >> 8) & 0xff)
	buf[2] = byte((v >> 0) & 0xff)
	return buf
}

func bytesToInt24(data []byte) int {
	// Create a 4-byte buffer with the high byte set to 0
	buf := make([]byte, 4)
	copy(buf[1:], data)

	// Convert the buffer to an integer using big endian byte order
	val := int(binary.BigEndian.Uint32(buf))
	return val
}

func sshPubKeyToID(key ssh.PublicKey) []byte {
	id_b64 := ssh.FingerprintSHA256(key)
	// id_b64 starts with SHA256:, so remove it
	id, _ := base64.RawStdEncoding.DecodeString(id_b64[7:])
	return id
}

func tsUTCNow() uint64 {
	return uint64(time.Now().UTC().Unix())
}

type Client struct {
	signer ssh.Signer
	rnd    io.Reader
}

func NewClient(signer ssh.Signer, rnd io.Reader) Client {
	return Client{signer, rnd}
}

func (c Client) Gnock(w io.Writer) error {
	buf := bytes.NewBuffer(make([]byte, 0, HDR_LEN))
	ts := tsUTCNow()

	buf.WriteByte(1)                        // Version
	binary.Write(buf, binary.BigEndian, ts) // Timestamp
	rnd := make([]byte, RAND_LEN)
	_, err := io.ReadFull(c.rnd, rnd) // Rand
	if err != nil {
		return err
	}
	buf.Write(rnd)

	// Pubkey ID
	pubkey := c.signer.PublicKey()
	hashed_pubkey_id := hashedPubKeyID(rnd, pubkey)
	_, err = buf.Write(hashed_pubkey_id[:])
	if err != nil {
		return err
	}

	sig, err := c.signer.Sign(c.rnd, buf.Bytes())
	if err != nil {
		return err
	}

	_, err = buf.WriteTo(w)
	if err != nil {
		return err
	}
	_, err = w.Write(intTo3ByteBigEndian(len(sig.Blob)))
	if err != nil {
		return err
	}
	_, err = w.Write(sig.Blob)
	return err
}

func CopyBidirectional(r io.Reader, w io.Writer, peer io.ReadWriteCloser) error {
	errChan := make(chan error)
	go func() {
		_, err := io.Copy(peer, r)
		peer.Close()
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(w, peer)
		peer.Close()
		errChan <- err
	}()

	err := <-errChan
	if err != nil {
		return err
	}
	return <-errChan
}

const FIONREAD = 0x541B

func AvailableBytesFd(fd uintptr) (uint, error) {
	var n uint
	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, FIONREAD, uintptr(unsafe.Pointer(&n))); err != 0 {
		return 0, err
	}
	return n, nil
}

func TCPMSS(conn net.Conn) (int, error) {
	tcpConn := conn.(*net.TCPConn)
	file, err := tcpConn.File()
	if err != nil {
		return 0, err
	}
	defer file.Close()

	fd := int(file.Fd())

	mss, err := syscall.GetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_MAXSEG)
	if err != nil {
		return 0, err
	}

	return mss, nil
}

func (c Client) WrapClient(cr io.Reader, cw io.Writer, peer net.Conn, ravailable uint, max_pkt_size int) error {
	remote_buf := bufio.NewWriterSize(peer, max_pkt_size)
	err := c.Gnock(remote_buf)
	if err != nil {
		return err
	}
	if ravailable > 0 {
		// Add available bytes from cr to remote_buf and flush it. The idea is to
		// send the gnock packet + as much original data as possible in the same TCP
		// packet.
		rem_buf := make([]byte, remote_buf.Available())
		// TODO: handle the case where that read will wait forever
		n, err := cr.Read(rem_buf)
		if err != nil {
			return err
		}
		_, err = remote_buf.Write(rem_buf[:n])
		if err != nil {
			return err
		}
	}
	err = remote_buf.Flush()
	if err != nil {
		return err
	}
	return CopyBidirectional(cr, cw, peer)
}

type PubKeyID [32]byte

type Verifier struct {
	known_pubkeys map[PubKeyID]ssh.PublicKey
	// This key is used to verify the signature if we don't know the pubkey ID,
	// so that a signature verification always happens. This is used to prevent
	// known public key enumeration via side channel.
	fake_pubkey ssh.PublicKey
	ar          AntiReplay
}

func NewVerifier() (*Verifier, error) {
	// Generate the fake private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	fake, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	ret := &Verifier{known_pubkeys: map[PubKeyID]ssh.PublicKey{}, fake_pubkey: fake, ar: NewAntiReplay()}
	return ret, nil
}

func (v *Verifier) addKnowPubKey(pubKey ssh.PublicKey) {
	id := sshPubKeyToID(pubKey)
	v.known_pubkeys[PubKeyID(id)] = pubKey
}

func (v *Verifier) AddAuthorizedKeysFromFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			return err
		}
		v.addKnowPubKey(pubKey)
	}

	return scanner.Err()
}

func hashedPubKeyID(rand []byte, key ssh.PublicKey) PubKeyID {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(rand)
	h.Write(sshPubKeyToID(key))
	return PubKeyID(h.Sum(nil))
}

func (v *Verifier) pubKeyFromHashedID(rand []byte, hashed_id PubKeyID) ssh.PublicKey {
	// Pre-compute hashes for all known keys and track the matching pubkey.
	// We must compute all hashes (O(n)) regardless of early matches to prevent
	// timing side-channels that would allow an attacker to enumerate authorized keys.
	var matchPubkey ssh.PublicKey = v.fake_pubkey

	for _, pubkey := range v.known_pubkeys {
		hashed_pubkey := hashedPubKeyID(rand, pubkey)
		if bytes.Equal(hashed_pubkey[:], hashed_id[:]) {
			matchPubkey = pubkey  // Track the matching key, don't return early
		}
	}

	// Always complete the loop over all keys before returning.
	// If a match was found, return the actual key; otherwise return fake_pubkey.
	return matchPubkey
}

func isTSValid(client uint64, now uint64) bool {
	if client > now {
		return client-now <= TS_HALF_WINDOW
	}
	return now-client <= TS_HALF_WINDOW
}

func (verifier *Verifier) Gnock(r io.Reader) error {
	buf := make([]byte, HDR_LEN+3)
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return err
	}

	// Version
	ver := int(buf[0])
	if ver != 1 {
		return errors.New("invalid version")
	}
	idx := VER_LEN

	// Timestamp
	ts := int64(binary.BigEndian.Uint64(buf[idx:(idx + TS_LEN)]))
	idx += TS_LEN

	// Random
	rand := buf[idx:(idx + RAND_LEN)]
	idx += RAND_LEN

	// Hashed pubkey ID == sha256(00||rand||pubkeyID)
	hashed_pubkey_id := PubKeyID(buf[idx:(idx + PUBKEYID_LEN)])
	idx += PUBKEYID_LEN
	pubkey := verifier.pubKeyFromHashedID(rand, hashed_pubkey_id)

	// Compute sha256(01||rand||hashedPubkeyID) and use the first 8 bytes for anti replay.
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(rand)
	h.Write(hashed_pubkey_id[:])
	hv := h.Sum(nil)
	arv := uint64(binary.BigEndian.Uint64(hv[:8]))
	err = verifier.ar.Check(ts, arv)
	if err != nil {
		return err
	}

	// Signature len
	sig_len := bytesToInt24(buf[idx:(idx + 3)])

	sig_buf := make([]byte, sig_len)
	n, err = r.Read(sig_buf)
	if err != nil {
		return err
	}
	if n != sig_len {
		return errors.New("signature too short")
	}
	sig := &ssh.Signature{Format: pubkey.Type(), Blob: sig_buf, Rest: []byte{}}

	// Verify signature
	err = pubkey.Verify(buf[:HDR_LEN], sig)
	if err != nil {
		return errors.New("signature verification failed")
	}
	return nil
}
