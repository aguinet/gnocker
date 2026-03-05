package gnocker

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"
)

func NewKey(t *testing.T) ssh.Signer {
	// Generate a new ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Convert the private key to SSH format
	ret, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	return ret
}

func TestProto(t *testing.T) {
	buf := new(bytes.Buffer)
	sig := NewKey(t)

	c := NewClient(sig, rand.Reader)
	err := c.Gnock(buf)
	if err != nil {
		t.Fatalf("client error: %v", err)
	}

	verifier, err := NewVerifier()
	if err != nil {
		t.Fatalf("verifier create error: %v", err)
	}
	verifier.addKnowPubKey(sig.PublicKey())
	reader := bytes.NewReader(buf.Bytes())
	err = verifier.Gnock(reader)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}

	// Trying again should lead to a replay error
	reader = bytes.NewReader(buf.Bytes())
	err = verifier.Gnock(reader)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestWrapClient(t *testing.T) {
	sig := NewKey(t)
	c := Client{sig, rand.Reader}

	// "Fake" peer connection
	peer_server, peer_client := net.Pipe()

	// Emulate stdin and stdout
	_, stdout_w := io.Pipe()
	stdin_r, stdin_w := io.Pipe()

	go func() {
		// Emulate original data from stdin
		stdin_w.Write([]byte("HELLO"))
	}()

	// Wrap the client
	go func() {
		c.WrapClient(stdin_r, stdout_w, peer_client, 5, 1000)
	}()

	// Verify gnock packet on server side
	verifier, err := NewVerifier()
	if err != nil {
		t.Fatalf("verifier create error: %v", err)
	}
	verifier.addKnowPubKey(sig.PublicKey())
	err = verifier.Gnock(peer_server)
	if err != nil {
		t.Fatalf("verifier error: %v", err)
	}

	// Verify we also have early data
	buf := make([]byte, 5)
	io.ReadFull(peer_server, buf)
	if !bytes.Equal([]byte("HELLO"), buf) {
		t.Fatalf("invalid early data")
	}
}
