package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"syscall"

	gnocker "github.com/aguinet/gnocker/lib"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

func loadIdentity(path string) (ssh.Signer, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			// TODO: it's sometimes possible to get the public key from an encrypted
			// private key, and thus verify if the SSH agent can sign for it.
			// https://security.stackexchange.com/questions/268793/is-it-possible-to-retrieve-the-public-key-from-an-encrypted-or-passphrase-protec

			// Ask for the passphrase!
			fmt.Print("Enter passphrase for private key: ")
			passphrase, err := terminal.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return nil, err
			}
			fmt.Println()

			signer, err = ssh.ParsePrivateKeyWithPassphrase(data, passphrase)
			if err != nil {
				return nil, err
			}
		} else {
			// Try to parse as a public key and find a signer in the SSH agent that
			// can handle the associated public key.
			pubKey, _, _, _, err := ssh.ParseAuthorizedKey(data)
			if err != nil {
				return nil, fmt.Errorf("unable to load key: %w", err)
			}
			signer, err = signerFromAgent(pubKey)
			if err != nil {
				return nil, err
			}
		}
	}
	return signer, nil
}

func signerFromAgent(pubKey ssh.PublicKey) (ssh.Signer, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("failed to open SSH_AUTH_SOCK: %w", err)
	}

	ac := agent.NewClient(conn)
	signers, err := ac.Signers()
	if err != nil {
		return nil, fmt.Errorf("unable to get signers from agent: %w", err)
	}

	pubKeyMarshal := pubKey.Marshal()
	for _, signer := range signers {
		if bytes.Equal(signer.PublicKey().Marshal(), pubKeyMarshal) {
			return signer, nil
		}
	}
	return nil, errors.New("can't find the provided identity within the SSH agent")
}

func main() {
	host := flag.String("h", "", "host to connect to")
	port := flag.String("p", "22", "port to connect to")
	identity := flag.String("i", "", "path to SSH private key, or a public key identity loaded in the SSH agent")

	flag.Parse()

	peer, err := net.Dial("tcp", net.JoinHostPort(*host, *port))
	if err != nil {
		log.Fatalf("unable to dial: %v\n", err)
		return
	}

	mss, err := gnocker.TCPMSS(peer)
	if err != nil {
		log.Fatalf("error getting TCP MSS: %v\n", err)
	}

	signer, err := loadIdentity(*identity)
	if err != nil {
		log.Fatalf("error loading identity: %v\n", err)
	}

	client := gnocker.NewClient(signer, rand.Reader)
	stdin_avail, _ := gnocker.AvailableBytesFd(uintptr(syscall.Stdin))
	client.WrapClient(os.Stdin, os.Stdout, peer, stdin_avail, mss)
}
