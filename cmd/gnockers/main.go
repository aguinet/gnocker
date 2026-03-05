package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	gnocker "github.com/aguinet/gnocker/lib"
)

func gracefulShutdown(sigChan chan os.Signal, listener net.Listener, wg *sync.WaitGroup) {
	<-sigChan
	signal.Stop(sigChan)
	close(sigChan)

	// Close the listener to stop accepting new connections. This will have the
	// effect of breaking the main "accept" loop and wait for all current
	// connections to finish.
	listener.Close()
}

func main() {
	akf := flag.String("akf", "", "authorized key file")
	server_host := flag.String("server-host", "", "SSH server hostname")
	server_port := flag.String("server-port", "22", "SSH server port")
	listen_host := flag.String("listen-host", "::", "listening host")
	listen_port := flag.String("listen-port", "22", "listening port")

	flag.Parse()

	verifier, err := gnocker.NewVerifier()
	if err != nil {
		log.Fatalf("error creating verifier: %v\n", err)
	}
	err = verifier.AddAuthorizedKeysFromFile(*akf)
	if err != nil {
		log.Fatalf("error while adding authorized key file: %v\n", err)
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(*listen_host, *listen_port))
	if err != nil {
		log.Fatalf("%v_n", err)
		return
	}
	defer ln.Close()

	var wg sync.WaitGroup
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go gracefulShutdown(sigChan, ln, &wg)

	server_dst := net.JoinHostPort(*server_host, *server_port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			break
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			err := verifier.Gnock(conn)
			defer conn.Close()
			if err != nil {
				log.Printf("error gnocking from '%s': peer verification error: %v\n", conn.RemoteAddr(), err)
				return
			}
			server, err := net.Dial("tcp", server_dst)
			if err != nil {
				log.Printf("unable to dial server: %v\n", err)
				return
			}
			log.Printf("successful gnocking from '%s'\n", conn.RemoteAddr())
			gnocker.CopyBidirectional(conn, conn, server)
		}()
	}

	log.Println("shutting down gracefully, waiting for current connections to close...")
	wg.Wait()
}
