// Go echo server for cross-language acceptance (PORTING-PLAN.md P7) and for the Go<->Go
// throughput baseline the C++ numbers are compared against (P6).
//
// Everything runs on 127.0.0.1 by default, so no firewall rule is involved during testing.
//
// Usage:
//
//	go run ./goserver -addr 127.0.0.1:9000 -crypt aes -key 0123456789abcdef -data 10 -parity 3
//
// Flags mirror goecho_client so run_matrix.py can drive both sides with the same tuple of
// (crypt, data_shards, parity_shards).
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	kcp "github.com/xtaci/kcp-go/v5"
	"kcpcpp/interop/kcpcrypt"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9000", "listen address")
	cryptName := flag.String("crypt", "aes", "none|simplexor|aes|aes-gcm|salsa20|tea|xtea")
	key := flag.String("key", "kcp-cpp-interop-key", "pre-shared key")
	dataShards := flag.Int("data", 10, "FEC data shards (0 disables FEC)")
	parityShards := flag.Int("parity", 3, "FEC parity shards (0 disables FEC)")
	flag.Parse()

	block, err := kcpcrypt.Make(*cryptName, []byte(*key))
	if err != nil {
		log.Fatalf("crypt: %v", err)
	}

	if (*dataShards > 0) != (*parityShards > 0) {
		log.Fatalf("data and parity shards must both be zero or both be non-zero")
	}

	listener, err := kcp.ListenWithOptions(*addr, block, *dataShards, *parityShards)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	// READY is the handshake line run_matrix.py waits for before starting the peer.
	fmt.Printf("READY crypt=%s fec=%d/%d addr=%s\n", *cryptName, *dataShards, *parityShards, *addr)
	_ = os.Stdout.Sync()

	for {
		sess, err := listener.AcceptKCP()
		if err != nil {
			log.Printf("accept: %v", err)
			return
		}
		sess.SetNoDelay(1, 10, 2, 1)
		sess.SetWindowSize(1024, 1024)
		sess.SetMtu(1400)
		log.Printf("session from %s", sess.RemoteAddr())
		go func(s *kcp.UDPSession) {
			defer s.Close()
			err := serveEcho(s)
			log.Printf("session %s closed: %v", s.RemoteAddr(), err)
		}(sess)
	}
}

// serveEcho copies the stream back to the peer until it closes.
func serveEcho(sess *kcp.UDPSession) error {
	buf := make([]byte, 64*1024)
	for {
		n, err := sess.Read(buf)
		if n > 0 {
			if _, werr := sess.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}
