// Go echo client: drives the Go server (Go<->Go baseline) or the C++ server (P7 reverse direction).
//
// Prints one machine-readable RESULT line so run_matrix.py does not have to parse log noise:
//
//	RESULT ok=1 bytes=1048576 sha256=... mbps=12.34 elapsed_ms=...
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
	"kcpcpp/interop/kcpcrypt"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9000", "server address")
	cryptName := flag.String("crypt", "aes", "none|simplexor|aes|aes-gcm|salsa20|tea|xtea")
	key := flag.String("key", "kcp-cpp-interop-key", "pre-shared key")
	dataShards := flag.Int("data", 10, "FEC data shards (0 disables FEC)")
	parityShards := flag.Int("parity", 3, "FEC parity shards (0 disables FEC)")
	size := flag.Int("bytes", 1<<20, "payload size in bytes")
	chunk := flag.Int("chunk", 32*1024, "write chunk size")
	timeout := flag.Duration("timeout", 30*time.Second, "overall deadline")
	flag.Parse()

	if err := execute(*addr, *cryptName, *key, *dataShards, *parityShards, *size, *chunk, *timeout); err != nil {
		fmt.Printf("RESULT ok=0 error=%q\n", err.Error())
		os.Exit(1)
	}
}

func execute(addr, cryptName, key string, dataShards, parityShards, size, chunk int,
	timeout time.Duration) error {
	block, err := kcpcrypt.Make(cryptName, []byte(key))
	if err != nil {
		return err
	}
	if (dataShards > 0) != (parityShards > 0) {
		return errors.New("data and parity shards must both be zero or both be non-zero")
	}

	sess, err := kcp.DialWithOptions(addr, block, dataShards, parityShards)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer sess.Close()
	sess.SetNoDelay(1, 10, 2, 1)
	sess.SetWindowSize(1024, 1024)
	sess.SetMtu(1400)
	if err := sess.SetDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("deadline: %w", err)
	}

	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i*7 + 11)
	}

	start := time.Now()
	go func() {
		for off := 0; off < len(payload); off += chunk {
			end := off + chunk
			if end > len(payload) {
				end = len(payload)
			}
			if _, werr := sess.Write(payload[off:end]); werr != nil {
				return
			}
		}
	}()

	echoed := make([]byte, size)
	if _, err := io.ReadFull(sess, echoed); err != nil {
		return fmt.Errorf("read echo: %w", err)
	}
	elapsed := time.Since(start)

	if !bytes.Equal(payload, echoed) {
		sumWant := sha256.Sum256(payload)
		sumGot := sha256.Sum256(echoed)
		return fmt.Errorf("echo mismatch: want %s got %s",
			hex.EncodeToString(sumWant[:8]), hex.EncodeToString(sumGot[:8]))
	}

	sum := sha256.Sum256(payload)
	mbps := float64(size) / (1024 * 1024) / elapsed.Seconds()
	fmt.Printf("RESULT ok=1 bytes=%d sha256=%s mbps=%.2f elapsed_ms=%.1f\n",
		size, hex.EncodeToString(sum[:]), mbps, float64(elapsed.Microseconds())/1000.0)
	return nil
}
