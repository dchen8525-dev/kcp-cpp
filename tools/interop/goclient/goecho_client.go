// Go echo client: drives the Go server (Go<->Go baseline) or the C++ server (P7 reverse direction).
//
// Prints one machine-readable RESULT line so run_matrix.py and run_bench.py do not have to parse
// log noise:
//
//	RESULT ok=1 bytes=104857600 sha256=... mbps=12.34 elapsed_ms=... iters=100
//
// -iters N sends N * -bytes bytes as one continuous stream and verifies the echo against the same
// payload repeated, so the measurement covers sustained throughput rather than N round trips. The
// C++ client in examples/echo_client.cc implements exactly the same loop.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
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
	iters := flag.Int("iters", 1, "repeat the payload this many times over one stream")
	timeout := flag.Duration("timeout", 30*time.Second, "overall deadline")
	// Explicit knobs, never the library defaults: PORTING-PLAN.md §6.3 (#68).
	sndwnd := flag.Int("sndwnd", 32, "send window (segments)")
	rcvwnd := flag.Int("rcvwnd", 32, "receive window (segments)")
	mtu := flag.Int("mtu", 1400, "mtu")
	flag.Parse()

	cfg := config{
		addr:         *addr,
		cryptName:    *cryptName,
		key:          *key,
		dataShards:   *dataShards,
		parityShards: *parityShards,
		size:         *size,
		chunk:        *chunk,
		iters:        *iters,
		timeout:      *timeout,
		sndwnd:       *sndwnd,
		rcvwnd:       *rcvwnd,
		mtu:          *mtu,
	}
	if err := execute(cfg); err != nil {
		fmt.Printf("RESULT ok=0 error=%q iters=%d\n", err.Error(), cfg.iters)
		os.Exit(1)
	}
}

type config struct {
	addr         string
	cryptName    string
	key          string
	dataShards   int
	parityShards int
	size         int
	chunk        int
	iters        int
	timeout      time.Duration
	sndwnd       int
	rcvwnd       int
	mtu          int
}

func execute(cfg config) error {
	block, err := kcpcrypt.Make(cfg.cryptName, []byte(cfg.key))
	if err != nil {
		return err
	}
	if (cfg.dataShards > 0) != (cfg.parityShards > 0) {
		return errors.New("data and parity shards must both be zero or both be non-zero")
	}

	sess, err := kcp.DialWithOptions(cfg.addr, block, cfg.dataShards, cfg.parityShards)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer sess.Close()
	sess.SetNoDelay(1, 10, 2, 1)
	sess.SetWindowSize(cfg.sndwnd, cfg.rcvwnd)
	sess.SetMtu(cfg.mtu)
	if err := sess.SetDeadline(time.Now().Add(cfg.timeout)); err != nil {
		return fmt.Errorf("deadline: %w", err)
	}

	payload := make([]byte, cfg.size)
	for i := range payload {
		payload[i] = byte(i*7 + 11)
	}
	total := cfg.size * cfg.iters

	start := time.Now()

	// Writer: pushes the whole stream without waiting for echoes, exactly like the C++ client.
	writeErr := make(chan error, 1)
	go func() {
		written := 0
		for written < total {
			off := written % cfg.size
			n := cfg.chunk
			if n > cfg.size-off {
				n = cfg.size - off
			}
			if n > total-written {
				n = total - written
			}
			if _, werr := sess.Write(payload[off : off+n]); werr != nil {
				writeErr <- werr
				return
			}
			written += n
		}
		writeErr <- nil
	}()

	// Reader: compares the echo against the payload repeated, so it never has to buffer the stream.
	buf := make([]byte, 64*1024)
	received := 0
	var readErr error
	for received < total {
		n, rerr := sess.Read(buf)
		if n > 0 {
			for i := 0; i < n; i++ {
				if buf[i] != payload[(received+i)%cfg.size] {
					readErr = fmt.Errorf("echo mismatch at byte %d", received+i)
					break
				}
			}
			received += n
		}
		if readErr != nil {
			break
		}
		if rerr != nil {
			readErr = fmt.Errorf("read echo: %w", rerr)
			break
		}
	}
	elapsed := time.Since(start)

	wErr := <-writeErr
	sess.Close()

	if wErr != nil {
		return fmt.Errorf("write: %w", wErr)
	}
	if readErr != nil {
		return readErr
	}
	if received != total {
		return fmt.Errorf("short read: %d of %d bytes", received, total)
	}

	sum := sha256.Sum256(payload)
	mbps := float64(total) / (1024 * 1024) / elapsed.Seconds()
	fmt.Printf("RESULT ok=1 bytes=%d sha256=%s mbps=%.2f elapsed_ms=%.1f iters=%d\n",
		total, hex.EncodeToString(sum[:]), mbps, float64(elapsed.Microseconds())/1000.0, cfg.iters)
	return nil
}
