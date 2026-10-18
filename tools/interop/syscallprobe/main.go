// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Platform calibration for PORTING-PLAN.md §6.3 / P8, Go side: what does one datagram send cost?
//
// bench/syscall_cost.cc measures the C++ wrappers. The surprising number there is that sendto() on an
// unconnected socket costs ~40us on this host while recvfrom() costs ~1us, and connecting the socket
// drops send() to ~3us. Since kcp-go also uses WriteTo (unconnected), the same probe has to run
// through Go's runtime before that number can be attributed to the host rather than to a wrapper.
//
// Usage: syscallprobe.exe [-count 2000] [-size 1400]

package main

import (
	"flag"
	"fmt"
	"net"
	"time"
)

func perOp(elapsed time.Duration, count int) float64 {
	if count == 0 {
		return 0
	}
	return float64(elapsed.Microseconds()) / float64(count)
}

func main() {
	count := flag.Int("count", 2000, "datagrams per measurement")
	size := flag.Int("size", 1400, "payload bytes")
	flag.Parse()

	payload := make([]byte, *size)

	rcv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		fmt.Printf("listen: %v\n", err)
		return
	}
	defer rcv.Close()
	dest := rcv.LocalAddr().(*net.UDPAddr)

	// Unconnected WriteTo: what kcp-go's output callback does.
	snd, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		fmt.Printf("listen: %v\n", err)
		return
	}
	start := time.Now()
	sent := 0
	for i := 0; i < *count; i++ {
		if _, err := snd.WriteTo(payload, dest); err == nil {
			sent++
		}
	}
	writeTo := perOp(time.Since(start), *count)
	snd.Close()

	// Connected send on a fresh socket: same payload, same destination, one less address argument.
	conn, err := net.DialUDP("udp4", nil, dest)
	if err != nil {
		fmt.Printf("dial: %v\n", err)
		return
	}
	start = time.Now()
	sentConn := 0
	for i := 0; i < *count; i++ {
		if _, err := conn.Write(payload); err == nil {
			sentConn++
		}
	}
	write := perOp(time.Since(start), *count)
	conn.Close()

	// recvfrom on the same socket, draining whatever the two loops above queued.
	buffer := make([]byte, *size+64)
	start = time.Now()
	received := 0
	rcv.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	for i := 0; i < *count*2; i++ {
		if _, _, err := rcv.ReadFromUDP(buffer); err != nil {
			break
		}
		received++
	}
	readFrom := perOp(time.Since(start), received)

	fmt.Printf("GOSYSCALL write_to_us=%.2f write_us=%.2f read_from_us=%.2f sent=%d/%d sent_conn=%d/%d received=%d\n",
		writeTo, write, readFrom, sent, *count, sentConn, *count, received)
}
