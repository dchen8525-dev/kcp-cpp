// Package kcptap records the first datagram that crosses a packet connection, in the plain-text
// format that tools/interop/dump_packet.py reads (PORTING-PLAN.md §6.1).
//
// The C++ side implements the same format in examples/echo_common.cc (echo::FirstPacketDump), so a
// capture taken by one implementation and a capture of the same datagram taken by the other are
// identical files apart from the direction tag. That equality is the test for both taps.
package kcptap

import (
	"fmt"
	"net"
	"os"
	"sync"
)

// Dumper writes exactly one packet to a file and then goes quiet. Safe for concurrent use: the
// session's read and write paths both reach it.
type Dumper struct {
	mu   sync.Mutex
	path string
	done bool
}

// New returns a dumper for path. An empty path yields a disabled dumper.
func New(path string) *Dumper {
	return &Dumper{path: path}
}

// Enabled reports whether anything will be written.
func (d *Dumper) Enabled() bool {
	return d != nil && d.path != ""
}

// Record writes the first packet, tagged with its direction. Later calls are ignored.
func (d *Dumper) Record(outgoing bool, data []byte) {
	if d == nil || d.path == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.done {
		return
	}
	d.done = true

	file, err := os.Create(d.path)
	if err != nil {
		return
	}
	defer file.Close()

	direction := "in"
	if outgoing {
		direction = "out"
	}
	fmt.Fprintf(file, "KCPDUMP 1 dir=%s len=%d\n", direction, len(data))
	// 32 bytes per line: "00000000 " then 64 lowercase hex digits.
	for offset := 0; offset < len(data); offset += 32 {
		end := offset + 32
		if end > len(data) {
			end = len(data)
		}
		fmt.Fprintf(file, "%08x %x\n", offset, data[offset:end])
	}
}

// Conn wraps a net.PacketConn so both directions become observable. Wrap the connection before
// handing it to kcp.ServeConn or kcp.NewConn; the kcp-go API accepts a net.PacketConn precisely so
// callers can interpose like this.
type Conn struct {
	net.PacketConn
	Dumper *Dumper
}

// ReadFrom records the first inbound datagram.
func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err == nil && n > 0 {
		c.Dumper.Record(false, p[:n])
	}
	return n, addr, err
}

// WriteTo records the first outbound datagram.
func (c *Conn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.Dumper.Record(true, p)
	return c.PacketConn.WriteTo(p, addr)
}
