// Package kcpcrypt maps stable cipher names to kcp-go BlockCrypt instances.
//
// The names are the contract between goecho_server, goecho_client, the C++ side and
// run_matrix.py; a mismatch here shows up as "cannot decrypt", which is expensive to debug.
package kcpcrypt

import (
	"fmt"

	kcp "github.com/xtaci/kcp-go/v5"
)

// Make returns the BlockCrypt for a cipher name with the key padded/truncated to the cipher's
// required size. Names: none, simplexor, aes, aes-gcm, salsa20, tea, xtea.
func Make(name string, key []byte) (kcp.BlockCrypt, error) {
	switch name {
	case "none":
		return kcp.NewNoneBlockCrypt(key)
	case "simplexor":
		return kcp.NewSimpleXORBlockCrypt(key)
	case "aes":
		return kcp.NewAESBlockCrypt(PadKey(key, 16))
	case "aes-gcm":
		return kcp.NewAESGCMCrypt(PadKey(key, 16))
	case "salsa20":
		return kcp.NewSalsa20BlockCrypt(PadKey(key, 32))
	case "tea":
		return kcp.NewTEABlockCrypt(PadKey(key, 16))
	case "xtea":
		return kcp.NewXTEABlockCrypt(PadKey(key, 16))
	default:
		return nil, fmt.Errorf("unknown cipher %q", name)
	}
}

// PadKey copies key into a fresh buffer of the given size.
func PadKey(key []byte, size int) []byte {
	out := make([]byte, size)
	copy(out, key)
	return out
}
