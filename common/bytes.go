package common

import (
	"encoding/hex"
	"fmt"
)

// Unhex decodes the supplied hexadecimal string, panicking on error.
func Unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("failed to decode %q: %v", s, err))
	}
	return b
}

// XOR operates on a and b, which must be the same length.
func XOR(a, b []byte) []byte {
	if len(a) != len(b) {
		panic(fmt.Sprintf("buffer lengths don't match (%v vs. %v)", len(a), len(b)))
	}
	x := make([]byte, len(a))
	for i := range a {
		x[i] = a[i] ^ b[i]
	}
	return x
}

// UpperBytes returns a buffer where lowercase ASCII letters in orig are uppercased.
// All other bytes are unchanged.
func UpperBytes(orig []byte) []byte {
	upper := make([]byte, len(orig))
	for i, b := range orig {
		if b >= 'a' && b <= 'z' {
			upper[i] = 'A' + (b - 'a')
		} else {
			upper[i] = b
		}
	}
	return upper
}

// AlphaBytes returns a buffer containing only ASCII letters from orig.
func AlphaBytes(orig []byte) []byte {
	alpha := make([]byte, 0, len(orig))
	for _, b := range orig {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') {
			alpha = append(alpha, b)
		}
	}
	return alpha
}
