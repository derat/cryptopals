package common

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
)

// Unhex decodes the supplied hexadecimal string, panicking on error.
func Unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("failed to decode %q: %v", s, err))
	}
	return b
}

// XOR xors a with b. If b is shorter than a, it is repeated.
func XOR(a, b []byte) []byte {
	x := make([]byte, len(a))
	for i := range a {
		x[i] = a[i] ^ b[i%len(b)]
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

// Hamming returns the Hamming distance (i.e. number of differing bits) between a and b,
// which must be of the same length.
func Hamming(a, b []byte) int {
	if len(a) != len(b) {
		panic(fmt.Sprintf("slice lengths differ (%v vs. %v)", len(a), len(b)))
	}
	dist := 0
	for i := range a {
		for diff := a[i] ^ b[i]; diff != 0; diff = diff >> 1 {
			if diff&0x1 == 0x1 {
				dist++
			}
		}
	}
	return dist
}

// RandBytes returns a slice of n cryptographically-secure random bytes.
func RandBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// RandInt64 returns a cryptographically-secure random integer in the range [0, n).
func RandInt64(max int64) int64 {
	v, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		panic(err)
	}
	return v.Int64()
}

// RandInt returns a cryptographically-secure random integer in the range [0, n).
func RandInt(max int) int {
	return int(RandInt64(int64(max)))
}
