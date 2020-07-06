// Copyright 2020 Daniel Erat. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// CBC bitflipping attacks
package main

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/derat/cryptopals/common"
)

const (
	prefix = "comment1=cooking%20MCs;userdata="
	suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
)

var key []byte = common.RandBytes(16)
var iv []byte = common.RandBytes(16)

// encrypt adds prefix and suffix to s and encrypts using AES-128 in CBC mode.
func encrypt(s string) []byte {
	s = strings.ReplaceAll(s, ";", "%3B")
	s = strings.ReplaceAll(s, "=", "%3D")
	plain := prefix + s + suffix
	padded := common.PadPKCS7([]byte(plain), 16)
	return common.EncryptAES(padded, key, iv)
}

// admin decrypts b and returns true if the resulting string contains ";admin=true;".
func admin(b []byte) bool {
	padded := common.DecryptAES(b, key, iv)
	return bytes.Contains(padded, []byte(";admin=true;"))
}

func main() {
	// From the challenge:
	//
	//   You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:
	//   * Completely scrambles the block the error occurs in
	//   * Produces the identical 1-bit error(/edit) in the next ciphertext block.
	//   Stop and think for a second.
	//   Before you implement this attack, answer this question: why does CBC mode have this property?
	//
	// When we flip a bit in ciphertext block C(n), the same bit will be flipped in plaintext block P(n+1)
	// since P(n+1) gets XOR-ed against C(n) after decrypting.

	const bs = 16 // TODO: Detect this by just adding bytes until we see it grow?
	f := func(b []byte) []byte { return encrypt(string(b)) }
	pl := common.PrefixLen(f, bs)
	fmt.Printf("Prefix length is %v\n", pl)

	pad := common.A(pl % bs)                          // pad out the first modifiable block
	b := append(pad, common.A(bs)...)                 // add a full block for flipping bits
	b = append(b, []byte("\x00admin\x00true\x00")...) // finally, add a target block
	enc := encrypt(string(b))

	bo := pl + len(pad) // bit-flipping offset
	enc[bo] ^= ';'
	enc[bo+6] ^= '='
	enc[bo+11] ^= ';'
	if a := admin(enc); a {
		fmt.Println("Got admin!")
	} else {
		fmt.Println("Didn't get admin. :-(")
	}
}
