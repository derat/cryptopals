// Copyright 2020 Daniel Erat. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// CTR bitflipping
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/derat/cryptopals/common"
)

const (
	prefix = "comment1=cooking%20MCs;userdata="
	suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
)

var key []byte = common.RandBytes(16)
var nonce uint64

func init() {
	if err := binary.Read(bytes.NewReader(common.RandBytes(8)), binary.LittleEndian, &nonce); err != nil {
		panic(err)
	}
}

// encrypt adds prefix and suffix to s and encrypts using AES-128 in CTR mode.
func encrypt(s string) []byte {
	s = strings.ReplaceAll(s, ";", "%3B")
	s = strings.ReplaceAll(s, "=", "%3D")
	plain := prefix + s + suffix

	var enc bytes.Buffer
	if err := common.NewCTR(key, nonce).Process(strings.NewReader(plain), &enc); err != nil {
		panic(err)
	}
	return enc.Bytes()
}

// admin decrypts b and returns true if the resulting string contains ";admin=true;".
func admin(b []byte) bool {
	var dec bytes.Buffer
	if err := common.NewCTR(key, nonce).Process(bytes.NewReader(b), &dec); err != nil {
		panic(err)
	}
	return bytes.Contains(dec.Bytes(), []byte(";admin=true;"))
}

func main() {
	// Determine the starting position of the text that we can modify.
	plen := -1
	a := encrypt("A")
	b := encrypt("B")
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			plen = i
			break
		}
	}
	if plen < 0 {
		panic("didn't find prefix length")
	}
	fmt.Println("Prefix has length", plen)

	// CTR seems pretty awful in any case where we can force processing multiple times from the beginning of the stream!
	// The plaintext gets XORed with the keystream, so all we need to do is encrypt once using placeholders for the ';'
	// and '=' characters, and then modify the ciphertext to substitute the desired characters.
	//
	// The ability to modify individual bytes in the ciphertext in isolation, without affecting how other bytes get
	// decrypted, seems generally problematic: even if we couldn't use simple XORs here, testing all combinations of
	// these three bytes in the ciphertext would be feasible (256**3 = ~16 million).
	enc := encrypt("foo\x00admin\x00true\x00")
	enc[plen+3] ^= ';'
	enc[plen+9] ^= '='
	enc[plen+14] ^= ';'
	if admin(enc) {
		fmt.Println("Got admin with ciphertext", hex.EncodeToString(enc))
	} else {
		panic("Didn't get admin")
	}
}
