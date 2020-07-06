// Copyright 2020 Daniel Erat. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Recover the key from CBC with IV=Key
package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/derat/cryptopals/common"
)

var key []byte = common.RandBytes(16)
var iv = key // reuse key as IV

// encrypt encrypts b using AES-128 in CBC mode using the key as the IV.
func encrypt(plain []byte) []byte {
	padded := common.PadPKCS7(plain, 16)
	return common.EncryptAES(padded, key, iv)
}

// check decrypts enc and checks the resulting plaintext. From the challenge:
//
//   Verify each byte of the plaintext for ASCII compliance (ie, look for high-ASCII values). Noncompliant messages
//   should raise an exception or return an error that includes the decrypted plaintext (this happens all the time in
//   real systems, for what it's worth).
func check(enc []byte) error {
	plain, err := common.UnpadPKCS7(common.DecryptAES(enc, key, iv))
	if err != nil {
		return errors.New("failed unpadding")
	}
	for _, b := range plain {
		if b > 127 {
			return fmt.Errorf("found non-ASCII byte %#x in %x", b, plain)
		}
	}
	return nil
}

func main() {
	const bs = 16

	// It's pretty weird that this challenge spells out all the steps to take.

	// From the challenge:
	//   Use your code to encrypt a message that is at least 3 blocks long:
	//   AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
	enc := encrypt(bytes.Repeat([]byte{255}, 4*bs)) // add a fourth block so padding block is preserved after modification

	// From the challenge:
	//   Modify the message (you are now the attacker):
	//   C_1, C_2, C_3 -> C_1, 0, C_1
	mod := append([]byte{}, enc...)  // preserve padding
	copy(mod[bs:], make([]byte, bs)) // clear second block
	copy(mod[2*bs:], enc[:bs])       // replace third block with first block

	// From the challenge:
	//   Decrypt the message (you are now the receiver) and raise the appropriate error if high-ASCII is found.
	//   As the attacker, recovering the plaintext from the error, extract the key:
	//   P'_1 XOR P'_3
	err := check(mod)
	if err == nil {
		panic("didn't get error")
	}
	es := err.Error()
	if !strings.Contains(es, "found non-ASCII byte") {
		panic(fmt.Sprintf("got unexpected error %q", es))
	}
	ef := strings.Fields(es)
	dec, err := hex.DecodeString(ef[len(ef)-1])
	if err != nil {
		panic(fmt.Sprint("failed to parse plaintext: ", err))
	}

	// During CBC decryption, plaintext block N is XORed with ciphertext block N-1.
	// Since we modified the second block to contain zeros, the third block is effectively not XORed.
	// We now have the same block XORed with the IV and unchanged, so we can XOR them together to get
	// the IV (which is the same as the key here).
	b1 := dec[:bs]
	b3 := dec[2*bs : 3*bs]
	rkey := common.XOR(b1, b3)

	// Now check that we're able to use the recovered key/IV to decrypt ciphertext encrypted using the
	// original key. (This isn't part of the challenge.)
	enc = encrypt(common.ReadBase64("data.txt"))
	if plain, err := common.UnpadPKCS7(common.DecryptAES(enc, rkey, rkey)); err != nil {
		panic(err)
	} else {
		fmt.Printf("%q\n", plain)
	}
}
