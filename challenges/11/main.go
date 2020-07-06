// Copyright 2020 Daniel Erat. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// An ECB/CBC detection oracle
package main

import (
	"bytes"
	"fmt"

	"github.com/derat/cryptopals/common"
)

// encrypt encrypts b using AES-128 with a random key and 5-10 random bytes before and after b.
// It uses ECB half the time and CBC with a random IV the other half.
func encrypt(b []byte) []byte {
	pre := common.RandBytes(5 + common.RandInt(6))
	suf := common.RandBytes(5 + common.RandInt(6))
	plain := make([]byte, 0, len(pre)+len(b)+len(suf))
	plain = append(plain, pre...)
	plain = append(plain, b...)
	plain = append(plain, suf...)
	plain = common.PadPKCS7(plain, 16)

	var iv []byte
	if common.RandInt(2) == 1 {
		iv = common.RandBytes(16) // use CBC
	}
	key := common.RandBytes(16)
	return common.EncryptAES(plain, key, iv)
}

func main() {
	plain := bytes.Repeat([]byte{'A'}, 3*16)
	var ecb, cbc int
	for i := 0; i < 100; i++ {
		enc := encrypt(plain)
		// Compare the second and third blocks, which should consist entirely of our plaintext.
		// If ECB is used, they'll be the same.
		if bytes.Equal(enc[16:32], enc[32:48]) {
			ecb++
		} else {
			cbc++
		}
	}
	fmt.Println("ECB:", ecb)
	fmt.Println("CBC:", cbc)
}
