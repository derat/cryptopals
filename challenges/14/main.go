// Copyright 2020 Daniel Erat. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Byte-at-a-time ECB decryption (Harder)
package main

import (
	"encoding/base64"
	"fmt"

	"github.com/derat/cryptopals/common"
)

const secret = `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`

var secretDec []byte // decoded version of secret
var key []byte = common.RandBytes(16)
var randomPrefix []byte = common.RandBytes(1 + common.RandInt(60))

func init() {
	var err error
	if secretDec, err = base64.StdEncoding.DecodeString(secret); err != nil {
		panic(err)
	}
}

// encrypt prepends a fixed random prefix and appends secretDec to b and encrypts using AES-128 in ECB mode.
func encrypt(b []byte) []byte {
	plain := make([]byte, 0, len(randomPrefix)+len(b)+len(secretDec))
	plain = append(plain, randomPrefix...)
	plain = append(plain, b...)
	plain = append(plain, secretDec...)
	plain = common.PadPKCS7(plain, 16)
	return common.EncryptAES(plain, key, nil)
}

func main() {
	bs := common.BlockSizeECB(encrypt)
	fmt.Println("Using ECB with block size", bs)
	pl := common.PrefixLen(encrypt, bs)
	sl := common.SuffixLen(encrypt, bs)
	fmt.Printf("Prefix length is %v, suffix is %v\n", pl, sl)
	pad := bs - (pl % bs)
	fmt.Printf("Need %v byte(s) to start new block\n", pad)

	// Wrap the encryption function to eliminate its fixed prefix.
	f := func(b []byte) []byte {
		enc := encrypt(append(common.A(pad), b...))
		return enc[pl+pad:]
	}

	var known []byte
	for len(known) < sl {
		known = append(known, common.NextSuffixByteECB(f, bs, known))
	}
	fmt.Printf("%q\n", known)
}
