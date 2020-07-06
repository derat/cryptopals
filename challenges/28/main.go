// Copyright 2020 Daniel Erat. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Implement a SHA-1 keyed MAC
package main

import (
	"bytes"

	"github.com/derat/cryptopals/common"
	"github.com/derat/cryptopals/sha1"
)

// From the challenge:
//
//   Write a function to authenticate a message under a secret key by using a secret-prefix MAC, which is simply:
//   SHA1(key || message)
func sign(msg, key []byte) []byte {
	concat := append([]byte{}, key...)
	concat = append(concat, msg...)
	mac := sha1.Sum(concat)
	return mac[:]
}

func verify(msg, mac, key []byte) bool {
	return bytes.Equal(sign(msg, key), mac)
}

func main() {
	// From the challenge:
	//
	//   Verify that you cannot tamper with the message without breaking the MAC you've produced, and that you can't
	//   produce a new MAC without knowing the secret key.

	var skey = common.RandBytes(16)
	const orig = "This is a test"
	mac := sign([]byte(orig), skey)
	if !verify([]byte(orig), mac, skey) {
		panic("failed verifying MAC")
	}

	mod := []byte(orig)
	mod[0] = 'A'
	if verify(mod, mac, skey) {
		panic("was able to reuse MAC with modified message")
	}

	copy(mod, []byte(orig))
	mod = append(mod, 'A')
	if verify(mod, mac, skey) {
		panic("was able to reuse MAC with appended message")
	}

	if verify(mod, sign(mac, nil), skey) {
		panic("was able to verify using MAC generated without key")
	}

	if verify(mod, sign(mac, common.A(16)), skey) {
		panic("was able to verify using MAC generated with incorrect key")
	}
}
