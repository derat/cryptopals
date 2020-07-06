// Copyright 2020 Daniel Erat. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Fixed XOR: Write a function that takes two equal-length buffers and produces their XOR combination.
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/derat/cryptopals/common"
)

func main() {
	const (
		a = "1c0111001f010100061a024b53535009181c"
		b = "686974207468652062756c6c277320657965"
	)
	fmt.Println(hex.EncodeToString(common.XOR(common.Unhex(a), common.Unhex(b))))
}
