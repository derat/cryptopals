// Copyright 2020 Daniel Erat. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Single-byte XOR cipher
package main

import (
	"fmt"

	"github.com/derat/cryptopals/common"
)

func main() {
	const s = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	enc := common.Unhex(s)
	key := common.SingleByteXOR(enc)
	fmt.Printf("%#x: %q\n", key, common.XOR(enc, []byte{key}))
}
