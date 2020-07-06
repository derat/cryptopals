// Copyright 2020 Daniel Erat. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// AES in ECB mode
package main

import (
	"fmt"

	"github.com/derat/cryptopals/common"
)

func main() {
	const key = "YELLOW SUBMARINE" // given in exercise
	enc := common.ReadBase64("7.txt")
	dec := common.DecryptAES(enc, []byte(key), nil /* nil IV for ECB */)
	fmt.Printf("%q\n", dec)
}
