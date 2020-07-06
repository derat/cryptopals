// Copyright 2020 Daniel Erat. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Implement PKCS#7 padding
package main

import (
	"fmt"

	"github.com/derat/cryptopals/common"
)

func main() {
	const in = "YELLOW SUBMARINE"
	fmt.Printf("%q\n", common.PadPKCS7([]byte(in), 20))
}
