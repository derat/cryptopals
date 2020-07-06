// Copyright 2020 Daniel Erat. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// PKCS#7 padding validation
package main

import (
	"fmt"

	"github.com/derat/cryptopals/common"
)

func main() {
	for _, s := range []string{
		"ICE ICE BABY\x04\x04\x04\x04", // valid
		"ICE ICE BABY\x05\x05\x05\x05", // invalid
		"ICE ICE BABY\x01\x02\x03\x04", // invalid
		"",                             // invalid (not in challenge)
		"\x12",                         // invalid (not in challenge)
	} {
		if u, err := common.UnpadPKCS7([]byte(s)); err != nil {
			fmt.Printf("UnpadPKCS7(%q) failed: %v\n", s, err)
		} else {
			fmt.Printf("UnpadPKCS7(%q) = %q\n", s, u)
		}
	}
}
