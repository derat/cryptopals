// Copyright 2020 Daniel Erat. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Detect single-character XOR
package main

import (
	"fmt"

	"github.com/derat/cryptopals/common"
)

func main() {
	var bestDec []byte
	var bestScore *common.Score
	for _, enc := range common.ReadHexLines("4.txt") {
		for i := 0; i < 256; i++ {
			dec := common.XOR(enc, []byte{byte(i)})
			if score := common.EnglishScore(dec); score.Better(bestScore) {
				bestDec = dec
				bestScore = &score
			}
		}
	}
	fmt.Printf("%q\n", bestDec)
}
