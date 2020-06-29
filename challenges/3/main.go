// Single-byte XOR cipher
package main

import (
	"bytes"
	"fmt"
	"math"

	"github.com/derat/cryptopals/common"
)

func main() {
	const s = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	enc := common.Unhex(s)

	bestDiff := math.MaxFloat64
	bestKey := -1
	var bestDec []byte

	for i := 0; i < 256; i++ {
		dec := common.XOR(enc, bytes.Repeat([]byte{byte(i)}, len(enc)))
		upper := common.UpperBytes(common.AlphaBytes(dec))
		freqs := common.ByteFreqs(common.CountBytes(upper))
		if diff := common.DiffByteFreqs(freqs, common.EnglishUpperFreqs); diff < bestDiff {
			bestKey = i
			bestDec = dec
			bestDiff = diff
		}
	}
	fmt.Printf("%#x: %q [%0.3f]\n", bestKey, bestDec, bestDiff)
}
