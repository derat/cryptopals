// Detect single-character XOR
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"math"
	"os"

	"github.com/derat/cryptopals/common"
)

func main() {
	f, err := os.Open("4.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	bestDiff := math.MaxFloat64
	var bestDec []byte

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		enc := common.Unhex(sc.Text())
		for i := 0; i < 256; i++ {
			dec := common.XOR(enc, bytes.Repeat([]byte{byte(i)}, len(enc)))
			upper := common.UpperBytes(common.AlphaBytes(dec))
			if float64(len(upper)) < float64(len(dec))*0.75 {
				continue
			}
			freqs := common.ByteFreqs(common.CountBytes(upper))
			if diff := common.DiffByteFreqs(freqs, common.EnglishUpperFreqs); diff < bestDiff {
				bestDec = dec
				bestDiff = diff
			}
		}
	}
	if sc.Err() != nil {
		panic(err)
	}

	// TODO: This prints the following: "nOW\x00THAT\x00THE\x00PARTY\x00IS\x00JUMPING*" [0.646]
	// That looks like the right string, but we're probably using the wrong key.
	fmt.Printf("%q [%0.3f]\n", bestDec, bestDiff)
}
