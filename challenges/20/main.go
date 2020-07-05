// Break fixed-nonce CTR statistically
package main

import (
	"bytes"
	"fmt"

	"github.com/derat/cryptopals/common"
)

var lines = common.ReadBase64Lines("20.txt")
var key = common.RandBytes(16)

const nonce = 0

func main() {
	ctr := common.NewCTR(key, nonce)
	encs := make([][]byte, len(lines))
	for i, ln := range lines {
		var enc bytes.Buffer
		ctr.Reset()
		if err := ctr.Process(bytes.NewReader(ln), &enc); err != nil {
			panic(fmt.Sprintf("failed encrypting line %d: %v", i, err))
		}
		encs[i] = enc.Bytes()
	}

	maxLen := 0
	for _, enc := range encs {
		if len(enc) > maxLen {
			maxLen = len(enc)
		}
	}

	decs := make([][]byte, len(encs))

	// This has the same problem as Challenge 19, where when we get to the ends of the
	// longer lines, we don't have enough characters to mount a successful attack and
	// often end up getting nonsense. It'd probably be possible to improve the results
	// here with some further tweaking to common.EnglishScore, but every time I touch
	// it, I cause regressions in earlier challenges that use it. It sounds from the
	// challenge like I'm maybe just supposed to solve to the length of the shortest
	// line, which this code does successfully.
	for i := 0; i < maxLen; i++ {
		buf := make([]byte, 0, len(encs)) // bytes at position i across all ciphertexts
		for _, enc := range encs {
			if i < len(enc) {
				buf = append(buf, enc[i])
			}
		}
		xor := common.SingleByteXOR(buf)
		for j, enc := range encs {
			if i < len(enc) {
				decs[j] = append(decs[j], enc[i]^xor)
			}
		}
	}
	for _, dec := range decs {
		fmt.Printf("%q\n", dec)
	}
}
