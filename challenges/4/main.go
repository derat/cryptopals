// Detect single-character XOR
package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/derat/cryptopals/common"
)

func main() {
	f, err := os.Open("4.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	var bestDec []byte
	var bestScore *common.Score

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		enc := common.Unhex(sc.Text())
		for i := 0; i < 256; i++ {
			dec := common.XOR(enc, []byte{byte(i)})
			if score := common.EnglishScore(dec); score.Better(bestScore) {
				bestDec = dec
				bestScore = &score
			}
		}
	}
	if sc.Err() != nil {
		panic(err)
	}

	fmt.Printf("%q\n", bestDec)
}
