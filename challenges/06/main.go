// Break repeating-key XOR
package main

import (
	"fmt"
	"sort"

	"github.com/derat/cryptopals/common"
)

func main() {
	// Suggested test of Hamming distance code (should be 37)
	//fmt.Println(common.Hamming([]byte("this is a test"), []byte("wokka wokka!!!")))

	enc := common.ReadBase64("6.txt")

	const (
		minKeysize  = 2
		maxKeysize  = 40
		keyBlocks   = 4
		numKeysizes = 5
	)
	if keyBlocks*maxKeysize > len(enc) {
		panic(fmt.Sprintf("can't check %v blocks of size %v in input of size %v", keyBlocks, maxKeysize, len(enc)))
	}

	type keysizeDist struct {
		size int
		dist float64
	}
	var keysizeDists []keysizeDist

	for ks := minKeysize; ks <= maxKeysize; ks++ {
		first := enc[0:ks]
		distSum := 0.0
		for i := 1; i < keyBlocks; i++ {
			start := i * ks
			second := enc[start : start+ks]
			distSum += float64(common.Hamming(first, second)) / float64(ks)
		}
		dist := distSum / float64(keyBlocks-1)
		keysizeDists = append(keysizeDists, keysizeDist{ks, dist})
	}
	sort.Slice(keysizeDists, func(i, j int) bool {
		return keysizeDists[i].dist < keysizeDists[j].dist
	})

	var bestKey, bestDec []byte
	var bestScore *common.Score
	for _, kd := range keysizeDists[:numKeysizes] {
		key := make([]byte, kd.size)
		for i := range key {
			var block []byte
			for j := i; j < len(enc); j += len(key) {
				block = append(block, enc[j])
			}
			key[i] = common.SingleByteXOR(block)
		}
		dec := common.XOR(enc, key)
		if score := common.EnglishScore(dec); score.Better(bestScore) {
			bestKey = key
			bestDec = dec
			bestScore = &score
		}
	}

	fmt.Printf("%q: %q", bestKey, bestDec)
}
