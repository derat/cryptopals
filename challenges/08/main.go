// Detect AES in ECB mode
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/derat/cryptopals/common"
)

func main() {
	const bs = 16
	for i, enc := range common.ReadHexLines("8.txt") {
		seen := make(map[string]struct{})
		for start := 0; start < len(enc); start += bs {
			block := hex.EncodeToString(enc[start : start+bs])
			if _, ok := seen[block]; ok {
				fmt.Printf("Block %q seen twice on line %d\n", block, i)
				os.Exit(0)
			}
			seen[block] = struct{}{}
		}
	}
	fmt.Println("Duplicate block not found")
}
