// Implement the MT19937 Mersenne Twister RNG
package main

import (
	"fmt"

	"github.com/derat/cryptopals/common"
)

func main() {
	mt := common.NewMT19937(1)
	for i := 0; i < 10; i++ {
		fmt.Println(mt.Extract())
	}
}
