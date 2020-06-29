// Implement repeating-key XOR
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/derat/cryptopals/common"
)

func main() {
	const plain = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"
	fmt.Println(hex.EncodeToString(common.XOR([]byte(plain), []byte("ICE"))))
}
