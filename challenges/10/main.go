// Implement CBC mode
package main

import (
	"fmt"

	"github.com/derat/cryptopals/common"
)

func main() {
	const key = "YELLOW SUBMARINE"
	enc := common.ReadBase64("10.txt")
	iv := make([]byte, 16)
	dec := common.DecryptAES_CBC(enc, []byte(key), iv)
	fmt.Printf("%q\n", dec)

	const txt = "Here's some example text. I'm just going to keep writing until I get bored."
	iv[0] = 0x23
	iv[4] = 0x41
	enc = common.EncryptAES_CBC([]byte(txt), []byte(key), iv)
	dec = common.DecryptAES_CBC(enc, []byte(key), iv)
	fmt.Printf("%q\n", dec)
}
