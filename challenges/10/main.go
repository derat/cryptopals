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
	dec := common.DecryptAES(enc, []byte(key), iv)
	fmt.Printf("%q\n", dec)

	const txt = "Here's some example text. I'm just going to keep writing until I get bored."
	iv[0] = 0x23
	iv[4] = 0x41
	b := common.PadPKCS7([]byte(txt), 16)
	enc = common.EncryptAES(b, []byte(key), iv)
	dec = common.DecryptAES(enc, []byte(key), iv)
	fmt.Printf("%q\n", dec)
}
