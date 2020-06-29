// AES in ECB mode
package main

import (
	"crypto/aes"
	"fmt"

	"github.com/derat/cryptopals/common"
)

func main() {
	const key = "YELLOW SUBMARINE" // given in exercise
	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err)
	}

	enc := common.ReadBase64("7.txt")
	dec := make([]byte, 0, len(enc))
	bs := cipher.BlockSize()
	for i := 0; i < len(enc); i += bs {
		src := make([]byte, bs)
		dst := make([]byte, bs)
		n := copy(src, enc[i:])
		cipher.Decrypt(dst, src)
		dec = append(dec, dst[:n]...)
	}
	fmt.Printf("%q\n", dec)
}
