// Byte-at-a-time ECB decryption (Simple)
package main

import (
	"encoding/base64"
	"fmt"

	"github.com/derat/cryptopals/common"
)

const secret = `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`

var secretDec []byte // decoded version of secret
var key []byte       // fixed key

func init() {
	var err error
	if secretDec, err = base64.StdEncoding.DecodeString(secret); err != nil {
		panic(err)
	}
	key = common.RandBytes(16)
}

// encrypt appends secretDec to b and encrypts using AES-128 in ECB mode with key.
func encrypt(b []byte) []byte {
	plain := make([]byte, 0, len(b)+len(secretDec))
	plain = append(plain, b...)
	plain = append(plain, secretDec...)
	plain = common.PadPKCS7(plain, 16)
	return common.EncryptAES(plain, key, nil)
}

func main() {
	bs := common.BlockSizeECB(encrypt)
	fmt.Println("Using ECB with block size", bs)
	secretLen := common.SuffixLen(encrypt, bs)
	fmt.Println("Secret text has length", secretLen)

	var known []byte
	for len(known) < secretLen {
		known = append(known, common.NextSuffixByteECB(encrypt, bs, known))
	}
	fmt.Printf("%q\n", known)
}
