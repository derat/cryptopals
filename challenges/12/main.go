// Byte-at-a-time ECB decryption (Simple)
package main

import (
	"bytes"
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
	return common.EncryptAES(plain, key, nil)
}

func main() {
	var bs int
	for i := 1; i < 32; i++ {
		enc := encrypt(bytes.Repeat([]byte{'A'}, 2*i))
		if bytes.Equal(enc[0:i], enc[i:2*i]) {
			bs = i
			break
		}
	}
	if bs == 0 {
		panic("failed determining block size")
	}
	fmt.Println("Using ECB with block size", bs)

	// Add characters until we see another block get added as padding.
	secretLen := len(encrypt(nil))
	for i := 1; ; i++ {
		if el := len(encrypt(bytes.Repeat([]byte{'A'}, i))); el > secretLen {
			secretLen -= i
			break
		}
	}
	fmt.Println("Secret text has length", secretLen)

	/*
	  With a block size of 4:
	  ''      -> AAAx (pad=3, block=0)
	  '1'     -> AA1x (pad=2, block=0)
	  '12'    -> A12x (pad=1, block=0)
	  '123'   -> 123x (pad=0, block=0)
	  '1234'  -> AAA1 234x (pad=3, block=1)
	  '12345' -> AA12 345x (pad=2, block=1)
	  ...
	*/
	findNext := func(known []byte) byte {
		// Insert padding so the secret byte ends up being the last byte in a block.
		numPad := 0
		for (len(known)+numPad+1)%bs != 0 {
			numPad++
		}

		// Get the encrypted block ending in the byte that we want.
		pad := bytes.Repeat([]byte{'A'}, numPad)
		enc := encrypt(pad)
		start := (len(pad) + len(known)) / bs * bs
		target := enc[start : start+bs]

		// Now get the plaintext that produced the encrypted block.
		// We know all of this except for its final byte.
		plain := make([]byte, bs)
		copy(plain, append(pad, known...)[start:])

		// Figure out what the last byte is.
		for i := 0; i < 256; i++ {
			plain[len(plain)-1] = byte(i)
			if enc := encrypt(plain); bytes.Equal(enc[:bs], target) {
				return byte(i)
			}
		}
		panic("didn't find next byte")
	}

	var known []byte
	for len(known) < secretLen {
		known = append(known, findNext(known))
	}
	fmt.Printf("%q\n", known)
}
