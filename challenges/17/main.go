// The CBC padding oracle
package main

import (
	"encoding/base64"
	"fmt"

	"github.com/derat/cryptopals/common"
)

var input = []string{ // provided by challenge
	"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
	"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
	"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
}

var key []byte = common.RandBytes(16)
var initVec []byte = common.RandBytes(16)

func encrypt() (enc, iv []byte) {
	bs := input[common.RandInt(len(input))]
	s, err := base64.StdEncoding.DecodeString(bs)
	if err != nil {
		panic(fmt.Sprintf("Failed decoding %q: %v", bs, err))
	}
	return common.EncryptAES([]byte(s), key, initVec), initVec
}

func checkPadding(enc []byte) (valid bool) {
	valid = true
	defer func() {
		if r := recover(); r != nil {
			valid = false
		}
	}()
	common.DecryptAES(enc, key, initVec)
	return
}

func decryptByte(enc, iv []byte, bs int, known []byte) byte {
	// From the challenge:
	//
	//   The fundamental insight behind this attack is that the byte 01h is valid padding, and occur
	//   in 1/256 trials of "randomized" plaintexts produced by decrypting a tampered ciphertext.
	//   - 02h in isolation is not valid padding.
	//   - 02h 02h is valid padding, but is much less likely to occur randomly than 01h.
	//   - 03h 03h 03h is even less likely.
	//   So you can assume that if you corrupt a decryption AND it had valid padding, you know what that padding byte is.
	//
	// The general approach for decrypting block N is:
	//
	// - Manipulate the last byte of block N-1 to force the last byte of N to 0x1, representing one byte of padding.
	// - Now use that knowledge to set the last byte of N to 0x2, representing two bytes of padding.
	// - Manipulate the second-to-last byte of of block N-1 until the padding is valid (i.e. that byte is also 0x2).
	// - Now we know the second-to-last byte of block N.
	// - Repeat until we know all of the bytes of block N.

	// When we're decrypting block 0, there's no previous block to twiddle.
	// The encryption function XORed block 0 with the IV, so we prepend the IV to the ciphertext so we can twiddle it.
	// During decryption, block 1 (formerly block 0) will be XORed with block 0 (now the IV).
	// In other words, the block still gets XORed against the same bytes (i.e. the IV), but now we can twiddle them!
	// I found this pretty subtle.
	enc = append(iv, enc...)

	// Drop all of the already-decrypted blocks so the target block will be interpreted as containing padding.
	for len(known) >= bs {
		known = known[:len(known)-bs]
		enc = enc[:len(enc)-bs]
	}

	target := len(enc) - 1 - len(known) // index of byte that we're targeting

	// Manipulate the second-to-last block of the ciphertext so that the target
	// byte and the bytes after it in the final block are all interpreted as padding.
	pad := len(enc) - target
	mod := append([]byte{}, enc...)
	for i, orig := range known {
		mod[target-bs+i+1] ^= (orig ^ byte(pad))
	}

	// Modify the target byte until we get valid padding.
	off := target - bs
	for i := 0; i < 256; i++ {
		mod[off] = enc[off] ^ byte(i)
		if checkPadding(mod) {
			// Special case: When we're targeting the final byte in the block, |pad| will be set to 1,
			// but the byte may have multiple values that will result in valid padding:
			// - 0x1 (always)
			// - 0x2 (if preceded by 0x2)
			// - 0x3 (if preceded by [0x3,0x3])
			// - etc.
			// In the 0x1 case, we'll still have valid padding after modifying the preceding byte.
			// In all other cases, doing this will break the padding.
			if len(known) == 0 {
				mod[off-1] ^= mod[off-1]
				if !checkPadding(mod) {
					mod[off-1] = enc[off-1] // undo the change
					continue
				}
			}

			return byte(i ^ pad)
		}
	}
	panic(fmt.Sprintf("failed to decode byte"))
}

func main() {
	const bs = 16
	enc, iv := encrypt()

	var known []byte
	for len(known) < len(enc) {
		b := decryptByte(enc, iv, bs, known)
		known = append([]byte{b}, known...)
	}
	plain, err := common.UnpadPKCS7(known)
	if err != nil {
		fmt.Printf("Failed unpadding %q: %v\n", known, err)
	} else {
		fmt.Printf("%q\n", plain)
	}
}
