package common

import (
	"crypto/aes"
	"fmt"
)

// PadPKCS7 returns a new buffer containing b padded to the
// supplied block size using PKCS#7 padding.
func PadPKCS7(b []byte, bs int) []byte {
	nb := len(b) / bs
	if len(b)%bs != 0 {
		nb++
	}
	padded := make([]byte, nb*bs)
	extra := byte(len(padded) - len(b))
	for n := copy(padded, b); n < len(padded); n++ {
		padded[n] = extra
	}
	return padded
}

func EncryptAES_CBC(b, key, iv []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	bs := cipher.BlockSize()
	if len(iv) != bs {
		panic(fmt.Sprintf("IV size is %v; need %v", len(iv), bs))
	}

	prev := iv
	var enc []byte
	for i := 0; i < len(b); i += bs {
		// Get the source block, padding it if needed.
		n := bs
		if rem := len(b) - i; rem < bs {
			n = rem
		}
		src := PadPKCS7(b[i:i+n], bs)

		// XOR with the previous ciphertext block (or the initialization vector).
		src = XOR(src, prev)

		// Encrypt the block and save it to XOR against the next plaintext block.
		dst := make([]byte, bs)
		cipher.Encrypt(dst, src)
		enc = append(enc, dst...)
		prev = dst
	}
	return enc
}

func DecryptAES_CBC(enc, key, iv []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	bs := cipher.BlockSize()
	if len(iv) != bs {
		panic(fmt.Sprintf("IV size is %v; need %v", len(iv), bs))
	}

	prev := iv
	dec := make([]byte, 0, len(enc))
	for i := 0; i < len(enc); i += bs {
		src := make([]byte, bs)
		dst := make([]byte, bs)
		n := copy(src, enc[i:])
		cipher.Decrypt(dst, src)
		dst = XOR(dst, prev)
		dec = append(dec, dst[:n]...)
		prev = src
	}
	// TODO: Remove padding?
	return dec
}
