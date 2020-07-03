package common

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"strings"
)

// PadPKCS7 returns a new buffer containing b padded to the
// supplied block size using PKCS#7 padding.
func PadPKCS7(b []byte, bs int) []byte {
	nb := len(b)/bs + 1
	padded := make([]byte, nb*bs)
	extra := byte(len(padded) - len(b))
	for n := copy(padded, b); n < len(padded); n++ {
		padded[n] = extra
	}
	return padded
}

// UnpadPKCS7 undoes padding added by PadPKCS7.
func UnpadPKCS7(b []byte) []byte {
	if len(b) == 0 {
		panic("Can't unpad empty buffer")
	}
	np := b[len(b)-1]
	return b[:len(b)-int(np)]
}

// A returns a buffer containing the byte 'A' repeated n times.
func A(n int) []byte {
	return bytes.Repeat([]byte{'A'}, n)
}

// B returns a buffer containing the byte 'B' repeated n times.
func B(n int) []byte {
	return bytes.Repeat([]byte{'B'}, n)
}

// BlockString returns a hex representation of b segmented into blocks.
func BlockString(b []byte, bs int) string {
	var s []string
	for start := 0; start < len(b); start += bs {
		end := start + bs
		if end > len(b) {
			end = len(b)
		}
		s = append(s, hex.EncodeToString(b[start:end]))
	}
	return strings.Join(s, " ")
}

// EncryptFunc encrypts the supplied buffer.
// An additional prefix and/or suffix may be applied.
// The same prefix, suffix, and key are used every time.
type EncryptFunc func(b []byte) []byte

// EncryptAES encrypts b using AES-128 with the supplied key.
// If iv is non-nil CBC mode is used; otherwise ECB is used.
func EncryptAES(b, key, iv []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	bs := cipher.BlockSize()

	if iv != nil && len(iv) != bs {
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
		if iv != nil {
			src = XOR(src, prev)
		}

		// Encrypt the block and save it to XOR against the next plaintext block.
		dst := make([]byte, bs)
		cipher.Encrypt(dst, src)
		enc = append(enc, dst...)
		if iv != nil {
			prev = dst
		}
	}
	return enc
}

// DecryptAES decrypts b using AES-128 with the supplied key.
// If iv is non-nil CBC mode is used; otherwise ECB is used.
func DecryptAES(enc, key, iv []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	bs := cipher.BlockSize()

	if iv != nil && len(iv) != bs {
		panic(fmt.Sprintf("IV size is %v; need %v", len(iv), bs))
	}
	prev := iv

	dec := make([]byte, 0, len(enc))
	for i := 0; i < len(enc); i += bs {
		src := make([]byte, bs)
		dst := make([]byte, bs)
		n := copy(src, enc[i:])
		cipher.Decrypt(dst, src)

		if iv != nil {
			dst = XOR(dst, prev)
		}

		dec = append(dec, dst[:n]...)
		if iv != nil {
			prev = src
		}
	}
	return UnpadPKCS7(dec)
}
