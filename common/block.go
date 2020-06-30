package common

import (
	"bytes"
	"crypto/aes"
	"fmt"
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

// EncryptFunc encrypts the supplied buffer.
// An additional prefix and/or suffix may be applied.
// The same prefix, suffix, and key are used every time.
type EncryptFunc func(b []byte) []byte

// FindECBBlockSize infers the block size used by f.
func FindECBBlockSize(f EncryptFunc) int {
	const (
		bufLen       = 1024
		minBlockSize = 4
		maxBlockSize = bufLen / 4
	)

	enc := f(bytes.Repeat([]byte{'A'}, bufLen))

	for bs := minBlockSize; bs <= maxBlockSize; bs++ {
		numNeeded := bufLen/bs - 2 // first or last may be misaligned
		var prevBlock []byte       // last block that was seen
		blockCount := 0            // consecutive occurrences of prevBlock
		for start := 0; start+bs < len(enc); start += bs {
			bl := enc[start : start+bs]
			if prevBlock == nil || !bytes.Equal(bl, prevBlock) {
				prevBlock = bl
				blockCount = 0
			} else {
				blockCount++
				if blockCount >= numNeeded {
					return bs
				}
			}
		}
	}
	panic("couldn't find block size")
}

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
