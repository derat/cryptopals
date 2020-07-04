package common

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"errors"
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
func UnpadPKCS7(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("can't unpad empty buffer")
	}
	np := int(b[len(b)-1])
	if np == 0 || np > len(b) {
		return nil, fmt.Errorf("%v byte(s) of padding on %v-byte buffer", np, len(b))
	}
	for i := 0; i < np; i++ {
		if idx := len(b) - i - 1; int(b[idx]) != np {
			return nil, fmt.Errorf("%v byte(s) of padding but byte %d is %v", np, idx, b[idx])
		}
	}
	return b[:len(b)-np], nil
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

// FirstModBlock returns the index of the first modifiable block for f,
// an ECB or CBC function with a fixed key and fixed prefix.
func FirstModBlock(f EncryptFunc, bs int) int {
	a := f(A(bs))
	b := f(B(bs))
	for i := 0; i*bs < len(a); i++ {
		// The first block that differs is the first one that we can modify.
		if !bytes.Equal(a[i*bs:(i+1)*bs], b[i*bs:(i+1)*bs]) {
			return i
		}
	}
	panic("couldn't find modifiable block")
}

// FixedLen returns the combined length of a fixed prefix and suffix used by f,
// an ECB or CBC function with a fixed key.
func FixedLen(f EncryptFunc, bs int) int {
	base := len(f(nil))
	for i := 1; ; i++ {
		if n := len(f(A(i))); n > base {
			return base - i
		}
	}
}

// PrefixLen returns the length of the fixed prefix used by f,
// an ECB or CBC function with a fixed key.
func PrefixLen(f EncryptFunc, bs int) int {
	start := FirstModBlock(f, bs) * bs
	end := start + bs

	// Figure out what the modifiable block looks like when its remaining bytes
	// are filled with our own characters.
	a := f(A(bs))[start:end]
	b := f(B(bs))[start:end]

	// Add bytes until we see the expected blocks.
	for i := 0; i < bs; i++ {
		if bytes.Equal(f(A(i + 1))[start:end], a) &&
			bytes.Equal(f(B(i + 1))[start:end], b) {
			return end - i - 1
		}
	}
	panic("couldn't find prefix length")
}

// SuffixLen returns the length of the fixed suffix used by f,
// an ECB or CBC function with a fixed key.
func SuffixLen(f EncryptFunc, bs int) int {
	return FixedLen(f, bs) - PrefixLen(f, bs)
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

	plain := PadPKCS7(b, bs)

	var enc []byte
	for i := 0; i < len(plain); i += bs {
		// Get the source block, padding it if needed.
		n := bs
		if rem := len(plain) - i; rem < bs {
			n = rem
		}
		src := plain[i : i+n]

		// If using CBC, XOR with the previous ciphertext block (or the initialization vector).
		if iv != nil {
			src = XOR(src, prev)
		}

		// Encrypt the block and save it to XOR against the next plaintext block (for CBC).
		dst := make([]byte, bs)
		cipher.Encrypt(dst, src)
		enc = append(enc, dst...)
		prev = dst
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
		prev = src
	}
	up, err := UnpadPKCS7(dec)
	if err != nil {
		panic(fmt.Sprintf("failed removing padding: %v", err))
	}
	return up
}
