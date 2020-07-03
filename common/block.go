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

// FindECBBlockSize infers the block size used by f.
func FindECBBlockSize(f EncryptFunc) int {
	const (
		bufLen       = 1024
		minBlockSize = 4
		maxBlockSize = bufLen / 4
	)

	enc := f(A(bufLen))

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

// FindECBFirstModBlock returns the index of the first modifiable block for f,
// an ECB function with a fixed key and fixed prefix.
func FindECBFirstModBlock(f EncryptFunc, bs int) int {
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

// FindECBFixedLen returns the combined length of a fixed prefix and suffix used by f.
func FindECBFixedLen(f EncryptFunc, bs int) int {
	base := len(f(nil))
	for i := 1; ; i++ {
		if n := len(f(A(i))); n > base {
			return base - (i - 1) // new block is just padding
		}
	}
}

// FindECBPrefixLen returns the length of the fixed prefix used by f.
func FindECBPrefixLen(f EncryptFunc, bs int) int {
	fb := FindECBFirstModBlock(f, bs)

	// Figure out how many bytes we need to pass to see matching blocks.
	for i := 0; i < bs; i++ {
		// Test both 'A' and 'B' to guard against those chars being at the
		// end/start of the prefix/suffix.
		a := f(A(2*bs + i))
		b := f(B(2*bs + i))

		start := fb * bs
		if i > 0 {
			start += bs
		}
		if bytes.Equal(a[start:start+bs], a[start+bs:start+2*bs]) &&
			bytes.Equal(b[start:start+bs], b[start+bs:start+2*bs]) {
			return start - i
		}
	}
	panic("couldn't find prefix length")
}

// FindECBSuffixLen returns the length of the fixed suffix used by f.
func FindECBSuffixLen(f EncryptFunc, bs int) int {
	return FindECBFixedLen(f, bs) - FindECBPrefixLen(f, bs)
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
