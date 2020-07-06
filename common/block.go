// Copyright 2020 Daniel Erat. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package common

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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

	if len(b)%bs != 0 {
		panic(fmt.Sprintf("buffer size %v isn't multiple of block size %v", len(b), bs))
	}

	var enc []byte
	for i := 0; i < len(b); i += bs {
		// Get the source block, padding it if needed.
		n := bs
		if rem := len(b) - i; rem < bs {
			n = rem
		}
		src := b[i : i+n]

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
	return dec
}

// CTR implements AES in CTR mode.
type CTR struct {
	key           []byte
	nonce, blocks uint64
	ks            []byte // next portion of keystream
}

func NewCTR(key []byte, nonce uint64) *CTR {
	return &CTR{key: key, nonce: nonce}
}

// Reset resets c's block counter to 0.
func (c *CTR) Reset() {
	c.blocks = 0
	c.ks = nil
}

// keystream returns the next n bytes from the keystream.
func (c *CTR) keystream(n int) []byte {
	b := make([]byte, n)
	off := 0

	for off < n {
		if len(c.ks) > 0 {
			copied := copy(b[off:], c.ks)
			off += copied
			c.ks = c.ks[copied:]
		} else {
			var buf bytes.Buffer
			buf.Grow(16)
			binary.Write(&buf, binary.LittleEndian, &c.nonce)
			binary.Write(&buf, binary.LittleEndian, &c.blocks)
			c.ks = EncryptAES(buf.Bytes(), c.key, nil)
			c.blocks++
		}
	}
	return b
}

// Process reads from r until EOF and writes encrypted or unencrypted data to w.
func (c *CTR) Process(r io.Reader, w io.Writer) error {
	b := make([]byte, 2048)
	for {
		n, rerr := r.Read(b)
		if n > 0 {
			ks := c.keystream(n)
			if _, err := w.Write(XOR(b[:n], ks)); err != nil {
				return err
			}
		}
		if rerr == io.EOF {
			return nil
		} else if rerr != nil {
			return rerr
		}
	}
}
