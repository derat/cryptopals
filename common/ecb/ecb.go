package ecb

import (
	"bytes"

	"github.com/derat/cryptopals/common"
)

// BlockSize infers the block size used by f.
func BlockSize(f common.EncryptFunc) int {
	const (
		bufLen       = 1024
		minBlockSize = 4
		maxBlockSize = bufLen / 4
	)

	enc := f(common.A(bufLen))

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

// FirstModBlock returns the index of the first modifiable block for f,
// an ECB function with a fixed key and fixed prefix.
func FirstModBlock(f common.EncryptFunc, bs int) int {
	a := f(common.A(bs))
	b := f(common.B(bs))
	for i := 0; i*bs < len(a); i++ {
		// The first block that differs is the first one that we can modify.
		if !bytes.Equal(a[i*bs:(i+1)*bs], b[i*bs:(i+1)*bs]) {
			return i
		}
	}
	panic("couldn't find modifiable block")
}

// FixedLen returns the combined length of a fixed prefix and suffix used by f.
func FixedLen(f common.EncryptFunc, bs int) int {
	base := len(f(nil))
	for i := 1; ; i++ {
		if n := len(f(common.A(i))); n > base {
			return base - (i - 1) // new block is just padding
		}
	}
}

// PrefixLen returns the length of the fixed prefix used by f.
func PrefixLen(f common.EncryptFunc, bs int) int {
	fb := FirstModBlock(f, bs)

	// Figure out how many bytes we need to pass to see matching blocks.
	for i := 0; i < bs; i++ {
		// Test both 'A' and 'B' to guard against those chars being at the
		// end/start of the prefix/suffix.
		a := f(common.A(2*bs + i))
		b := f(common.B(2*bs + i))

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

// SuffixLen returns the length of the fixed suffix used by f.
func SuffixLen(f common.EncryptFunc, bs int) int {
	return FixedLen(f, bs) - PrefixLen(f, bs)
}

// NextSuffixByte attacks f to find the next byte in a fixed suffix.
// The bytes decoded so far should be passed in known.
// f should not use a fixed prefix.
func NextSuffixByte(f common.EncryptFunc, bs int, known []byte) byte {
	// This code is gnarly. With a block size of 4:
	// ''      -> AAAx (pad=3, block=0)
	// '1'     -> AA1x (pad=2, block=0)
	// '12'    -> A12x (pad=1, block=0)
	// '123'   -> 123x (pad=0, block=0)
	// '1234'  -> AAA1 234x (pad=3, block=1)
	// '12345' -> AA12 345x (pad=2, block=1)
	// ...

	// Insert padding so the secret byte ends up being the last byte in a block.
	numPad := 0
	for (len(known)+numPad+1)%bs != 0 {
		numPad++
	}

	// Get the encrypted block ending in the byte that we want.
	pad := common.A(numPad)
	enc := f(pad)
	start := (len(pad) + len(known)) / bs * bs
	target := enc[start : start+bs]

	// Now get the plaintext that produced the encrypted block.
	// We know all of this except for its final byte.
	plain := make([]byte, bs)
	copy(plain, append(pad, known...)[start:])

	// Figure out what the last byte is.
	for i := 0; i < 256; i++ {
		plain[len(plain)-1] = byte(i)
		if enc := f(plain); bytes.Equal(enc[:bs], target) {
			return byte(i)
		}
	}
	panic("didn't find next byte")
}
