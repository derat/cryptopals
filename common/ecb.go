// Copyright 2020 Daniel Erat. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package common

import (
	"bytes"
)

// BlockSizeECB infers the block size used by f, an ECB function.
func BlockSizeECB(f EncryptFunc) int {
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

// NextSuffixByteECB attacks f to find the next byte in a fixed suffix.
// The bytes decoded so far should be passed in known.
// f should not use a fixed prefix.
func NextSuffixByteECB(f EncryptFunc, bs int, known []byte) byte {
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
	pad := A(numPad)
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
