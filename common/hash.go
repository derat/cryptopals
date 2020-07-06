// Copyright 2020 Daniel Erat. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package common

import (
	"bytes"
	"encoding/binary"
)

// MDPadding computes SHA-1, MD4, etc. padding for a message of length mlen *bytes*.
// bo specifies the byte order used when appending the length (SHA-1 uses big-endian,
// while MD4 uses little-endian).
//
// Pseudocode from https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode:
//
//   append the bit '1' to the message e.g. by adding 0x80 if message length is a multiple of 8 bits.
//   append 0 ≤ k < 512 bits '0', such that the resulting message length in bits
//     is congruent to −64 ≡ 448 (mod 512)
//   append ml, the original message length, as a 64-bit big-endian integer.
//   Thus, the total length is a multiple of 512 bits.
func MDPadding(mlen int, bo binary.ByteOrder) []byte {
	var b bytes.Buffer
	b.Grow(64)

	// Start with a '1' bit (while filling the rest of the byte with zeros).
	b.Write([]byte{0x80})

	// Pad out the message so the length so far (including the byte we just added) modulo 64 is 56 bytes.
	for (mlen+b.Len())%64 != 56 {
		b.Write([]byte{0x0})
	}

	// Now add the original length in bits.
	binary.Write(&b, bo, uint64(mlen*8))

	return b.Bytes()
}
