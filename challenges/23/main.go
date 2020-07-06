// Copyright 2020 Daniel Erat. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Clone an MT19937 RNG from its output
package main

import (
	"fmt"

	"github.com/derat/cryptopals/common"
)

// reverse solves for y after an operation of the form "v = y ^ ((y SHIFT sw) & m)".
// sd describes the direction of SHIFT, and w specifies the bit width.
//
// MT.Extract performs the following steps on Y, a W-bit value from the state array:
//
//   y ^= (y >> U) & D
//   y ^= (y << S) & B
//   y ^= (y << T) & C
//   y ^= (y >> L)
//   y &= 0xffffffff
//
// We get the resulting value V and need to reverse the steps to get the original state value.
//
// The essence of each of these steps is:
// - shift Y left or right by S bits
// - bitwise AND with mask M
// - bitwise XOR against Y
//
// Another way of thinking about this is that we want to determine the value of
// each bit in the original Y that would produce V. Since we're using shift and XOR operations,
// a single bit can have an effect on multiple bits in the result.
//
// The challenge is that shift and AND operations are destructive.
//
// In the right-shift case:
// - The upper S bits are unchanged, since the shift brings in zeros which we then XOR against Y.
// - For the next S bits to the right, we know the bits from the shift (i.e. the upper S bits) and
//   can apply the mask and then XOR against V's bits to get Y's bits.
// - Now that we know more bits from Y, we can repeat the previous operation until we know all of
//   the bits from Y.
//
// The left-shift case is similar, except we need to solve starting from the rightmost bits.
func reverse(v uint64, w int, sd shiftDir, sw int, m uint64) uint64 {
	if sw <= 0 || sw >= w {
		panic(fmt.Sprintf("can't undo %v-bit shift of %v-bit number", sw, w))
	}

	var smask uint64 = (1 << sw) - 1 // mask for s bits
	if sd == rightShift {
		smask <<= w - sw // if the operation right-shifted, start from the left side
	}

	var y uint64 = v & smask                  // preserve bits that were unchanged by the operation
	for known := sw; known < w; known += sw { // solve for remaining groups of s bits
		bmask := lshift(smask, known*int(sd)) // mask for the s bits being solved
		prev := lshift(y, sw*int(sd))         // already-known bits
		y |= bmask & ((prev & m) ^ v)
	}
	return y
}

type shiftDir int

const (
	leftShift  shiftDir = 1
	rightShift shiftDir = -1
)

// lshift left-shifts v by s bits. If s is negative, it right-shifts instead.
func lshift(v uint64, s int) uint64 {
	if s < 0 {
		return v >> -s
	}
	return v << s
}

func main() {
	const (
		mask = 0x1234FACE
		orig = 0xDEADBEEF
	)
	for _, sw := range []int{
		1, 12, 16, 17, 31,
	} {
		val := uint64(orig) ^ (uint64(orig)>>sw)&mask
		if rev := reverse(val, 32, rightShift, sw, mask); rev != orig {
			panic(fmt.Sprintf("Failed to reverse %d-bit right shift:\ngot  %032b\nwant %032b", sw, rev, orig))
		}
		val = uint64(orig) ^ (uint64(orig)<<sw)&mask
		if rev := reverse(val, 32, leftShift, sw, mask); rev != orig {
			panic(fmt.Sprintf("Failed to reverse %d-bit left shift:\ngot  %032b\nwant %032b", sw, rev, orig))
		}
	}

	const seed = 145653542
	mt := common.NewMT19937(seed)
	p := mt.Params()
	vals := make([]uint64, p.N)
	for i := 0; i < p.N; i++ {
		vals[i] = mt.Extract()
	}

	// Compute mt's initial state.
	state := make([]uint64, p.N)
	for i := p.N - 1; i >= 0; i-- {
		y := vals[i]
		y = reverse(y, p.W, rightShift, p.L, 0xFFFFFFFF)
		y = reverse(y, p.W, leftShift, p.T, p.C)
		y = reverse(y, p.W, leftShift, p.S, p.B)
		y = reverse(y, p.W, rightShift, p.U, p.D)
		state[i] = y
	}

	// Create a new PRNG, inject the initial state, and skip through the known numbers.
	rmt := common.NewMT19937(0)
	rmt.SetState(state)
	for i := 0; i < p.N; i++ {
		rmt.Extract()
	}

	// Check that both PRNGs are in the same state now.
	for i := 0; i < 10; i++ {
		a := mt.Extract()
		b := rmt.Extract()
		if a == b {
			fmt.Printf("Original and cloned PRNGs both produced %v\n", a)
		} else {
			fmt.Printf("Original PRNG produced %v; cloned produced %v\n", a, b)
		}
	}
}
