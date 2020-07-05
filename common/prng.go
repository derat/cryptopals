package common

import "fmt"

// MT is a PRNG implementing the Mersenne Twister algorithm.
// See https://en.wikipedia.org/wiki/Mersenne_Twister for details and pseudocode.
type MT struct {
	mt     []uint64
	index  int
	lmask  uint64
	umask  uint64
	params *MTParams
}

func newMT(params *MTParams, seed uint64) *MT {
	var lm uint64 = (1 << params.R) - 1

	m := &MT{
		mt:     make([]uint64, params.N),
		index:  params.N,
		lmask:  lm,
		umask:  ^lm & params.WMask,
		params: params,
	}

	m.mt[0] = seed
	for i := 1; i < params.N; i++ {
		m.mt[i] = params.WMask & (params.F*(m.mt[i-1]^(m.mt[i-1]>>(params.W-2))) + uint64(i))
	}

	return m
}

// Params returns a copy of the constant parameters used by the algorithm.
func (m *MT) Params() MTParams {
	return *m.params
}

// SetState replaces m's internal state with st.
// m's index is also reset to 0.
func (m *MT) SetState(st []uint64) {
	if len(st) != m.params.N {
		panic(fmt.Sprintf("state has size %v; need %v", len(st), m.params.N))
	}
	copy(m.mt, st)
	m.index = 0
}

// Extract returns the next number.
func (m *MT) Extract() uint64 {
	if m.index >= m.params.N {
		m.twist()
	}

	y := m.mt[m.index]
	y ^= (y >> m.params.U) & m.params.D
	y ^= (y << m.params.S) & m.params.B
	y ^= (y << m.params.T) & m.params.C
	y ^= (y >> m.params.L)

	m.index++
	return y & m.params.WMask
}

func (m *MT) twist() {
	for i := 0; i < m.params.N; i++ {
		x := (m.mt[i] & m.umask) + (m.mt[(i+1)%m.params.N] & m.lmask)
		xa := x >> 1
		if x%2 != 0 { // lowest bit of x is 1
			xa ^= m.params.A
		}
		m.mt[i] = m.mt[(i+m.params.M)%m.params.N] ^ xa
	}
	m.index = 0
}

// NewMT19937 returns a new MT using the Mersenne prime 2^19937−1.
func NewMT19937(seed uint64) *MT {
	return newMT(&mt19937Params, seed)
}

// Parameter values are listed at https://en.wikipedia.org/wiki/Mersenne_Twister.
type MTParams struct {
	W     int    // word size (in number of bits)
	N     int    // degree of recurrence
	M     int    // middle word, an offset used in the recurrence relation defining the series x, 1 ≤ m < n
	A     uint64 // coefficients of the rational normal form twist matrix
	B, C  uint64 // TGFSR(R) tempering bitmasks
	D     uint64 // additional Mersenne Twister tempering bitmask
	R     int    // separation point of one word, or the number of bits of the lower bitmask, 0 ≤ r ≤ w - 1
	S, T  int    // TGFSR(R) tempering bit shifts
	U, L  int    // additional Mersenne Twister tempering bit shifts
	F     uint64 // "another parameter to the generator, though not part of the algorithm proper"
	WMask uint64 // mask for bottom w bits
}

var mt19937Params = MTParams{
	W:     32,
	N:     624,
	M:     397,
	A:     0x9908B0DF,
	B:     0x9D2C5680,
	C:     0xEFC60000,
	D:     0xFFFFFFFF,
	R:     31,
	S:     7,
	T:     15,
	U:     11,
	L:     18,
	F:     1812433253,
	WMask: (1 << 32) - 1,
}
