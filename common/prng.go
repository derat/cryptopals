package common

// MT is a PRNG implementing the Mersenne Twister algorithm.
// See https://en.wikipedia.org/wiki/Mersenne_Twister for details and pseudocode.
type MT struct {
	mt     []uint64
	index  int
	lmask  uint64
	umask  uint64
	params *mtParams
}

func newMT(params *mtParams, seed uint64) *MT {
	var lm uint64 = (1 << params.r) - 1

	m := &MT{
		mt:     make([]uint64, params.n),
		index:  params.n,
		lmask:  lm,
		umask:  ^lm & params.wm,
		params: params,
	}

	m.mt[0] = seed
	for i := 1; i < params.n; i++ {
		m.mt[i] = params.wm & (params.f*(m.mt[i-1]^(m.mt[i-1]>>(params.w-2))) + uint64(i))
	}

	return m
}

// Extract returns the next number.
func (m *MT) Extract() uint64 {
	if m.index >= m.params.n {
		m.twist()
	}

	y := m.mt[m.index]
	y ^= (y >> m.params.u) & m.params.d
	y ^= (y << m.params.s) & m.params.b
	y ^= (y << m.params.t) & m.params.c
	y ^= (y >> m.params.l)

	m.index++
	return y & m.params.wm
}

func (m *MT) twist() {
	for i := 0; i < m.params.n; i++ {
		x := (m.mt[i] & m.umask) + (m.mt[(i+1)%m.params.n] & m.lmask)
		xa := x >> 1
		if x%2 != 0 { // lowest bit of x is 1
			xa ^= m.params.a
		}
		m.mt[i] = m.mt[(i+m.params.m)%m.params.n] ^ xa
	}
	m.index = 0
}

// NewMT19937 returns a new MT using the Mersenne prime 2^19937−1.
func NewMT19937(seed int) *MT {
	return newMT(&mt19937Params, uint64(seed))
}

// Parameter values are listed at https://en.wikipedia.org/wiki/Mersenne_Twister.
type mtParams struct {
	w    int    // word size (in number of bits)
	n    int    // degree of recurrence
	m    int    // middle word, an offset used in the recurrence relation defining the series x, 1 ≤ m < n
	r    int    // separation point of one word, or the number of bits of the lower bitmask, 0 ≤ r ≤ w - 1
	a    uint64 // coefficients of the rational normal form twist matrix
	b, c uint64 // TGFSR(R) tempering bitmasks
	s, t int    // TGFSR(R) tempering bit shifts
	u, l int    // additional Mersenne Twister tempering bit shifts
	d    uint64 // additional Mersenne Twister tempering bitmask
	f    uint64 // "another parameter to the generator, though not part of the algorithm proper"

	wm uint64 // mask for bottom w bits
}

var mt19937Params = mtParams{
	w:  32,
	n:  624,
	m:  397,
	r:  31,
	a:  0x9908B0DF,
	b:  0x9D2C5680,
	c:  0xEFC60000,
	s:  7,
	t:  15,
	u:  11,
	l:  18,
	d:  0xFFFFFFFF,
	f:  1812433253,
	wm: (1 << 32) - 1,
}
