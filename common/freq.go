package common

import "math"

// EnglishUpperFreqs contains relative frequencies of 'A' through 'Z' in English words.
// All other bytes are 0.
var EnglishUpperFreqs [256]float64

func init() {
	// http://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
	var counts [256]int
	for b, c := range map[byte]int{
		'E': 21912,
		'T': 16587,
		'A': 14810,
		'O': 14003,
		'I': 13318,
		'N': 12666,
		'S': 11450,
		'R': 10977,
		'H': 10795,
		'D': 7874,
		'L': 7253,
		'U': 5246,
		'C': 4943,
		'M': 4761,
		'F': 4200,
		'Y': 3853,
		'W': 3819,
		'G': 3693,
		'P': 3316,
		'B': 2715,
		'V': 2019,
		'K': 1257,
		'X': 315,
		'Q': 205,
		'J': 188,
		'Z': 128,
	} {
		counts[b] = c
	}
	EnglishUpperFreqs = ByteFreqs(counts)
}

// CountBytes returns an array containing the number of times each byte occurs in buf.
func CountBytes(buf []byte) [256]int {
	var bc [256]int
	for _, b := range buf {
		bc[b]++
	}
	return bc
}

// ByteFreqs returns a table of normalized frequencies in [0.0, 1.0] of bytes with the supplied counts.
func ByteFreqs(counts [256]int) [256]float64 {
	total := 0
	for i := range counts {
		total += counts[i]
	}
	var bf [256]float64
	for i := range counts {
		bf[i] = float64(counts[i]) / float64(total)
	}
	return bf
}

// DiffByteFreqs returns the sum of byte frequency differences between a and b.
func DiffByteFreqs(a, b [256]float64) float64 {
	var total float64
	for i := 0; i < 256; i++ {
		total += math.Abs(a[i] - b[i])
	}
	return total
}
