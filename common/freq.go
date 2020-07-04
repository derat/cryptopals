package common

import (
	"math"
	"unicode"
)

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
	if total > 0 {
		for i := range counts {
			bf[i] = float64(counts[i]) / float64(total)
		}
	}
	return bf
}

// DiffByteFreqs characterizes byte frequency differences between a and b.
// The frequency distributions should each be normalized to sum to 1 (see ByteFreqs).
func DiffByteFreqs(a, b [256]float64) float64 {
	var total float64
	for i := 0; i < 256; i++ {
		total += math.Abs(a[i] - b[i])
	}
	return total
}

type Score struct {
	Chars    int     // letters, digits, spaces
	FreqDiff float64 // letter frequency difference (see DiffByteFreqs)
}

func (s *Score) Better(o *Score) bool {
	if o == nil {
		return true
	}

	if s.Chars > o.Chars {
		return true
	} else if o.Chars > s.Chars {
		return false
	}

	return s.FreqDiff < o.FreqDiff
}

// EnglishScore generates an ad-hoc score for the likelihood that b contains English text.
func EnglishScore(b []byte) Score {
	var s Score
	if len(b) == 0 {
		return s
	}

	// Casting to string here is important so that we iterate over runes rather than bytes.
	for _, r := range string(b) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsSpace(r) {
			s.Chars++
		}
	}

	// Compare letters against the English distribution.
	upper := UpperBytes(AlphaBytes(b))
	freqs := ByteFreqs(CountBytes(upper))
	s.FreqDiff = DiffByteFreqs(freqs, EnglishUpperFreqs)

	return s
}

// SingleByteXOR tries to find the byte that's most likely to have been used for single-byte
// XOR encryption of English text.
func SingleByteXOR(enc []byte) byte {
	var bestKey byte
	var bestScore *Score
	for i := 0; i < 256; i++ {
		dec := XOR(enc, []byte{byte(i)})
		if score := EnglishScore(dec); score.Better(bestScore) {
			bestKey = byte(i)
			bestScore = &score
		}
	}
	return bestKey
}
