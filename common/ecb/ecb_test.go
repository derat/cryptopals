package ecb

import (
	"testing"

	"github.com/derat/cryptopals/common"
)

func TestECB(t *testing.T) {
	const (
		key = "YELLOW SUBMARINE"
		bs  = 16

		almost = "123456789012345"
		full   = "1234567890123456"
		extra  = "12345678901234567"
	)

	for _, tc := range []struct {
		pre, suf string
	}{
		{"", ""},
		{"1", ""},
		{"", "1"},
		{"1", "1"},
		{almost, ""},
		{"", almost},
		{almost, almost},
		{full, ""},
		{"", full},
		{full, full},
		{extra, ""},
		{"", extra},
		{extra, extra},
		{"A", ""},
		{"", "A"},
		{"A", "A"},
	} {
		f := func(b []byte) []byte {
			plain := make([]byte, 0, len(tc.pre)+len(b)+len(tc.suf))
			plain = append(plain, []byte(tc.pre)...)
			plain = append(plain, b...)
			plain = append(plain, []byte(tc.suf)...)
			return common.EncryptAES(plain, []byte(key), nil)
		}

		if got := BlockSize(f); got != bs {
			t.Errorf("FindBlockSize() with prefix %q and suffix %q = %v; want %v",
				tc.pre, tc.suf, got, bs)
		}
		fb := len(tc.pre) / bs
		if got := FirstModBlock(f, bs); got != fb {
			t.Errorf("FindFirstModBlock() with prefix %q and suffix %q = %v; want %v",
				tc.pre, tc.suf, got, fb)
		}
		fl := len(tc.pre) + len(tc.suf)
		if got := FixedLen(f, bs); got != fl {
			t.Errorf("FindFixedLen() with prefix %q and suffix %q = %v; want %v",
				tc.pre, tc.suf, got, fl)
		}
		if got := PrefixLen(f, bs); got != len(tc.pre) {
			t.Errorf("FindPrefixLen() with prefix %q and suffix %q = %v; want %v",
				tc.pre, tc.suf, got, len(tc.pre))
		}
		if got := SuffixLen(f, bs); got != len(tc.suf) {
			t.Errorf("FindSuffixLen() with prefix %q and suffix %q = %v; want %v",
				tc.pre, tc.suf, got, len(tc.suf))
		}
	}
}
