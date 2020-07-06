package common

import (
	"bytes"
	"strings"
	"testing"
)

func TestPKCS7(t *testing.T) {
	for _, tc := range []struct {
		unpadded string
		bs       int
		padded   string
	}{
		{"", 8, "\x08\x08\x08\x08\x08\x08\x08\x08"},
		{"123", 8, "123\x05\x05\x05\x05\x05"},
		{"123456", 8, "123456\x02\x02"},
		{"1234567", 8, "1234567\x01"},
		{"12345678", 8, "12345678\x08\x08\x08\x08\x08\x08\x08\x08"},
		{"123456789", 8, "123456789\x07\x07\x07\x07\x07\x07\x07"},
	} {
		if padded := PadPKCS7([]byte(tc.unpadded), tc.bs); !bytes.Equal(padded, []byte(tc.padded)) {
			t.Errorf("PadPKCS7(%q, %d) = %q; want %q", tc.unpadded, tc.bs, padded, tc.padded)
		}
		if unpadded, err := UnpadPKCS7([]byte(tc.padded)); err != nil {
			t.Errorf("UnpadPKCS7(%q) failed: %v", tc.padded, err)
		} else if !bytes.Equal(unpadded, []byte(tc.unpadded)) {
			t.Errorf("UnpadPKCS7(%q) = %q; want %q", tc.padded, unpadded, tc.unpadded)
		}
	}
}

func TestUnpadPKCS7_Invalid(t *testing.T) {
	for _, s := range []string{
		"1234567\x00",                  // need at least one byte of padding
		"",                             // empty buffers are invalid
		"\x12",                         // buffer isn't large enough
		"ICE ICE BABY\x05\x05\x05\x05", // from challenge 15
		"ICE ICE BABY\x01\x02\x03\x04", // from challenge 15
	} {
		if _, err := UnpadPKCS7([]byte(s)); err == nil {
			t.Errorf("UnpadPKCS7(%q) unexpectedly reported success", s)
		}
	}
}

func TestBlockString(t *testing.T) {
	const bs = 4
	for _, tc := range []struct {
		b, want string
	}{
		{"", ""},
		{"AAAA", "41414141"},
		{"AAAAAAAA", "41414141 41414141"},
	} {
		if got := BlockString([]byte(tc.b), bs); got != tc.want {
			t.Errorf("BlockString(%q) = %q; want %q", tc.b, got, tc.want)
		}
	}
}

func TestBlock_Misc(t *testing.T) {
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
		for _, iv := range [][]byte{nil, A(bs)} {
			f := func(b []byte) []byte {
				plain := make([]byte, 0, len(tc.pre)+len(b)+len(tc.suf))
				plain = append(plain, []byte(tc.pre)...)
				plain = append(plain, b...)
				plain = append(plain, []byte(tc.suf)...)
				padded := PadPKCS7(plain, bs)
				return EncryptAES(padded, []byte(key), iv)
			}

			mode := "ECB"
			if len(iv) > 0 {
				mode = "CBC"
			}

			// We can only get the block size for ECB.
			if len(iv) == 0 {
				if got := BlockSizeECB(f); got != bs {
					t.Errorf("%v BlockSize(%q...%q) = %v; want %v", mode, tc.pre, tc.suf, got, bs)
				}
			}

			fb := len(tc.pre) / bs
			if got := FirstModBlock(f, bs); got != fb {
				t.Errorf("%v FirstModBlock(%q...%q) = %v; want %v", mode, tc.pre, tc.suf, got, fb)
			}
			fl := len(tc.pre) + len(tc.suf)
			if got := FixedLen(f, bs); got != fl {
				t.Errorf("%v FixedLen(%q...%q) = %v; want %v", mode, tc.pre, tc.suf, got, fl)
			}
			if got := PrefixLen(f, bs); got != len(tc.pre) {
				t.Errorf("%v PrefixLen(%q...%q) = %v; want %v", mode, tc.pre, tc.suf, got, len(tc.pre))
			}
			if got := SuffixLen(f, bs); got != len(tc.suf) {
				t.Errorf("%v SuffixLen(%q...%q) = %v; want %v", mode, tc.pre, tc.suf, got, len(tc.suf))
			}
		}
	}
}

func TestAES_ECB(t *testing.T) {
	const (
		key   = "YELLOW SUBMARINE"
		plain = "This is the plaintext. It's more than a single block long."
	)
	padded := PadPKCS7([]byte(plain), 16)
	enc := EncryptAES(padded, []byte(key), nil)
	dec := DecryptAES(enc, []byte(key), nil)
	if !bytes.Equal(dec, padded) {
		t.Fatalf("Decrypted %q; want %q", dec, padded)
	}
}

func TestAES_CBC(t *testing.T) {
	const (
		plain = "This is the plaintext. It's more than a single block long."
		key   = "YELLOW SUBMARINE"
		iv    = "1234567890123456"
	)
	padded := PadPKCS7([]byte(plain), 16)
	enc := EncryptAES(padded, []byte(key), []byte(iv))
	dec := DecryptAES(enc, []byte(key), []byte(iv))
	if !bytes.Equal(dec, padded) {
		t.Fatalf("Decrypted %q; want %q", dec, padded)
	}
}

func TestCTR(t *testing.T) {
	const (
		key   = "YELLOW SUBMARINE"
		nonce = 123
	)

	for _, plain := range []string{
		"",
		"123456789",              // less than a block
		"1234567890123456",       // exactly one block
		"Here is the plaintext!", // more than a block
	} {
		ctr := NewCTR([]byte(key), nonce)
		var enc bytes.Buffer
		if err := ctr.Process(strings.NewReader(plain), &enc); err != nil {
			t.Errorf("Encrypting %q failed: %v", plain, err)
			continue
		}
		ctr.Reset()
		var dec bytes.Buffer
		if err := ctr.Process(&enc, &dec); err != nil {
			t.Errorf("Decrypting %q failed: %v", plain, err)
		} else if dec.String() != plain {
			t.Errorf("Decrypted %q to %q", plain, dec.String())
		}
	}
}

func TestCTR_MultipleWrites(t *testing.T) {
	const (
		key   = "YELLOW SUBMARINE"
		nonce = 123
	)

	// Check that we properly save unused portions of the keystream to use
	// in later writes.
	chunks := []string{
		"",
		"This is short,",
		" while this spans a couple of different blocks of the keystream. ",
		"Now ",
		"let's ",
		"throw ",
		"in ",
		"some ",
		"more ",
		"short ",
		"writes.",
	}

	ctr := NewCTR([]byte(key), nonce)
	var enc bytes.Buffer
	for _, ch := range chunks {
		if err := ctr.Process(strings.NewReader(ch), &enc); err != nil {
			t.Fatalf("Encrypting %q failed: %v", ch, err)
		}
	}

	ctr.Reset()
	var dec bytes.Buffer
	if err := ctr.Process(&enc, &dec); err != nil {
		t.Errorf("Decrypting failed: %v", err)
	} else if full := strings.Join(chunks, ""); dec.String() != full {
		t.Errorf("Decrypted to %q; want %q", dec.String(), full)
	}
}
