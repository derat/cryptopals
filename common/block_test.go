package common

import (
	"bytes"
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
		if unpadded := UnpadPKCS7([]byte(tc.padded)); !bytes.Equal(unpadded, []byte(tc.unpadded)) {
			t.Errorf("UnpadPKCS7(%q) = %q; want %q", tc.padded, unpadded, tc.unpadded)
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

func TestAES_ECB(t *testing.T) {
	const (
		key   = "YELLOW SUBMARINE"
		plain = "This is the plaintext. It's more than a single block long."
	)
	enc := EncryptAES([]byte(plain), []byte(key), nil)
	dec := DecryptAES(enc, []byte(key), nil)
	if string(dec) != plain {
		t.Fatalf("Decrypted %q; want %q", dec, plain)
	}
}

func TestAES_CBC(t *testing.T) {
	const (
		plain = "This is the plaintext. It's more than a single block long."
		key   = "YELLOW SUBMARINE"
		iv    = "1234567890123456"
	)
	enc := EncryptAES([]byte(plain), []byte(key), []byte(iv))
	dec := DecryptAES(enc, []byte(key), []byte(iv))
	if string(dec) != plain {
		t.Fatalf("Decrypted %q; want %q", dec, plain)
	}
}
