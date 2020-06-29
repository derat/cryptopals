package common

// PadPKCS7 returns a new buffer containing b padded to the
// supplied block size using PKCS#7 padding.
func PadPKCS7(b []byte, bs int) []byte {
	nb := len(b) / bs
	if len(b)%bs != 0 {
		nb++
	}
	padded := make([]byte, nb*bs)
	extra := byte(len(padded) - len(b))
	for n := copy(padded, b); n < len(padded); n++ {
		padded[n] = extra
	}
	return padded
}
