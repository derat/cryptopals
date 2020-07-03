// CBC bitflipping attacks
package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/derat/cryptopals/common"
)

const (
	prefix = "comment1=cooking%20MCs;userdata="
	suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
)

var key []byte = common.RandBytes(16)
var iv []byte = common.RandBytes(16)

// encrypt adds prefix and suffix to s and encrypts using AES-128 in CBC mode.
func encrypt(s string) []byte {
	s = strings.ReplaceAll(s, ";", "%3B")
	s = strings.ReplaceAll(s, "=", "%3D")
	plain := prefix + s + suffix
	return common.EncryptAES([]byte(plain), key, iv) // pads input
}

// admin decrypts b and returns true if the resulting string contains ";admin=true;".
func admin(b []byte) bool {
	return bytes.Contains(common.DecryptAES(b, key, iv), []byte(";admin=true;"))
}

func main() {
	// From the challenge:
	//
	//   You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:
	//   * Completely scrambles the block the error occurs in
	//   * Produces the identical 1-bit error(/edit) in the next ciphertext block.
	//   Stop and think for a second.
	//   Before you implement this attack, answer this question: why does CBC mode have this property?
	//
	// When we flip a bit in ciphertext block C(n), the same bit will be flipped in plaintext block P(n+1)
	// since P(n+1) gets XOR-ed against C(n) after decrypting.

	const bs = 16 // TODO: Detect this by just adding bytes until we see it grow?
	f := func(b []byte) []byte { return encrypt(string(b)) }
	pl := common.PrefixLen(f, bs)
	fmt.Printf("Prefix length is %v\n", pl)

	pad := common.A(pl % bs)                 // pad out the first modifiable block
	b := append(pad, common.A(bs)...)        // add a full block for flipping bits
	b = append(b, []byte("_admin_true_")...) // finally, add a target block
	enc := encrypt(string(b))

	off := pl + len(pad) // bit-flipping offset

	// Now try all combinations of the target bytes in the preceding block to get the
	// characters that would be escaped.
	for i := 0; i < 256; i++ {
		enc[off] = byte(i) // first ';'
		for j := 0; j < 256; j++ {
			enc[off+6] = byte(j) // '='
			for k := 0; k < 256; k++ {
				enc[off+11] = byte(k) // second ';'
				if a := admin(enc); a {
					fmt.Printf("Got admin with i=%d, j=%d, k=%d!\n", i, j, k)
					os.Exit(0)
				}
			}
		}
	}
	fmt.Println("Didn't get admin. :-(")
}
