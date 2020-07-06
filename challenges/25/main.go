// Break fixed-nonce CTR statistically
package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/derat/cryptopals/common"
)

var key = common.RandBytes(16)

const nonce = 0xBEEFFACEDEADDEAD

func edit(enc []byte, offset int, newText []byte) {
	ctr := common.NewCTR(key, nonce)
	if err := ctr.Process(bytes.NewReader(make([]byte, offset)), ioutil.Discard); err != nil {
		panic(fmt.Sprintf("failed seeking in keystream: %v", err))
	}
	var b bytes.Buffer
	if err := ctr.Process(bytes.NewReader(newText), &b); err != nil {
		panic(fmt.Sprintf("failed writing: %v", err))
	}
	copy(enc[offset:], b.Bytes())
}

func testEdit() {
	ctr := common.NewCTR(key, nonce)
	var enc bytes.Buffer
	ctr.Process(strings.NewReader("My first name is Dave!"), &enc)
	edit(enc.Bytes(), 17, []byte("John"))
	var dec bytes.Buffer
	ctr.Reset()
	ctr.Process(&enc, &dec)
	if exp := "My first name is John!"; dec.String() != exp {
		panic(fmt.Sprintf("got %q after edit; want %q", dec.String(), exp))
	}
}

func main() {
	testEdit()

	// Argh, this is stupid. Why does this challenge use the same ECB-encrypted data
	// as challenge 7 instead of just giving us unencrypted data? What's the point
	// of decrypting it just so we can re-encrypt it immediately afterwards?
	// (I'm grumpy because I wasted time debugging why my code wasn't working before
	// realizing that the "plaintext" that I was recovering was already encrypted.)
	secret := common.DecryptAES(common.ReadBase64("25.txt"), []byte("YELLOW SUBMARINE"), nil)
	ctr := common.NewCTR(key, nonce)
	var enc bytes.Buffer
	if err := ctr.Process(bytes.NewReader(secret), &enc); err != nil {
		panic(fmt.Sprintf("failed encrypting data: %v", err))
	}

	// This seems too easy: "edit" an empty buffer to get the full keystream, and then XOR
	// it against the ciphertext to get the plaintext. What's the point of even having an
	// "edit" function? We could use the same attack with an encrypt function that always
	// rewinds to the beginning of the keystream.
	empty := make([]byte, enc.Len())
	edit(empty, 0, make([]byte, enc.Len()))
	fmt.Printf("%q\n", common.XOR(enc.Bytes(), empty))

	// After reading a bit online to see if it's really this simple, I saw that there's an even
	// simpler approach: just pass the ciphertext to edit() as the new string. When it gets
	// XORed with the keystream, we end up with the plaintext.
	edit(enc.Bytes(), 0, enc.Bytes())
	fmt.Printf("%q\n", enc.Bytes())

	// I'm still not sure what the point of having an edit() function was. It made me initially
	// think that we'd need to seek around to different points in the ciphertext. Maybe it'll
	// be necessary in a later challenge...
}
