// Create the MT19937 stream cipher and break it
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/derat/cryptopals/common"
)

// process initializes an MT19937 PRNG with seed and repeatedly XORs its output against plain.
// Each 32-bit output from the PRNG is interpreted in big-endian order.
func process(seed uint64, plain []byte) []byte {
	mt := common.NewMT19937(uint64(seed))
	enc := make([]byte, 0, len(plain))
	pr := bytes.NewReader(plain)
	for {
		// Read plaintext in chunks of up to 4 bytes.
		buf := make([]byte, 4)
		n, rerr := io.ReadFull(pr, buf)
		buf = buf[:n]

		// Read the next 32-bit value from the PRNG and XOR it against the plaintext.
		var ks bytes.Buffer
		binary.Write(&ks, binary.BigEndian, uint32(mt.Extract()))
		enc = append(enc, common.XOR(buf, ks.Bytes())...)

		// If we got an EOF during the read, we're done.
		if rerr != nil {
			return enc
		}
	}
}

func testProcess() {
	const (
		seed  = 31337
		plain = "This is the plaintext. Woo!"
	)
	enc := process(seed, []byte(plain))
	dec := process(seed, enc)
	if string(dec) != plain {
		panic(fmt.Sprintf("Decrypted to %q; want %q\n", dec, plain))
	}
}

func main() {
	// Check that process() is reversible.
	testProcess()

	// Per the challenge: use a 16-bit seed to encrypt a known string
	// preceded by a random number of random bytes.
	seed := uint64(common.RandInt(1 << 16))
	prefix := common.RandBytes(10 + common.RandInt(64))
	known := common.A(14)
	enc := process(seed, append(prefix, known...))

	// Now brute-force the initial seed and use it to find the prefix.
	var found []byte
	for s := 0; s < 1<<16; s++ {
		b := process(uint64(s), enc)
		if bytes.Contains(b, known) {
			log.Println("Found seed:", s)
			found = b[:len(b)-len(known)]
			break
		}
	}
	if !bytes.Equal(found, prefix) {
		panic(fmt.Sprintf("Found prefix %v; want %v\n", found, prefix))
	}

	// Per the challenge:
	//
	//   Use the same idea to generate a random "password reset token" using MT19937 seeded from the current time.
	//   Write a function to check if any given password token is actually the product of an MT19937 PRNG seeded with
	//   the current time.
	//
	// This seems underspecified. Should I use the bottom 16 bits of the current Unix time, or the whole thing?
	// A 32-bit seed seems like it'll take much longer to brute-force. Or maybe I just search the last X seconds'
	// worth of seeds? I'm assuming that I should use the raw output of the PRNG as the token (i.e. encrypt a stream
	// of zero bytes), since if I encrypt random bytes, I'm just getting back noise and won't have any way to test
	// validity.

	const (
		tokenLen    = 16
		maxDuration = 24 * time.Hour
	)
	tokenBuf := make([]byte, tokenLen) // empty buf of tokenLen

	// Returns a token generated using |now|'s Unix timestamp as a seed.
	makeToken := func(now time.Time) []byte { return process(uint64(now.Unix()), tokenBuf) }

	// Check whether |token| was generated using a recent timestamp.
	tokenValid := func(token []byte) bool {
		earliest := time.Now().Add(-maxDuration)
		for t := time.Now(); t.After(earliest); t = t.Add(-time.Second) {
			if bytes.Equal(makeToken(t), token) {
				return true
			}
		}
		return false
	}

	if token := makeToken(time.Now().Add(-time.Hour)); tokenValid(token) {
		fmt.Printf("Detected %q as seeded by time\n", hex.EncodeToString(token))
	} else {
		panic(fmt.Sprintf("Failed to detect %q as seeded by time\n", hex.EncodeToString(token)))
	}
	if token := common.RandBytes(tokenLen); tokenValid(token) {
		panic(fmt.Sprintf("Incorrectly detected %q as seeded by time\n", hex.EncodeToString(token)))
	} else {
		fmt.Printf("Detected %q as not seeded by time\n", hex.EncodeToString(token))
	}
}
