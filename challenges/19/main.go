// Copyright 2020 Daniel Erat. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Break fixed-nonce CTR mode using substitutions
package main

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/derat/cryptopals/common"
)

var data = []string{ // provided by challenge
	"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
	"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
	"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
	"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
	"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
	"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
	"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
	"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
	"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
	"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
	"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
	"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
	"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
	"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
	"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
	"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
	"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
	"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
	"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
	"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
	"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
	"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
	"U2hlIHJvZGUgdG8gaGFycmllcnM/",
	"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
	"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
	"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
	"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
	"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
	"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
	"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
	"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
	"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
	"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
	"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
	"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
	"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
	"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
	"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
	"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
	"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
}

var key = common.RandBytes(16)

const nonce = 0

func main() {
	ctr := common.NewCTR(key, nonce)
	encs := make([][]byte, len(data))
	for i, d := range data {
		sec, err := base64.StdEncoding.DecodeString(d)
		if err != nil {
			panic(fmt.Sprintf("failed decoding secret %q: %v", d, err))
		}
		var enc bytes.Buffer
		ctr.Reset()
		if err := ctr.Process(bytes.NewReader(sec), &enc); err != nil {
			panic(fmt.Sprintf("failed encrypting string %d: %v", i, err))
		}
		encs[i] = enc.Bytes()
	}

	maxLen := 0
	for _, enc := range encs {
		if len(enc) > maxLen {
			maxLen = len(enc)
		}
	}

	decs := make([][]byte, len(encs))

	// Whoops, I think I accidentally used the approach from Challenge 20 here.
	// Reading online afterwords, it sounds like many people just skipped this challenge
	// and went to number 20. What's the point of doing this manually just to see how much it sucks?
	for i := 0; i < maxLen; i++ {
		buf := make([]byte, 0, len(encs)) // bytes at position i across all ciphertexts
		for _, enc := range encs {
			if i < len(enc) {
				buf = append(buf, enc[i])
			}
		}
		xor := common.SingleByteXOR(buf)

		// When the cross-section consists only of letters, common.EnglishScore can't tell
		// whether they should be lowercase or upper case. It also has trouble with the later
		// bytes, where there's less data due to some of the lines being short. Hardcode some
		// trickier bytes that I determined manually by looking at the automated results.
		if i == 0 {
			xor = encs[0][i] ^ 'I'
		} else if i == 7 {
			xor = encs[0][i] ^ 'm'
		} else if i == 25 {
			xor = encs[5][i] ^ 'd'
		} else if i == 28 {
			xor = encs[33][i] ^ 't'
		} else if i == 29 {
			xor = encs[35][i] ^ 't'
		} else if i == 30 {
			xor = encs[6][i] ^ 'i'
		} else if i == 31 {
			xor = encs[6][i] ^ 'd'
		} else if i == 32 {
			xor = encs[27][i] ^ 'd'
		} else if i == 33 {
			xor = encs[4][i] ^ 'e'
		} else if i == 34 {
			xor = encs[4][i] ^ 'a'
		} else if i == 35 {
			xor = encs[4][i] ^ 'd'
		} else if i == 36 {
			xor = encs[37][i] ^ 'n'
		} else if i == 37 {
			xor = encs[37][i] ^ ','
		}

		for j, enc := range encs {
			if i < len(enc) {
				decs[j] = append(decs[j], enc[i]^xor)
			}
		}
	}

	for _, dec := range decs {
		fmt.Printf("%q\n", dec)
	}
}
