// Copyright 2020 Daniel Erat. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package common

import (
	"encoding/hex"
	"testing"
)

func TestHMACSHA1(t *testing.T) {
	for _, tc := range []struct {
		msg, key, hmac string
	}{
		// Expected HMACs are from https://www.freeformatter.com/hmac-generator.html,
		// which uses Bouncy Castle and was the first Google result for [sha1 hmac online].
		{"This is a test.", "YELLOW SUBMARINE", "6f775ec8c6fc22f32c033ad21af882648b3153fa"},
		{"Another test.", "YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE", "43efb1f215af28970767192db359dd0f4b9b7502"},
		{"One more.", "1234567890123456789012345678901234567890123456789012345678901234567890", "def3b8dbed54b32260bde45c2919615ddabca899"},
	} {
		h := HMACSHA1([]byte(tc.msg), []byte(tc.key))
		if hs := hex.EncodeToString(h); hs != tc.hmac {
			t.Errorf("HMACSHA1(%q, %q) = %v; want %v", tc.msg, tc.key, hs, tc.hmac)
		}
	}
}
