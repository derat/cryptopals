// ECB cut-and-paste
package main

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/derat/cryptopals/common"
)

var key []byte = common.RandBytes(16) // fixed key

// parseKeyVals parses a string like "foo=bar&baz=qux&zap=zazzle".
func parseKeyVals(s string) (map[string]string, error) {
	m := make(map[string]string)
	for _, p := range strings.Split(s, "&") {
		kv := strings.Split(p, "=")
		if len(kv) != 2 {
			return nil, fmt.Errorf("bad keyval %q", p)
		}
		m[kv[0]] = kv[1]
	}
	return m, nil
}

// profileFor returns a string for parseKeyVals.
func profileFor(email string) string {
	email = strings.ReplaceAll(email, "&", "")
	email = strings.ReplaceAll(email, "=", "")
	return fmt.Sprintf("email=%v&uid=10&role=user", email)
}

func encrypt(email string) []byte {
	return common.EncryptAES([]byte(profileFor(email)), key, nil)
}

func decrypt(enc []byte) (map[string]string, error) {
	return parseKeyVals(string(common.DecryptAES(enc, key, nil)))
}

func main() {
	bs := common.FindECBBlockSize(func(b []byte) []byte {
		return encrypt(string(b))
	})

	// Create a block containing "admin" followed by PKCS#7 padding.
	addrLen := bs - len("email=")
	buf := append(bytes.Repeat([]byte{'A'}, addrLen), common.PadPKCS7([]byte("admin"), bs)...)
	enc := encrypt(string(buf))
	adminBlock := enc[bs:]

	// Figure out how long the address needs to be to push the role value to the beginning of a block.
	addrLen = -1
	var lastEnc []byte
	for i := 0; i <= 2*bs; i++ {
		enc := encrypt(strings.Repeat("A", i))
		if lastEnc != nil && len(enc) > len(lastEnc) {
			// There's always at least one byte of padding: when we fill the
			// last block, then we get a new block entirely filled with padding.
			// We want to push the length four bytes more so that "user" gets
			// pushed to the start of the final block.
			addrLen = i + 3 // TODO: Why does this need to be 3 rather than 4?
			break
		}
		lastEnc = enc
	}
	if addrLen < 0 {
		panic("failed finding address length")
	}
	fmt.Printf("Address length is %v\n", addrLen)

	// Generate an encrypted buffer and overwrite "user" with "admin".
	enc = encrypt(strings.Repeat("A", addrLen))
	copy(enc[len(enc)-bs:], adminBlock)

	if m, err := decrypt(enc); err != nil {
		fmt.Printf("Decryption failed: %v\n", err)
	} else {
		fmt.Println(m)
	}
}
