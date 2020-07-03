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
	f := func(b []byte) []byte { return encrypt(string(b)) }
	bs := common.BlockSizeECB(f)
	pl := common.PrefixLen(f, bs)
	sl := common.SuffixLen(f, bs)
	fmt.Printf("Prefix length is %v, suffix is %v\n", pl, sl)

	// Create a block containing "admin" followed by PKCS#7 padding.
	addrLen := bs - pl
	buf := append(bytes.Repeat([]byte{'A'}, addrLen), common.PadPKCS7([]byte("admin"), bs)...)
	enc := encrypt(string(buf))
	adminBlock := enc[bs:]

	// Figure out how long the address needs to be to push the role value to the beginning of a block.
	// In other words, we want the last four bytes of the suffix ("user") to be at the start of a block.
	addrLen = bs - ((pl + sl - 4) % bs)
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
