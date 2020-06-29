// Convert hex to base64
package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func main() {
	const orig = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	b, err := hex.DecodeString(orig)
	if err != nil {
		panic(err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(b))
}
