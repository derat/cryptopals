// Implement CTR, the stream cipher mode
package main

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/derat/cryptopals/common"
)

const (
	secret = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	key    = "YELLOW SUBMARINE"
	nonce  = 0
)

func main() {
	enc, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		panic(fmt.Sprintf("failed decoding secret: %v", err))
	}

	var plain bytes.Buffer
	ctr := common.NewCTR([]byte(key), nonce)
	if err := ctr.Process(bytes.NewReader(enc), &plain); err != nil {
		panic(fmt.Sprintf("failed processing data: %v", err))
	}
	fmt.Printf("%q\n", plain.String())
}
