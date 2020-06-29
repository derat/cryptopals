package common

import (
	"encoding/base64"
	"io/ioutil"
)

// ReadBase64 reads base64 data from the file at p.
// It panics on error.
func ReadBase64(p string) []byte {
	b, err := ioutil.ReadFile(p)
	if err != nil {
		panic(err)
	}
	dec, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		panic(err)
	}
	return dec
}
