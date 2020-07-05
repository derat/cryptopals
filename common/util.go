package common

import (
	"bufio"
	"encoding/base64"
	"io/ioutil"
	"os"
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

// ReadHexLines reads and decodes hex lines from p.
func ReadHexLines(p string) [][]byte {
	f, err := os.Open(p)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	var bufs [][]byte
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		bufs = append(bufs, Unhex(sc.Text()))
	}
	if sc.Err() != nil {
		panic(err)
	}
	return bufs
}

// ReadHexLines reads and decodes base64 lines from p.
func ReadBase64Lines(p string) [][]byte {
	f, err := os.Open(p)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	var bufs [][]byte
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		dec, err := base64.StdEncoding.DecodeString(sc.Text())
		if err != nil {
			panic(err)
		}
		bufs = append(bufs, dec)
	}
	if sc.Err() != nil {
		panic(err)
	}
	return bufs
}
