// Copyright 2020 Daniel Erat. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package common

import (
	"bufio"
	"encoding/base64"
	"io/ioutil"
	"math"
	"math/rand"
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

// RandWord returns a randomly-chosen word from /usr/share/dict/words.
// The maximum length of all words is also returned.
func RandWord() (word string, maxLen int) {
	rand.Seed(RandInt64(math.MaxInt64)) // rand package seeds with 1 by default

	f, err := os.Open("/usr/share/dict/words")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	nw := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		nw++
		w := sc.Text()
		if len(w) > maxLen {
			maxLen = len(w)
		}
		if rand.Float64() < 1/float64(nw) {
			word = w
		}
	}
	if err := sc.Err(); err != nil {
		panic(err)
	}

	return word, maxLen
}
