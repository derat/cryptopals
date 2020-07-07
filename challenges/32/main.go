// Copyright 2020 Daniel Erat. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Break HMAC-SHA1 with a slightly less artificial timing leak
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/derat/cryptopals/common"
)

const hmacLen = 20 // hardcoded for SHA-1

// insecureCompare compares a and b one byte at a time.
// It sleeps 5 milliseconds after each successful comparison and returns immediately
// after the first differing byte.
func insecureCompare(a, b []byte) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
	return len(a) == len(b)
}

// getNextByte performs a timing attack to get the next byte of the HMAC.
// The hex-encoded HMAC will be appended to the end of urlPrefix.
func getNextByte(urlPrefix string, known []byte) byte {
	type result struct {
		b byte
		d time.Duration
	}
	todo := make(chan []byte, 256) // HMACs to test
	done := make(chan result, 256) // test results

	// Start some goroutines to test HMACs in parallel.
	const (
		numGoroutines = 24
		numChecks     = 5
	)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			for hmac := range todo {
				url := urlPrefix + hex.EncodeToString(hmac)

				minDelay := time.Hour
				for j := 0; j < numChecks; j++ {
					start := time.Now()
					if resp, err := http.Post(url, "text/plain", &bytes.Buffer{}); err != nil {
						panic(fmt.Sprintf("request to %v failed: %v", url, err))
					} else {
						if delay := time.Now().Sub(start); delay < minDelay {
							minDelay = delay
						}
						resp.Body.Close()
					}
				}

				done <- result{hmac[len(known)], minDelay}
			}
		}()
	}

	// Generate HMACs using all possible next bytes.
	for i := 0; i < 256; i++ {
		hmac := make([]byte, hmacLen)
		copy(hmac, known)
		hmac[len(known)] = byte(i)
		todo <- hmac
	}

	// Wait on the results and choose the one that took the longest.
	var maxByte byte
	var maxDelay time.Duration
	for i := 0; i < 256; i++ {
		res := <-done
		if res.d > maxDelay {
			maxByte = res.b
			maxDelay = res.d
		}
	}
	return maxByte
}

func main() {
	var (
		key  = common.RandBytes(1 + common.RandInt(64))
		addr = "127.0.0.1:8345"
	)

	http.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		file := r.FormValue("file")
		sig := r.FormValue("signature")

		h1 := common.HMACSHA1([]byte(file), key)
		h2, err := hex.DecodeString(sig)
		if err != nil {
			http.Error(w, "unparseable signature", http.StatusBadRequest)
			return
		}

		// If the HMAC is wrong, return a 500 (per the challenge).
		if !insecureCompare(h1, h2) {
			http.Error(w, "invalid signature", http.StatusInternalServerError)
			return
		}

		io.WriteString(w, "ok\n")
	})

	go http.ListenAndServe(addr, nil)

	// Wait for the server to start.
	for {
		if conn, err := net.DialTimeout("tcp", addr, 5*time.Second); err == nil {
			conn.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	const file = "filename.txt"
	url := fmt.Sprintf("http://%v/test?file=%v&signature=", addr, file)

	var hmac []byte
	for len(hmac) < hmacLen {
		hmac = append(hmac, getNextByte(url, hmac))
		fmt.Printf("HMAC: %x\n", hmac)
	}
	fmt.Printf("Constructed HMAC %x for file %q\n", hmac, file)

	// TODO: This doesn't get the correct HMAC every time, but it at least works sometimes.
	// I could probably tweak the getNextByte() function further more to improve it, but it
	// doesn't seem worthwhile -- I get the idea.
	url += hex.EncodeToString(hmac)
	resp, err := http.Post(url, "text/plain", &bytes.Buffer{})
	if err != nil {
		panic(fmt.Sprintf("request to %v failed: %v", url, err))
	} else if resp.StatusCode != 200 {
		panic(fmt.Sprintf("request to %v returned %v", url, resp.Status))
	} else {
		fmt.Println("HMAC works!")
	}
	resp.Body.Close()
}
