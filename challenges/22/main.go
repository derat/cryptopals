// Copyright 2020 Daniel Erat. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Crack an MT19937 seed
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/derat/cryptopals/common"
)

func randDuration(min, max time.Duration) time.Duration {
	return min + time.Duration(common.RandInt64(int64(max-min)))
}

// getRand simulates sleeping 40-1000 seconds, generating a pseudorandom number using the
// "current" Unix timestamp as a seed, and then sleeping another 40-1000 seconds.
// The number and total amount of time slept are returned.
func getRand() (uint64, time.Duration) {
	dur := randDuration(40*time.Second, 1000*time.Second)
	num := common.NewMT19937(uint64(time.Now().Add(dur).Unix())).Extract()
	return num, dur + randDuration(40*time.Second, 1000*time.Second)
}

func main() {
	// From the challenge:
	//
	//   Write a routine that performs the following operation:
	//   * Wait a random number of seconds between, I don't know, 40 and 1000.
	//   * Seeds the RNG with the current Unix timestamp
	//   * Waits a random number of seconds again.
	//   * Returns the first 32 bit output of the RNG.

	start := time.Now()
	num, dur := getRand()
	end := start.Add(dur)

	for t := start; t.Before(end); t = t.Add(time.Second) {
		seed := uint64(t.Unix())
		if n := common.NewMT19937(seed).Extract(); n == num {
			fmt.Printf("Seed %v produces %v\n", seed, num)
			os.Exit(0)
		}
	}
	panic(fmt.Sprintf("didn't find seed between %v and %v producing %v", start.Unix(), end.Unix(), num))
}
