package common

import (
	"testing"
)

func TestMT19937(t *testing.T) {
	// There is example output at http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/mt19937-64.out.txt,
	// but it looks like it came from MT19937-64 rather than the 32-bit version.
	//
	// Expected values came from the following C++ program:
	//
	//   #include <iostream>
	//   #include <random>
	//
	//   int main(int argc, char** argv) {
	//     std::mt19937 mt_rand(12345);
	//     for (int i = 0; i < 1000; i++) {
	//   	auto n = mt_rand();
	//   	if (i % 100 == 0) std::cout << n << std::endl;
	//     }
	//     return 0;
	//   }
	//
	// Compile with "g++ -std=c++11 rand.cpp".
	const (
		seed = 12345
		iter = 1000
		mod  = 100
	)
	exps := []uint64{
		3992670690,
		2282559898,
		840933102,
		3790886053,
		3637592465,
		447125268,
		1271688334,
		926638379,
		3946885367,
		1683921108,
	}

	mt := NewMT19937(seed)
	for i := 0; i < iter; i++ {
		n := mt.Extract()
		if i%mod == 0 {
			if exp := exps[i/mod]; n != exp {
				t.Errorf("Extract() = %v at iteration %v; want %v", n, i, exp)
			}
		}
	}
}
