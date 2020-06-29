// Implement PKCS#7 padding
package main

import (
	"fmt"

	"github.com/derat/cryptopals/common"
)

func main() {
	const in = "YELLOW SUBMARINE"
	fmt.Printf("%q\n", common.PadPKCS7([]byte(in), 20))
}
