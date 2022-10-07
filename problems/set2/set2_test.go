package set2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPKCS7Padding(t *testing.T) {
	input := "YELLOW SUBMARINE"

	output := "YELLOW SUBMARINE\x04\x04\x04\x04"
	padded := PKCS7Padding([]byte(input), 20)
	require.Equal(t, output, string(padded))

	output = "YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
	padded = PKCS7Padding([]byte(input), 16)
	require.Equal(t, output, string(padded))
}

func TestCBCMode(t *testing.T) {
	//   msg := []byte("YELLOW SUBMARINEYELLOW SUBMARINE")
	//   iv := make([]byte,16)
	//   b,_ := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	//   res :=

}
