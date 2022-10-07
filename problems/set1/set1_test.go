package set1

import (
	"bufio"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConvertHexToBase64(t *testing.T) {
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	output := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	ret, err := ConvertToHexToBase64(input)
	require.NoError(t, err)
	require.Equal(t, output, ret)
}

func TestFixedXOR(t *testing.T) {
	input := "1c0111001f010100061a024b53535009181c"
	xorInput := "686974207468652062756c6c277320657965"
	output := "746865206b696420646f6e277420706c6179"
	ret, err := FixedXOR(input, xorInput)
	require.NoError(t, err)

	require.Equal(t, output, ret)
}

func TestDeCipherAgainstSingleXOR(t *testing.T) {
	hexedInput := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	corpus, err := buildCorpusFromFile("../../testData/alice.txt")
	require.NoError(t, err)

	ret, key, _ := DecryptSingleXOR(decodeHex(t, hexedInput), corpus)

	t.Logf("find key is %s!\n", string(key))
	t.Log("text is\n")
	t.Log(string(ret))
}

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	v, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal("failed to decode hex")
	}
	return v
}

func buildCorpusFromFile(name string) (map[rune]float64, error) {
	bytes, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return buildCorpus(string(bytes)), nil
}

func TestDetectSingleCharacterXOR(t *testing.T) {

	f, err := os.Open("../../testData/set1-4.txt")
	require.NoError(t, err)
	defer f.Close()

	scanner := bufio.NewScanner(f)

	corpus, err := buildCorpusFromFile("../../testData/alice.txt")
	require.NoError(t, err)
	var maxScore float64
	var ret []byte
	var retKey byte

	for scanner.Scan() {

		out, key, score := DecryptSingleXOR(decodeHex(t, scanner.Text()), corpus)
		if maxScore < score {
			ret = out
			retKey = key
			maxScore = score
		}
	}

	t.Logf("find key is %s!\n", string(retKey))
	t.Log("text is\n")
	t.Log(string(ret))
}

func TestEncryptWithRepeatingXOR(t *testing.T) {

	key := "ICE"
	input := []byte(`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`)

	ret := RepeatingXOR(input, []byte(key))
	require.Equal(t, decodeHex(t, "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"), ret)
}

func decodeBase64(t *testing.T, text string) []byte {
	t.Helper()
	v, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		t.Fatal("failed to decode base64")
	}
	return v
}

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	v, err := os.ReadFile(name)
	if err != nil {
		t.Fatal("failed to readfile")
	}
	return v
}

func TestHammingDistance(t *testing.T) {
	ret, err := hammingDistance([]byte("this is a test"), []byte("wokka wokka!!!"))
	require.NoError(t, err)
	require.Equal(t, 37, ret)
}

func TestBreakRepeatingXOR(t *testing.T) {
	text := decodeBase64(t, string(readFile(t, "../../testData/set1-6.txt")))
	keySize, err := findRepeatingXORSize(text)
	require.NoError(t, err)
	t.Logf("keySize is %d\n", keySize)

	corpus, err := buildCorpusFromFile("../../testData/alice.txt")
	require.NoError(t, err)
	key, err := findRepeatingXORKey(text, corpus)
	require.NoError(t, err)
	t.Logf("key is %s\n", string(key))

	t.Logf("answer is %s\n", RepeatingXOR(text, key))

}

func TestDecryptEBS(t *testing.T) {
	text := decodeBase64(t, string(readFile(t, "../../testData/set1-7.txt")))
	b, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	require.NoError(t, err)

	ret, err := DecryptAES_ECB(text, b)
	require.NoError(t, err)

	t.Log(string(ret))
}

//ECBの弱点は同じ平文からは同じ暗号文が生まれてしまうこと
func TestDetectECB(t *testing.T) {
	f, err := os.Open("../../testData/set1-8.txt")
	require.NoError(t, err)
	defer f.Close()

	scanner := bufio.NewScanner(f)

	i := 0
	for scanner.Scan() {
		ret, err := DetectECB(decodeHex(t, scanner.Text()), 16)
		require.NoError(t, err)
		if ret {
			t.Logf("line number %d is encrypted with ECB!\n", i+1)
		}

		i++
	}

}
