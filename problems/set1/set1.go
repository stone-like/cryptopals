package set1

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math"
	"math/bits"
	"unicode/utf8"
)

var (
	ErrInvalidLen       = errors.New("invalidLenError")
	ErrInvalidBlockSize = errors.New("invalidBlockSizeError")
	ErrInvalidDistance  = errors.New("two string is different len")
)

func ConvertToHexToBase64(input string) (string, error) {
	v, err := hex.DecodeString(input)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(v), nil
}

func xor(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, ErrInvalidLen
	}

	out := make([]byte, len(a))

	for i := 0; i < len(a); i++ {
		out[i] = a[i] ^ b[i]
	}

	return out, nil
}

func FixedXOR(input1, input2 string) (string, error) {
	hexed1, err := hex.DecodeString(input1)
	if err != nil {
		return "", err
	}
	hexed2, err := hex.DecodeString(input2)
	if err != nil {
		return "", err
	}
	bytes, err := xor(hexed1, hexed2)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}

func buildCorpus(text string) map[rune]float64 {
	m := make(map[rune]float64)

	for _, r := range text {
		m[r]++
	}

	totalCharNum := utf8.RuneCountInString(text)
	for r, _ := range m {
		m[r] = m[r] / float64(totalCharNum)
	}

	return m
}

func singleXOR(input []byte, key byte) []byte {
	ret := make([]byte, len(input))
	for index, v := range input {
		ret[index] = v ^ key
	}

	return ret
}

func scoreEnglish(text string, corpus map[rune]float64) float64 {
	var score float64
	for _, r := range text {
		s, exists := corpus[r]
		if !exists {
			continue
		}
		score += s
	}

	return score
}

func DecryptSingleXOR(input []byte, corpus map[rune]float64) (ret []byte, key byte, maxScore float64) {

	//256通りは8bitで1bit、なので半角英数字を表している(実際256より少ないけど)
	for k := 0; k < 256; k++ {
		out := singleXOR(input, byte(k))
		score := scoreEnglish(string(out), corpus)

		if maxScore < score {
			maxScore = score
			ret = out
			key = byte(k)
		}
	}

	return ret, key, maxScore

}

func RepeatingXOR(input []byte, key []byte) []byte {
	ret := make([]byte, len(input))
	for index, r := range input {
		ret[index] = r ^ key[index%len(key)]
	}

	return ret
}

func hammingDistance(a, b []byte) (int, error) {
	if len(a) != len(b) {
		return -1, ErrInvalidDistance
	}

	ret := 0
	for i := 0; i < len(a); i++ {
		ret += bits.OnesCount8(a[i] ^ b[i])
	}
	return ret, nil
}

func findRepeatingXORSize(input []byte) (int, error) {
	ret := 0
	smallestScore := math.MaxFloat64

	for keyLen := 2; keyLen <= 40; keyLen++ {

		a, b := input[:keyLen*4], input[keyLen*4:keyLen*4*2]

		distance, err := hammingDistance(a, b)
		if err != nil {
			return -1, err
		}
		score := float64(distance) / float64(keyLen)

		if score < smallestScore {
			ret = keyLen
			smallestScore = score
		}

	}

	return ret, nil
}

func findRepeatingXORKey(input []byte, corpus map[rune]float64) ([]byte, error) {
	keySize, err := findRepeatingXORSize(input)
	if err != nil {
		return nil, err
	}
	column := make([]byte, (len(input)+keySize-1)/keySize)
	key := make([]byte, keySize)
	for col := 0; col < keySize; col++ {
		for row := 0; row < len(column); row++ {
			if row*keySize+col >= len(input) {
				continue
			}
			column[row] = input[row*keySize+col]
		}
		_, k, _ := DecryptSingleXOR(column, corpus)
		key[col] = k
	}
	return key, nil
}

func DecryptAES_ECB(input []byte, b cipher.Block) ([]byte, error) {

	if len(input)%b.BlockSize() != 0 {
		return nil, ErrInvalidBlockSize
	}

	ret := make([]byte, len(input))

	for i := 0; i < len(input); i += b.BlockSize() {
		b.Decrypt(ret[i:], input[i:])
	}

	return ret, nil
}

//ECBなのでBlockSizeは16固定?
func DetectECB(input []byte, blockSize int) (bool, error) {
	if len(input)%blockSize != 0 {
		return false, ErrInvalidBlockSize
	}

	seen := make(map[string]struct{})

	for i := 0; i < len(input); i += blockSize {
		target := string(input[i : i+blockSize])
		if _, exists := seen[target]; exists {
			return true, nil
		}

		seen[target] = struct{}{}
	}

	return false, nil
}
