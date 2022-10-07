package set2

import "crypto/cipher"

func PKCS7Padding(input []byte, blockSize int) []byte {
	blockNum := len(input) % blockSize

	paddingSize := blockSize - blockNum

	ret := make([]byte, len(input)+paddingSize)
	copy(ret, input)
	for i := 0; i < paddingSize; i++ {
		ret[len(input)+i] = byte(paddingSize)
	}
	return ret
}

func EncryptCBC(src, iv []byte, b cipher.Block) ([]byte, error) {
	// blockSize := b.BlockSize()
	// if len(src) &blockSize != 0{
	// 	return nil,
	// }

	return nil, nil
}
