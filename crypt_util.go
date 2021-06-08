package go_utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// AesCbcPKCS5PaddingEncrypt AES CBC PKCS5Padding encrypt
func AesCbcPKCS5PaddingEncrypt(src, key, iv string) (string, error) {
	if strings.TrimSpace(src) == "" {
		return "", errors.New("plain content empty")
	}
	plaintext := PKCS5Padding([]byte(src), aes.BlockSize)
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, []byte(iv))
	mode.CryptBlocks(ciphertext, plaintext)
	return fmt.Sprintf("%x", ciphertext), err
}

// AesCbcPKCS5PaddingDecrypt AES CBC PKCS5Padding decrypt
func AesCbcPKCS5PaddingDecrypt(src, key, iv string) (string, error) {
	if strings.TrimSpace(src) == "" {
		return "", errors.New("crypto content empty")
	}
	ciphertext, _ := hex.DecodeString(src)
	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("cipher text too short")
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, []byte(iv))
	mode.CryptBlocks(plaintext, ciphertext)
	origin := PKCS5UnPadding(plaintext)
	return string(origin), err
}

// AesEcbPKCS5PaddingEncrypt AES ECB PKCS5Padding encrypt
func AesEcbPKCS5PaddingEncrypt(src, key string) (string, error) {
	if strings.TrimSpace(src) == "" {
		return "", errors.New("plain content empty")
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	ecb := NewECBEncrypter(block)
	plaintext := PKCS5Padding([]byte(src), block.BlockSize())
	ciphertext := make([]byte, len(plaintext))
	ecb.CryptBlocks(ciphertext, plaintext)
	return fmt.Sprintf("%x", ciphertext), nil
}

// AesEcbPKCS5PaddingDecrypt AES ECB PKCS5Padding decrypt
func AesEcbPKCS5PaddingDecrypt(src, key string) (string, error) {
	if strings.TrimSpace(src) == "" {
		return "", errors.New("crypto content empty")
	}
	ciphertext, _ := hex.DecodeString(src)
	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("cipher text too short")
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	ecb := NewECBDecrypter(block)
	plaintext := make([]byte, len(ciphertext))
	ecb.CryptBlocks(plaintext, ciphertext)
	origin := PKCS5UnPadding(plaintext)
	return string(origin), nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

type ecb struct {
	block     cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *ecb {
	return &ecb{
		block:     b,
		blockSize: b.BlockSize(),
	}
}

type ecbEncrypter ecb

func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(b))
}
func (x *ecbEncrypter) BlockSize() int {
	return x.blockSize
}
func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.block.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

type ecbDecrypter ecb

func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}
func (x *ecbDecrypter) BlockSize() int {
	return x.blockSize
}
func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.block.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}
