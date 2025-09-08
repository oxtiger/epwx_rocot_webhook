package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// AESCipher 提供AES加解密功能
type AESCipher struct {
	Key []byte // AES密钥，长度必须为16、24或32字节
	IV  []byte // 初始向量，长度必须为16字节
}

// NewAESCipher 创建一个新的AES加解密器
// encodingAESKey 是Base64编码的AES密钥
func NewAESCipher(encodingAESKey string) (*AESCipher, error) {
	// 确保encodingAESKey长度为43个字符
	if len(encodingAESKey) != 43 {
		return nil, errors.New("encoding AES key must be 43 characters")
	}

	// 添加=号并进行Base64解码
	key, err := base64.StdEncoding.DecodeString(encodingAESKey + "=")
	if err != nil {
		return nil, fmt.Errorf("decode AES key error: %v", err)
	}

	// 确保解码后的密钥长度为32字节
	if len(key) != 32 {
		return nil, errors.New("AES key length must be 32 bytes after decoding")
	}

	// 使用密钥的前16字节作为IV
	return &AESCipher{
		Key: key,
		IV:  key[:16],
	}, nil
}

// Encrypt 使用AES-CBC模式加密数据
func (c *AESCipher) Encrypt(plaintext []byte) (string, error) {
	// 创建AES加密块
	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return "", fmt.Errorf("create AES cipher error: %v", err)
	}

	// 对数据进行PKCS#7填充
	plaintext = pkcs7Padding(plaintext, block.BlockSize())

	// 创建CBC模式的加密器
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, c.IV)
	mode.CryptBlocks(ciphertext, plaintext)

	// 将加密结果进行Base64编码
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt 使用AES-CBC模式解密数据
func (c *AESCipher) Decrypt(ciphertextB64 string) ([]byte, error) {
	// Base64解码
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode error: %v", err)
	}

	// 创建AES解密块
	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher error: %v", err)
	}

	// 检查密文长度是否为块大小的整数倍
	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	// 创建CBC模式的解密器
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, c.IV)
	mode.CryptBlocks(plaintext, ciphertext)

	// 去除PKCS#7填充
	plaintext, err = pkcs7Unpadding(plaintext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// GenerateRandomAESKey 生成一个随机的AES密钥并返回其Base64编码
func GenerateRandomAESKey() (string, error) {
	// 生成32字节的随机密钥
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return "", fmt.Errorf("generate random key error: %v", err)
	}

	// Base64编码并去掉末尾的=号
	encoded := base64.StdEncoding.EncodeToString(key)
	return encoded[:len(encoded)-1], nil
}

// pkcs7Padding 对数据进行PKCS#7填充
func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// pkcs7Unpadding 去除PKCS#7填充
func pkcs7Unpadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("invalid padding data")
	}

	padding := int(data[length-1])
	if padding > length {
		return nil, errors.New("invalid padding size")
	}

	return data[:length-padding], nil
}