package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

// RSACipher 提供RSA加解密功能
type RSACipher struct {
	PublicKey  *rsa.PublicKey
	PrivateKey *rsa.PrivateKey
}

// NewRSACipherFromKeys 从PEM格式的公钥和私钥创建RSA加解密器
func NewRSACipherFromKeys(publicKeyPEM, privateKeyPEM string) (*RSACipher, error) {
	cipher := &RSACipher{}
	var err error

	// 解析公钥（如果提供）
	if publicKeyPEM != "" {
		cipher.PublicKey, err = parseRSAPublicKeyFromPEM(publicKeyPEM)
		if err != nil {
			return nil, err
		}
	}

	// 解析私钥（如果提供）
	if privateKeyPEM != "" {
		cipher.PrivateKey, err = parseRSAPrivateKeyFromPEM(privateKeyPEM)
		if err != nil {
			return nil, err
		}
		// 如果没有提供公钥，从私钥中提取
		if cipher.PublicKey == nil {
			cipher.PublicKey = &cipher.PrivateKey.PublicKey
		}
	}

	return cipher, nil
}

// GenerateRSAKeyPair 生成新的RSA密钥对
func GenerateRSAKeyPair(bits int) (*RSACipher, string, string, error) {
	// 生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, "", "", fmt.Errorf("generate RSA key error: %v", err)
	}

	// 将私钥转换为PEM格式
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// 将公钥转换为PEM格式
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, "", "", fmt.Errorf("marshal public key error: %v", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// 创建RSA加解密器
	cipher := &RSACipher{
		PublicKey:  &privateKey.PublicKey,
		PrivateKey: privateKey,
	}

	return cipher, string(publicKeyPEM), string(privateKeyPEM), nil
}

// Encrypt 使用RSA公钥加密数据
func (c *RSACipher) Encrypt(plaintext []byte) (string, error) {
	if c.PublicKey == nil {
		return "", errors.New("public key is not available")
	}

	// 使用RSA-OAEP算法加密
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, c.PublicKey, plaintext, nil)
	if err != nil {
		return "", fmt.Errorf("RSA encrypt error: %v", err)
	}

	// 将加密结果进行Base64编码
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt 使用RSA私钥解密数据
func (c *RSACipher) Decrypt(ciphertextB64 string) ([]byte, error) {
	if c.PrivateKey == nil {
		return nil, errors.New("private key is not available")
	}

	// Base64解码
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode error: %v", err)
	}

	// 使用RSA-OAEP算法解密
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, c.PrivateKey, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA decrypt error: %v", err)
	}

	return plaintext, nil
}

// 从PEM格式字符串解析RSA公钥
func parseRSAPublicKeyFromPEM(publicKeyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, errors.New("key type is not RSA")
	}
}

// 从PEM格式字符串解析RSA私钥
func parseRSAPrivateKeyFromPEM(privateKeyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the private key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return priv, nil
}