package test

import (
	"testing"

	"github.com/twq/epwx_rocot_webhook/internal/crypto"
)

func TestAESEncryptDecrypt(t *testing.T) {
	// 创建一个43字符的EncodingAESKey
	encodingAESKey := "jWmYm7qr5nMoAUwZRjGtBxmz3KA1tkAj3ykkR6q2B2C"

	// 创建AES加解密器
	aesCipher, err := crypto.NewAESCipher(encodingAESKey)
	if err != nil {
		t.Fatalf("Failed to create AES cipher: %v", err)
	}

	// 测试数据
	plaintext := "Hello, this is a test message for AES encryption!"

	// 加密
	ciphertext, err := aesCipher.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// 解密
	decrypted, err := aesCipher.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// 验证结果
	if string(decrypted) != plaintext {
		t.Errorf("Decrypted text does not match original plaintext.\nExpected: %s\nGot: %s", plaintext, string(decrypted))
	}
}

func TestAESKeyGeneration(t *testing.T) {
	// 生成随机AES密钥
	encodingAESKey, err := crypto.GenerateRandomAESKey()
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	// 验证密钥长度
	if len(encodingAESKey) != 43 {
		t.Errorf("Generated AES key has incorrect length. Expected: 43, Got: %d", len(encodingAESKey))
	}

	// 验证密钥可用于创建AES加解密器
	_, err = crypto.NewAESCipher(encodingAESKey)
	if err != nil {
		t.Fatalf("Failed to create AES cipher with generated key: %v", err)
	}
}