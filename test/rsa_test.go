package test

import (
	"testing"

	"github.com/twq/epwx_rocot_webhook/internal/crypto"
)

func TestRSAEncryptDecrypt(t *testing.T) {
	// 生成RSA密钥对
	rsaCipher, publicKey, privateKey, err := crypto.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// 测试数据
	plaintext := "Hello, this is a test message for RSA encryption!"

	// 加密
	ciphertext, err := rsaCipher.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// 解密
	decrypted, err := rsaCipher.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// 验证结果
	if string(decrypted) != plaintext {
		t.Errorf("Decrypted text does not match original plaintext.\nExpected: %s\nGot: %s", plaintext, string(decrypted))
	}

	// 测试从PEM字符串创建RSA加解密器
	rsaCipher2, err := crypto.NewRSACipherFromKeys(publicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create RSA cipher from PEM keys: %v", err)
	}

	// 使用新创建的加解密器进行测试
	ciphertext2, err := rsaCipher2.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatalf("Encryption with new cipher failed: %v", err)
	}

	decrypted2, err := rsaCipher2.Decrypt(ciphertext2)
	if err != nil {
		t.Fatalf("Decryption with new cipher failed: %v", err)
	}

	// 验证结果
	if string(decrypted2) != plaintext {
		t.Errorf("Decrypted text with new cipher does not match original plaintext.\nExpected: %s\nGot: %s", plaintext, string(decrypted2))
	}
}
