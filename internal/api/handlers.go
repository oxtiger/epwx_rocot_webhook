package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oxtiger/epwx_rocot_webhook/internal/crypto"
)

// EncryptHandler 处理加密请求
func EncryptHandler(c *gin.Context) {
	var req EncryptRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	switch req.Algorithm {
	case "aes":
		handleAESEncrypt(c, req)
	case "rsa":
		handleRSAEncrypt(c, req)
	case "wxbiz":
		handleWXBizEncrypt(c, req)
	default:
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: "Unsupported algorithm",
		})
	}
}

// DecryptHandler 处理解密请求
func DecryptHandler(c *gin.Context) {
	var req DecryptRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	switch req.Algorithm {
	case "aes":
		handleAESDecrypt(c, req)
	case "rsa":
		handleRSADecrypt(c, req)
	case "wxbiz":
		handleWXBizDecrypt(c, req)
	default:
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: "Unsupported algorithm",
		})
	}
}

// GenerateKeyHandler 处理生成密钥请求
func GenerateKeyHandler(c *gin.Context) {
	var req GenerateKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}

	switch req.Algorithm {
	case "aes":
		handleAESKeyGeneration(c)
	case "rsa":
		handleRSAKeyGeneration(c, req)
	default:
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: "Unsupported algorithm",
		})
	}
}

// AES加密处理
func handleAESEncrypt(c *gin.Context, req EncryptRequest) {
	// 创建AES加解密器
	aesCipher, err := crypto.NewAESCipher(req.EncodingAESKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid AES key: " + err.Error(),
		})
		return
	}

	// 加密数据
	ciphertext, err := aesCipher.Encrypt([]byte(req.Plaintext))
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Encryption failed: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, EncryptResponse{
		Ciphertext: ciphertext,
	})
}

// RSA加密处理
func handleRSAEncrypt(c *gin.Context, req EncryptRequest) {
	// 创建RSA加解密器
	rsaCipher, err := crypto.NewRSACipherFromKeys(req.PublicKey, "")
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid RSA key: " + err.Error(),
		})
		return
	}

	// 加密数据
	ciphertext, err := rsaCipher.Encrypt([]byte(req.Plaintext))
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Encryption failed: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, EncryptResponse{
		Ciphertext: ciphertext,
	})
}

// 企业微信加密处理
func handleWXBizEncrypt(c *gin.Context, req EncryptRequest) {
	// 创建企业微信加解密器
	wxCrypt, err := crypto.NewWXBizMsgCrypt(req.Token, req.EncodingAESKey, req.ReceiveID)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid WXBiz parameters: " + err.Error(),
		})
		return
	}

	// 使用请求中的时间戳和随机数，或者生成新的
	timestamp := req.Timestamp
	nonce := req.Nonce
	if timestamp == 0 {
		timestamp = int(time.Now().Unix())
	}
	if nonce == "" {
		nonce = crypto.GenerateRandomString(16)
	}

	// 加密消息
	encryptedMsg, signature, timestamp, err := wxCrypt.EncryptMsg([]byte(req.Plaintext), timestamp, nonce)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Encryption failed: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, EncryptResponse{
		Ciphertext: encryptedMsg,
		Signature:  signature,
		Timestamp:  timestamp,
		Nonce:      nonce,
	})
}

// AES解密处理
func handleAESDecrypt(c *gin.Context, req DecryptRequest) {
	// 创建AES加解密器
	aesCipher, err := crypto.NewAESCipher(req.EncodingAESKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid AES key: " + err.Error(),
		})
		return
	}

	// 解密数据
	plaintext, err := aesCipher.Decrypt(req.Ciphertext)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Decryption failed: " + err.Error(),
		})
		return
	}

	// 尝试解析明文为JSON
	var jsonData interface{}
	if err := json.Unmarshal(plaintext, &jsonData); err == nil {
		// 如果成功解析为JSON，则返回JSON对象
		c.JSON(http.StatusOK, gin.H{
			"plaintext": jsonData,
			"format":    "json",
		})
	} else {
		// 如果不是有效的JSON，则返回原始字符串
		c.JSON(http.StatusOK, DecryptResponse{
			Plaintext: string(plaintext),
			Format:    "text",
		})
	}
}

// RSA解密处理
func handleRSADecrypt(c *gin.Context, req DecryptRequest) {
	// 创建RSA加解密器
	rsaCipher, err := crypto.NewRSACipherFromKeys("", req.PrivateKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid RSA key: " + err.Error(),
		})
		return
	}

	// 解密数据
	plaintext, err := rsaCipher.Decrypt(req.Ciphertext)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Decryption failed: " + err.Error(),
		})
		return
	}

	// 尝试解析明文为JSON
	var jsonData interface{}
	if err := json.Unmarshal(plaintext, &jsonData); err == nil {
		// 如果成功解析为JSON，则返回JSON对象
		c.JSON(http.StatusOK, gin.H{
			"plaintext": jsonData,
			"format":    "json",
		})
	} else {
		// 如果不是有效的JSON，则返回原始字符串
		c.JSON(http.StatusOK, DecryptResponse{
			Plaintext: string(plaintext),
			Format:    "text",
		})
	}
}

// 企业微信解密处理
func handleWXBizDecrypt(c *gin.Context, req DecryptRequest) {
	// 创建企业微信加解密器
	wxCrypt, err := crypto.NewWXBizMsgCrypt(req.Token, req.EncodingAESKey, req.ReceiveID)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid WXBiz parameters: " + err.Error(),
		})
		return
	}

	// 解密消息
	plaintext, err := wxCrypt.DecryptMsg(req.Signature, req.Timestamp, req.Nonce, req.Ciphertext)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Decryption failed: " + err.Error(),
		})
		return
	}

	// 尝试解析明文为JSON
	var jsonData interface{}
	if err := json.Unmarshal(plaintext, &jsonData); err == nil {
		// 如果成功解析为JSON，则返回JSON对象
		c.JSON(http.StatusOK, jsonData)
	} else {
		// 如果不是有效的JSON，则返回错误
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Decryption failed: " + err.Error(),
		})
	}
}

// AES密钥生成处理
func handleAESKeyGeneration(c *gin.Context) {
	// 生成随机AES密钥
	encodingAESKey, err := crypto.GenerateRandomAESKey()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Key generation failed: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, GenerateKeyResponse{
		EncodingAESKey: encodingAESKey,
	})
}

// RSA密钥对生成处理
func handleRSAKeyGeneration(c *gin.Context, req GenerateKeyRequest) {
	// 默认使用2048位
	bits := 2048
	if req.Bits > 0 {
		bits = req.Bits
	}

	// 生成RSA密钥对
	_, publicKey, privateKey, err := crypto.GenerateRSAKeyPair(bits)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Key generation failed: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, GenerateKeyResponse{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	})
}
