package api

// EncryptRequest 加密请求模型
type EncryptRequest struct {
	// 加密算法类型: "aes" 或 "rsa"
	Algorithm string `json:"algorithm" binding:"required,oneof=aes rsa wxbiz"`
	// 明文数据
	Plaintext string `json:"plaintext" binding:"required"`

	// AES加密参数
	EncodingAESKey string `json:"encoding_aes_key,omitempty" binding:"required_if=Algorithm aes,required_if=Algorithm wxbiz,omitempty"`

	// RSA加密参数
	PublicKey string `json:"public_key,omitempty" binding:"required_if=Algorithm rsa,omitempty"`

	// 企业微信加密参数
	Token     string `json:"token,omitempty" binding:"required_if=Algorithm wxbiz,omitempty"`
	ReceiveID string `json:"receive_id,omitempty" binding:"omitempty"`
	Timestamp int    `json:"timestamp,omitempty" binding:"required_if=Algorithm wxbiz,omitempty"`
	Nonce     string `json:"nonce,omitempty" binding:"required_if=Algorithm wxbiz,omitempty"`
}

// EncryptResponse 加密响应模型
type EncryptResponse struct {
	// 加密后的密文
	Ciphertext string `json:"ciphertext"`
	// 企业微信加密时的签名
	Signature string `json:"signature,omitempty"`
	// 企业微信加密时的时间戳
	Timestamp int `json:"timestamp,omitempty"`
	// 企业微信加密时的随机数
	Nonce string `json:"nonce,omitempty"`
}

// DecryptRequest 解密请求模型
type DecryptRequest struct {
	// 加密算法类型: "aes" 或 "rsa"
	Algorithm string `json:"algorithm" binding:"required,oneof=aes rsa wxbiz"`
	// 密文数据
	Ciphertext string `json:"ciphertext" binding:"required"`

	// AES解密参数
	EncodingAESKey string `json:"encoding_aes_key,omitempty" binding:"required_if=Algorithm aes,required_if=Algorithm wxbiz,omitempty"`

	// RSA解密参数
	PrivateKey string `json:"private_key,omitempty" binding:"required_if=Algorithm rsa,omitempty"`

	// 企业微信解密参数
	Token     string `json:"token,omitempty" binding:"required_if=Algorithm wxbiz,omitempty"`
	ReceiveID string `json:"receive_id,omitempty" binding:"omitempty"`
	Signature string `json:"signature,omitempty" binding:"required_if=Algorithm wxbiz,omitempty"`
	Timestamp string `json:"timestamp,omitempty" binding:"required_if=Algorithm wxbiz,omitempty"`
	Nonce     string `json:"nonce,omitempty" binding:"required_if=Algorithm wxbiz,omitempty"`
}

// DecryptResponse 解密响应模型
type DecryptResponse struct {
	// 解密后的明文
	Plaintext string `json:"plaintext"`
	// 明文格式，可能是"text"或"json"
	Format string `json:"format,omitempty"`
}

// ErrorResponse 错误响应模型
type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// GenerateKeyRequest 生成密钥请求模型
type GenerateKeyRequest struct {
	// 加密算法类型: "aes" 或 "rsa"
	Algorithm string `json:"algorithm" binding:"required,oneof=aes rsa"`
	// RSA密钥长度
	Bits int `json:"bits,omitempty" binding:"omitempty,oneof=1024 2048 4096"`
}

// GenerateKeyResponse 生成密钥响应模型
type GenerateKeyResponse struct {
	// AES密钥
	EncodingAESKey string `json:"encoding_aes_key,omitempty"`
	// RSA公钥
	PublicKey string `json:"public_key,omitempty"`
	// RSA私钥
	PrivateKey string `json:"private_key,omitempty"`
}
