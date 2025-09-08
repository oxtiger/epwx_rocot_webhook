package crypto

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// WXBizMsgCrypt 企业微信消息加解密类
type WXBizMsgCrypt struct {
	Token          string
	EncodingAESKey string
	ReceiveID      string
	AESCipher      *AESCipher
}

// NewWXBizMsgCrypt 创建企业微信消息加解密器
func NewWXBizMsgCrypt(token, encodingAESKey, receiveID string) (*WXBizMsgCrypt, error) {
	// 创建AES加解密器
	aesCipher, err := NewAESCipher(encodingAESKey)
	if err != nil {
		return nil, err
	}

	return &WXBizMsgCrypt{
		Token:          token,
		EncodingAESKey: encodingAESKey,
		ReceiveID:      receiveID,
		AESCipher:      aesCipher,
	}, nil
}

// VerifyURL 验证URL函数，用于验证回调URL的有效性
func (w *WXBizMsgCrypt) VerifyURL(msgSignature, timestamp, nonce, echoStr string) (string, error) {
	// 验证签名
	if !w.verifySignature(msgSignature, timestamp, nonce, echoStr) {
		return "", errors.New("signature verification failed")
	}

	// 解密echoStr
	plaintext, err := w.AESCipher.Decrypt(echoStr)
	if err != nil {
		return "", fmt.Errorf("decrypt echo string error: %v", err)
	}

	// 解析解密后的数据
	msg, err := w.extractEncryptedMsg(plaintext)
	if err != nil {
		return "", err
	}

	return string(msg), nil
}

// DecryptMsg 解密消息
func (w *WXBizMsgCrypt) DecryptMsg(msgSignature, timestamp, nonce, encryptedMsg string) ([]byte, error) {
	// 验证签名
	if !w.verifySignature(msgSignature, timestamp, nonce, encryptedMsg) {
		return nil, errors.New("signature verification failed")
	}

	// 解密消息
	plaintext, err := w.AESCipher.Decrypt(encryptedMsg)
	if err != nil {
		return nil, fmt.Errorf("decrypt message error: %v", err)
	}

	// 解析解密后的数据
	msg, err := w.extractEncryptedMsg(plaintext)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

// EncryptMsg 加密消息
func (w *WXBizMsgCrypt) EncryptMsg(replyMsg []byte, timestamp, nonce string) (string, string, string, error) {
	// 生成16字节的随机字符串
	randomBytes := make([]byte, 16)
	for i := 0; i < 16; i++ {
		randomBytes[i] = byte('a' + (i % 26))
	}

	// 构造明文字符串: randomBytes + msgLen(4字节网络字节序) + msg + receiveID
	msgLen := len(replyMsg)
	msgLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(msgLenBytes, uint32(msgLen))

	plaintext := bytes.Buffer{}
	plaintext.Write(randomBytes)
	plaintext.Write(msgLenBytes)
	plaintext.Write(replyMsg)
	plaintext.WriteString(w.ReceiveID)

	// 加密消息
	encryptedMsg, err := w.AESCipher.Encrypt(plaintext.Bytes())
	if err != nil {
		return "", "", "", fmt.Errorf("encrypt message error: %v", err)
	}

	// 生成签名
	msgSignature := w.generateSignature(timestamp, nonce, encryptedMsg)

	return encryptedMsg, msgSignature, timestamp, nil
}

// 验证签名
func (w *WXBizMsgCrypt) verifySignature(msgSignature, timestamp, nonce, encryptedMsg string) bool {
	expectedSignature := w.generateSignature(timestamp, nonce, encryptedMsg)
	return strings.EqualFold(expectedSignature, msgSignature)
}

// 生成签名
func (w *WXBizMsgCrypt) generateSignature(timestamp, nonce, encryptedMsg string) string {
	// 将token、timestamp、nonce、encryptedMsg四个参数按照字典序排序
	params := []string{w.Token, timestamp, nonce, encryptedMsg}
	sort.Strings(params)

	// 将四个参数字符串拼接成一个字符串
	concatenated := strings.Join(params, "")

	// 对字符串进行sha1计算
	h := sha1.New()
	h.Write([]byte(concatenated))
	return hex.EncodeToString(h.Sum(nil))
}

// 从解密后的数据中提取消息内容
func (w *WXBizMsgCrypt) extractEncryptedMsg(decrypted []byte) ([]byte, error) {
	if len(decrypted) < 20 { // 至少需要16字节随机字符串+4字节消息长度
		return nil, errors.New("decrypted message too short")
	}

	// 解析消息长度（网络字节序）
	msgLen := binary.BigEndian.Uint32(decrypted[16:20])

	// 检查消息长度是否合法
	if len(decrypted) < int(20+msgLen) {
		return nil, errors.New("invalid message length")
	}

	// 提取消息内容
	msg := decrypted[20 : 20+msgLen]

	// 提取receiveID并验证
	receiveID := string(decrypted[20+msgLen:])
	if w.ReceiveID != "" && receiveID != w.ReceiveID {
		return nil, errors.New("receive ID mismatch")
	}

	return msg, nil
}

// ParseEncryptedRequestBody 解析加密的请求体
func ParseEncryptedRequestBody(encryptedBody []byte) (string, error) {
	// 这里简化处理，假设encryptedBody是JSON格式，包含encrypt字段
	// 在实际应用中，应该使用json.Unmarshal解析

	// 简单示例，实际应用中应使用JSON解析库
	encryptStr := string(encryptedBody)
	start := strings.Index(encryptStr, "\"encrypt\":\"")
	if start == -1 {
		return "", errors.New("encrypt field not found")
	}
	start += 11 // 跳过"encrypt":"

	end := strings.Index(encryptStr[start:], "\"")
	if end == -1 {
		return "", errors.New("invalid encrypt field format")
	}

	return encryptStr[start : start+end], nil
}

// GenerateRandomString 生成指定长度的随机字符串
func GenerateRandomString(length int) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = chars[i%len(chars)]
	}
	return string(result)
}

// GenerateSignature 生成签名
func GenerateSignature(token, timestamp, nonce, encryptedMsg string) string {
	// 将token、timestamp、nonce、encryptedMsg四个参数按照字典序排序
	params := []string{token, timestamp, nonce, encryptedMsg}
	sort.Strings(params)

	// 将四个参数字符串拼接成一个字符串
	concatenated := strings.Join(params, "")

	// 对字符串进行sha1计算
	h := sha1.New()
	h.Write([]byte(concatenated))
	return hex.EncodeToString(h.Sum(nil))
}

// Base64Encode 进行Base64编码
func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// Base64Decode 进行Base64解码
func Base64Decode(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}