package test

import (
	"testing"

	"github.com/twq/epwx_rocot_webhook/internal/crypto"
)

func TestWXBizMsgCrypt(t *testing.T) {
	// 测试参数
	token := "QDG6eK"
	encodingAESKey := "jWmYm7qr5nMoAUwZRjGtBxmz3KA1tkAj3ykkR6q2B2C"
	receiveID := "wx5823bf96d3bd56c7"

	// 创建企业微信加解密器
	wxCrypt, err := crypto.NewWXBizMsgCrypt(token, encodingAESKey, receiveID)
	if err != nil {
		t.Fatalf("Failed to create WXBizMsgCrypt: %v", err)
	}

	// 测试数据
	plaintext := "<xml><ToUserName><![CDATA[wx5823bf96d3bd56c7]]></ToUserName><FromUserName><![CDATA[mycreate]]></FromUserName><CreateTime>1409659813</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[hello]]></Content><MsgId>4561255354251345929</MsgId><AgentID>218</AgentID></xml>"
	timestamp := "1409659813"
	nonce := "1372623149"

	// 加密
	encryptedMsg, signature, _, err := wxCrypt.EncryptMsg([]byte(plaintext), timestamp, nonce)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// 解密
	decrypted, err := wxCrypt.DecryptMsg(signature, timestamp, nonce, encryptedMsg)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// 验证结果
	if string(decrypted) != plaintext {
		t.Errorf("Decrypted text does not match original plaintext.\nExpected: %s\nGot: %s", plaintext, string(decrypted))
	}
}

func TestSignatureGeneration(t *testing.T) {
	// 测试参数
	token := "QDG6eK"
	timestamp := "1409659813"
	nonce := "1372623149"
	encryptedMsg := "RypEvHKD8QQKFhvQ6QleEB4J58tiPdvo+rtK1I9qca6aM/wvqnLSV5zEPeusUiX5L5X/0lWfrf0QADHHhGd3QczcdCUpj911L3vg3W/sYYvuJTs3TUUkSUXxaccAS0qhxchrRYt66wiSpGLYL42aM6A8dTT+6k4aSknmPj48kzJs8qLjvd4Xgpue06DOdnLxAUHzM6+kDZ+HMZfJYuR+LtwGc2hgf5gsijff0ekUNXZiqATP7PF5mZxZ3Izoun1s4zG4LUMnvw2r+KqCKIw+3IQH03v+BCA9nMELNqbSf6tiWSrXJB3LAVGUcallcrw8V2t9EL4EhzJWrQUax5wLVMNS0+rUPA3k22Ncx4XXZS9o0MBH27Bo6BpNelZpS+/uh9KsNlY6bHCmJU9p8g7m3fVKn28H3KDYA5Pl/T8Z1ptDAVe0lXdQ2YoyyH2uyPIGHBZZIs2pDBS8R07+qN+E7Q=="

	// 生成签名
	signature := crypto.GenerateSignature(token, timestamp, nonce, encryptedMsg)

	// 预期的签名
	expectedSignature := "477715d11cdb4164915debcba66cb864d751f3e6"

	// 验证结果
	if signature != expectedSignature {
		t.Errorf("Generated signature does not match expected signature.\nExpected: %s\nGot: %s", expectedSignature, signature)
	}
}
