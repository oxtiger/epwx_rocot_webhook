package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/twq/epwx_rocot_webhook/internal/crypto"
)

// WXBizVerifyHandler 处理企业微信URL验证请求
func WXBizVerifyHandler(c *gin.Context) {
	// 获取URL参数
	msgSignature := c.Query("msg_signature")
	timestamp := c.Query("timestamp")
	nonce := c.Query("nonce")
	echostr := c.Query("echostr")

	// 检查必要参数
	if msgSignature == "" || timestamp == "" || nonce == "" || echostr == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: "Missing required parameters",
		})
		return
	}

	// 从配置中获取企业微信参数
	token := "HxTJpvXsv4GHpCtzzLtQfjDwuun"
	encodingAESKey := "D7MLgYrwP2FQpYTYn9WscjiUAtqIxO04E7wnjl5M41A"
	receiveID := "" // URL验证时可以不验证receiveID

	// 创建企业微信加解密器
	wxCrypt, err := crypto.NewWXBizMsgCrypt(token, encodingAESKey, receiveID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Failed to create WXBizMsgCrypt: " + err.Error(),
		})
		return
	}

	// 验证URL
	result, err := wxCrypt.VerifyURL(msgSignature, timestamp, nonce, echostr)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: "URL verification failed: " + err.Error(),
		})
		return
	}

	// 返回解密后的明文
	c.String(http.StatusOK, result)
}