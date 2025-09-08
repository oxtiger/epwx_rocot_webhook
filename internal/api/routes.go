package api

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// SetupRouter 配置API路由
func SetupRouter() *gin.Engine {
	// 创建默认的Gin引擎
	r := gin.Default()

	// 配置CORS
	r.Use(cors.Default())

	// 健康检查
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "ok",
		})
	})

	// API路由组
	api := r.Group("/api/v1")
	{
		// 加密接口
		api.POST("/encrypt", EncryptHandler)

		// 解密接口
		api.POST("/decrypt", DecryptHandler)

		// 生成密钥接口
		api.POST("/generate-key", GenerateKeyHandler)

		// 企业微信相关接口
		wxbiz := api.Group("/wxbiz")
		{
			// 企业微信URL验证接口
			wxbiz.GET("/verify", WXBizVerifyHandler)
		}
	}

	return r
}