package main

import (
	"log"
	"os"

	"github.com/twq/epwx_rocot_webhook/internal/api"
)

func main() {
	// 设置日志格式
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// 获取端口配置，默认为8080
	port := os.Getenv("PORT")
	if port == "" {
		port = "8083"
	}

	// 设置路由
	router := api.SetupRouter()

	// 启动服务
	log.Printf("Server starting on port %s...", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}