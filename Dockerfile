# 第一阶段：构建阶段
FROM golang:1.24.3-alpine AS builder

# 设置工作目录
WORKDIR /app

# 安装必要的构建工具
RUN apk add --no-cache git

# 复制go.mod和go.sum文件并下载依赖
COPY go.mod go.sum ./
RUN go mod download

# 复制源代码
COPY . .

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o epwx_rocot_webhook ./cmd/main.go

# 第二阶段：运行阶段
FROM alpine:3.18

# 安装必要的运行时依赖
RUN apk --no-cache add ca-certificates tzdata && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone

WORKDIR /app

# 从构建阶段复制编译好的应用
COPY --from=builder /app/epwx_rocot_webhook .

# 创建配置目录
RUN mkdir -p /app/config

# 暴露应用端口
EXPOSE 8083

# 设置健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8083/health || exit 1

# 运行应用
CMD ["/app/epwx_rocot_webhook"]