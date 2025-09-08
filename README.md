# 加解密服务项目

基于Golang的Gin框架实现的简易加解密服务，支持AES、RSA以及企业微信加解密方案。

## 功能特性

- 支持AES-CBC模式加解密
- 支持RSA加解密
- 支持企业微信消息加解密方案
- 提供密钥生成功能
- RESTful API接口设计

## 项目结构

```
.
├── cmd/                # 应用程序入口
│   └── main.go        # 主程序
├── internal/           # 内部包
│   ├── api/            # API接口
│   │   ├── handlers.go # 请求处理器
│   │   ├── models.go   # 数据模型
│   │   └── routes.go   # 路由配置
│   └── crypto/         # 加解密核心功能
│       ├── aes.go      # AES加解密
│       ├── rsa.go      # RSA加解密
│       └── wxbizmsg.go # 企业微信加解密
├── pkg/                # 公共包
├── test/               # 单元测试
│   ├── aes_test.go     # AES测试
│   ├── rsa_test.go     # RSA测试
│   └── wxbizmsg_test.go# 企业微信加解密测试
└── README.md           # 项目说明
```

## 安装与运行

### 前置条件

- Go 1.16+
- Docker (可选，用于容器化部署)

### 本地开发

#### 安装依赖

```bash
go mod tidy
```

#### 运行服务

```bash
go run cmd/main.go
```

默认情况下，服务将在 `http://localhost:8083` 上启动。可以通过设置环境变量 `PORT` 来更改端口。

### Docker部署

#### 构建镜像

```bash
docker build -t epwx_rocot_webhook:latest .
```

#### 运行容器

```bash
docker run -d -p 8083:8083 --name epwx_webhook epwx_rocot_webhook:latest
```

#### 使用GitHub容器仓库镜像

本项目配置了GitHub Actions自动构建并发布Docker镜像到GitHub Container Registry。

```bash
# 拉取最新镜像
docker pull ghcr.io/[用户名]/epwx_rocot_webhook:latest

# 运行容器
docker run -d -p 8083:8083 --name epwx_webhook ghcr.io/[用户名]/epwx_rocot_webhook:latest
```

### 运行测试

```bash
go test ./test/...
```

## API接口说明

### 1. 加密接口

**请求**：

```
POST /api/v1/encrypt
```

**请求参数**：

```json
{
  "algorithm": "aes",           // 加密算法: "aes", "rsa" 或 "wxbiz"
  "plaintext": "要加密的数据",   // 明文数据
  
  // AES加密参数
  "encoding_aes_key": "...",   // AES密钥(Base64编码，43字符)
  
  // RSA加密参数
  "public_key": "...",        // RSA公钥(PEM格式)
  
  // 企业微信加密参数
  "token": "...",             // 企业微信Token
  "receive_id": "...",        // 接收者ID
  "timestamp": "...",         // 时间戳
  "nonce": "..."              // 随机数
}
```

**响应**：

```json
{
  "ciphertext": "加密后的数据",  // 密文数据
  "signature": "...",         // 企业微信签名(仅wxbiz算法)
  "timestamp": "...",         // 时间戳(仅wxbiz算法)
  "nonce": "..."              // 随机数(仅wxbiz算法)
}
```

### 2. 解密接口

**请求**：

```
POST /api/v1/decrypt
```

**请求参数**：

```json
{
  "algorithm": "aes",           // 解密算法: "aes", "rsa" 或 "wxbiz"
  "ciphertext": "要解密的数据",  // 密文数据
  
  // AES解密参数
  "encoding_aes_key": "...",   // AES密钥(Base64编码，43字符)
  
  // RSA解密参数
  "private_key": "...",        // RSA私钥(PEM格式)
  
  // 企业微信解密参数
  "token": "...",             // 企业微信Token
  "receive_id": "...",        // 接收者ID
  "signature": "...",         // 签名
  "timestamp": "...",         // 时间戳
  "nonce": "..."              // 随机数
}
```

**响应**：

```json
{
  "plaintext": "解密后的数据"    // 明文数据
}
```

### 3. 生成密钥接口

**请求**：

```
POST /api/v1/generate-key
```

**请求参数**：

```json
{
  "algorithm": "aes",           // 算法类型: "aes" 或 "rsa"
  "bits": 2048                 // RSA密钥长度(可选，默认2048)
}
```

**响应**：

```json
{
  // AES密钥
  "encoding_aes_key": "...",   // 仅当algorithm=aes时
  
  // RSA密钥对
  "public_key": "...",        // 仅当algorithm=rsa时
  "private_key": "..."        // 仅当algorithm=rsa时
}
```

## 企业微信加解密说明

本项目实现了企业微信的消息加解密方案，包括：

1. 消息签名验证
2. 消息加密与解密
3. 回调URL验证

详细的加解密方案请参考项目中的文档：

- `/docs/加解密方案说明.md`
- `/docs/回调和回复的加解密方案.md`

## 示例

### AES加密示例

```bash
curl -X POST http://localhost:8080/api/v1/encrypt \
  -H "Content-Type: application/json" \
  -d '{
    "algorithm": "aes",
    "plaintext": "Hello, World!",
    "encoding_aes_key": "jWmYm7qr5nMoAUwZRjGtBxmz3KA1tkAj3ykkR6q2B2C"
  }'
```

### RSA密钥生成示例

```bash
curl -X POST http://localhost:8080/api/v1/generate-key \
  -H "Content-Type: application/json" \
  -d '{
    "algorithm": "rsa",
    "bits": 2048
  }'
```

## CI/CD

本项目使用GitHub Actions进行持续集成和持续部署：

- 当代码推送到主分支（main或master）时，自动构建Docker镜像并推送到GitHub Container Registry
- 当创建新的版本标签（如v1.0.0）时，自动构建带版本号的Docker镜像
- 在Pull Request中自动构建镜像但不推送，用于验证构建过程

### 配置说明

GitHub Actions工作流配置文件位于`.github/workflows/docker-build.yml`，主要实现以下功能：

1. 检出代码
2. 设置Docker Buildx
3. 登录到GitHub Container Registry
4. 提取Docker元数据（标签、标签等）
5. 构建并推送Docker镜像

### 镜像标签策略

- 分支构建：`ghcr.io/[用户名]/epwx_rocot_webhook:main`
- 标签构建：`ghcr.io/[用户名]/epwx_rocot_webhook:v1.0.0`、`ghcr.io/[用户名]/epwx_rocot_webhook:v1.0`
- 提交构建：`ghcr.io/[用户名]/epwx_rocot_webhook:sha-abc123`

## 许可证

MIT