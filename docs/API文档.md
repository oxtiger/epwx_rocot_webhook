


          
# 加解密服务 API 文档

## 简介

本服务提供多种加解密算法的 API 接口，支持 AES、RSA 和企业微信加解密方案，可用于数据安全传输和存储。

## API 接口

### 1. 加密接口

**请求方式**：POST

**URL**：`/api/v1/encrypt`

**请求参数**：

```json
{
  "algorithm": "aes|rsa|wxbizmsg",  // 加密算法类型
  "plaintext": "要加密的明文",      // 必填，待加密的原始数据
  
  // AES 算法参数
  "aes_key": "base64编码的AES密钥",  // 当 algorithm=aes 时必填
  
  // RSA 算法参数
  "rsa_public_key": "PEM格式的RSA公钥",  // 当 algorithm=rsa 时必填
  
  // 企业微信加密参数
  "token": "企业微信配置的Token",       // 当 algorithm=wxbizmsg 时必填
  "encoding_aes_key": "企业微信的EncodingAESKey",  // 当 algorithm=wxbizmsg 时必填
  "receiver_id": "企业微信的CorpID或AppID"  // 当 algorithm=wxbizmsg 时必填
}
```

**响应参数**：

```json
{
  "ciphertext": "加密后的密文",  // base64编码的密文
  "msg_signature": "消息签名"   // 仅企业微信加密时返回
}
```

### 2. 解密接口

**请求方式**：POST

**URL**：`/api/v1/decrypt`

**请求参数**：

```json
{
  "algorithm": "aes|rsa|wxbizmsg",  // 解密算法类型
  "ciphertext": "要解密的密文",    // 必填，base64编码的密文
  
  // AES 算法参数
  "aes_key": "base64编码的AES密钥",  // 当 algorithm=aes 时必填
  
  // RSA 算法参数
  "rsa_private_key": "PEM格式的RSA私钥",  // 当 algorithm=rsa 时必填
  
  // 企业微信解密参数
  "token": "企业微信配置的Token",       // 当 algorithm=wxbizmsg 时必填
  "encoding_aes_key": "企业微信的EncodingAESKey",  // 当 algorithm=wxbizmsg 时必填
  "receiver_id": "企业微信的CorpID或AppID",  // 当 algorithm=wxbizmsg 时必填
  "msg_signature": "消息签名",  // 当 algorithm=wxbizmsg 时必填
  "timestamp": "时间戳",       // 当 algorithm=wxbizmsg 时必填
  "nonce": "随机字符串"        // 当 algorithm=wxbizmsg 时必填
}
```

**响应参数**：

```json
{
  "plaintext": "解密后的明文"  // 解密后的原始数据
}
```

### 3. 生成密钥接口

**请求方式**：POST

**URL**：`/api/v1/generate-key`

**请求参数**：

```json
{
  "algorithm": "aes|rsa",  // 密钥算法类型
  "key_size": 256         // 可选，AES密钥长度(128/192/256)或RSA密钥长度(1024/2048/4096)
}
```

**响应参数**：

```json
// AES 算法响应
{
  "aes_key": "base64编码的AES密钥"
}

// RSA 算法响应
{
  "private_key": "PEM格式的RSA私钥",
  "public_key": "PEM格式的RSA公钥"
}
```

## 使用示例

### AES 加密示例

```bash
curl -X POST http://localhost:8080/api/v1/encrypt \
  -H "Content-Type: application/json" \
  -d '{
    "algorithm": "aes",
    "plaintext": "Hello World",
    "aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="
  }'
```

### RSA 解密示例

```bash
curl -X POST http://localhost:8080/api/v1/decrypt \
  -H "Content-Type: application/json" \
  -d '{
    "algorithm": "rsa",
    "ciphertext": "base64编码的RSA密文",
    "rsa_private_key": "-----BEGIN RSA PRIVATE KEY-----\n...私钥内容...\n-----END RSA PRIVATE KEY-----"
  }'
```

## 错误码

| 错误码 | 描述 |
| ----- | ---- |
| 400 | 请求参数错误 |
| 401 | 认证失败 |
| 500 | 服务器内部错误 |

## 注意事项

1. 所有密钥和密文均使用 Base64 编码传输
2. RSA 加密使用 OAEP 填充方式，AES 使用 CBC 模式和 PKCS#7 填充
3. 企业微信加解密遵循官方规范，用于回调消息的安全验证