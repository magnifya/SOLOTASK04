# SOLOTASK04 可验证凭证后端

要实现一个可验证凭证后端，用 Python 加 cryptography，同时提供 HTTP 服务和命令行入口。DID 注册走 POST /v1/dids，请求体是 JSON，含 method 与 public_key 两个字符串字段，返回 201 与 did 和 public_key，did 形如 did:example 加标识；同一 public_key 再次提交返回其既有 DID；缺少字段返回 400 并说明原因。查询走 GET /v1/dids/{did}，返回 public_key 与 created_at，不存在返回 404。凭证签发走 POST /v1/credentials，请求体是 JSON，含 issuer_did、subject_did 与 claims 对象；用 ES256 对凭证正文签名，签名覆盖正文按 key 升序的规范化 JSON 序列化结果；返回 201 与 credential_id 和 signature；任一 DID 不存在返回 400 并指明是哪一个。查询走 GET /v1/credentials/{credential_id}，返回正文与 signature，不存在返回 404。命令行提供 did-create、did-show、issue 与 verify 四个子命令，verify 用签发者现取的公钥校验，成功输出 true，正文被改动则输出 false 并说明原因。

## 当前状态

已实现。代码结构：

- `vc_backend/crypto.py` — ES256（P-256 + SHA-256）签名，签名为 base64url 编码的 64 字节 `r||s`；规范化 JSON 为按 key 升序、紧凑分隔符的 UTF-8 序列化。
- `vc_backend/store.py` — 内存 DID 注册表（按 public_key 去重）与凭证库。
- `vc_backend/server.py` — HTTP 服务（仅依赖标准库 http.server）。
- `vc_backend/cli.py` — 命令行：`did-create` / `did-show` / `issue` / `verify`。
- `tests/test_api.py` — 端到端测试。

说明：`did-create` 在本地生成 P-256 密钥对，注册时把公钥与私钥一并提交给服务端，服务端据此签发凭证（演示性质，生产环境不应上传私钥）。若直接走 HTTP 注册而未提供私钥，服务端会在首次签发时为该 DID 生成密钥对并更新登记的公钥，`verify` 现取的即为新公钥。数据保存在内存中，服务重启即清空。

### 安装依赖

```bash
pip install -r requirements.txt
```

### 启动服务

```bash
python -m vc_backend.server --host 127.0.0.1 --port 8000
```

### 命令行用法

```bash
# 注册 DID（生成密钥对并登记，输出 did 与 public_key）
python -m vc_backend.cli did-create
python -m vc_backend.cli did-show did:example:<标识>

# 签发凭证（claims 为 JSON 串，也可用 @claims.json 从文件读取）
python -m vc_backend.cli issue <issuer_did> <subject_did> --claims '{"name":"alice"}'

# 校验：按 credential_id 从服务器现取，或用 --file 校验本地（可能被篡改的）凭证文档
python -m vc_backend.cli verify <credential_id>
python -m vc_backend.cli verify --file credential.json   # 正文被改动时输出 false 并说明原因
```

`--server` 参数可指定非默认服务地址（默认 `http://127.0.0.1:8000`）。

### 运行测试

```bash
python -m unittest discover -s tests -v
```
