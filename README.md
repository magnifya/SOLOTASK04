# SOLOTASK04 可验证凭证后端

用 Python + `cryptography` 实现的可验证凭证（VC）后端，同时提供 HTTP 服务与命令行入口。
仅依赖 `cryptography`，HTTP 层使用标准库 `http.server`，无需第三方 Web 框架。

## 安装依赖

```bash
python3 -m pip install -r requirements.txt
```

> 开发环境为 Python 3.10 + cryptography 3.4.8，无其他依赖。

## 启动 HTTP 服务

```bash
python3 -m vcbackend.cli serve --host 127.0.0.1 --port 8080
# 可选：--store 指定状态文件；也可用环境变量 VCBACKEND_STORE
```

状态默认保存在当前目录 `.vcbackend_store.json`（HTTP 服务与 CLI 共用，原子写入）。

### HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/v1/dids` | 注册 DID，请求体 `{"method","public_key"}`，返回 201 与 `did`、`public_key` |
| GET | `/v1/dids/{did}` | 返回 `did`、`public_key`、`created_at`；不存在 404 |
| POST | `/v1/credentials` | 签发凭证，请求体 `{"issuer_did","subject_did","claims"}`，返回 201 与 `credential_id`、`signature` |
| GET | `/v1/credentials/{credential_id}` | 返回 `credential_id`、`body`、`signature`；不存在 404 |

- DID 形如 `did:example:<32 位 hex>`。
- 同一 `public_key` 再次提交返回其既有 DID（按提交原文去重）。
- 缺少/非法字段返回 400 并在 `error` 中说明原因；任一 DID 不存在时 400 并指明是 `issuer_did` 还是 `subject_did`。

### curl 示例

```bash
curl -X POST localhost:8080/v1/dids -d '{"method":"example","public_key":"alice-key"}'
curl localhost:8080/v1/dids/did:example:<id>
curl -X POST localhost:8080/v1/credentials \
  -d '{"issuer_did":"did:example:<a>","subject_did":"did:example:<b>","claims":{"role":"admin"}}'
curl localhost:8080/v1/credentials/vc_<id>
```

## 命令行

CLI 通过 HTTP 与服务通信（因此 `verify` 使用的是从服务**现取**的签发者公钥）。
用 `--base-url` 或环境变量 `VCBACKEND_URL` 指定服务地址（默认 `http://127.0.0.1:8080`）。

```bash
export VCBACKEND_URL=http://127.0.0.1:8080

python3 -m vcbackend.cli did-create --method example --public-key alice-key
python3 -m vcbackend.cli did-show  did:example:<id>
python3 -m vcbackend.cli issue --issuer did:example:<a> --subject did:example:<b> \
    --claims '{"role":"admin"}'
python3 -m vcbackend.cli verify vc_<id>     # 成功输出 true（退出码 0）
                                           # 正文被改动输出 false，并在 stderr 说明原因（退出码 1）
```

## 签名与验真

- 算法为 **ES256**：ECDSA over P-256 与 SHA-256，签名编码为 64 字节裸 `R||S` 的 base64url（无填充）。
- 签名覆盖凭证**正文按 key 升序的规范化 JSON**（紧凑序列化、UTF-8、嵌套对象同样递归排序）。
- 凭证正文包含 `credential_id`、`issuer_did`、`subject_did`、`claims`、`issued_at`，
  对其任一字段（含 claims 内部）的改动都会使验签失败。

### 密钥模型

为保证「服务端签发的签名能用注册时返回的公钥验真」，注册时由系统为该
`public_key` 句柄铸造 P-256 密钥对：接口返回并登记真实公钥 PEM，私钥由服务端内部持有
（随状态文件保存，仅用于本演示）。`public_key` 提交串作为幂等去重的句柄。

## 测试

```bash
python3 tests/e2e_test.py
```

脚本会临时在本地端口启动服务，覆盖：201/200/400/404 各路径、同 key 去重、
缺失字段原因、不存在 DID 指明、现取公钥验签成功、篡改 claims/顶层字段验签失败。

## 代码结构

```
vcbackend/
  crypto.py    ES256 签名/验签、规范化 JSON、P-256 密钥
  models.py    DIDRecord / CredentialRecord 数据模型
  store.py     文件持久化存储、DID 去重与凭证签发业务逻辑
  service.py   标准库 HTTP 路由与错误映射
  cli.py       did-create / did-show / issue / verify / serve
tests/e2e_test.py  端到端测试
```
