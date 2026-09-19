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
| POST | `/v1/dids` | 注册 DID，请求体 `{"method","public_key","key_mode"?}`，返回 201 与 `did`、`public_key`、`key_mode`、`key_handle`、`key_version` |
| GET | `/v1/dids/{did}` | 返回 `did`、`public_key`、`key_mode`、`key_handle`、`key_version`、`created_at`；不存在 404 |
| POST | `/v1/dids/{did}/keys/rotate` | 轮换密钥，请求体 `{"key_handle":"新句柄"}`，返回 200 与 `did`、`public_key`、`key_handle`、`key_version` |
| POST | `/v1/credentials` | 签发凭证，请求体 `{"issuer_did","subject_did","claims"}`，返回 201 与 `credential_id`、`signature`、`issuer_key_version` |
| GET | `/v1/credentials/{credential_id}` | 返回 `credential_id`、`body`、`signature`、`issuer_key_version`；不存在 404 |
| POST | `/v1/credentials/{credential_id}/verify` | 服务端验签，请求体 `{"signature":"..."}`；结果恒为 200，成功 `{"valid":true}`，失败 `{"valid":false,"reason":"中文原因"}` |

- DID 形如 `did:example:<32 位 hex>`。
- `public_key` 是**非空、非 PEM 的密钥句柄**：提交 PEM 公钥会得到 400。
  同一 `public_key` 句柄再次提交返回其既有 DID（按提交原文去重）。
- `key_mode` 缺省或 `"server"` 合法，其他值返回 400。
- 缺少/非法字段返回 400 并在 `error` 中说明原因；任一 DID 不存在时 400 并指明是 `issuer_did` 还是 `subject_did`。
- 密钥轮换：未知 DID 返回 404；句柄为空、为 PEM 或与该 DID 的历史/当前句柄重复返回 400。
  每次轮换铸造新的 P-256 密钥，`key_version` 原子递增，旧公钥保留在版本历史中；
  新凭证用当前密钥签发，旧凭证按签发时版本对应的历史公钥验签。
- 验签接口以服务端存储的 `credential_id`、`issuer_did`、`issuer_key_version`
  为锚（不采信请求体里的 DID/版本），任何失败（含未知凭证、非法请求体、坏签名）
  都是 200 + `valid:false` + 非空中文 `reason`，绝不返回 500 或泄露私钥。

### curl 示例

```bash
curl -X POST localhost:8080/v1/dids -d '{"method":"example","public_key":"alice-key"}'
curl localhost:8080/v1/dids/did:example:<id>
curl -X POST localhost:8080/v1/dids/did:example:<id>/keys/rotate \
  -d '{"key_handle":"alice-key-2026"}'
curl -X POST localhost:8080/v1/credentials \
  -d '{"issuer_did":"did:example:<a>","subject_did":"did:example:<b>","claims":{"role":"admin"}}'
curl localhost:8080/v1/credentials/vc_<id>
curl -X POST localhost:8080/v1/credentials/vc_<id>/verify \
  -d '{"signature":"<GET 凭证返回的 signature>"}'
```

## 命令行

CLI 通过 HTTP 与服务通信；`verify` 调用服务端验签接口，由服务端按存储的
签发者 DID 与密钥版本（含历史公钥）完成验签。
用 `--base-url` 或环境变量 `VCBACKEND_URL` 指定服务地址（默认 `http://127.0.0.1:8080`）。

```bash
export VCBACKEND_URL=http://127.0.0.1:8080

python3 -m vcbackend.cli did-create --method example --public-key alice-key
python3 -m vcbackend.cli did-show  did:example:<id>
python3 -m vcbackend.cli issue --issuer did:example:<a> --subject did:example:<b> \
    --claims '{"role":"admin"}'
python3 -m vcbackend.cli verify vc_<id>     # 成功输出 true（退出码 0）
                                           # 失败输出 false，并在 stderr 说明原因（退出码 1）
```

## 签名与验真

- 算法为 **ES256**：ECDSA over P-256 与 SHA-256，签名编码为 64 字节裸 `R||S` 的 base64url（无填充）。
- 签名覆盖凭证**正文按 key 升序的规范化 JSON**（紧凑序列化、UTF-8、嵌套对象同样递归排序）。
- 凭证正文包含 `credential_id`、`issuer_did`、`issuer_key_version`、`subject_did`、
  `claims`、`issued_at`，对其任一字段（含 claims 内部）的改动都会使验签失败。
- `issuer_key_version` 是签发时 DID 当前密钥的整数版本。轮换后新凭证锚定新版本，
  旧凭证仍按其正文里的版本取对应历史公钥验签；升级前签发的旧凭证正文缺该字段时按版本 1 处理（不改原签名）。

### 密钥模型与轮换

为保证「服务端签发的签名能用注册时返回的公钥验真」，注册时由系统为该
`public_key` 句柄铸造 P-256 密钥对：接口返回并登记真实公钥 PEM，私钥由服务端内部持有
（随状态文件保存，仅用于本演示）。`public_key` 提交串是一个非空、非 PEM 的句柄，
同时作为幂等去重的键。

- 每个 DID 记录 `key_mode="server"`、`key_handle`、`key_version`（起始为 1）与按版本
  排列的公钥历史；各版本私钥仅在服务端保存。
- `POST /v1/dids/{did}/keys/rotate` 铸造新 P-256 密钥，原子递增 `key_version`，
  更新当前 `key_handle`/`public_key` 并把公钥追加进历史。句柄非空、非 PEM、不得与
  该 DID 历史或当前句柄重复。
- 升级前创建的旧状态文件在加载时自动迁移为 server/1：历史公钥即原 `public_key`，
  句柄取原 `submitted_public_key`，缺省则回退为原 `public_key`。

## 测试

```bash
python3 tests/e2e_test.py
```

脚本会临时在本地端口启动服务，覆盖：201/200/400/404 各路径、同 key 去重、
缺失字段原因、不存在 DID 指明、PEM 句柄与非法 key_mode 拒绝、现取公钥验签成功、
篡改 claims/顶层字段验签失败、密钥轮换（版本递增/句柄去重/404/400）、
轮换后历史公钥验旧凭证、服务端验签接口的成功与各类失败、CLI verify 退出码与原因输出，
以及旧状态文件的自动迁移。

## 代码结构

```
vcbackend/
  crypto.py    ES256 签名/验签、规范化 JSON、P-256 密钥
  models.py    DIDRecord / CredentialRecord 数据模型
  store.py     文件持久化、DID 去重/迁移、密钥轮换历史、凭证签发与锚定验签
  service.py   标准库 HTTP 路由与错误映射（验签接口恒 200）
  cli.py       did-create / did-show / issue / verify / serve
tests/e2e_test.py  端到端测试
```
