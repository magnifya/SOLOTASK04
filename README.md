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
| POST | `/v1/dids/{did}/keys/rotate` | 轮换密钥，请求体 `{"key_handle"}`，返回 200 与 `did`、`public_key`、`key_handle`、`key_version` |
| POST | `/v1/credentials` | 签发凭证，请求体 `{"issuer_did","subject_did","claims"}`，返回 201 与 `credential_id`、`signature`、`issuer_key_version` |
| GET | `/v1/credentials/{credential_id}` | 返回 `credential_id`、`body`、`signature`；不存在 404 |
| PUT | `/v1/credentials/{credential_id}/status` | 登记状态，请求体必须恰为 `{"status":"active"}`；首次 201、重复 200，均含 `credential_id`、`status`、`updated_at`（重复保持首次值）；已吊销 409 |
| GET | `/v1/credentials/{credential_id}/status` | 返回 `credential_id`、`status`、`updated_at`；历史无状态按 `active` 返回且 `updated_at` 为 `null`；不存在 404 |
| POST | `/v1/credentials/{credential_id}/revoke` | 吊销凭证；`reason` 可省略（默认“持证人主动吊销”），否则须为字符串且首尾裁剪后非空；返回 200 与 `credential_id`、`status:"revoked"`、`reason`、`revoked_at`、`updated_at`；不存在 404 |
| POST | `/v1/credentials/{credential_id}/verify` | 验签，请求体 `{"body","signature"}`；**任何失败一律 HTTP 200**，返回 `valid`（失败时附分类中文 `reason`） |
| POST | `/v1/credentials/{credential_id}/present` | 选择性披露，请求体**恰为** `{"disclose":[路径...]}`；返回 201 与 `presentation_id`、`credential_id`、`issuer_did`、`issuer_key_version`、`disclose`、`claims` 投影、`proof`；请求体问题 400，未知凭证 404 |
| POST | `/v1/presentations/{presentation_id}/verify` | 验真展示，请求体恰为 `{"presentation":对象}`；**任何失败一律 HTTP 200**，成功 `{"valid":true}`，失败附非空中文 `reason`（已吊销凭证返回“凭证已吊销：<原因>”） |

- DID 形如 `did:example:<32 位 hex>`。
- `public_key` 为**句柄**：非空且不能是 PEM 文本；同一句柄再次提交返回其既有 DID（按提交原文去重）。
- `key_mode` 缺省为 `server`（服务端托管密钥），其余取值一律 400。
- 缺少/非法字段返回 400 并在 `error` 中说明原因；任一 DID 不存在时 400 并指明是 `issuer_did` 还是 `subject_did`。

### curl 示例

```bash
curl -X POST localhost:8080/v1/dids -d '{"method":"example","public_key":"alice-key"}'
curl localhost:8080/v1/dids/did:example:<id>
curl -X POST localhost:8080/v1/dids/did:example:<id>/keys/rotate \
  -d '{"key_handle":"alice-key-v2"}'
curl -X POST localhost:8080/v1/credentials \
  -d '{"issuer_did":"did:example:<a>","subject_did":"did:example:<b>","claims":{"role":"admin"}}'
curl localhost:8080/v1/credentials/vc_<id>
curl -X PUT localhost:8080/v1/credentials/vc_<id>/status \
  -d '{"status":"active"}'
curl localhost:8080/v1/credentials/vc_<id>/status
curl -X POST localhost:8080/v1/credentials/vc_<id>/revoke \
  -d '{"reason":"持证人造假"}'   # reason 可省略
curl -X POST localhost:8080/v1/credentials/vc_<id>/verify \
  -d '{"body":{...},"signature":"..."}'
curl -X POST localhost:8080/v1/credentials/vc_<id>/present \
  -d '{"disclose":["/role","/addr/city"]}'   # [] 为零披露
curl -X POST localhost:8080/v1/presentations/vp_<id>/verify \
  -d '{"presentation":{...}}'
```

## 命令行

CLI 通过 HTTP 与服务通信（`verify` 调用服务端验签端点，由服务端按
`issuer_key_version` 从签发者公钥历史中取公钥验签）。
用 `--base-url` 或环境变量 `VCBACKEND_URL` 指定服务地址（默认 `http://127.0.0.1:8080`）。

```bash
export VCBACKEND_URL=http://127.0.0.1:8080

python3 -m vcbackend.cli did-create --method example --public-key alice-key
python3 -m vcbackend.cli did-show  did:example:<id>
python3 -m vcbackend.cli issue --issuer did:example:<a> --subject did:example:<b> \
    --claims '{"role":"admin"}'
python3 -m vcbackend.cli verify vc_<id>     # 成功输出 true（退出码 0）
                                           # 正文被改动或 GET 凭证失败均输出 false，
                                           # stderr 说明原因（退出码 1）
```

## 签名与验真

- 算法为 **ES256**：ECDSA over P-256 与 SHA-256，签名编码为 64 字节裸 `R||S` 的 base64url（无填充）。
- 签名覆盖凭证**正文按 key 升序的规范化 JSON**（紧凑序列化、UTF-8、嵌套对象同样递归排序）。
- 凭证正文包含 `credential_id`、`issuer_did`、`subject_did`、`claims`、`issued_at`
  与整数 `issuer_key_version`（签发时签发者的当前密钥版本，随正文一起签名），
  对其任一字段（含 claims 内部）的改动都会使验签失败。
- `POST /v1/credentials/{credential_id}/verify` 以**存储的** `credential_id`、
  `issuer_did`、`issuer_key_version` 为锚：正文锚定字段与存储不一致即判失败；
  验签公钥按 `issuer_key_version` 从签发者公钥历史中取出。
- verify 端点采用统一公开错误协议：无论请求体缺失、不是合法 JSON 或不是对象，
  缺少 `body`/`signature`、`body` 不是对象、`signature` 不是非空字符串，
  `credential_id` 不存在，正文 `credential_id`/`issuer_did`/`issuer_key_version`
  与存储锚不一致，签名格式错误、签名校验失败还是历史公钥不可用，**都返回
  HTTP 200** 与 `{"valid": false, "reason": "<非空中文原因>"}`，绝不返回
  400/404/500，也不泄露私钥或堆栈。`reason` 按类别措辞以区分
  请求（`请求…`）、资源（`凭证不存在`）、锚定（`锚定校验失败…`）、
  签名格式（`签名格式错误…`）、签名校验（`签名校验失败…`）与
  密钥（`历史公钥不可用…`）。验签成功返回 200 `{"valid": true}`。
- 其他路径仍沿用原状态码协议：字段问题 400、资源不存在 404。
- 旧凭证正文缺 `issuer_key_version` 时按版本 1 验签，签名本身不受影响。

### 凭证状态与吊销

- `PUT .../status` 请求体必须**恰为** `{"status":"active"}`：缺失 `status`、
  取值非 `active`、含多余字段、请求体缺失/非法 JSON/非对象一律 400 并返回
  非空 `error`。无状态登记返回 201，重复登记 200；两者均返回
  `credential_id`、`status`、`updated_at`，重复登记保持首次 `updated_at`
  与状态不变。
- `GET .../status` 返回 `credential_id`、`status`、`updated_at`；历史无状态
  凭证按 `active` 返回、`updated_at` 为 `null`；未知凭证 404。
- `POST .../revoke`：未知凭证 404。首次请求可省略 `reason`（空请求体或
  `{}` 均可），默认“持证人主动吊销”；提供时必须是字符串且首尾裁剪后非空
  （显式 `null`、数字、空白串均为 400）。保存并返回裁剪后的值，成功为 200，
  返回 `credential_id`、`status:"revoked"`、`reason`、`revoked_at`、
  `updated_at`。已吊销时再次调用，任何 `reason`（含非法值）都被忽略并返回
  首次结果；非法 `reason` 仅首次请求返回 400。
- 已 `revoked` 的凭证再 `PUT .../status` 返回 409 与非空 `error`，状态与
  时间字段保持不变。
- 状态随状态文件持久化，**跨重启保留**。
- verify 在签名与锚定均成功后检查状态：`revoked` 返回 200、
  `{"valid":false,"reason":"凭证已吊销：<保存的 reason>"}`；`active` 或
  无状态维持原结果（签名失败仍优先返回签名类原因）。

### 选择性披露展示

- `POST /v1/credentials/{credential_id}/present` 请求体必须**恰为**
  `{"disclose":[路径...]}`：缺失 `disclose`、含多余字段、请求体缺失/非法
  JSON/非对象一律 400；未知凭证 404。
- 路径按 [RFC 6901](https://www.rfc-editor.org/rfc/rfc6901) JSON Pointer
  书写（`~1`/`~0` 转义），必须为字符串、非空且以 `/` 开头并命中凭证
  `claims` 内属性。禁止根路径（`""`）、数组索引（进入数组）与越界键；
  同一语义路径不得重复，任意两条路径不得构成祖先/后代重叠。
  `disclose: []` 为**零披露**，投影为 `{}`。
- 成功返回 201：`presentation_id`（`vp_` 加 32 位小写 hex）、
  `credential_id`、`issuer_did`、`issuer_key_version`（旧凭证缺版本按
  1）、回显的 `disclose`、仅含所选值的 `claims` 投影、`proof`。
- `proof` 为 ES256（64 字节裸 `R||S` 的无填充 base64url），签名覆盖
  **除 `proof` 外按 key 升序规范化的 JSON**，使用签发者
  `issuer_key_version` 对应的历史版本私钥。
- 展示记录随状态文件**持久化，跨重启可验签**。
- `POST /v1/presentations/{presentation_id}/verify` 请求体必须恰为
  `{"presentation":对象}`，任何失败都返回 **HTTP 200** 与
  `{"valid":false,"reason":"<非空中文原因>"}`，绝不返回 400/404/500。
  服务端以**存储记录**为锚：路径 ID 必须已持久化且等于对象
  `presentation_id`；按凭证 `claims` 与存储 `disclose` 重算投影，逐字段
  核对 `credential_id`、`issuer_did`、`issuer_key_version`、`disclose`、
  `claims`（且除 `proof` 外无多余/缺失字段），再用历史版本公钥验
  `proof`。成功返回 `{"valid":true}`。
- 验真在所有校验与 `proof` 验签成功后检查凭证状态：已吊销返回
  `{"valid":false,"reason":"凭证已吊销：<保存原因>"}`。

### 密钥模型与轮换

为保证「服务端签发的签名能用注册时返回的公钥验真」，注册时由系统为该
`public_key` 句柄铸造 P-256 密钥对：接口返回并登记真实公钥 PEM，私钥由服务端内部持有
（随状态文件保存，仅用于本演示）。`public_key` 提交串作为幂等去重的句柄。

- 每个 DID 维护 `key_history`：`[{version, key_handle, public_key, ...}]`，版本自 1 起。
- `POST /v1/dids/{did}/keys/rotate` 生成新 P-256 密钥对，原子递增 `key_version`
  并登记历史；新句柄须非空、非 PEM 且未被任何 DID 使用过。未知 DID 404，非法句柄 400。
- 轮换后**新签发用当前版本私钥**，**验签按 `issuer_key_version` 取历史公钥**，
  因此旧凭证在轮换后仍可验真。
- 旧状态文件中缺少密钥元数据的 DID 在加载时自动迁移为 `server`/版本 1：
  历史即原 `public_key`，句柄取 `submitted_public_key`（缺省为原 `public_key`）。

## 测试

```bash
python3 tests/e2e_test.py
```

脚本会临时在本地端口启动服务，覆盖：201/200/400/404/409 各路径、同 key 去重、
PEM 句柄与非法 key_mode 拒绝、密钥轮换（含 404/400 路径）、轮换前后
`issuer_key_version` 验签、verify 端点 valid=true/false、CLI verify 成功与失败、
状态登记（201/200 幂等、严格 400、未知 404、已吊销 409）、吊销（默认/裁剪
reason、重复吊销忽略 reason、非法 reason 仅首次 400）、verify 对已吊销凭证
返回 valid:false、状态跨重启保留，以及旧状态文件迁移与旧凭证按版本 1 验签；
还覆盖选择性披露：零披露/部分披露投影、present 严格 400/未知 404、路径
（根/越界/数组索引/重复/祖先重叠）拒绝、presentation verify 的 valid:true 与
公开错误协议（未持久化 ID、ID 不符、绑定字段/disclose/投影/proof 被改、
多余字段）、已吊销返回“凭证已吊销：”原因、以及展示记录跨重启验签。

## 代码结构

```
vcbackend/
  crypto.py    ES256 签名/验签、规范化 JSON、P-256 密钥
  jsonptr.py   RFC6901 指针解析、路径校验与选择性披露投影
  models.py    DIDRecord / CredentialRecord / PresentationRecord 数据模型
  store.py     文件持久化存储、DID 去重、密钥轮换与凭证/展示签发验签业务逻辑
  service.py   标准库 HTTP 路由与错误映射
  cli.py       did-create / did-show / issue / verify / serve
tests/e2e_test.py  端到端测试
```
