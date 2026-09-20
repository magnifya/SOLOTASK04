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
| POST | `/v1/credentials/{credential_id}/present` | 生成选择性披露演示，请求体恰为 `{"disclose":[路径...]}` 加可选 `challenge`、`expires_in`；成功 201 返回演示对象；字段问题 400、未知凭证 404 |
| POST | `/v1/presentations/{presentation_id}/verify` | 校验演示，新演示请求体恰为 `{"presentation":对象,"challenge":串}`（旧演示恰为 `{"presentation":对象}`）；**任何失败一律 HTTP 200**，成功 `{"valid":true}`，失败附非空中文 `reason` |
| POST | `/v1/credentials/{credential_id}/prove` | 生成谓词证明，请求体恰为 `{"predicates":[项...]}` 加可选 `challenge`、`expires_in`；成功 201 返回证明对象；字段问题 400、未知凭证 404 |
| POST | `/v1/proofs/{proof_id}/verify` | 校验谓词证明，请求体恰为 `{"proof":对象,"challenge":串}`；**任何失败一律 HTTP 200**，成功 `{"valid":true}`，失败附非空中文 `reason` |
| POST | `/v1/trust/anchors` | 注册信任锚点，请求体 `{"did","public_key","key_version"}`（非空字符串、P-256 PEM、非布尔正整数）；返回 201 与 `did`、`public_key`、`key_version`、`status:"active"`、`updated_at:null` |
| POST | `/v1/trust/anchors/{did}/rotate` | 带前置版本校验的密钥轮换，请求体须恰含 `from_key_version`（非布尔正整数）、`public_key`（P-256 PEM）；目标版本为 `from_key_version+1`；新建 201、同前置同 PEM 幂等重试 200，响应字段同 GET 元素 |
| GET | `/v1/trust/anchors/{did}` | 返回该 DID 的全部锚点版本数组（按 `key_version` 升序）；未知 DID 404 |
| PUT | `/v1/trust/anchors/{did}/{key_version}/status` | 吊销锚点版本，请求体必须恰为 `{"status":"revoked"}`；首次与重复均 200，首次置 UTC 秒精度 `updated_at`，重复保持不变；未知版本 404 |
| POST | `/v1/trust/verify` | 信任验签，请求体含非空字符串 `issuer_did`、正整数 `issuer_key_version`、非空字符串 `signature`；**缺失、吊销或验签失败均 HTTP 200**，返回 `{"valid":false,"reason":...}`，成功 `{"valid":true}` |
| POST | `/v1/trust/credentials/verify` | 跨系统凭证验真：验证未在本租户签发或存储的外部凭证，无需登记 DID/凭证；请求体须恰含 `body`、`signature`；**任何失败均 HTTP 200**，返回 `{"valid":false,"reason":...}`，成功 `{"valid":true}` |
| POST | `/v1/trust/credential-status/sync` | 外部凭证状态同步：请求体须恰含 `body`、`signature`，`body` 须恰含 `issuer_did`、`credential_id`、`status`、`updated_at`、`issuer_key_version`，可选 `reason`；请求/字段非法 400；锚点或签名失败 HTTP 200、`valid:false` 且不写入；首次同步 201、相同重放 200 不重复审计、严格更新替换、同时间不同内容 409 |
| GET | `/v1/trust/credential-status/{credential_id}?issuer_did=...` | 查询已同步的外部凭证状态；`issuer_did` 须唯一非空；已同步返回 `status`、`reason`、`updated_at`，未同步（含他租户）404 |
| GET | `/v1/trust/credential-status/{credential_id}/history?issuer_did=...&limit=&after=` | 只读查询外部凭证状态历史（兼容同步）；按 `updated_at` 升序、同值按 `cursor`；缺/重/空 `issuer_did` 400，`limit`/`after` 非法 400，未同步双键（含他租户）404 |
| GET | `/v1/audit?limit=&after=` | 查询本租户审计事件，按 seq 升序；返回 `events`、`next_after`，参数校验见下文 |

- 所有 `/v1` 请求读取 `X-Tenant-ID` 头确定租户：**缺省为 `default`**；显式提供时必须非空，否则 400。
- DID、凭证、演示与 `key_handle` 均按租户隔离：同一句柄可在不同租户分别注册；访问他租户资源一律按不存在处理（DID/凭证/演示为 404，跨租户引用 DID 签发为 400 并指明 `issuer_did`/`subject_did`，验签类端点仍遵循公开错误协议返回 200/`valid:false`）。
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
  -d '{"disclose":["/role","/addr/city"]}'   # [] 为零披露；可附 challenge/expires_in
curl -X POST localhost:8080/v1/presentations/vp_<id>/verify \
  -d '{"presentation":{...},"challenge":"<演示的 challenge>"}'
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

### 选择性披露演示

- `POST /v1/credentials/{credential_id}/present` 请求体必须**恰为**
  `{"disclose":[路径...]}` 加可选 `challenge`、`expires_in`：缺失
  `disclose`、不是数组、含多余字段一律 400；未知凭证 404。`[]` 表示
  **零披露**。`challenge` 须为非空字符串且按 Unicode 码点不超过 256，
  缺省生成 32 位小写 hex；`expires_in` 须为非布尔整数且在 1–86400
  之间，缺省 300。
- 路径按 [RFC 6901](https://www.rfc-editor.org/rfc/rfc6901) JSON Pointer
  解释，相对于凭证 `claims`：
  - 必须以 `/` 开头并命中实际 `claims` 属性，支持 `~0`/`~1` 转义；
  - **禁止根路径**（零披露请传 `[]`）、**禁止数组索引**（数组只能整值披露）、
    越界/经过非对象叶子均 400；
  - 路径不得重复、不得存在祖先/后代重叠（如 `/a` 与 `/a/b`）。
- 成功返回 201，字段恰为：
  `presentation_id`（`vp_` 加 32 位小写 hex）、`credential_id`、`issuer_did`、
  `issuer_key_version`（旧凭证缺省按 1）、`disclose`（原样回显）、
  `claims`（**仅含所选值**的投影，未选属性不出现）、`challenge`、
  `expires_at`（UTC 当前时间加 `expires_in` 秒，Z 结尾秒精度）、`proof`。
  `challenge` 与 `expires_at` 均写入被签名正文并随演示记录持久化。
- `proof` 为 **ES256**、无填充 base64url 的裸 `R||S` 签名，覆盖**除 `proof`
  外按 key 升序规范化 JSON**，使用凭证 `issuer_key_version` 对应的**历史版本
  私钥**；因此签发者轮换密钥后，旧演示仍可用历史公钥验真。
- 演示记录随状态文件持久化在 `presentations` 中，**重启后仍可验签**。
- `POST /v1/presentations/{presentation_id}/verify` 采用与凭证验签相同的
  公开错误协议：**任何失败都返回 HTTP 200** 与
  `{"valid":false,"reason":"<非空中文原因>"}`。新演示（存储记录含
  `challenge`）请求体必须**恰为** `{"presentation":对象,"challenge":串}`
  且 `challenge` 为非空字符串；旧演示（无 `challenge`）只接受恰含
  `presentation` 的请求，不做挑战、过期与消费检查。新演示校验顺序：
  请求 -> 资源 ID -> 绑定（字段集合、`presentation_id`、`credential_id`、
  `issuer_did`、`issuer_key_version`、`disclose`，以及请求 `challenge`、
  演示 `challenge` 与 proof 覆盖的存储 `challenge` 三者一致）-> 已消费
  （`演示已消费`，优先于过期与吊销）-> 过期（当前时间大于等于
  `expires_at`，`演示已过期`）-> 按存储凭证 `claims` 与存储 `disclose`
  **重算投影**并核对对象 `claims` -> `proof` 格式与签名 -> 吊销。
  未过期、未吊销且验签成功才进入消费；在**消费锁内复查**已消费、
  `expires_at` 与吊销状态后标记已消费：若复查时已到期则返回
  `演示已过期`，**不消费、不记审计**（修复“锁外验签期间到期仍被
  消费”的竞态）。未到期并发验证仅一次返回 200 `{"valid":true}`
  （无其他字段）并记一次 `presentation.consumed`，过期或失败不消费，
  消费记录跨重启保留，重复验证返回 `演示已消费`。
- 凭证已吊销时，演示在签名与锚定全部通过后返回 200、
  `{"valid":false,"reason":"凭证已吊销：<保存的 reason>"}`，且**不消费**；
  签名失败仍优先返回签名类原因。

```bash
curl -X POST localhost:8080/v1/credentials/vc_<id>/present \
  -d '{"disclose":["/role","/addr/city"],"challenge":"abc","expires_in":300}'
curl -X POST localhost:8080/v1/presentations/vp_<id>/verify \
  -d '{"presentation":{ ...上一步返回的整个演示对象... },"challenge":"abc"}'
```

### 谓词证明

- `POST /v1/credentials/{credential_id}/prove` 请求体必须**恰为**
  `{"predicates":[项...]}` 加可选 `challenge`、`expires_in`：
  `predicates` 须为**非空数组**，每项恰含 `path`、`op` 与可选
  `value`（`exists` **禁止** `value`，其余 op 必须提供）；缺字段、
  多余字段、类型非法一律 400；未知凭证 404。`challenge` 须为非空
  字符串且按 Unicode 码点不超过 256，缺省生成 32 位小写 hex；
  `expires_in` 须为非布尔整数且在 1–86400 之间，缺省 300。
- `path` 按 RFC 6901 解释（相对凭证 `claims`），规则与选择性披露
  一致：必须以 `/` 开头并命中实际属性、支持 `~0`/`~1` 转义、
  **禁根路径、禁数组索引**、越界 400；路径不得重复、不得存在
  祖先/后代重叠。
- `op ∈ {exists, eq, gte, lte}`：`eq` 为 JSON 精确相等（布尔与数字
  不互通，容器递归比较）；`gte`/`lte` 要求谓词 `value` 与 claims
  命中值**均为非布尔数字**，否则 400。
- 成功返回 201，字段恰为：`proof_id`（`zp_` 加 32 位小写 hex）、
  `credential_id`、`issuer_did`、`issuer_key_version`、`predicates`
  （原样回显）、`results`（与 `predicates` **同序的布尔数组**）、
  `challenge`、`expires_at`、`proof`。
- `proof` 为 **ES256**、无填充 base64url 的裸 `R||S` 签名，覆盖
  除 `proof` 外上述字段**加 `tenant_id`** 按 key 升序的规范化 JSON，
  使用凭证 `issuer_key_version` 对应的历史私钥；证明记录随状态文件
  持久化（`proofs`），重启后仍可验签。
- `POST /v1/proofs/{proof_id}/verify` 采用与演示 verify 相同的公开
  错误协议：**任何失败都返回 HTTP 200** 与
  `{"valid":false,"reason":"<非空中文原因>"}`，成功返回
  `{"valid":true}`（无其他字段）。请求体须恰为
  `{"proof":对象,"challenge":串}`。校验顺序：请求 -> 资源 ID ->
  绑定（字段集合与各锚定字段、请求/证明/存储 challenge 三者一致）
  -> 已消费（`证明已消费`，优先于过期）-> 过期（`证明已过期`）->
  按存储凭证 `claims` 与存储 `predicates` **重算 results** 并核对 ->
  `proof` 格式与签名。验签成功后在消费锁内复查已消费/到期再标记
  已消费：**失败不消费**，未到期并发验证仅一次成功并记一次
  `proof.consumed`，消费记录跨重启保留。
- 审计：创建记 `proof.created`、成功消费记 `proof.consumed`，
  `resource_type` 均为 `predicate_proof`、`resource_id` 为
  `proof_id`；失败与只读路径不记审计。

```bash
curl -X POST localhost:8080/v1/credentials/vc_<id>/prove \
  -d '{"predicates":[{"path":"/age","op":"gte","value":18},
       {"path":"/role","op":"eq","value":"admin"},
       {"path":"/name","op":"exists"}],"challenge":"abc"}'
curl -X POST localhost:8080/v1/proofs/zp_<id>/verify \
  -d '{"proof":{ ...上一步返回的整个证明对象... },"challenge":"abc"}'
```

### 信任锚点注册表

- 信任锚点按租户隔离：锚点仅在所属租户内可见，跨租户访问按不存在
  处理（GET/吊销为 404，验签端点仍遵循公开错误协议返回 200/`valid:false`）。
- `POST /v1/trust/anchors` 请求体须恰含 `did`、`public_key`、`key_version`，
  依次为**非空字符串**、**可解析的 P-256 公钥 PEM**、**非布尔正整数**；
  缺字段、类型非法、多余字段一律 400。成功返回 201，字段恰为
  `{did, public_key, key_version, status:"active", updated_at:null}`。
- 同一 `(did, key_version)` 再次提交：PEM **相同**视为幂等重试，返回
  **200** 与既有记录（含已吊销状态与 `updated_at`），每次重试都记
  `trust.anchor.registered`；PEM **不同**返回 **409**，不记审计。
- `GET /v1/trust/anchors/{did}` 返回该 DID 的**全部锚点版本数组**
  （按 `key_version` 升序，元素字段同注册响应）；DID 未知（含他租户）404。
- `PUT /v1/trust/anchors/{did}/{key_version}/status` 请求体必须恰为
  `{"status":"revoked"}`（其他值/多余字段/路径版本非正整数均 400）；
  锚点版本未知（含他租户）404。首次吊销与重复吊销均返回 **200**：
  首次置 `updated_at` 为当前 UTC 秒精度时间（Z 结尾），重复吊销保持
  首次 `updated_at` 不变，两次都记 `trust.anchor.revoked`。
- `POST /v1/trust/verify` 采用公开错误协议：请求体缺失/非法 JSON/非对象、
  缺 `issuer_did`（非空字符串）、`issuer_key_version`（非布尔正整数）、
  `signature`（非空字符串），锚点不存在、已吊销，还是签名格式错误或
  验签失败，**一律返回 HTTP 200** 与
  `{"valid":false,"reason":"<非空中文原因>"}`；成功返回
  `{"valid":true}`（无其他字段）。验签为只读操作，**不记审计**。
- 验签签名为 **ES256**、无填充 base64url 的裸 `R||S`，覆盖**请求对象
  去掉 `signature` 字段后**按 key 升序的规范化 JSON（紧凑序列化、UTF-8、
  嵌套对象递归排序）；公钥取本租户匹配 `(issuer_did, issuer_key_version)`
  的锚点，且仅 `active` 状态参与验签。
- `POST /v1/trust/credentials/verify` 验证**未在本租户签发或存储的外部
  凭证**：无需登记 DID/凭证，只读、不写凭证/状态/审计，跨租户各自使用
  本租户锚点，重启后行为不变。
  - 请求体必须**恰含** `body`（JSON 对象）与 `signature`（非空字符串）；
    缺失、多余字段、请求体缺失/非法 JSON/非对象一律按请求错误返回
    HTTP 200 + `{"valid":false,"reason":"请求…"}`。
  - `body` 必须含 `credential_id`、`issuer_did`、`subject_did`、
    `claims`、`issued_at`，依次为非空字符串、非空字符串、非空字符串、
    对象、非空字符串；缺失或类型非法返回前缀“凭证”的原因。
  - `issuer_key_version` 可省略：省略时按版本 **1** 查锚点，且**不得注入
    签名正文**（签名覆盖的就是请求中的完整 `body` 原文）；提供时须为
    非布尔正整数。其他扩展字段允许出现在 `body` 中且**全部参与签名**。
  - 校验顺序：请求结构 → 凭证字段 → 锚点 → 签名格式 → 密码学验签。
    锚点按本租户 `(issuer_did, 版本)` 查找，仅 `active` 的 P-256 公钥
    可用：缺失返回前缀“锚点”的原因，已吊销返回前缀“锚点”的吊销原因。
  - 签名为 **ES256/SHA-256**，64 字节裸 `R||S` 的无填充 base64url，覆盖
    完整 `body` 的递归排序紧凑 JSON；签名编码非法返回前缀“签名格式错误”，
    密码学验签失败返回前缀“签名校验失败”。成功仅返回 `{"valid":true}`。
- `POST /v1/trust/anchors/{did}/rotate` 在既有锚点上做带前置版本校验的
  密钥轮换：
  - 请求体必须**恰含** `from_key_version`（非布尔正整数）与 `public_key`
    （可解析的 P-256 公钥 PEM）；缺失、多余字段、类型或 PEM 非法一律
    **400**。DID 在本租户不存在（含他租户）为 **404**。
  - 目标版本恒为 `from_key_version + 1`：
    - 目标已由**同一前置**创建且 PEM **相同**：视为幂等重试，返回
      **200** 与原锚点、状态不变——即使前置或目标后来已吊销也照此幂等；
      每次重试都记 `trust.anchor.rotated`；
    - 目标已有**不同 PEM**，或 PEM 相同但**前置不同**（如该版本是经
      注册接口直接创建）：返回 **409**，不记审计；
    - 目标不存在时，仅允许 `from_key_version` 为本租户该 DID **当前最高
      且 active** 的版本：前置版本不存在为 **404**；前置已吊销或不是
      最高版本为 **400**。任何失败都不改动版本。
  - 轮换成功后新版本为 `active`、`updated_at` 为 `null`，**旧版本状态
    原样保留**；响应字段同 GET 元素（`{did, public_key, key_version,
    status, updated_at}`），新建 **201**、幂等 **200**。
  - 新建与幂等重试均记 `trust.anchor.rotated`（`resource_type` 为
    `trust_anchor`、`resource_id` 为 `<did>#<目标版本>`）；冲突、请求
    校验失败与验签不记。轮换与审计在同一把锁内经同一次原子写落盘，
    落盘失败回滚（版本不新增、事件不记录）；重启后版本、状态与审计保留。
  - 旧版本在被显式吊销前仍可用于验签，新版本同样可验签；跨租户继续
    遵循既有 404（轮换/查询/吊销）或 200/`valid:false`（验签）规则。
- 锚点、状态与审计随状态文件持久化，**跨重启保留**；状态变更与审计
  事件在同一把锁内经同一次原子写落盘，落盘失败回滚（变更不生效、
  事件不记录）。

```bash
curl -X POST localhost:8080/v1/trust/anchors -d '{
  "did":"did:web:example.com",
  "public_key":"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
  "key_version":1}'
curl localhost:8080/v1/trust/anchors/did:web:example.com
curl -X PUT localhost:8080/v1/trust/anchors/did:web:example.com/1/status \
  -d '{"status":"revoked"}'
curl -X POST localhost:8080/v1/trust/verify \
  -d '{"issuer_did":"did:web:example.com","issuer_key_version":1,
       "payload":{...},"signature":"<base64url R||S>"}'
curl -X POST localhost:8080/v1/trust/credentials/verify \
  -d '{"body":{"credential_id":"vc_ext_1","issuer_did":"did:web:example.com",
       "subject_did":"did:web:subject","claims":{...},"issued_at":"2026-09-21T00:00:00Z",
       "issuer_key_version":1},"signature":"<base64url R||S>"}'
```

### 外部凭证状态同步

在不改变本租户既有凭证状态的前提下，按信任锚点同步**外部**凭证的状态。
状态保存在独立的 `credential_status_sync` 命名空间，与本租户签发的凭证
（`credentials`）互不影响；按租户与 `(issuer_did, credential_id)` 双键隔离。

- `POST /v1/trust/credential-status/sync` 请求体必须**恰含** `body`
  （JSON 对象）与 `signature`（非空字符串）；缺失、多余字段、请求体
  缺失/非法 JSON/非对象一律 **400**。
- `body` 必须**恰含** `issuer_did`、`credential_id`、`status`、
  `updated_at`、`issuer_key_version`，并可选 `reason`：
  - `issuer_did`、`credential_id` 为**非空字符串**；
  - `status` 仅 `active`、`revoked`、`unknown`；
  - `issuer_key_version` 为**非布尔正整数**；
  - `updated_at` 为 **UTC 秒精度 Z 格式**（`YYYY-MM-DDTHH:MM:SSZ`，
    不接受毫秒/时区偏移/空格分隔/非法时刻）；
  - `reason` 提供时必须为**非空字符串**（按原文保存，不做裁剪）。
  任一字段缺失、类型非法、含多余字段均 **400**。
- 签名为 **ES256/SHA-256**、64 字节裸 `R||S` 的无填充 base64url，覆盖
  **完整 `body`** 的递归排序紧凑 JSON。公钥取本租户匹配
  `(issuer_did, issuer_key_version)` 的信任锚点，且仅 **active** 锚点
  可用。锚点缺失/已吊销、签名格式错误、密码学验签失败均返回
  **HTTP 200** 与 `{"valid":false,"reason":...}`，`reason` 前缀依次为
  **锚点**、**签名格式错误**、**签名校验失败**，且**不写入、不记审计**。
- 验签通过后按双键持久化：
  - **首次同步**返回 **201**；
  - **相同内容重放**（同 `updated_at` 且 `status`/`issuer_key_version`/
    `reason` 全同）返回 **200**，不替换、**不重复审计**；
  - `updated_at` **严格更新**（更晚）才替换旧值，返回 **200** 并记一次
    审计；更早的 `updated_at` 被忽略（保持新值，200、不记审计）；
  - **同 `updated_at` 但内容不同**返回 **409**，不写入、不记审计。
- 成功变更（首次或严格更新）记 `trust.credential.status.synced`，
  `resource_type` 为 `trust_credential_status`、`resource_id` 为
  `<issuer_did>#<credential_id>`；锚点/签名失败、400/409、重放与更早日
  期均不记。状态替换与审计事件在同一把锁内经**同一次原子写**落盘，
  落盘失败回滚（状态不变、事件不记录）。
- 同步结果响应字段恰为：`issuer_did`、`credential_id`、`status`、
  `reason`、`updated_at`、`issuer_key_version`。
- `GET /v1/trust/credential-status/{credential_id}?issuer_did=...`：
  `issuer_did` 查询参数**必须提供且唯一、非空**（缺失/重复/空值 400）；
  已同步返回 **200** 与恰三字段 `status`、`reason`、`updated_at`
  （`active`/`unknown` 等无原因时 `reason` 为 `null`）；未同步或属
  他租户一律 **404**（跨租户不可探测双键是否存在）。

```bash
curl -X POST localhost:8080/v1/trust/credential-status/sync -d '{
  "body":{"issuer_did":"did:web:example.com","credential_id":"vc_ext_1",
          "status":"revoked","updated_at":"2026-09-21T00:00:00Z",
          "issuer_key_version":1,"reason":"持证人违规"},
  "signature":"<base64url R||S>"}'
curl "localhost:8080/v1/trust/credential-status/vc_ext_1?issuer_did=did:web:example.com"
```

#### 外部凭证状态历史（只读）

`GET /v1/trust/credential-status/{credential_id}/history` 在不改变同步
语义与本地凭证状态的前提下，只读返回某双键外部凭证的状态变更历史，
与同步完全兼容。

- 查询参数 `issuer_did` **必须提供且唯一、非空**；缺失、重复或空值
  一律 **400**。`limit` 缺省 **50**，须为 **1–200** 的 ASCII 十进制
  整数；`after` 缺省 **0**，须为**非负** ASCII 十进制整数；重复参数、
  空白、布尔词、小数、符号、Unicode 数字等一律 **400**。
- 双键在本租户**未同步（含属他租户）一律 404**（跨租户不可探测）。
- **仅首次同步或 `updated_at` 更晚的严格更新才追加**历史项；相同重放、
  更早的 `updated_at`、同 `updated_at` 内容冲突（409）以及锚点/验签/
  字段失败（200/`valid:false` 或 400）均**不追加**。
- 历史按 **`updated_at` 升序**，同一 `updated_at` 按 **`cursor`** 升序。
  每项恰含：`status`、`reason`、`updated_at`、`issuer_key_version`、
  `audit_seq`、`audit_timestamp`、`cursor`。
- `cursor` 为**持久化正整数**，按追加顺序单调递增；`after` 排除
  `cursor` 不大于其值的记录，`next_after` 为本页末项的 `cursor`，
  **空页保持为 `after`**。
- `audit_seq`/`audit_timestamp` **关联产生该状态的同步审计事件**
  （`trust.credential.status.synced`）；无法追溯时为 `null`。
  `audit_seq` 为 `null` 的兼容项仍照常按 `cursor` 返回与分页。
- **旧状态兼容**：旧版本状态文件中已同步但无历史的双键，在加载时补
  一条内容取自旧状态行的兼容项，`cursor` 为新分配的持久化正整数，
  `audit_seq`/`audit_timestamp` 为 `null`；该兼容项随下一次原子写
  一并落盘，重启后 `cursor` 稳定。
- 历史项、当前状态与审计事件在同一把锁内经**同一次原子写**落盘，
  落盘失败一并回滚（历史不追加、游标不前进、状态不变、事件不记录），
  跨重启保留。历史查询为只读，**不记审计**、不改变同步语义，也不触碰
  本租户签发凭证的状态。
- 响应字段恰为：`issuer_did`、`credential_id`、`events`、`next_after`。

```bash
curl "localhost:8080/v1/trust/credential-status/vc_ext_1/history?issuer_did=did:web:example.com&limit=50&after=0"
```

### 多租户与审计日志

- 所有 `/v1` 请求以 `X-Tenant-ID` 头标识租户，缺省 `default`；显式
  空值一律 400。资源（DID、凭证、演示）与句柄仅在所属租户内可见，
  同句柄可跨租户注册，跨租户访问均按 404（签发时引用他租户 DID 为
  400）。旧版顶层状态文件加载时整体迁移进 `default` 租户桶。
- 状态变更在同一把锁内追加审计事件并经**同一次原子写**落盘；落盘
  失败则回滚内存变更——操作不生效，事件也不记录（“失败不记”）。
- 审计 `seq` **全局连续、自 1 起**（跨租户共享序号），事件按 seq
  升序存储。每条事件恰含：
  `seq`（整数）、`timestamp`（UTC 秒级 Unix 时间戳，整数）、
  `tenant_id`、`action`、`resource_type`、`resource_id`。
- 动作映射：

  | 操作 | action | resource_type |
  | --- | --- | --- |
  | DID 注册（含同句柄幂等重试，每次都记） | `did.created` | `did` |
  | 签发凭证 | `credential.issued` | `credential` |
  | 密钥轮换 | `key.rotated` | `did` |
  | active 登记（首次 201 与幂等 200 均记） | `status.updated` | `credential` |
  | 吊销凭证（首次与幂等重试均记） | `credential.revoked` | `credential` |
  | 创建演示 | `presentation.created` | `presentation` |
  | 演示消费成功（并发仅一次） | `presentation.consumed` | `presentation` |
  | 创建谓词证明 | `proof.created` | `predicate_proof` |
  | 谓词证明消费成功（并发仅一次） | `proof.consumed` | `predicate_proof` |
  | 信任锚点注册（含同 DID/版本同 PEM 幂等重试，每次都记） | `trust.anchor.registered` | `trust_anchor` |
  | 信任锚点吊销（首次与幂等重试均记） | `trust.anchor.revoked` | `trust_anchor` |
  | 信任锚点轮换（新建与同前置同 PEM 幂等重试均记） | `trust.anchor.rotated` | `trust_anchor` |
  | 外部凭证状态首次同步 / 严格更新（重放、更早日、失败不记） | `trust.credential.status.synced` | `trust_credential_status` |

  信任锚点审计 `resource_id` 为 `<did>#<key_version>`（轮换取目标版本
  `from_key_version+1`）；注册冲突 409、轮换冲突 409/校验失败 400、
  验签（成功或失败）等只读或失败路径不记审计。外部凭证状态同步审计
  `resource_id` 为 `<issuer_did>#<credential_id>`；锚点/签名失败、
  400/409、相同重放与更早日均不记。

  验签失败、演示已消费、演示过期、凭证/演示吊销判定等**只读或失败
  路径不记审计**。
- `GET /v1/audit?limit=&after=` 返回本租户事件（按 seq 升序）：
  - `limit` 缺省 50，须为非布尔整数且在 1–200；`after` 缺省 0，须为
    非布尔非负整数；重复参数、空白、布尔词、小数、符号等一律 400；
  - 返回 `{"events":[...], "next_after": n}`，**排除 seq 不大于
    `after`** 的事件；`next_after` 为本页最后一个事件的 seq，
    **空页保持为 `after`**，可直接作为下一页游标。

```bash
curl -H 'X-Tenant-ID: acme' localhost:8080/v1/dids \
  -d '{"method":"example","public_key":"alice-key"}'
curl -H 'X-Tenant-ID: acme' 'localhost:8080/v1/audit?limit=50&after=0'
```

## 测试

```bash
python3 tests/e2e_test.py
python3 tests/tenant_audit_test.py
python3 tests/trust_anchor_test.py
python3 tests/trust_anchor_rotate_test.py
python3 tests/predicate_proof_test.py
python3 tests/trust_credential_verify_test.py
python3 tests/trust_credential_status_sync_test.py
python3 tests/trust_credential_status_history_test.py
```

脚本会临时在本地端口启动服务。`e2e_test.py` 覆盖：201/200/400/404/409 各路径、同 key 去重、
PEM 句柄与非法 key_mode 拒绝、密钥轮换（含 404/400 路径）、轮换前后
`issuer_key_version` 验签、verify 端点 valid=true/false、CLI verify 成功与失败、
状态登记（201/200 幂等、严格 400、未知 404、已吊销 409）、吊销（默认/裁剪
reason、重复吊销忽略 reason、非法 reason 仅首次 400）、verify 对已吊销凭证
返回 valid:false、状态跨重启保留，以及旧状态文件迁移与旧凭证按版本 1 验签；
选择性披露覆盖：present 201 字段与投影、零披露、数组整值/数组索引拒绝、
`~0`/`~1` 转义、各类 400（缺字段/类型/不以 `/` 开头/根路径/重复/祖先重叠/
越界/非法 JSON/challenge 与 expires_in 非法值及边界）、未知凭证 404、
演示 verify 的全部分类失败与中文 reason、challenge 三方一致、过期、
消费（重复验证返回“演示已消费”、失败不消费、并发仅一次成功）、
轮换后历史版本验签、吊销原因（吊销不消费）、旧格式演示（无 challenge）
兼容旧流程，以及演示记录与消费标记跨重启保留。
`tenant_audit_test.py` 覆盖：租户头缺省/显式空值 400、同句柄跨租户
注册与资源/句柄隔离（跨租户均 404、验签端点 200/valid:false）、审计
事件字段与动作映射（幂等每次记录、失败/已消费/过期/吊销不记）、
全局连续 seq 与租户内分页（limit/after 边界与各类非法参数 400、空页
保持游标）、过期演示锁内复查不消费、并发仅一次消费且仅一条审计、
seq 跨重启接续，以及落盘失败时内存回滚（变更不生效、审计不记录）。

## 代码结构

```
vcbackend/
  crypto.py    ES256 签名/验签、规范化 JSON、P-256 密钥
  models.py    DIDRecord / CredentialRecord / CredentialStatusRecord /
               PresentationRecord / PredicateProofRecord /
               TrustAnchorRecord / CredentialStatusSyncRecord /
               CredentialStatusHistoryEvent / AuditEvent 数据模型
  store.py     多租户文件存储（租户分桶、旧格式迁移）、DID 去重、密钥
               轮换、凭证签发/验签、选择性披露演示（RFC6901 路径校验、
               claims 投影）、谓词证明（谓词校验/求值、results 重算）、
               消费锁内复查过期，信任锚点注册/吊销/验签/
               带前置版本校验的轮换、跨系统外部凭证验真、外部凭证状态
               同步（双键隔离、严格更新、重放幂等、原子审计）、外部凭证
               状态历史（持久化游标、旧状态兼容补项、追加与查询），以及
               全局连续审计事件与状态变更的同一次原子写（失败回滚）
  service.py   标准库 HTTP 路由、X-Tenant-ID 租户解析、/v1/audit、
               /v1/trust/credential-status/{id}/history 与错误映射
  cli.py       did-create / did-show / issue / verify / serve
tests/e2e_test.py                  端到端测试（默认租户，全协议兼容）
tests/tenant_audit_test.py         租户隔离 / 审计 / 过期竞态测试
tests/trust_anchor_test.py         信任锚点注册/查询/吊销/验签测试
tests/trust_anchor_rotate_test.py  信任锚点密钥轮换（400/404/409/幂等/审计/重启）
tests/predicate_proof_test.py      谓词证明（prove 字段/400/404、verify 消费/
                                   过期/篡改/跨租户/并发/审计/重启）
tests/trust_credential_verify_test.py  跨系统凭证验真（请求/凭证/锚点/
                                   签名格式/验签分类 reason、省略版本不注入、
                                   扩展字段参与签名、只读不记审计、跨租户/重启）
tests/trust_credential_status_sync_test.py  外部凭证状态同步（请求/字段 400、
                                   锚点/签名格式/验签分类 reason、201/200/409、
                                   严格更新与更早日忽略、重放不重复审计、
                                   GET 三字段/404、跨租户双键隔离、不改本地
                                   凭证状态、重启持久化、落盘失败回滚）
tests/trust_credential_status_history_test.py  外部凭证状态历史（追加规则：
                                   仅首次/严格更新追加，重放/更早/冲突/验签
                                   失败不追加；字段与审计关联、updated_at/
                                   cursor 排序、limit/after 分页与空页保持、
                                   各类非法参数 400、双键 404、租户隔离、
                                   只读不审计、重启 cursor 持久化、旧状态补
                                   兼容项 audit 为 null、落盘失败回滚）
```
