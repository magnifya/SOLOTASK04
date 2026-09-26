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
| POST | `/v1/dids/{did}/deactivate` | 停用 DID；空体或 `{}` 省略 `reason`（默认“DID 主动停用”），非空须恰含 `reason`（裁剪后非空字符串，非法 400）；未知或他租户 DID 404；首次 200 返回 `did`、`status:"deactivated"`、`reason`、`updated_at`，重复忽略 `reason`（含非法值）并幂等返回首次结果 |
| GET | `/v1/dids/{did}/status` | 只读 DID 生命周期状态；200 恰返 `{did,status,reason,updated_at}`，活动为 `active`/`null`/`null`，停用后为首次原因与 UTC 秒精度 Z 时间；未知或他租户 404 |
| GET | `/v1/dids/{did}/history?limit=&after=` | 只读 DID 注册与停用历史；200 恰含 `did`、`events`、`next_after`，事件恰含 `{action,status,reason,updated_at,audit_seq,audit_timestamp,cursor}` 且按 `cursor` 升序；注册为 `did.created`/`active`/`null`，首次停用为 `did.deactivated`/`deactivated`/首次裁剪 reason；幂等重试或失败不追加；游标租户内跨 DID 持久递增且独立于其他历史；分页参数规则同其他历史接口；未知或跨租户 DID 404，空页 `next_after=after`，只读不记审计 |
| GET | `/v1/dids/{did}/document` | 只读 DID 文档：返回 `did`、`current_key_version`、按版本升序的 `verification_methods`（每项 `key_version`、`key_handle`、`public_key` P-256 PEM）与 `document_proof`；可选 `?version=N`（ASCII 十进制正整数，仅该版本并重新生成证明），版本不存在 404，参数非法 400；不暴露私钥、不改变任何状态 |
| POST | `/v1/dids/{did}/keys/rotate` | 轮换密钥，请求体 `{"key_handle"}`，返回 200 与 `did`、`public_key`、`key_handle`、`key_version` |
| POST | `/v1/dids/{did}/keys/{key_version}/revoke` | 吊销旧密钥版本；空体或 `{}` 省略 `reason`，非空须恰含 `reason`（裁剪后非空字符串，非法 400）；`key_version` 须为 ASCII 正整数，DID/版本（含他租户）不存在 404，当前版本 409；旧版本首次 200 返回 `did`、`key_version`、`status:"revoked"`、`reason`、`updated_at`，重复忽略 `reason` 并返回首次结果 |
| GET | `/v1/dids/{did}/keys/{key_version}/status` | 只读查询密钥版本吊销状态；路径版本须为 ASCII 正整数（非法 400），DID/版本不存在（含跨租户）404；200 恰返 `{did,key_version,status,reason,updated_at}`，active 为 `null`/`null`，revoked 为首次原因与 UTC 秒精度 Z 时间 |
| GET | `/v1/dids/{did}/keys/revocations?limit=&after=` | 只读查询 DID 密钥吊销历史；响应恰含 `did`、`events`、`next_after`，事件恰含 `{key_version,reason,updated_at,cursor}`；仅首次成功吊销追加；`limit` 默认 50、限 1–200，`after` 默认 0、须非负，重复/非空 ASCII 数字外取值均 400；未知或跨租户 DID 404，已有 DID 无历史返空页 |
| GET | `/v1/dids/{did}/keys/history?limit=&after=` | 只读查询 DID 密钥生命周期历史；200 恰含 `did`、`events`、`next_after`，事件恰含 `{key_version,key_handle,public_key,action,status,updated_at,audit_seq,audit_timestamp,cursor}` 且按 `cursor` 升序、禁止私钥；新建版本追加 active（v1 为 `did.created`、轮换为 `key.rotated`），首次吊销追加 revoked/`key.revoked` 并同秒，重复/失败/幂等不追加；游标租户内跨 DID 持久递增且与吊销历史隔离；分页参数沿用 `keys/revocations`；未知或跨租户 DID 404，空页 `next_after=after`，只读不记审计 |
| POST | `/v1/credentials` | 签发凭证，请求体 `{"issuer_did","subject_did","claims"}` 加可选 `expires_at`；提供时必须是 UTC 秒精度 Z 格式 `YYYY-MM-DDTHH:MM:SSZ` 且严格晚于当前时刻（否则 400），仅在提供时写入正文并参与签名；返回 201 与 `credential_id`、`signature`、`issuer_key_version` |
| GET | `/v1/credentials/{credential_id}` | 返回 `credential_id`、`body`、`signature`；不存在 404 |
| PUT | `/v1/credentials/{credential_id}/status` | 登记/变更状态，请求体必须恰为 `{"status":"active"}` 或 `{"status":"suspended","reason":"原因"}`（reason 裁剪后 1–256 码点，非法 400）；无状态→active 首次 201，active/无状态→suspended 与 suspended→active 为 200，同状态同原因幂等 200（保持首次 `updated_at`），suspended 同状态不同原因 409，已 revoked 任意目标 409；响应恰含 `credential_id`、`status`、`updated_at` |
| GET | `/v1/credentials/{credential_id}/status` | 返回 `credential_id`、`status`、`updated_at`；历史无状态按 `active` 返回且 `updated_at` 为 `null`；suspended 为暂停状态、revoked 含吊销信息（本响应仅三键）；不存在或他租户 404 |
| GET | `/v1/credentials/{credential_id}/status/history?limit=&after=` | 只读查询本地凭证状态历史；响应恰含 `credential_id`、`events`、`next_after`，事件恰含 `{status,reason,updated_at,revoked_at,audit_seq,audit_timestamp,cursor}`；首次 active、每次暂停/恢复与首次 revoke 各追加一条（暂停保存原因、恢复 reason/revoked_at 为 null），同状态幂等、重复吊销与失败路径不追加；按 `updated_at`、`cursor` 升序；未知或跨租户凭证 404，有凭证无状态空页；参数规则同其他历史接口，只读不记审计 |
| POST | `/v1/credentials/{credential_id}/revoke` | 吊销凭证；`reason` 可省略（默认“持证人主动吊销”），否则须为字符串且首尾裁剪后非空；返回 200 与 `credential_id`、`status:"revoked"`、`reason`、`revoked_at`、`updated_at`；不存在 404 |
| POST | `/v1/credentials/{credential_id}/verify` | 验签，请求体 `{"body","signature"}`；**任何失败一律 HTTP 200**，返回 `valid`（失败时附分类中文 `reason`） |
| POST | `/v1/credentials/{credential_id}/present` | 生成选择性披露演示，请求体恰为 `{"disclose":[路径...]}` 加可选 `challenge`、`expires_in`、`holder_binding`；成功 201 返回演示对象（绑定时另含 `holder_did`、`holder_key_version`、`holder_proof`）；字段问题 400、未知凭证 404 |
| POST | `/v1/credentials/{credential_id}/present-batch` | 原子批量生成选择性披露演示，请求体须恰为 `{"presentations":[项...]}`，数组非空且不超过 50 项；每项恰含 `disclose` 及可选 `challenge`、`expires_in`、`holder_binding`，规则同单项 present（challenge 非空串≤256 码点、缺省 32 位小写 hex；`expires_in` 非布尔整数 1–86400、缺省 300；`holder_binding` 布尔、缺省 false，绑定时 subject_did 须本租户已注册 DID）；disclose 按 RFC6901 命中 claims，禁根/数组索引/越界/重复/祖先重叠，`[]` 零披露；外层或任一项非法 400（非空中文原因）且整批不写入、不记审计，未知凭证 404；成功 201 返回 `{"presentations":[...]}`，与输入等长、同序，项键序固定为 `presentation_id`、`credential_id`、`issuer_did`、`issuer_key_version`、`disclose`、`claims`、`challenge`、`expires_at`、`proof`（绑定项末尾加 `holder_did`、`holder_key_version`、`holder_proof`）；全部记录与每条演示的审计事件同一次原子提交，失败整体回滚，ES256 签名与单项一致、重启可验签 |
| POST | `/v1/presentations/{presentation_id}/verify` | 校验演示，新演示请求体恰为 `{"presentation":对象,"challenge":串}`（旧演示恰为 `{"presentation":对象}`）；**任何失败一律 HTTP 200**，成功 `{"valid":true}`，失败附非空中文 `reason` |
| POST | `/v1/credentials/{credential_id}/prove` | 生成谓词证明，请求体恰为 `{"predicates":[项...]}` 加可选 `challenge`、`expires_in`；成功 201 返回证明对象；字段问题 400、未知凭证 404 |
| POST | `/v1/proofs/{proof_id}/verify` | 校验谓词证明，请求体恰为 `{"proof":对象,"challenge":串}`；**任何失败一律 HTTP 200**，成功 `{"valid":true}`，失败附非空中文 `reason` |
| POST | `/v1/trust/anchors` | 注册信任锚点，请求体 `{"did","public_key","key_version","uses"?}`（非空字符串、P-256 PEM、非布尔正整数；`uses` 可选，须为非空无重复字符串数组，取值限且按规范序 `generic`、`vc`、`vp`、`proof`、`did`、`status`、`deactivation`，省略为全用途）；返回 201 与 `did`、`public_key`、`key_version`、`status:"active"`、`updated_at:null` |
| POST | `/v1/trust/anchors/{did}/rotate` | 带前置版本校验的密钥轮换，请求体须恰含 `from_key_version`（非布尔正整数）、`public_key`（P-256 PEM）；目标版本为 `from_key_version+1` 并继承前置 `uses`；新建 201、同前置同 PEM 幂等重试 200，响应字段同 GET 元素 |
| GET | `/v1/trust/anchors/{did}` | 返回该 DID 的全部锚点版本数组（按 `key_version` 升序）；未知 DID 404 |
| GET | `/v1/trust/anchors/{did}/{key_version}/uses` | 只读返回锚点版本用途白名单；200 按键序恰返 `did`、`key_version`、`uses`（`uses` 按规范序，省略注册或旧记录为全用途）；路径版本非 ASCII 正整数 400，未知或跨租户 404 |
| PUT | `/v1/trust/anchors/{did}/{key_version}/uses` | 收紧锚点版本用途白名单（无需轮换即可撤销用途）；请求体须恰含 `from_uses`、`uses`（均为非空无重复字符串数组，取值限且按规范序），否则 400；路径版本非 ASCII 正整数 400，未知或跨租户 404，已吊销 409；目标等于当前值幂等 200 且无副作用，否则 `from_uses` 须等于当前值且目标须为其真子集，前置不匹配或扩权均 409，并发不同收紧最多一个成功；200 按键序恰返 `did`、`key_version`、`uses`；实际变更仅记一次 `trust.anchor.uses.updated` 审计（`resource_type:trust_anchor`、`resource_id:<did>#<key_version>`），用途与审计原子落盘、失败回滚、重启保持 |
| GET | `/v1/trust/anchors/{did}/{key_version}/uses/history?limit=&after=` | 只读查询锚点版本用途历史；路径版本须为 ASCII 正整数（非法 400），查询参数仅允许 `limit`（缺省 50、限 1–200）与 `after`（缺省 0、非负），二者须唯一、非空 ASCII 十进制，其他或重复参数 400；非法请求 400、未知或跨租户锚点 404，均仅返单键非空中文 `error`；200 按序恰返 `did`、`key_version`、`events`、`next_after`，事件按 `cursor` 升序且键序恰为 `cursor`、`action`、`from_uses`、`uses`、`updated_at`；新版本注册/轮换追加 `registered`/`rotated`（`from_uses:null`），实际收紧追加 `updated`（前后用途数组均保存），幂等、冲突、失败、吊销不追加；`updated_at` 为 UTC 秒精度 Z 字符串，`cursor` 为租户内跨 DID 持久递增正整数；返 `cursor>after`，空页 `next_after=after`，否则取页末 `cursor`；旧锚点加载时补 `snapshot`（`from_uses`/`updated_at` 为 `null`、`uses` 为当前值，跨重启稳定）；新建、轮换、收紧时锚点、历史、游标与审计原子落盘、失败全回滚；只读不记审计 |
| GET | `/v1/trust/anchors?limit=&after=&status=` | 只读跨 DID 发现本租户锚点版本；响应恰含 `anchors`、`next_after`，每项恰含 `did`、`public_key`、`key_version`、`status`、`updated_at`、`cursor`；先按 `status`（可省略，或 `active`/`revoked`）过滤，再按 `cursor>after` 升序取至多 `limit`（默认 50、限 1–200，`after` 默认 0 且非负）；无锚点也返回 200 空数组，空结果 `next_after` 等于 `after`；参数仅允许这三个，重复/空值/空白/符号/Unicode 数字/越界/未知参数均 400；只读不记审计 |
| GET | `/v1/trust/anchors/{did}/history?limit=&after=` | 只读查询信任锚点生命周期历史；200 恰含 `did`、`events`、`next_after`，事件恰含 `{key_version,action,status,updated_at,cursor}`；仅新版本注册、轮换目标版本（active、`updated_at:null`）与首次吊销（revoked、首次吊销 UTC 秒 Z 时间）追加，幂等重试与失败不追加；`cursor` 为租户内跨 DID 共享的持久化正整数；`limit` 默认 50、限 1–200，`after` 默认 0、须非负，重复/非空 ASCII 数字外取值均 400；未知或跨租户 DID 404，已有 DID 无历史返空页；只读不记审计 |
| PUT | `/v1/trust/anchors/{did}/{key_version}/status` | 吊销锚点版本，请求体必须恰为 `{"status":"revoked"}`；首次与重复均 200，首次置 UTC 秒精度 `updated_at`，重复保持不变；未知版本 404 |
| GET | `/v1/trust/anchor-changes?after=&signer_did=` | 只读可签名信任锚点变更流：查询参数仅允许唯一 `after`（缺省 0、非负 ASCII 十进制整数）与唯一非空 `signer_did`，缺失/空值/重复/空白/符号/小数/布尔词/Unicode 数字/未知参数均 400 且仅 `{"error":非空中文}`；签名 DID 须为本租户**活动本地 DID**，未知（含他租户）404、已停用 409；200 键序 `events,next_after,signer_did,signer_key_version,signature`，事件按 `cursor>after` 升序至多 200 项，每项键序 `cursor,action,did,key_version,public_key,status,uses`，注册/轮换/首次吊销/实际用途收紧依次产生 `registered`/`rotated`/`revoked`/`uses.updated`（幂等/冲突/失败不产生，值为变更后状态，`uses` 为既有规范序）；`cursor` 租户内跨 DID 持久递增且与其他历史隔离，空页 `next_after=after` 否则取页末 cursor；`signature` 由签名 DID **当前版本私钥**对前四键递归键升序紧凑 UTF-8 JSON 做 ES256（P-256+SHA-256）64 字节裸 `R||S` 无填充 base64url 签名；旧锚点加载时按 did/版本序补 `snapshot`、重启不变；变更、游标与审计同一次原子写落盘/回滚；GET 只读、不记审计 |
| POST | `/v1/trust/anchor-changes/verify` | 跨系统信任锚点变更流只读验真（不依赖本地事件、不写状态/游标/审计）：请求体恰含 `changes`（JSON 对象）、`after`（非布尔非负整数），缺漏/多余字段或类型非法均 400 且仅 `{"error":非空中文}`，显式空租户头 400、缺省 `default`、按租户隔离；外层合法后任何失败均 **HTTP 200** 按键序恰返 `{"valid":false,"reason"}`，原因依次为“变更流非法”（changes 恰含 `events,next_after,signer_did,signer_key_version,signature`，事件协议沿用 GET 入口：events 至多 200 项、cursor 严格递增且均大于 after、非空 next_after 等于末项 cursor、空时等于 after）、“锚点不可用”（本租户同 signer_did/版本且含 generic 用途的 active 锚点，他租户/吊销/无 generic 均属之）、“签名格式错误”、“签名校验失败”；`signature` 沿用 ES256（P-256+SHA-256）64 字节裸 `R||S` 无填充 base64url，覆盖 changes 除 signature 外四键的递归键升序紧凑 UTF-8 JSON；成功仅 `{"valid":true}`；结论随状态文件重启稳定 |
| POST | `/v1/trust/anchor-changes/sync` | 跨系统信任锚点变更流的同步接收与防重放检查点（验真通过的变更页按来源可靠落盘，不记审计）：请求体协议与 `/v1/trust/anchor-changes/verify` 完全一致（恰含 `changes` 对象、`after` 非布尔非负整数，缺失/非法 JSON/非对象/键集或类型错误均 400 且仅 `{"error":非空中文}`，显式空租户头 400、缺省 `default`、按租户隔离）；完整复用 `/verify` 的变更流结构、锚点用途、签名格式、验签顺序及四类失败响应（HTTP 200 + `{"valid":false,"reason"}`），失败不写入；验真成功后以 `(租户, signer_did)` 为检查点键：首个非空页须 `after=0`，续页须等于已存 `next_after`；同 `after` 且 `changes` 递归键升序紧凑 UTF-8 JSON 字节相同为幂等重放，旧页/跳页/同位异内容均 409 且仅 `{"error":"同步游标冲突"}`；首个非空页 201、后续新页 200，重放或空页 200 且不推进；成功响应键序恰为 `valid,signer_did,next_after,accepted`，`valid=true`，新页 `accepted` 为 `events` 长度、重放或空页为 0；每个新页将原始 `events`、`changes` 规范化字节摘要与检查点原子落盘，存储失败全部回滚（检查点、页面、租户桶与临时容器均恢复到调用前，内存与重载状态一致，重试从原游标继续）并 500 仅返 `{"error":"存储失败"}`；并发同一检查点至多一项推进，其余按重放或冲突处理，重启后结论不变 |
| GET | `/v1/trust/anchor-changes/sync-history?signer_did=&limit=&after=` | 只读查询某签名方已落盘的锚点变更同步页历史：查询参数仅此三项且均只能出现一次，`signer_did` 必填非空，`limit` 缺省 50、须为 1–200 的 ASCII 十进制，`after` 缺省 0、须为 ASCII 非负整数；空值、重复、符号、Unicode 数字、越界或未知参数均 400 且仅 `{"error":非空中文}`；该签名方未接收非空页或跨租户均 404 同形；200 按键序恰返 `signer_did`、`pages`、`next_after`，`pages` 按来源 `next_after` 升序取 `next_after>after` 的前 `limit` 页，每页键序恰为 `after`、`next_after`、`digest`、`events`（前两项为非负整数且 `after<next_after`，`digest` 为 64 位小写 hex，`events` 为落盘原文，值、顺序与键序不变）；空页 `next_after` 等于 `after`，否则等于末页 `next_after`；纯只读、不推进检查点、不记审计，重启一致 |
| GET | `/v1/trust/anchor-changes/synced-state?signer_did=&at=&limit=&after=` | 只读查询某签名方已同步锚点变更在指定时点的汇聚状态视图：查询参数仅此四项且均只能出现一次，`signer_did` 必填非空，`at` 缺省取该签名方同步检查点、须为 ASCII 非负整数，`limit` 缺省 50、须为 1–200 的 ASCII 十进制，`after` 缺省 0、须为 ASCII 非负整数；空值、重复、未知参数、非 ASCII 数字、符号、越界或 `after>at` 均 400 且仅 `{"error":非空中文}`；该签名方未同步或跨租户 404 同形，`at` 超过检查点 409 同形；200 按键序恰返 `signer_did`、`at`、`anchors`、`next_after`（`at` 非负整数），取 `cursor<=at` 的已同步事件、以 `(did,key_version)` 末项为准，按 `last_cursor>after` 升序取 `limit` 项，每项键序恰为 `did`、`key_version`（正整数）、`public_key`、`status`（`active`/`revoked`）、`uses`（规范序字符串数组）、`last_action`、`last_cursor`（正整数）；空页 `next_after=after`，否则取末项 `last_cursor`；`at` 分页不受后续同步影响，重启逐字节一致；纯只读、不推进检查点、不写状态或审计，租户头缺省 `default`、显式空值 400 并隔离 |
| GET | `/v1/trust/ac-proof?cursor=&snapshot=&signer_did=` | 锚点变更 Merkle 包含证明（只读、不记审计）：查询参数仅允许唯一 `cursor`、`snapshot`、`signer_did`；`cursor`、`snapshot` 均为 ASCII 十进制**正整数**且 `cursor<=snapshot<=本租户最大游标`，`signer_did` 唯一非空；缺失/空值/重复/空白/符号/小数/布尔词/Unicode 数字/未知参数/越界（含 `cursor>snapshot`、`snapshot>最大游标`）均 400 且仅 `{"error":非空中文}`，显式空租户头 400、缺省 `default`、按租户隔离；签名 DID 沿用变更流入口判定（本租户活动本地 DID：未知含他租户 404、已停用 409）；`cursor` 事件在 snapshot 前缀内不存在 404。200 键序恰为 `event,snapshot,root,path,signer_did,signer_key_version,signature`；`event` 沿用变更流事件协议（键序 `cursor,action,did,key_version,public_key,status,uses`）；以 cursor 升序的 snapshot 前缀（`1<=cursor<=snapshot` 全部事件）建树，叶=`SHA-256(0x00||事件规范JSON的UTF-8)`（规范 JSON 为递归键升序紧凑 UTF-8），父=`SHA-256(0x01||左||右)`（左右为 32 字节原始摘要），奇数层末项复制；`root` 为 64 位小写 hex；`path` 自叶向根，每项键序恰为 `side,hash`，`side` 限 `left`/`right`（兄弟所在侧），`hash` 同为 64 位小写 hex，单叶 path 为空；`signature` 由签名 DID 当前版本私钥对前六键（`event,snapshot,root,path,signer_did,signer_key_version`）递归键升序紧凑 UTF-8 JSON 做 ES256（P-256+SHA-256）64 字节裸 `R||S` 无填充 base64url 签名；证明随状态文件重启稳定 |
| POST | `/v1/trust/ac-proof` | 校验锚点变更证明（**不依赖本地事件**、只读、不写状态/游标/审计）：请求体须恰含 `proof`（JSON 对象），否则 400 且仅 `{"error":非空中文}`（缺漏/多余键、非对象、非法 JSON/非对象、显式空租户头均同形，缺省 `default`、按租户隔离）；`proof` 须恰含 `event,snapshot,root,path,signer_did,signer_key_version,signature` 七键。外层合法后任何失败均 **HTTP 200** 按键序恰返 `{"valid":false,"reason"}`，顺序为“证明非法”（七键集合；`event` 沿用变更流事件协议含 cursor 正整数、action、非空 did、key_version 正整数、非空 public_key、status active/revoked、非空且规范序的合法 uses；snapshot/signer_key_version 为非布尔正整数且 `snapshot>=event.cursor`；root/hash 为 64 位小写 hex；path 为数组、项恰含 `side`(`left`/`right`) 与 `hash`；signer_did/signature 非空字符串）→“锚点不可用”（本租户同 signer_did/版本且含 generic 用途的 active 锚点；未知/他租户/吊销/无 generic/版本不符均属之）→“签名格式错误”（ES256 裸 `R||S` 无填充 base64url 严格格式）→“签名校验失败”（覆盖 proof 除 signature 外六键规范化 JSON 的密码学验签失败）→“包含证明校验失败”（按 path 自叶向根用 0x00 叶/0x01 父规则重算 root，与所声明 root 不一致）；成功仅 `{"valid":true}`；结论随状态文件重启稳定 |
| POST | `/v1/trust/ac-proof/verify-batch` | 批量校验锚点变更证明（**不依赖本地变更事件**、只读、不写状态/游标/审计）：请求体须恰为 `{"items":[证明...]}`，数组限 1–100 项；空体、非法 JSON、非对象、键集错误、`items` 非数组/空/超限均 **HTTP 200** 且按键序恰返 `{"results":[],"reason":"请求非法"}`；显式空租户头 400、缺省 `default`、按租户隔离。合法批次原子读取批初本租户信任锚点快照，逐项不短路，`results` 等长同序；并发吊销或用途收紧不得令同批观察到混合状态。每项须为 `POST /v1/trust/ac-proof` 中的 `proof` 对象（七键、字段类型、事件协议、Merkle 路径、ES256 裸 `R||S` 无填充 base64url 及签名覆盖范围均沿用该接口），逐项按证明结构、同 signer_did/版本且含 generic 用途的 active 快照锚点、签名格式、验签、路径重算顺序校验；成功项仅 `{"valid":true}`，失败项键序恰为 `valid`、`reason`，`reason` 恰为“证明非法”“锚点不可用”“签名格式错误”“签名校验失败”“包含证明校验失败”之一；顶层 HTTP 200 且仅含 `results` |
| POST | `/v1/trust/verify` | 信任验签，请求体含非空字符串 `issuer_did`、正整数 `issuer_key_version`、非空字符串 `signature`；**缺失、吊销或验签失败均 HTTP 200**，返回 `{"valid":false,"reason":...}`，成功 `{"valid":true}` |
| POST | `/v1/trust/credentials/verify` | 跨系统凭证验真：验证未在本租户签发或存储的外部凭证，无需登记 DID/凭证；请求体须恰含 `body`、`signature`；**任何失败均 HTTP 200**，返回 `{"valid":false,"reason":...}`，成功 `{"valid":true}` |
| POST | `/v1/trust/credentials/verify-synced` | 以同步锚点验真外部凭证（只读）：请求体恰含 `signer_did`（非空字符串）、`at`（非布尔非负整数）、`body`（对象）、`signature`（非空字符串）；非法 JSON、非对象、键集或类型错误均 **400** 且仅 `{"error":非空中文}`；`signer_did` 未同步或跨租户 **404**、`at` 超过同步检查点 **409**，同形仅 `{error}`；`body` 字段、规范化 JSON 签名与 `expires_at` 规则沿用 `/v1/trust/credentials/verify`（`issuer_key_version` 省略按 1 且不注入正文）；取该来源 `cursor<=at` 的已同步事件，以 `(issuer_did,版本)` 最后事件为锚点，缺失、非 active 或 `uses` 无 `vc` 均 **200** 按键序恰返 `{"valid":false,"reason":"同步锚点不可用"}`；签名须为 ES256、64 字节裸 `R||S` 无填充 base64url，格式错、验签错、到期同形依次返“签名格式错误”“签名校验失败”“凭证已过期”，凭证字段错误沿用既有“凭证”分类原因；成功仅 `{"valid":true}`；纯只读：不改同步页、检查点、锚点、凭证、状态或审计，重启一致；租户头缺省 `default`、显式空 400 并隔离 |
| POST | `/v1/trust/credentials/verify-synced-batch` | 批量以同步锚点快照验真外部凭证（只读）：请求体恰含 `signer_did`（非空字符串）、`at`（非布尔非负整数）、`credentials`（1–100 项数组）；空体、非法 JSON、非对象、键集或类型错误、空数组或超限均 **400** 且仅 `{"error":"请求非法"}`；来源未同步或跨租户 **404** 仅 `{"error":"同步来源不存在"}`，`at` 超过同步检查点 **409** 仅 `{"error":"同步游标冲突"}`；合法时 **200** 仅返 `{"results":[...]}`，逐项不短路、等长同序：项须恰含 `body`（对象）与非空 `signature`，否则该项 `{"valid":false,"reason":"请求项非法"}`；合法项沿用单条 `verify-synced` 的凭证字段、版本兼容、签名覆盖、有效期及校验顺序，按该来源 `cursor<=at` 的 `(DID,版本)` 末项验真，锚点缺失、非 active 或 `uses` 无 `vc` 为“同步锚点不可用”，格式、验签、过期依次为“签名格式错误”“签名校验失败”“凭证已过期”，字段错误以“凭证”开头；成功项仅 `{"valid":true}`，失败项键序 `valid`、`reason`；纯只读：不改同步页、检查点、锚点、凭证、状态或审计，重启一致；租户头缺省 `default`、显式空 400 并隔离 |
| POST | `/v1/trust/credentials/verify-synced-batch-with-status` | 批量以同步锚点快照验真外部凭证并合并批初本租户状态快照（只读）：请求级协议与 `verify-synced-batch` 完全一致，请求体恰含 `signer_did`（非空字符串）、`at`（非布尔非负整数）、`credentials`（1–100 项数组）；空体、非法 JSON、非对象、键集或类型错误、空数组或超限均 **400** 且仅 `{"error":"请求非法"}`；来源未同步或跨租户 **404** 仅 `{"error":"同步来源不存在"}`，`at` 超过同步检查点 **409** 仅 `{"error":"同步游标冲突"}`，均先于逐项校验；合法时 **200** 仅返 `{"results":[...]}`，逐项不短路、等长同序：项须恰含 `body`（对象）与非空 `signature`，否则该项 `{"valid":false,"reason":"请求项非法"}`；合法项沿用 `verify-synced-batch` 的凭证字段、版本兼容、`cursor<=at` 末锚点、签名、期限、顺序及原因；验真通过后按 `(issuer_did, credential_id)` 查批初原子读取的本租户状态快照：未同步、revoked、unknown 分别返“外部凭证状态未同步”“外部凭证已吊销：<reason>”（空原因用“未知原因”）“外部凭证状态未知”，active 成功；成功项仅 `{"valid":true}`，失败项键序 `valid`、`reason`；纯只读：不写状态或审计；租户头缺省 `default`、显式空 400 并隔离 |
| POST | `/v1/trust/credentials/verify-receipt` | 跨系统凭证验真签名回执（只读）：请求体恰含 `body`、`signature`、`verifier_did`、`nonce`（`verifier_did` 非空串，`nonce` 为 1–256 码点非空串）；非法 JSON、非对象、键集或两者非法均 **400** 仅 `{error}`；再依既有外部凭证验真全规则处理 `body`、`signature`，任一失败先 **200** 恰返 `{valid:false,reason}` 并沿用原原因、不查询验证者；仅成功才查本租户验证者 DID：未知或跨租户 **404**、停用 **409**，均仅 `{error}`；成功 **200** 按序恰返 `valid:true`、`receipt`、`receipt_signature`；`receipt` 按序恰含 `credential_id`、`issuer_did`、`issuer_key_version`、`credential_digest`、`verifier_did`、`verifier_key_version`、`nonce`，两版本为正整数，`credential_digest` 为 `{body,signature}` 递归键升序紧凑 UTF-8 JSON 的 SHA-256 小写 64 位 hex，`receipt_signature` 以验证者当前私钥按既有 ES256 裸 R\|\|S 无填充 base64url 规则签 `receipt`；不落盘、不审计；租户头缺省 `default`、空值 400 并隔离 |
| POST | `/v1/trust/credentials/receipt/consume` | 验真并消费跨系统凭证验真签名回执（防重放）：请求与字段约束同 `/v1/trust/credentials/receipt/verify`（恰含 `receipt`、`receipt_signature`、`body`、`signature`、`nonce`），外层非法 **400** 仅 `{error}`；外层合法后先按同一七阶段顺序验真，失败沿用原 **200** 固定 `reason` 及优先级且不写状态；验真成功后按租户以 `(verifier_did, nonce)` 为唯一键消费：首次 **200** 按序恰返 `valid:true`、`receipt_id`、`consumed_at`（`receipt_id` 为 `receipt` 规范化 JSON 字节的 SHA-256 小写 64 位 hex，`consumed_at` 为 UTC 秒精度 Z），同键重放（`receipt` 可不同）**200** 恰返 `{"valid":false,"reason":"回执已消费"}`，并发仅一次成功；首次消费与审计（`trust.credential.receipt.consumed` / `credential_receipt` / `receipt_id`）同一次原子落盘，重放与验真失败不记；落盘失败回滚二者，**500** 仅返 `{"error":"存储失败"}`，可重试，重启仍判重；租户头缺省 `default`、空值 400 并隔离 |
| POST | `/v1/trust/credentials/receipt/consume-batch` | 批量验真并消费跨系统凭证验真签名回执（防重放）：请求体恰为 `{"items":[项...]}`，数组非空且不超过 100 项；空体、非法 JSON、非对象、键集错误、`items` 非数组/空/超限均 **200** 按键序返 `{"results":[],"reason":"请求..."}`；合法批次逐项不短路，每项恰含 `receipt`、`receipt_signature`、`body`、`signature`、`nonce`（类型与 `nonce` 规则同单条），项结构非法返 `{"valid":false,"reason":"请求项非法"}`，其余复用单条七阶段顺序、`reason` 及优先级；验真通过后按租户 `(verifier_did, nonce)` 判重，批内首项成功，后项或历史重放返 `{"valid":false,"reason":"回执已消费"}`；成功项键序 `valid`、`receipt_id`、`consumed_at`，取值同单条，`results` 与输入等长同序；本批全部新消费与审计（`trust.credential.receipt.consumed` / `credential_receipt` / `receipt_id`）同锁一次原子落盘，失败全回滚，**500** 仅返 `{"error":"存储失败"}`；与单条 consume 并发每键仅一次成功，重启保持；租户头缺省 `default`、空值 400 并隔离 |
| GET | `/v1/trust/credentials/receipt/consumptions?limit=&after=&verifier_did=` | 只读查询本租户验真回执消费历史：查询参数仅允许 `limit`、`after`、`verifier_did` 且不得重复（未知、空值、重复均 400 仅返非空中文 `error`）；`limit` 缺省 50、限 1–200，`after` 缺省 0，二者须为非空 ASCII 十进制且 `after` 非负；`verifier_did` 可省略，提供时须非空；成功 **200** 按键序恰返 `events`、`next_after`，事件按键序恰含 `cursor`、`receipt_id`、`verifier_did`、`nonce`、`consumed_at`（依次为正整数与四个字符串，`consumed_at` 为 UTC 秒精度 Z）；先按 `verifier_did` 精确过滤，再取 `cursor>after` 的前 `limit` 项并按 `cursor` 升序，空页 `next_after=after`，否则为末项 `cursor`；首次消费按租户跨验证者分配持久递增 `cursor`，消费记录、消费历史、游标与既有审计原子落盘，重放或验真失败不追加，存储失败全部回滚，单条与批量并发仍每键仅一次成功；旧记录按 `consumed_at`、`verifier_did`、`nonce` 稳定补录、重启游标不变；纯只读、不写状态或审计；租户头缺省 `default`、显式空值 400 并隔离 |
| GET | `/v1/trust/credentials/receipt/consumptions/manifest?snapshot=&signer_did=&limit=&after=` | 只读生成验真回执消费历史导出的签名摘要清单：取 export 的 `limit`、`after`、`snapshot`（`snapshot` **必填**、显式提供且不得超过当时最大游标，越界/空值/重复/未知/格式或范围非法均 400 且仅 `{error}`；`after` 不得大于生效 `snapshot`）与唯一非空 `signer_did`；签名 DID 须为本租户**活动本地 DID**，未知（含他租户）404、已停用 409（400 判定优先）；不接受 `verifier_did` 等 export 之外的参数；200 键序恰为 `snapshot,filters,count,alg,digest,signer_did,key_version,signature`，`filters` 键序恰为 `after,limit`、值为生效整数（缺省 0/1000）；`count` 为本页非负整数行数，`alg` 恒为 `SHA-256`，`digest` 为同参数回执 NDJSON 页字节（与 export 同形状，空页零字节）的 64 位小写 hex SHA-256；`signature` 由签名 DID **当前私钥**按既有 ES256 裸 R\|\|S 无填充 base64url 规则签署前七键的规范化 JSON；纯只读、租户隔离，签名 ECDSA 字节每次可变但跨重启可验真 |
| POST | `/v1/trust/credentials/receipt/consumptions/manifest/verify` | 校验验真回执消费历史清单与其 NDJSON 导出内容：请求体须恰为 `{"manifest":对象,"ndjson":字符串}`；外层错误（非法 JSON/非对象、缺漏或多余字段、`manifest` 非对象、`ndjson` 非字符串）一律 **400** 且仅 `{"error":...}`。外层合法后任何失败均 **HTTP 200**，依次校验清单结构（`filters` 恰含非负 `after` 与 1–10000 的正整数 `limit`）、本租户同 `signer_did`/`key_version` 且**含 `vc` 用途**的 active 锚点、签名格式、密码学签名、UTF-8 字节 SHA-256 摘要及 LF 行数；失败返 `{"valid":false,"reason":...}`，`reason` 依次恰为“清单非法”“锚点不可用”“签名格式错误”“签名校验失败”“导出内容不匹配”，成功仅 `{"valid":true}`；纯只读、租户隔离、不记审计，结论跨重启稳定 |
| POST | `/v1/trust/dids/verify-document` | 跨系统 DID 文档验真：未在本租户注册的 DID 仅凭提交文档完成结构、证明与信任判断；请求体恰含 `document` 对象（恰含 `did`、`current_key_version`、`verification_methods`、`document_proof`）；**请求、字段、锚点、签名格式或验签失败均 HTTP 200** 返回 `valid:false` 与非空中文分类原因，成功仅 `{"valid":true}`；**原验真成功后查本租户外部 DID 停用通告**，命中同 did 返回 200 且键序 `valid,reason`，值为 `false`、“外部DID已停用：<reason>”，未命中维持原结果；纯只读、不登记资源、不写历史或审计 |
| POST | `/v1/trust/dids/verify-document-synced` | 以同步锚点快照验真外部 DID 文档（只读）：请求体恰含 `signer_did`（非空字符串）、`at`（非布尔非负整数）、`document`（对象）；空体、非法 JSON、非对象、键集或类型错误均 **400** 且仅 `{"error":"请求非法"}`；来源未同步或跨租户 **404** 仅 `{"error":"同步来源不存在"}`，`at` 超过同步检查点 **409** 仅 `{"error":"同步游标冲突"}`，均先于文档校验；文档四字段、验证方法升序无重、P-256 PEM、禁私钥、当前版本最高及 proof 覆盖规则沿用 `/v1/trust/dids/verify-document`；取该来源 `cursor<=at` 事件中 `(did,current_key_version)` 末项为锚点，缺失、非 active、`uses` 无 `did` 或公钥与文档当前版本不逐字相同均 **200** 返 `{"valid":false,"reason":"同步锚点不可用"}`；按文档、锚点、签名格式、验签、停用通告顺序，失败 reason 依次为“DID文档非法”“签名格式错误”“签名校验失败”，验签成功后命中本租户外部 DID 停用通告返“外部DID已停用：<reason>”，否则仅 `{"valid":true}`，失败键序 `valid`、`reason`；纯只读不审计；租户头缺省 `default`、显式空 400 并隔离 |
| POST | `/v1/trust/dids/verify-document-synced-batch` | 批量以同一同步锚点快照与停用通告快照验真外部 DID 文档（只读）：请求体恰含 `signer_did`（非空字符串）、`at`（非布尔非负整数）、`documents`（1–100 项数组）；空体、非法 JSON、非对象、键集或类型错误、空数组或超限均 **400** 且仅 `{"error":"请求非法"}`；来源未同步或跨租户 **404** 仅 `{"error":"同步来源不存在"}`，`at` 超过同步检查点 **409** 仅 `{"error":"同步游标冲突"}`，均先于项校验；合法时 **200** 仅返 `{"results":[...]}`，逐项不短路、等长同序：非对象项失败原因为“DID文档非法”，其余项沿用单条 `verify-document-synced` 的文档结构、`cursor<=at` 末锚点、ES256 proof 覆盖、校验顺序与停用判定，失败 `reason` 恰为“DID文档非法”“同步锚点不可用”“签名格式错误”“签名校验失败”或“外部DID已停用：<reason>”；成功项仅 `{"valid":true}`，失败项键序 `valid`、`reason`；批初原子读取同步视图与本租户停用通告，并发写入不造成批内混合结论；纯只读：不写数据、不推进检查点、不审计，重启一致；租户头缺省 `default`、显式空 400 并隔离 |
| POST | `/v1/trust/dids/deactivate-sync` | 登记外部 DID 停用通告：请求恰含 `body`、`signature`，`body` 恰含 `did`（非空串）、`key_version`（非布尔正整数）、`reason`（1–256 码点且首尾无空白）、`deactivated_at`（UTC 秒精度 Z）；结构或值非法 400 且仅含非空中文 `error`；用本租户同 did/版本 active P-256 锚点按既有规范化 JSON 与 ES256 裸 R||S 无填充 base64url 验签 body；锚点不可用、签名格式错、验签失败均 HTTP 200、键序 `valid,reason`，值为 `false` 及“锚点不可用”/“签名格式错误”/“签名校验失败”，且不写入；首次接受 201、完全重放 200、同 did 不同通告 409 仅 `{error}`；成功响应键序 `valid,did,key_version,reason,deactivated_at`，`valid:true`；按租户+did 原子持久化、失败回滚、重启稳定。**首次接受即与通告在同一次原子写中追加一条停用通告审计事件**（重放/冲突/锚点签名失败均不追加，批量逐项提交） |
| GET | `/v1/trust/dids/deactivations?limit=&after=&did=&key_version=&from=&to=` | 只读查询本租户外部 DID 停用通告审计事件：仅允许六参数且不得重复，空值/未知/格式或范围非法均 400 且恰返非空中文 `{"error":...}`；`limit` 缺省 50、为 1–200 的 ASCII 整数，`after` 缺省 0、为非负 ASCII 整数，`did` 非空，`key_version` 为 ASCII 正整数，`from`/`to` 为 UTC 秒精度 Z 时间且 `from≤to`；先按 `did`、`key_version` 精确过滤及 `deactivated_at` 闭区间过滤，再取 `cursor>after` 按 cursor 升序分页；200 键序 `events,next_after`，事件键序 `cursor,did,key_version,reason,deactivated_at`（整数/字符串/整数/字符串/字符串），空页 `next_after=after`，否则取页末 cursor；`cursor` 为租户内跨 DID 递增正整数，旧通告加载时按 `deactivated_at,did` 升序补录、重启不变；无结果仍 200，缺省 `default`、显式空租户头 400、仅返本租户事件 |
| GET | `/v1/trust/dids/deactivations/manifest?snapshot=&signer_did=&limit=&after=&did=&key_version=&from=&to=` | 只读生成停用通告导出的签名摘要清单：取 export 的七参数（`snapshot` **必填**、显式提供且不得超过当时最大游标，越界/空值/重复/未知/格式或范围非法均 400 且仅 `{error}`）与唯一非空 `signer_did`；签名 DID 须为本租户**活动本地 DID**，未知（含他租户）404、已停用 409（400 越界判定优先）；200 键序 `snapshot,filters,count,alg,digest,signer_did,key_version,signature`，`filters` 键序 `after,limit,did,key_version,from,to`、按序记录显式生效值、缺省项为 `null`；`count` 为本页非负整数行数，`alg` 恒为 `SHA-256`，`digest` 为本页 NDJSON 字节（与 export 同形状）的 64 位小写 hex SHA-256；`signature` 由签名 DID **当前私钥**按既有 ES256 裸 R||S 无填充 base64url 规则签署前七键的规范化 JSON；纯只读、租户隔离，签名 ECDSA 字节每次可变但跨重启可验真 |
| POST | `/v1/trust/dids/deactivations/manifest/verify` | 校验停用通告清单与其 NDJSON 导出内容：请求体须恰为 `{"manifest":对象,"ndjson":字符串}`；外层错误（非法 JSON/非对象、缺漏或多余字段、`manifest` 非对象、`ndjson` 非字符串）一律 **400** 且仅 `{"error":...}`。外层合法后任何失败均 **HTTP 200**，依次校验清单结构、本租户同 `signer_did`/`key_version` 的 **active 信任锚点**、签名格式、密码学签名、UTF-8 字节 SHA-256 摘要及行数；失败返 `{"valid":false,"reason":...}`，`reason` 依次恰为“清单非法”“锚点不可用”“签名格式错误”“签名校验失败”“导出内容不匹配”，成功仅 `{"valid":true}`；纯只读、租户隔离、不记审计，结论跨重启稳定 |
| POST | `/v1/trust/dids/deactivations/manifest/verify-batch` | 批量校验停用通告清单与 NDJSON（只读）：请求体恰为 `{"items":[项...]}`，数组非空且不超过 100 项，每项恰含 `manifest` 对象与 `ndjson` 字符串；**任何失败均 HTTP 200**——请求级非法（空体、非法 JSON、非对象、字段缺失或多余、`items` 非数组、空数组或超限）返回 `{"results":[],"reason":"请求..."}`，合法批次逐项沿用单项验真顺序（清单结构、本租户 active 锚点、签名格式、签名、摘要及行数）不短路返回等长同序 `{"results":[...]}`，成功项仅 `{"valid":true}`、失败项键序 `valid,reason`（五种原因之一，项结构非法按“清单非法”）；不写状态、历史或审计，结论跨重启稳定 |
| POST | `/v1/trust/presentations/verify` | 跨系统演示验真：验证其他系统生成且未在本租户保存的演示，无需登记 DID/凭证/演示；请求体须恰为 `{"presentation":对象,"challenge":非空串}`；**任何失败均 HTTP 200**，返回 `{"valid":false,"reason":...}`，成功 `{"valid":true}` |
| POST | `/v1/trust/presentations/verify-synced` | 以同步锚点验真未绑定外部演示（只读）：请求体恰含 `signer_did`（非空字符串）、`at`（非布尔非负整数）、`presentation`（对象）、`challenge`（非空字符串）；空体、非法 JSON、非对象、键集或类型错误均 **400** 且仅 `{"error":非空中文}`；`signer_did` 未同步或跨租户 **404**、`at` 超过同步检查点 **409**，同形仅 `{error}`；演示九字段、`challenge`、`expires_at`、`proof` 覆盖及“请求→演示→挑战→锚点→签名格式→验签→期限”顺序沿用 `/v1/trust/presentations/verify`（演示含 `holder_*` 字段即非法）；取该来源 `cursor<=at` 的已同步事件，以 `(issuer_did,版本)` 最后事件为锚点，缺失、非 active 或 `uses` 无 `vp` 均 **200** 按键序恰返 `{"valid":false,"reason":"同步锚点不可用"}`；proof 格式错、验签失败、到期同形依次返“签名格式错误”“签名校验失败”“演示已过期”，较早错误优先；成功仅 `{"valid":true}`；纯只读：不改同步页、检查点、锚点、演示、状态或审计，重启一致；租户头缺省 `default`、显式空 400 并隔离 |
| POST | `/v1/trust/presentations/verify-synced-batch` | 批量以同步锚点快照验真未绑定外部演示（只读）：请求体恰含 `signer_did`（非空字符串）、`at`（非布尔非负整数）、`presentations`（1–100 项数组）；空体、非法 JSON、非对象、键集或类型错误、空数组或超限均 **400** 且仅 `{"error":"请求非法"}`；来源未同步或跨租户 **404** 仅 `{"error":"同步来源不存在"}`，`at` 超过同步检查点 **409** 仅 `{"error":"同步游标冲突"}`，先于项校验；合法时 **200** 仅返 `{"results":[...]}`，逐项不短路、等长同序：项须恰含 `presentation`（对象）与非空 `challenge`，否则该项 `{"valid":false,"reason":"请求项非法"}`；合法项沿用单条 `verify-synced` 的未绑定九字段、`holder_*` 禁令、签名覆盖及“演示→挑战→锚点→格式→验签→期限”顺序，按该来源 `cursor<=at` 的 `(DID,版本)` 末项验真，锚点缺失、非 active 或 `uses` 无 `vp` 为“同步锚点不可用”，格式、验签、过期依次为“签名格式错误”“签名校验失败”“演示已过期”；成功项仅 `{"valid":true}`，失败项键序 `valid`、`reason`；纯只读：不改同步页、检查点、锚点、演示、状态或审计，重启一致；租户头缺省 `default`、显式空 400 并隔离 |
| POST | `/v1/trust/presentations/verify-synced-batch-with-status` | 批量以同步锚点快照验真未绑定外部演示并合并批初本租户状态快照（只读）：请求级协议与 `verify-synced-batch` 完全一致，请求体恰含 `signer_did`（非空字符串）、`at`（非布尔非负整数）、`presentations`（1–100 项数组）；空体、非法 JSON、非对象、键集或类型错误、空数组或超限均 **400** 且仅 `{"error":"请求非法"}`；来源未同步或跨租户 **404** 仅 `{"error":"同步来源不存在"}`，`at` 超过同步检查点 **409** 仅 `{"error":"同步游标冲突"}`，均先于逐项校验；合法时 **200** 仅返 `{"results":[...]}`，逐项不短路、等长同序：项须恰含 `presentation`（对象）与非空 `challenge`，否则该项 `{"valid":false,"reason":"请求项非法"}`；合法项沿用 `verify-synced-batch` 的 `holder_*` 禁令、挑战、`cursor<=at` 末锚点、proof 覆盖、签名、期限、顺序及原因；验真通过后按演示的 `(issuer_did, credential_id)` 查批初原子读取的本租户状态快照：未同步、revoked、unknown 分别返“外部凭证状态未同步”“外部凭证已吊销：<reason>”（空原因用“未知原因”）“外部凭证状态未知”，active 成功；成功项仅 `{"valid":true}`，失败项键序 `valid`、`reason`；纯只读：不写状态或审计；租户头缺省 `default`、显式空 400 并隔离 |
| POST | `/v1/trust/presentations/verify-batch` | 批量跨系统演示验真：请求体恰为 `{"presentations":[项...]}`，数组非空且不超过 100 项；每项可复用单项未绑定形态（恰含 `presentation` 对象与非空 `challenge`，演示不得含任何 `holder_*` 字段）或持有者绑定形态（另恰含非空 `source_tenant_id`，演示恰为九字段加 `holder_did`、`holder_key_version`、`holder_proof`，双锚点双签名，`source_tenant_id` 作为 holder proof 覆盖的 `tenant_id`）；**任何失败均 HTTP 200**，返回 `{"results":[...]}`（长度与顺序与输入一致，成功 `{"valid":true}`、失败 `{"valid":false,"reason":...}`，不短路）；请求级非法（缺失、非法 JSON、非对象、字段缺失或多余、presentations 非数组、空数组或超限）返回 `{"results":[],"reason":"请求..."}`；纯只读、不消费、不审计 |
| POST | `/v1/trust/proofs/verify` | 跨系统谓词证明验真：验证未在本租户保存的外部谓词证明，原本地 `/v1/proofs/{id}/verify` 不变；请求体须恰含 `proof`、`challenge`、`source_tenant_id`（后两项为非空字符串），proof 恰为 prove 九字段；**任何失败均 HTTP 200** 返回 `valid:false` 与分类中文 reason，成功仅 `{"valid":true}`；只读、不消费、不审计 |
| POST | `/v1/trust/proofs/verify-synced` | 以同步锚点验真外部谓词证明（只读）：请求体恰含 `signer_did`（非空字符串）、`at`（非布尔非负整数）、`proof`（对象）、`challenge`（非空字符串）、`source_tenant_id`（非空字符串）；空体、非法 JSON、非对象、键集或类型错误均 **400** 且仅 `{"error":非空中文}`；`signer_did` 未同步或跨租户 **404**、`at` 超过同步检查点 **409**，同形仅 `{error}`；证明九字段、谓词、results、`challenge`、`expires_at` 及“请求→证明→挑战→锚点→签名格式→验签→期限”顺序沿用 `/v1/trust/proofs/verify`；取该来源 `cursor<=at` 的已同步事件，以 `(issuer_did,版本)` 最后事件为锚点，缺失、非 active 或 `uses` 无 `proof` 均 **200** 按键序恰返 `{"valid":false,"reason":"同步锚点不可用"}`；proof 须为 ES256、64 字节裸 `R||S` 无填充 base64url，覆盖证明除 proof 外八字段并加入 `tenant_id=source_tenant_id` 的规范化 JSON，格式错、验签错、到期同形依次返“签名格式错误”“签名校验失败”“证明已过期”，较早错误优先；成功仅 `{"valid":true}`；纯只读：不改同步页、检查点、锚点、证明、状态或审计，重启一致；租户头缺省 `default`、显式空 400 并隔离 |
| POST | `/v1/trust/proofs/verify-synced-batch` | 批量以同步锚点快照验真外部谓词证明（只读）：请求体恰含 `signer_did`（非空字符串）、`at`（非布尔非负整数）、`proofs`（1–100 项数组）；空体、非法 JSON、非对象、键集或类型错误、空数组或超限均 **400** 且仅 `{"error":"请求非法"}`；来源未同步或跨租户 **404** 仅 `{"error":"同步来源不存在"}`，`at` 超过同步检查点 **409** 仅 `{"error":"同步游标冲突"}`，先于项校验；合法时 **200** 仅返 `{"results":[...]}`，逐项不短路、等长同序：项须恰含 `proof`（对象）、非空 `challenge`、非空 `source_tenant_id`，否则该项 `{"valid":false,"reason":"请求项非法"}`；合法项沿用单条 `verify-synced` 的证明九字段、谓词/results、RFC6901 路径、挑战、签名覆盖（除 proof 外八字段加 `tenant_id=source_tenant_id`）及“证明→挑战→锚点→格式→验签→期限”顺序，按该来源 `cursor<=at` 的 `(DID,版本)` 末项验真，锚点缺失、非 active 或 `uses` 无 `proof` 为“同步锚点不可用”，格式、验签、过期依次为“签名格式错误”“签名校验失败”“证明已过期”，较早错误优先；成功项仅 `{"valid":true}`，失败项键序 `valid`、`reason`；纯只读：不改同步页、检查点、锚点、证明、状态或审计，重启一致；租户头缺省 `default`、显式空 400 并隔离 |
| POST | `/v1/trust/proofs/verify-synced-batch-with-status` | 批量以同步锚点快照验真外部谓词证明并合并批初本租户状态快照（只读）：请求级协议与 `verify-synced-batch` 完全一致，请求体恰含 `signer_did`（非空字符串）、`at`（非布尔非负整数）、`proofs`（1–100 项数组）；空体、非法 JSON、非对象、键集或类型错误、空数组或超限均 **400** 且仅 `{"error":"请求非法"}`；来源未同步或跨租户 **404** 仅 `{"error":"同步来源不存在"}`，`at` 超过同步检查点 **409** 仅 `{"error":"同步游标冲突"}`，均先于逐项校验；合法时 **200** 仅返 `{"results":[...]}`，逐项不短路、等长同序：项须恰含 `proof`（对象）、非空 `challenge`、非空 `source_tenant_id`，否则该项 `{"valid":false,"reason":"请求项非法"}`；合法项沿用 `verify-synced-batch` 的证明九字段、谓词/results、RFC6901 路径、挑战、`cursor<=at` 末锚点、签名覆盖、签名、期限、顺序及原因；验真通过后按证明的 `(issuer_did, credential_id)` 查批初原子读取的本租户状态快照：未同步、revoked、unknown 分别返“外部凭证状态未同步”“外部凭证已吊销：<reason>”（空或缺失 reason 用“未知原因”）“外部凭证状态未知”，active 成功；成功项仅 `{"valid":true}`，失败项键序 `valid`、`reason`；纯只读：不写同步页、检查点、锚点、证明、状态、历史或审计；租户头缺省 `default`、显式空 400 并隔离，重启一致 |
| POST | `/v1/trust/proofs/verify-batch` | 批量跨系统谓词证明验真：请求体恰为 `{"proofs":[项...]}`，数组非空且不超过 100 项，每项规则与单项验真一致；**任何失败均 HTTP 200**，返回 `{"results":[...]}`（长度与顺序与输入一致，成功 `{"valid":true}`、失败 `{"valid":false,"reason":...}`，不短路）；请求体非法、空数组或超上限时返回 `{"results":[],"reason":"请求..."}`；只读、不消费、不审计 |
| POST | `/v1/trust/proofs/verify-with-status` | 外部谓词证明验真并合并同步状态（只读）：请求体与验真规则同 `/v1/trust/proofs/verify`；**任何验真失败均 HTTP 200** 返回 `valid:false` 与中文 `reason`；验真通过后按本租户 `(issuer_did, credential_id)` 查同步记录：未同步 `valid:false`/“外部凭证状态未同步”，active 仅 `{"valid":true}`，revoked 为“外部凭证已吊销：<reason>”（无 reason 用“未知原因”），unknown 为“外部凭证状态未知”；不消费、不登记资源、不写状态/历史/审计 |
| POST | `/v1/trust/proofs/verify-batch-with-status` | 批量外部谓词证明验真并合并同步状态（只读）：请求体恰为 `{"proofs":[项...]}`，数组非空且不超过 100 项；请求级非法（缺失、非法 JSON、非对象、字段缺失或多余、proofs 非数组、空数组或超限）统一 HTTP 200 返回 `{"results":[],"reason":"请求..."}`；合法批次逐项复用 `/v1/trust/proofs/verify-with-status` 规则（含同步状态合并），按输入顺序不短路返回 `{"results":[...]}`，成功 `{"valid":true}`、失败 `{"valid":false,"reason":...}`；不消费、不登记资源、不写状态/历史/审计 |
| POST | `/v1/trust/credentials/verify-batch` | 批量跨系统凭证验真：请求体恰为 `{"credentials":[项...]}`，数组非空且不超过 100 项，每项规则与单项验真一致；**任何失败均 HTTP 200**，返回 `{"results":[...]}`（长度与顺序与输入一致，成功 `{"valid":true}`、失败 `{"valid":false,"reason":...}`，不短路）；请求体非法、空数组或超上限时返回 `{"results":[],"reason":"请求..."}` |
| POST | `/v1/trust/credentials/verify-with-status` | 外部凭证验真并合并同步状态（只读）：请求体与验真规则同 `/v1/trust/credentials/verify`；**任何验真/过期失败均 HTTP 200** 返回 `valid:false` 与中文 `reason`；验签通过后按本租户 `(issuer_did, credential_id)` 查同步记录：未同步 `valid:false`/“外部凭证状态未同步”，active 仅 `{"valid":true}`，revoked 为“外部凭证已吊销：<reason>”（无 reason 用“未知原因”），unknown 为“外部凭证状态未知”；不创建凭证、不改状态、不写同步记录或审计 |
| POST | `/v1/trust/credentials/verify-batch-with-status` | 批量外部凭证验真并合并同步状态（只读）：请求体恰为 `{"credentials":[项...]}`，数组非空且不超过 100 项；请求级非法（缺失、非法 JSON、非对象、字段缺失或多余、credentials 非数组、空数组或超限）统一 HTTP 200 返回 `{"results":[],"reason":"请求..."}`；合法批次逐项复用 `/v1/trust/credentials/verify-with-status` 规则（含同步状态合并），按输入顺序不短路返回 `{"results":[...]}`，成功 `{"valid":true}`、失败 `{"valid":false,"reason":...}`；不写凭证、状态、历史或审计 |
| POST | `/v1/trust/credentials/import` | 导入并持久化外部凭证：请求体须恰含 `body`、`signature`，`body` 规则同 `/v1/trust/credentials/verify`（必含 `credential_id`/`issuer_did`/`subject_did`/`claims`/`issued_at`，可省略 `issuer_key_version`）；请求/字段非法 400 仅 `{error}`；锚点缺失/非 active、签名格式错、验签失败、凭证过期均 HTTP 200 `{"valid":false,"reason":...}`（非空中文）且不写入；首次按 `tenant+issuer_did+credential_id` 保存 201，键序 `imported,issuer_did,credential_id,body,signature` 且 `imported:true`；相同内容重放 200 返回原响应，不同内容 409 仅 `{error}` |
| GET | `/v1/trust/credentials/imported/{credential_id}?issuer_did=...` | 读取已导入的外部凭证原文；`issuer_did` 须唯一非空，缺失/重复/空值 400；未导入、跨租户或 `issuer_did` 不匹配 404；成功 200 键序 `issuer_did,credential_id,body,signature`；纯只读、不记审计，重启后可读 |
| POST | `/v1/trust/credentials/imported/{credential_id}/verify?issuer_did=...` | 重启后重新验证已落盘凭证；请求体须恰为 `{}`，`issuer_did` 须唯一非空，缺失/重复/空值、非法 JSON、非对象或请求体不恰为 `{}` 均 400；未导入、错配或跨租户 404；取存储 body/signature 原文（`issuer_key_version` 缺省按 1）以同 DID/版本 active 锚点做 ES256 验签；锚点缺失或吊销、签名格式错、验签失败、凭证过期均 HTTP 200 返回 `{"valid":false,"reason":...}`（原因恰为“锚点不可用”/“签名格式错误”/“签名校验失败”/“凭证已过期”），成功仅 `{"valid":true}`；纯只读、不写记录/状态/历史/审计，重启及锚点吊销后结论稳定 |
| POST | `/v1/trust/credentials/imported/{credential_id}/verify-with-status?issuer_did=...` | 重验已导入凭证并合并本租户同步状态（只读）：请求级规则（`issuer_did` 唯一非空、请求体恰为 `{}`、400/404 协议）与上一行单项重验完全一致，验签规则同样复用存储 body/signature（`issuer_key_version` 缺省按 1）；锚点不可用、签名格式错、验签失败、凭证过期均 HTTP 200 返回 `{"valid":false,"reason":...}`（同四个固定原因）；重验通过后按本租户 `(issuer_did, credential_id)` 查同步记录：未同步 `valid:false`/“外部凭证状态未同步”，active 仅 `{"valid":true}`，revoked 为“外部凭证已吊销：<reason>”（空或缺失 reason 固定“未知原因”），unknown 为“外部凭证状态未知”；失败响应键序固定 `valid,reason`；纯只读、不写记录/状态/历史/审计，重启及租户隔离结论稳定 |
| POST | `/v1/trust/credentials/imported/verify-batch-with-status` | 批量重验已导入凭证并合并本租户同步状态（只读）：请求体恰为 `{"items":[项...]}`，每项恰含非空字符串 `issuer_did`、`credential_id`，数组非空且不超过 100 项；请求级非法（缺失、非法 JSON、非对象、字段缺失或多余、`items` 非数组·空·超限）统一 HTTP 200 返回 `{"results":[],"reason":"请求..."}`；合法批次等长同序返回 `{"results":[...]}`，每项键序固定 `valid,http_status,reason`：项非法为 `false,400,"请求项非法"`，记录不存在或跨租户为 `false,404,"资源不存在"`，锚点缺失/吊销、签名格式错、验签失败、过期为 `false,200,<单项重验同因>`；重验成功后只读合并同步状态——未同步 `false,200,"外部凭证状态未同步"`，active `true,200,null`，revoked `false,200,"外部凭证已吊销：<reason>"`（空原因用“未知原因”），unknown `false,200,"外部凭证状态未知"`；不写记录/状态/历史/审计，重启结论稳定 |
| POST | `/v1/trust/credential-status/sync` | 外部凭证状态同步：请求体须恰含 `body`、`signature`，`body` 须恰含 `issuer_did`、`credential_id`、`status`、`updated_at`、`issuer_key_version`，可选 `reason`；请求/字段非法 400；锚点或签名失败 HTTP 200、`valid:false` 且不写入；首次同步 201、相同重放 200 不重复审计、严格更新替换、同时间不同内容 409 |
| POST | `/v1/trust/credential-status/sync-batch` | 批量外部凭证状态同步：请求体须恰含 `items`（数组 1–100 项），逐项复用单项规则、失败不短路；请求级非法（缺失/非法 JSON/非对象/字段缺失多余/`items` 非数组·空·超限）返 HTTP 200 `{"results":[],"reason":"请求..."}`；失败项键序 `valid,http_status,reason`（字段错 400、同秒冲突 409、锚点/签名失败 200），成功项键序 `valid,http_status,issuer_did,credential_id,status,reason,updated_at,issuer_key_version`（首次 201、重放/更早 200、更晚 200 并记审计），`results` 与输入等长同序 |
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
# 吊销旧密钥版本（须先轮换；空体省略 reason）
curl -X POST localhost:8080/v1/dids/did:example:<id>/keys/1/revoke \
  -d '{"reason":"旧版本密钥疑似泄漏"}'
# 查询密钥版本吊销状态与吊销历史（只读）
curl localhost:8080/v1/dids/did:example:<id>/keys/1/status
curl "localhost:8080/v1/dids/did:example:<id>/keys/revocations?limit=50&after=0"
curl "localhost:8080/v1/dids/did:example:<id>/keys/history?limit=50&after=0"
curl localhost:8080/v1/dids/did:example:<id>/document
curl "localhost:8080/v1/dids/did:example:<id>/document?version=1"
curl -X POST localhost:8080/v1/credentials \
  -d '{"issuer_did":"did:example:<a>","subject_did":"did:example:<b>","claims":{"role":"admin"}}'
# 可选有效期（UTC 秒精度 Z，且必须晚于当前时刻）
curl -X POST localhost:8080/v1/credentials \
  -d '{"issuer_did":"did:example:<a>","subject_did":"did:example:<b>","claims":{"role":"admin"},"expires_at":"2030-01-01T00:00:00Z"}'
curl localhost:8080/v1/credentials/vc_<id>
curl -X PUT localhost:8080/v1/credentials/vc_<id>/status \
  -d '{"status":"active"}'
curl -X PUT localhost:8080/v1/credentials/vc_<id>/status \
  -d '{"status":"suspended","reason":"违规调查中"}'   # 暂停（恢复再 PUT active）
curl localhost:8080/v1/credentials/vc_<id>/status
curl -X POST localhost:8080/v1/credentials/vc_<id>/revoke \
  -d '{"reason":"持证人造假"}'   # reason 可省略
curl -X POST localhost:8080/v1/credentials/vc_<id>/verify \
  -d '{"body":{...},"signature":"..."}'
curl -X POST localhost:8080/v1/credentials/vc_<id>/present \
  -d '{"disclose":["/role","/addr/city"]}'   # [] 为零披露；可附 challenge/expires_in
# 可选持有者绑定：holder_binding 为 true 时 subject_did 须为本租户已注册 DID，
# 响应另含 holder_did、holder_key_version、holder_proof
curl -X POST localhost:8080/v1/credentials/vc_<id>/present \
  -d '{"disclose":["/role"],"holder_binding":true}'
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
  与整数 `issuer_key_version`（签发时签发者的当前密钥版本，随正文一起签名）；
  当且仅当请求提供 `expires_at` 时，正文还包含 `expires_at`（UTC 秒精度
  Z 格式），一并参与规范化签名，未提供时不注入该字段（旧凭证无期限）。
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

### 凭证有效期

- `POST /v1/credentials` 在原有 `issuer_did`、`subject_did`、`claims`
  之外接受**可选** `expires_at`：
  - 未提供时正文**不含**该字段，凭证无期限，行为与旧凭证完全一致；
  - 提供时必须是 **UTC 秒精度 Z 格式** `YYYY-MM-DDTHH:MM:SSZ`
    （不接受毫秒/小数秒、时区偏移、空格分隔、缺 `Z`、未补零或非法
    时刻），且必须**严格晚于服务接收时刻**；格式或时刻非法、等于或
    早于当前时间一律 **400** 并在 `error` 中说明。
  - 提供时 `expires_at` 按原文写入凭证正文并参与 ES256 规范化签名，
    对它的任何篡改都会使验签失败；`GET /v1/credentials/{id}` 原样
    返回，签发响应字段保持 `credential_id`、`signature`、
    `issuer_key_version` 三项不变。
- `POST /v1/credentials/{id}/verify` 在**请求、资源、锚定与签名均成功**
  后检查有效期：当前时间大于等于 `expires_at` 时返回 **HTTP 200**、
  `{"valid":false,"reason":"凭证已过期"}`；未到期保持 `valid:true`；
  无 `expires_at` 的旧凭证无期限。请求/资源/锚定/签名等其余失败仍
  **优先返回原分类原因**（如正文被篡改仍返回“签名校验失败…”）。
  过期判定为**只读**操作，**不记审计**。
- 选择性披露演示与谓词证明的 `verify`：在自身绑定与签名校验均成功后，
  若其底层凭证已到期，同样返回 **HTTP 200**、`valid:false`、
  `reason`“凭证已过期”，且**不消费、不记消费审计**；它们的生成接口
  （`present`/`prove`）协议不变（仍可对已到期凭证生成，由 verify 兜底）。
- `POST /v1/trust/credentials/verify` 验证外部凭证时，若请求 `body`
  **含** `expires_at`：必须为同样的 UTC 秒精度 Z 格式（非法返回
  200/`valid:false`，原因为“凭证字段 expires_at …”），并在到期时
  返回 200/`{"valid":false,"reason":"凭证已过期"}`；签名等先置校验
  失败仍优先返回各自原因；`body` 不含该字段时保持兼容（无期限）。
  该判定同样只读、不写状态、不记审计。
- `expires_at` 随凭证记录在状态文件中持久化，**重启后结论一致**。

### 凭证状态与吊销

- `PUT .../status` 请求体必须**恰为** `{"status":"active"}` 或
  `{"status":"suspended","reason":"原因"}`：缺失 `status`/`reason`、
  取值非法、active 携带 `reason` 等多余字段、请求体缺失/非法 JSON/非对象
  一律 400 并返回非空 `error`。`reason` 须为字符串且首尾裁剪后为
  **1–256 个 Unicode 码点**（空白串、超长均 400），保存裁剪后的值。
  - **无状态→active** 首次登记返回 **201**；**无状态→suspended** 直接
    暂停返回 **200**；**active/无状态→suspended**、**suspended→active**
    （恢复）均为状态变更 **200**；
  - **同状态幂等**：active→active 与 suspended→suspended 同原因返回
    **200**，保持首次 `updated_at` 不变；**suspended→suspended 不同
    原因**返回 **409** 与非空 `error`；
  - 所有成功路径（含幂等）均返回 `credential_id`、`status`、`updated_at`
    三个键（暂停/恢复均记 `status.updated` 审计；幂等不追加历史）；
  - **revoked 为终态**：已吊销凭证再 PUT 任意状态（active/suspended）
    均 **409**，状态与时间字段保持不变。
- `GET .../status` 返回 `credential_id`、`status`、`updated_at`；历史无状态
  凭证按 `active` 返回、`updated_at` 为 `null`；未知凭证或他租户凭证 404。
- `POST .../revoke`：未知凭证 404。首次请求可省略 `reason`（空请求体或
  `{}` 均可），默认“持证人主动吊销”；提供时必须是字符串且首尾裁剪后非空
  （显式 `null`、数字、空白串均为 400）。保存并返回裁剪后的值，成功为 200，
  返回 `credential_id`、`status:"revoked"`、`reason`、`revoked_at`、
  `updated_at`。已吊销时再次调用，任何 `reason`（含非法值）都被忽略并返回
  首次结果；非法 `reason` 仅首次请求返回 400。已暂停凭证可直接吊销进入
  终态（暂停原因随之清除，状态历史仍保留暂停/恢复事件）。
- 状态随状态文件持久化，**跨重启保留**。
- verify 在签名、密钥、DID、有效期检查均通过后检查凭证状态（判定位置与
  吊销相同）：`suspended` 返回 200、
  `{"valid":false,"reason":"凭证已暂停：<保存的 reason>"}`，**不消费**
  演示/证明、不记审计，恢复后即可正常使用；`revoked` 返回
  `{"valid":false,"reason":"凭证已吊销：<保存的 reason>"}`；过期优先于
  暂停/吊销，`active` 或无状态维持原结果（签名失败仍优先返回签名类原因）。
- present / present-batch / prove 对已暂停凭证返回 **409** 与非空
  `error`，不创建演示/证明、不记审计；恢复后可正常生成。已吊销凭证仍
  沿用“可生成、验签处拒绝”的既有行为。

#### 凭证状态历史（只读）

`GET /v1/credentials/{credential_id}/status/history` 只读返回本租户
签发凭证的状态变更历史，与签发、验签、状态登记与吊销协议完全兼容。

- 未知凭证或访问他租户凭证一律 **404**（跨租户不可探测）；显式空
  `X-Tenant-ID` 为 **400**。凭证在本租户已存在但从未登记状态时返回
  **空页**（`events:[]`、`next_after` 取 `after`），不因此 404。
- 200 响应恰含 `credential_id`、`events`、`next_after`。`events` 按
  **`updated_at` 升序**，同一 `updated_at` 按 **`cursor`** 升序；每项
  恰含 `status`、`reason`、`updated_at`、`revoked_at`、`audit_seq`、
  `audit_timestamp`、`cursor`：
  - **首次 active 登记**（无状态 `PUT .../status` 首次 201）追加一条
    `status:"active"` 事件，`reason`/`revoked_at` 均为 `null`，
    `updated_at` 为首次登记时间（UTC 秒精度 Z）；
  - **暂停**（active/无状态→suspended，200）追加一条
    `status:"suspended"` 事件，`reason` 为裁剪后 1–256 码点的暂停原因，
    `revoked_at` 为 `null`；
  - **恢复**（suspended→active，200）追加一条 `status:"active"` 事件，
    `reason`/`revoked_at` 均为 `null`；
  - **首次 revoke** 追加一条 `status:"revoked"` 事件，`reason` 为
    裁剪后的吊销原因，`revoked_at`/`updated_at` 为首次吊销时间
    （UTC 秒精度 Z，二者相同）；
  - 重复 active 登记（200）、同状态同原因幂等暂停（200，每次仍记审计）、
    重复吊销（每次仍记审计）与任何失败路径（首次非法 reason 400、未知
    凭证 404、同状态不同原因 409、已吊销再变更 409）均**不追加**；
  - 未先登记 active 直接吊销时历史仅含一条 revoked 事件；未先登记
    active 直接暂停时历史以 suspended 事件开始。
- `audit_seq`/`audit_timestamp` **关联产生该状态变更的审计事件**
  （active/suspended/恢复均为 `status.updated`、revoke 为
  `credential.revoked`，`resource_type` 均为 `credential`）；旧状态补录
  的兼容项无法追溯时两者均为 `null`，仍照常返回与分页。
- `cursor` 为**租户内持久化正整数**：同一租户内不同凭证的状态事件
  共享同一游标空间，按追加顺序单调递增并跨重启稳定；不同租户各自
  从 1 计起。
- `limit` 缺省 **50**，须为 **1–200** 的 ASCII 十进制整数；`after`
  缺省 **0**，须为**非负** ASCII 十进制整数。二者均**只能出现一次**
  且须为**非空 ASCII 数字**：重复参数、空白、布尔词、小数、符号、
  Unicode 数字等一律 **400**。`after` 排除 `cursor` 不大于其值的事件，
  `next_after` 为本页末项的 `cursor`，**空页等于 `after`**。
- **旧状态兼容**：旧版本状态文件中凭证已有状态（active/revoked）但
  无状态历史时，加载时按（租户、credential_id）稳定顺序为每个缺
  历史的凭证补一条兼容事件，内容取自状态行（active 的
  reason/revoked_at 为 `null`，revoked 保存裁剪 reason 与 revoked_at），
  `cursor` 为该租户内新分配的持久化正整数，`audit_seq`/`audit_timestamp`
  为 `null`；兼容项随下一次原子写一并落盘，即使加载后无写操作，重启
  时也按相同顺序重建为**相同 cursor**。
- 首次 active / 首次暂停 / 恢复 / 首次 revoke 时，**状态、历史、游标与
  审计事件在同一把锁内经同一次原子写落盘，落盘失败一并回滚**（状态不变、
  历史不追加、游标不前进、审计不记录）。该历史接口为纯只读查询，**不记
  审计**、不触发落盘，`GET .../status`、签发、验签与吊销的幂等响应
  均保持不变。

```bash
curl -X PUT localhost:8080/v1/credentials/vc_<id>/status -d '{"status":"active"}'
curl -X PUT localhost:8080/v1/credentials/vc_<id>/status -d '{"status":"suspended","reason":"违规调查中"}'
curl -X PUT localhost:8080/v1/credentials/vc_<id>/status -d '{"status":"active"}'
curl -X POST localhost:8080/v1/credentials/vc_<id>/revoke -d '{"reason":"持证人造假"}'
curl "localhost:8080/v1/credentials/vc_<id>/status/history?limit=50&after=0"
```

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

### 密钥版本吊销

`POST /v1/dids/{did}/keys/{key_version}/revoke` 吊销某 DID 的一个**历史**
密钥版本（当前版本须先轮换再吊销）。吊销只影响后续验真结论，被吊销版本
仍保留在 DID 文档历史与 `key_history` 中，已用该版本签发的凭证/演示/证明
签名仍可按历史公钥验签，但验签通过后会被密钥吊销判定拦截。

- 路径 `key_version` 须为 **ASCII 十进制正整数**：空值、`0`、符号
  （`-1`/`+1`）、小数、空白、布尔词、字母或 Unicode 数字一律 **400**。
- DID 不存在或该版本不在其密钥历史中（**含访问他租户资源**）一律
  **404**（跨租户不可探测）；吊销**当前版本**返回 **409** 与非空 `error`。
- 请求体：空体或 `{}` 表示省略 `reason`（默认“密钥版本主动吊销”）；
  非空时必须**恰含** `reason`，多余字段 400；`reason` 提供时必须为字符串
  且首尾裁剪后非空（显式 `null`、数字、空白串均 400），保存并返回裁剪后
  的值。非法 `reason` 仅首次请求返回 400：已吊销版本再次调用时任何
  `reason`（含非法值）都被忽略并返回首次结果。
- 旧版本**首次**吊销成功 **200**，返回字段恰为 `did`、`key_version`、
  `status:"revoked"`、`reason`、`updated_at`（UTC 秒精度 Z）；重复吊销
  同样 200 并返回首次的 `reason`/`updated_at`（每次重复都记审计）。
- 审计：首次与幂等重试均记 **`key.revoked`**（`resource_type` 为 `did`、
  `resource_id` 为 `<did>#<key_version>`）；400/404/409 等失败路径不记。
  吊销标记与审计在同一把锁内经**同一次原子写**落盘，失败回滚（版本不
  变更、事件不记录），**重启保留**。
- 轮换仍可正常进行，新版本照常签发；被吊销的是历史版本，不影响当前版本
  与后续轮换。
- 吊销版本对验真类端点（均为只读、不记审计）的影响，检查顺序为：
  - `POST /v1/credentials/{id}/verify`：验签成功后按**签发密钥 → 有效期
    → 凭证吊销**判定。签发密钥版本已吊销时返回 200、
    `{"valid":false,"reason":"签发密钥已吊销：<reason>"}`。
  - 演示 verify：按 **issuer proof 验签 → 签发密钥 → holder proof 验签 →
    持有者密钥**顺序，分别返回“签发密钥已吊销：…”或
    “持有者密钥已吊销：…”；**已消费（“演示已消费”）与演示自身过期
    （“演示已过期”）优先**于密钥吊销；密钥吊销失败**不消费**，并在
    消费锁内复查以防竞态。
  - 谓词证明 verify：验签成功后查**签发密钥**版本，已吊销返回
    “签发密钥已吊销：…”，失败不消费。
  - 以上判定均在密码学验签成功之后：签名/锚定失败仍优先返回各自原因。
- `present`/`prove` 生成时若凭证的签发密钥版本已吊销，或持有者绑定版本
  已吊销，返回 **400** 且**不留任何记录/审计**。
- 旧凭证正文缺 `issuer_key_version` 时按版本 1 兼容判定；密钥吊销按租户
  隔离，跨租户不可探测。

#### 密钥版本状态与吊销历史（只读）

`GET /v1/dids/{did}/keys/{key_version}/status` 与
`GET /v1/dids/{did}/keys/revocations` 为密钥吊销提供只读查询，均
**不记审计**、不触发落盘，租户规则与其他 `/v1` 接口一致。

**单版本状态：**

- 路径 `key_version` 须为 **ASCII 十进制正整数**：空值、`0`、符号
  （`-1`/`+1`）、小数、空白、布尔词、字母或 Unicode 数字一律 **400**。
- DID 不存在或该版本不在其密钥历史中（**含访问他租户资源**）一律
  **404**（跨租户不可探测）。
- 200 响应恰含 `did`、`key_version`、`status`、`reason`、`updated_at`：
  - 未吊销版本 `status:"active"`，`reason`/`updated_at` 均为 `null`
    （当前版本与旧版本一致）；
  - 已吊销版本 `status:"revoked"`，`reason`/`updated_at` 为**首次**
    吊销的裁剪原因与 UTC 秒精度 Z 时间，重复吊销不改变其值。

**吊销历史：**

- 响应恰含 `did`、`events`、`next_after`；`events` 按 `cursor` 升序，
  每项恰含 `key_version`、`reason`、`updated_at`、`cursor`。
- **仅首次成功吊销追加**事件；重复吊销（每次仍记审计）与任何失败路径
  （400/404/409）均不追加。
- `cursor` 为**租户内持久化正整数**：同一租户内不同 DID 的吊销事件
  共享同一游标空间，按追加顺序单调递增并跨重启稳定。
- `limit` 缺省 **50**，须为 **1–200** 的 ASCII 十进制整数；`after`
  缺省 **0**，须为**非负** ASCII 十进制整数。二者均**只能出现一次**
  且须为**非空 ASCII 数字**：重复参数、空白、布尔词、小数、符号、
  Unicode 数字等一律 **400**。
- `after` 排除 `cursor` 不大于其值的事件，`next_after` 为本页末项的
  `cursor`，**空页等于 `after`**。
- DID 在本租户已存在但从未吊销时返回**空页**（`events:[]`、
  `next_after` 取 `after`）；未知 DID 或访问他租户 DID 返回 **404**。
- **旧状态兼容**：旧版本状态文件中密钥版本已吊销（key_history 条目标记）
  但无吊销历史时，加载时按（租户、DID、版本）稳定顺序为每个缺历史的
  吊销版本补一条兼容事件，内容取自吊销标记，`cursor` 为该租户内新分配
  的持久化正整数；兼容项随下一次原子写一并落盘，即使加载后无写操作，
  重启时也按相同顺序重建为**相同 cursor**。
- 首次吊销时**吊销标记、历史事件与原审计事件**在同一把锁内经**同一次
  原子写**落盘，落盘失败一并回滚（版本状态不变、历史不追加、游标不
  前进、审计不记录）。DID 文档、密钥历史、吊销的幂等响应及验真优先级
  均保持不变。

```bash
curl localhost:8080/v1/dids/did:example:<id>/keys/1/status
curl "localhost:8080/v1/dids/did:example:<id>/keys/revocations?limit=50&after=0"
curl "localhost:8080/v1/dids/did:example:<id>/keys/history?limit=50&after=0"
```

#### 密钥生命周期历史（只读）

`GET /v1/dids/{did}/keys/history` 只读返回某 DID 各密钥版本的完整
生命周期（创建/轮换/吊销），与注册、轮换、吊销协议完全兼容，游标空间
与 `keys/revocations` 吊销历史**相互隔离**。

- 租户规则与其他 `/v1` 接口一致：缺省 `default`，显式空
  `X-Tenant-ID` 为 **400**；未知 DID 或访问他租户 DID 一律 **404**
  （跨租户不可探测）。
- 200 响应**恰含** `did`、`events`、`next_after`；`events` 按
  **`cursor` 升序**，每项**恰含** `key_version`、`key_handle`、
  `public_key`、`action`、`status`、`updated_at`、`audit_seq`、
  `audit_timestamp`、`cursor`：
  - **新建版本追加 active**：版本 1 的 `action` 为 `did.created`，
    `updated_at` 取 DID 的 `created_at`；轮换产生的新版本 `action` 为
    `key.rotated`，`updated_at` 取**轮换成功时刻**（UTC 秒精度 Z）；
  - 版本**首次吊销追加**一条 `action:"key.revoked"`、
    `status:"revoked"` 事件，`updated_at` 为首次吊销时间，与吊销标记、
    吊销历史事件**同秒**；
  - `key_handle`/`public_key` 为该版本注册时的句柄与 P-256 公钥 PEM，
    **绝不包含私钥**（响应任何位置不出现私钥 PEM）；
  - `audit_seq`/`audit_timestamp` **关联产生该事件的审计动作**
    （`did.created`/`key.rotated`/`key.revoked`），`audit_timestamp`
    为该审计事件的 Unix 秒，且与 `updated_at` 为**同一秒**；旧状态补录
    的兼容项二者均为 `null`。
- **重复、失败与幂等请求不追加**：同句柄幂等注册（仍记审计）、重复
  吊销（仍记审计）以及 400/404/409 等失败路径均不产生事件；已写入的
  active 历史**永不改写**。
- `cursor` 为**租户内跨 DID 持久递增正整数**：同一租户内不同 DID 的
  生命周期事件共享同一游标空间，按追加顺序单调递增并跨重启稳定；不同
  租户各自从 1 计起。该游标空间与 `keys/revocations` **完全隔离**，
  两者互不影响。
- 分页参数规则**沿用 `keys/revocations`**：`limit` 缺省 **50**、须为
  **1–200** 的 ASCII 十进制整数；`after` 缺省 **0**、须为**非负**
  ASCII 十进制整数；二者均只能出现一次且须为非空 ASCII 数字，重复、
  空白、布尔词、小数、符号、Unicode 数字等一律 **400**。`after` 排除
  `cursor` 不大于其值的事件，`next_after` 为本页末项 `cursor`，
  **空页等于 `after`**。DID 已存在但无历史返回空页。
- **旧状态兼容**：旧版本状态文件中密钥版本存在但无生命周期历史时，
  加载时按（租户、**DID 字典序**、版本升序）稳定补录，同一版本固定
  **先 active 后 revoked**：
  - 每个版本补一条 active：版本 1 的 `action` 为 `did.created`、
    `updated_at` 取 DID `created_at`；其余版本补 `key.rotated`、
    `updated_at` 为 **`null`**（轮换时刻无法追溯）；
  - 已吊销版本再补一条 `key.revoked`，`updated_at` 取版本行的
    `revoked_at`，缺失时为 `null`；
  - 补录项 `audit_seq`/`audit_timestamp` 均为 `null`，`cursor` 为该
    租户内新分配的持久化正整数；兼容项随下一次原子写一并落盘，即使
    加载后无写操作，重启时也按相同顺序重建为**相同 cursor**。
- 注册/轮换/吊销变更时，**密钥状态、生命周期历史、吊销历史、游标与
  审计事件在同一把锁内经同一次原子写落盘，落盘失败一并回滚**（版本
  状态不变、历史不追加、游标不前进、审计不记录）。该接口为纯只读
  查询，**不记审计**、不触发落盘，`keys/revocations`、单版本状态、
  DID 文档及各写接口的幂等响应均保持不变。

```bash
curl "localhost:8080/v1/dids/did:example:<id>/keys/history?limit=50&after=0"
```

### DID 生命周期停用

`POST /v1/dids/{did}/deactivate` 将 DID 置为生命周期终态 `deactivated`
（不可恢复），与密钥版本吊销相互独立：停用不改变密钥历史、公钥状态与
既有凭证，历史 DID 文档、公钥版本状态与凭证查询始终保持可读。

- 请求体**仅允许**空体、`{}` 或恰含可选 `reason`：
  - 空体/`{}` 省略 `reason`，缺省原因 **“DID 主动停用”**；
  - `reason` 提供时必须为字符串且首尾裁剪后非空（显式 `null`、数字、
    空白串均 400），保存并返回裁剪后的值；含多余字段、非法 JSON、
    非对象请求体一律 400。非法 `reason` 仅首次请求返回 400。
- DID 未知或访问他租户 DID 一律 **404**（跨租户不可探测）。
- **首次**停用成功 **200**，响应恰含 `did`、`status:"deactivated"`、
  `reason`、`updated_at`（UTC 秒精度 Z）；**重复停用**忽略任何新
  `reason`（含非法值），幂等返回首次的 `reason`/`updated_at`，每次重复
  都记审计。
- `GET /v1/dids/{did}/status` 为只读查询，响应恰含
  `{did,status,reason,updated_at}`：活动 DID 为
  `status:"active"`、`reason`/`updated_at` 均为 `null`；停用后返回首次
  原因与时间。未知或他租户 DID 404；纯只读、**不记审计**。
- **停用后禁止**的操作（均返回 **409** 与非空 `error`，**不写任何
  记录/审计**）：
  - 密钥轮换（`POST .../keys/rotate`）；
  - 作为 `issuer_did` 签发凭证（作为 `subject_did` 不受影响）；
  - 为其已签发凭证生成选择性披露演示（`present`）或谓词证明（`prove`）。
- **验签类端点**（均 HTTP 200 公开错误协议、只读、失败不消费、不记
  审计）在**锚定与密码学签名成功之后**检查签发者 DID：
  - 已停用时返回 `{"valid":false,"reason":"签发DID已停用：<首次原因>"}`，
    **优先于凭证有效期与凭证吊销**；
  - 签名/锚定/签名格式等其他失败仍按原分类协议返回各自原因，不提前
    暴露停用状态；演示/谓词证明验签的已消费、自身过期与签发密钥版本
    吊销判定仍先于 DID 停用；持有者密钥吊销在 issuer 侧停用判定之后；
  - 演示与谓词证明的消费锁内会复查停用状态，停用失败**不消费**。
- 跨系统信任接口（`/v1/trust/...`）使用独立的信任锚点注册表，不读取
  本地 DID 停用状态，行为完全不变。
- 审计：首次停用与幂等重试均记 **`did.deactivated`**
  （`resource_type` 为 `did`、`resource_id` 为 DID 本身）；400/404/409
  等失败路径不记。停用状态与审计在同一把锁内经**同一次原子写**落盘，
  落盘失败回滚（状态不变、事件不记录），**重启后结论稳定**，并遵守
  `X-Tenant-ID` 租户隔离。

```bash
curl -X POST localhost:8080/v1/dids/did:example:<id>/deactivate \
  -d '{"reason":"机构业务终止"}'
curl localhost:8080/v1/dids/did:example:<id>/status
```

#### DID 生命周期历史（只读）

`GET /v1/dids/{did}/history` 只读返回某 DID 的注册与停用事件，与注册、
停用协议完全兼容，游标空间与密钥吊销、密钥生命周期、锚点等其他历史
**相互独立**。

- 租户规则与其他 `/v1` 接口一致：缺省 `default`，显式空
  `X-Tenant-ID` 为 **400**；未知 DID 或访问他租户 DID 一律 **404**
  （跨租户不可探测）。
- 200 响应**恰含** `did`、`events`、`next_after`；`events` 按
  **`cursor` 升序**，每项**恰含** `action`、`status`、`reason`、
  `updated_at`、`audit_seq`、`audit_timestamp`、`cursor`：
  - **注册事件**：`action:"did.created"`、`status:"active"`、
    `reason:null`，`updated_at` 为 DID 的 `created_at`（UTC 秒精度 Z）；
  - **首次停用事件**：`action:"did.deactivated"`、
    `status:"deactivated"`，`reason` 为首次停用的裁剪原因，
    `updated_at` 为首次停用时间（UTC 秒精度 Z，与停用响应同值）；
  - `audit_seq`/`audit_timestamp` **关联产生该事件的审计动作**
    （`did.created`/`did.deactivated`），`audit_timestamp` 为该审计
    事件的 Unix 秒，且与 `updated_at` 为**同一秒**；旧状态补录的
    兼容项二者均为 `null`。
- **幂等重试、重复停用与失败请求不追加**：同句柄幂等注册（仍记审计）、
  重复停用（仍记审计）以及 400/404/409 等失败路径均不产生事件。
- `cursor` 为**租户内跨 DID 持久递增正整数**：同一租户内不同 DID 的
  事件共享同一游标空间，按追加顺序单调递增并跨重启稳定；不同租户各自
  从 1 计起。该游标空间与其他历史接口**完全隔离**，互不影响。
- 分页参数**仅允许** `limit`、`after`：`limit` 缺省 **50**、须为
  **1–200** 的**非空 ASCII 十进制**整数；`after` 缺省 **0**、须为
  **非空非负 ASCII 十进制**整数；二者均只能出现一次。重复参数、空值、
  空白、符号、小数、布尔词、Unicode 数字或任何未知参数一律 **400**。
  `after` 排除 `cursor` 不大于其值的事件，`next_after` 为本页末项
  `cursor`，**空页等于 `after`**。
- **旧状态兼容**：旧版本状态文件中 DID 已注册（或已停用）但无该历史时，
  加载时按（租户、**`created_at`**、**did**、动作）稳定顺序补事件：每个
  DID 先补一条 `did.created`（`updated_at` 取 DID `created_at`），已停用
  的再补一条 `did.deactivated`（`reason`/`updated_at` 取首次停用行）；
  补录项 `audit_seq`/`audit_timestamp` 均为 `null`，`cursor` 为该租户内
  新分配的持久化正整数；兼容项随下一次原子写一并落盘，即使加载后无写
  操作，重启时也按相同顺序重建为**相同 cursor**。
- 注册与首次停用时，**状态、历史、游标与审计事件在同一把锁内经同一次
  原子写落盘，落盘失败一并回滚**（状态不变、历史不追加、游标不前进、
  审计不记录）。该接口为纯只读查询，**不记审计**、不触发落盘，注册、
  停用、状态查询及各既有入口的响应均保持不变。

```bash
curl "localhost:8080/v1/dids/did:example:<id>/history?limit=50&after=0"
```

### DID 文档与历史公钥（只读）

`GET /v1/dids/{did}/document` 为密钥轮换前签发物提供历史公钥，纯只读，
不改变审计、凭证、演示、状态及轮换结果。

- 响应字段恰为 `did`、`current_key_version`、`verification_methods`、
  `document_proof`：
  - `current_key_version` 为 DID 当前密钥版本，与注册、轮换及
    `GET /v1/dids/{did}` 的 `key_version` 一致；
  - `verification_methods` 按 `key_version` **升序**，每项恰含
    `key_version`、`key_handle`、`public_key`；`public_key` 为可用于
    ES256 验签的 P-256 PEM（SubjectPublicKeyInfo），**绝不暴露
    private_key**；
  - `document_proof` 为 **ES256**、无填充 base64url 的裸 `R||S` 签名，
    覆盖**除 `document_proof` 外的整个响应对象**按 key 升序的规范化
    JSON（紧凑序列化、UTF-8、嵌套递归排序）；签名私钥恒为 **DID 当前
    版本私钥**。
- 查询参数 `version` **可选且只能出现一次**：
  - 缺省时返回全部历史版本；
  - 提供时须为 **ASCII 十进制正整数**：仅返回该版本的
    `verification_methods`（单项），`current_key_version` 仍为当前版本，
    并**重新生成 `document_proof`**（仍由当前版本私钥签发）；
  - 空值、`0`、符号（`-1`/`+1`）、小数、空白、布尔词、字母或
    **Unicode 数字**（如阿拉伯-印度数字 `१`）以及重复参数一律 **400**
    并返回非空 `error`；
  - 版本不存在（含对未知 DID）返回 **404** 与非空 `error`。
- 租户规则与其他 `/v1` 接口一致：缺省 `default`，显式空
  `X-Tenant-ID` 为 **400**，未知 DID 或他租户资源为 **404**。
- 文档内容（公钥历史）与证明所用私钥均**随状态文件持久化**：
  `document_proof` 每次请求按当前状态重新生成，但重启后用响应中的
  当前版本公钥验签结论稳定。旧状态缺密钥元数据时按既有迁移规则公开
  版本 1，已有接口行为保持不变。
- 该接口为只读查询，**不记审计**。

```bash
curl localhost:8080/v1/dids/did:example:<id>/document
curl "localhost:8080/v1/dids/did:example:<id>/document?version=1"
```

### 选择性披露演示

- `POST /v1/credentials/{credential_id}/present` 请求体必须**恰为**
  `{"disclose":[路径...]}` 加可选 `challenge`、`expires_in`、`holder_binding`：
  缺失 `disclose`、不是数组、含多余字段一律 400；未知凭证 404。`[]` 表示
  **零披露**。`challenge` 须为非空字符串且按 Unicode 码点不超过 256，
  缺省生成 32 位小写 hex；`expires_in` 须为非布尔整数且在 1–86400
  之间，缺省 300。`holder_binding` 必须为**布尔**，缺省 `false`；
  为 `true` 时凭证 `subject_did` 必须是**本租户已注册 DID**，否则
  **400**（未注册或属他租户）。
- 路径按 [RFC 6901](https://www.rfc-editor.org/rfc/rfc6901) JSON Pointer
  解释，相对于凭证 `claims`：
  - 必须以 `/` 开头并命中实际 `claims` 属性，支持 `~0`/`~1` 转义；
  - **禁止根路径**（零披露请传 `[]`）、**禁止数组索引**（数组只能整值披露）、
    越界/经过非对象叶子均 400；
  - 路径不得重复、不得存在祖先/后代重叠（如 `/a` 与 `/a/b`）。
- 成功返回 201，未绑定（缺省/`false`）字段恰为：
  `presentation_id`（`vp_` 加 32 位小写 hex）、`credential_id`、`issuer_did`、
  `issuer_key_version`（旧凭证缺省按 1）、`disclose`（原样回显）、
  `claims`（**仅含所选值**的投影，未选属性不出现）、`challenge`、
  `expires_at`（UTC 当前时间加 `expires_in` 秒，Z 结尾秒精度）、`proof`。
  `holder_binding:true` 时**额外**返回三个字段：`holder_did`（即凭证
  `subject_did`）、`holder_key_version`（生成时持有者的**当前**密钥版本）、
  `holder_proof`（持有者签名，见下）；其余字段与未绑定完全一致，
  未绑定流程与旧版本**完全兼容**。
  `challenge` 与 `expires_at` 均写入被签名正文并随演示记录持久化。
- `proof`（issuer proof）为 **ES256**、无填充 base64url 的裸 `R||S` 签名，
  覆盖**除 `proof` 外按 key 升序规范化 JSON**，使用凭证
  `issuer_key_version` 对应的**历史版本私钥**；持有者绑定**不改变**
  issuer proof 的覆盖范围（不含任何 `holder_*` 字段），因此签发者
  轮换密钥后，旧演示仍可用历史公钥验真。
- `holder_proof` 为持有者第二签名：同为 **ES256** 裸 `R||S` 无填充
  base64url，覆盖**去掉 `proof`、`holder_proof` 后的完整演示对象**
  （含 `holder_did`、`holder_key_version`）**及 `tenant_id`**，按
  key 升序规范化 JSON（紧凑序列化、UTF-8）签名；私钥为生成时持有者
  `holder_key_version` 的当前私钥。绑定信息（holder DID、版本与签名）
  随演示记录持久化在 `presentations` 中：**重启或持有者密钥轮换后**，
  verify 按记录的 `holder_key_version` 从持有者公钥历史中取**历史公钥**
  验签，结论不变。
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
  **重算投影**并核对对象 `claims` -> `proof` 格式与签名 -> 持有者绑定
  校验（仅绑定演示）-> 吊销。
  **持有者绑定演示**（存储记录含 `holder_did`）的请求结构不变（仍为
  `{"presentation":对象,"challenge":串}`），对象须**恰为**未绑定字段
  外加 `holder_did`、`holder_key_version`、`holder_proof`（任一缺失或
  多余均失败）；校验锚定 `holder_did`（须与存储及凭证 `subject_did`
  一致）、`holder_key_version`（须与存储一致），并按该版本从持有者
  公钥历史取**历史公钥**验证 `holder_proof`（覆盖去 `proof`、
  `holder_proof` 后的对象加 `tenant_id`）。持有者 DID 跨租户/不存在、
  历史公钥不可用、`holder_proof` 格式错误或双签名任一不通过，均
  HTTP 200 返回 `valid:false` 与非空中文 `reason`，**不消费**。
  未过期、未吊销且 **issuer 与持有者双签名均通过**才进入消费；在
  **消费锁内复查**已消费、`expires_at` 与吊销状态后标记已消费：若
  复查时已到期则返回 `演示已过期`，**不消费、不记审计**（修复
  “锁外验签期间到期仍被消费”的竞态）。未到期并发验证仅一次返回
  200 `{"valid":true}`（无其他字段）并记一次 `presentation.consumed`，
  过期或失败不消费，消费记录跨重启保留，重复验证返回 `演示已消费`。
  绑定记录与持有者密钥版本随状态文件持久化，**重启或持有者密钥轮换
  后仍以历史公钥完成双签名验证**。
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
  另可选 `uses` 用途白名单：提供时须为**非空、无重复的字符串数组**，
  取值限 `generic`、`vc`、`vp`、`proof`、`did`、`status`、`deactivation`
  且须按此**规范序**给出；省略（及不含 `uses` 的旧记录）为全用途。
  缺字段、类型非法、`uses` 不合规、多余字段一律 400（仅含非空中文
  `error`）。成功返回 201，字段恰为
  `{did, public_key, key_version, status:"active", updated_at:null}`
  （响应不含 `uses`）。
- 同一 `(did, key_version)` 再次提交：PEM **相同**且 `uses` **相同**
  （省略与显式全用途等价）视为幂等重试，返回 **200** 与既有记录
  （含已吊销状态与 `updated_at`），每次重试都记
  `trust.anchor.registered`；PEM **不同**或 `uses` **不同**返回
  **409**，不记审计。
- `uses` 按租户持久化，与注册/轮换变更及审计同一次原子写落盘，重启后
  稳定。`GET /v1/trust/anchors/{did}/{key_version}/uses` 只读返回锚点
  版本的用途白名单：200 按键序恰返 `{did, key_version, uses}`（`uses`
  按规范序）；路径版本非 ASCII 正整数 400，未知或跨租户 404。
- `PUT /v1/trust/anchors/{did}/{key_version}/uses` 收紧锚点版本的用途
  白名单，**无需轮换密钥即可撤销用途**：请求体须**恰含** `from_uses`
  与 `uses`，两者均须为非空无重复字符串数组、取值限且按规范序（同注册
  规则），缺漏/多余字段或取值不合规一律 400（仅含非空中文 `error`）；
  路径版本非 ASCII 正整数 400，未知或跨租户锚点 404，已吊销 409。
  目标等于当前值（省略注册或旧记录视为全用途）时幂等返回 **200** 且
  无副作用；否则 `from_uses` 须等于当前值且目标须为其**真子集**——
  前置不匹配或扩权均 **409**，并发提交的不同收紧最多一个成功。成功
  200 按键序恰返 `{did, key_version, uses}`；变更立即作用于全部
  `/v1/trust` 用途门控（拒绝响应沿用各入口既有协议）。实际变更仅追加
  一次 `trust.anchor.uses.updated` 审计（`resource_type:trust_anchor`、
  `resource_id:<did>#<key_version>`），用途与审计同一次原子写落盘，
  落盘失败 500 并回滚，重启保持；轮换产生的新版本继承当前用途。
- 用途门控：`/v1/trust` 下各验签/同步入口按用途选用锚点——
  `verify` 用 `generic`，`credentials*` 用 `vc`，`presentations*` 用
  `vp`，`proofs*` 用 `proof`，`dids/verify-document*` 用 `did`，
  `credential-status/*` 用 `status`，`dids/deactivate-sync*` 与
  `dids/deactivations/manifest/verify*` 用 `deactivation`。active 锚点
  不含该用途时，沿用该入口“锚点不可用”的状态码与原因（较早错误优先），
  失败不写入、不消费、不记审计。
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
  - `expires_at` 同为可选扩展字段：在请求结构、凭证字段、锚点与签名
    全部通过后才检查——`body` 不含该字段时保持兼容（无期限）；含该
    字段时必须为 UTC 秒精度 Z 格式 `YYYY-MM-DDTHH:MM:SSZ`（非法返回
    前缀“凭证字段 expires_at”的原因），当前时间大于等于它时返回
    `{"valid":false,"reason":"凭证已过期"}`；签名等先置失败仍优先
    返回各自原因。该判定只读、不写状态、不记审计。
  - 校验顺序：请求结构 → 凭证字段 → 锚点 → 签名格式 → 密码学验签。
    锚点按本租户 `(issuer_did, 版本)` 查找，仅 `active` 的 P-256 公钥
    可用：缺失返回前缀“锚点”的原因，已吊销返回前缀“锚点”的吊销原因。
  - 签名为 **ES256/SHA-256**，64 字节裸 `R||S` 的无填充 base64url，覆盖
    完整 `body` 的递归排序紧凑 JSON；签名编码非法返回前缀“签名格式错误”，
    密码学验签失败返回前缀“签名校验失败”。成功仅返回 `{"valid":true}`。
- `POST /v1/trust/dids/verify-document` 为**跨系统 DID 文档验真**：DID
  无需在本租户注册，依赖方仅凭提交的文档原文即可完成结构、证明与信任
  判断；不读取本地 DID 注册表，只读、不登记任何资源、不写历史或审计，
  跨租户各自使用本租户锚点，结论随状态文件重启后稳定。原有
  `GET /v1/dids/{did}/document`、注册、轮换、吊销与各类凭证/演示/证明
  验真接口协议均保持不变。
  - 请求体必须**恰含** `document`（JSON 对象）；缺失、多余字段、请求体
    缺失/非法 JSON/非对象、`document` 非对象一律按请求错误返回 HTTP 200
    + `{"valid":false,"reason":"请求…"}`。
  - `document` 必须**恰含**四个字段：`did`（非空字符串）、
    `current_key_version`（**非布尔正整数**）、`verification_methods`
    （非空数组）、`document_proof`（非空字符串）；缺字段或多余字段返回
    前缀“DID文档”的原因。
  - `verification_methods` 每项须**恰含** `key_version`（非布尔正整数）、
    `key_handle`（非空字符串）、`public_key`（可解析的 **P-256 公钥
    PEM**，SubjectPublicKeyInfo，非 P-256/不可解析均失败）；方法须按
    `key_version` **严格升序且无重复**。文档序列化后任何位置出现私钥
    PEM 标记（`PRIVATE KEY-----`）一律失败——提交文档不得携带私钥。
  - `current_key_version` 必须等于方法中的**最高版本**（不一致返回
    “DID文档”类原因）。
  - 信任判断：按**当前租户** `(did, current_key_version)` 查信任锚点，
    锚点不存在（含他租户未注册，跨租户不可探测）返回前缀“锚点”的
    原因，已吊销返回前缀“锚点”的吊销原因；锚点 `public_key` 必须与
    文档最高版本方法的 `public_key` **原文完全匹配**，否则失败。
  - `document_proof` 遵循与 `GET /v1/dids/{did}/document` 完全相同的
    **ES256 裸签名和规范化 JSON 规则**：64 字节裸 `R||S` 的无填充
    base64url，覆盖**除 `document_proof` 外的整个文档**按 key 升序的
    规范化 JSON（紧凑序列化、UTF-8、嵌套递归排序）；编码非法返回前缀
    “签名格式错误”，密码学验签失败返回前缀“签名校验失败”。验签公钥
    即上一步匹配通过的当前版本锚点公钥。
  - 校验顺序：请求结构 → 文档字段与结构 → 锚点（存在/active/公钥匹配）
    → 签名格式 → 密码学验签。任何失败均 **HTTP 200** 返回
    `{"valid":false,"reason":"<非空中文原因>"}`，成功仅返回
    `{"valid":true}`（无其他字段）；显式空 `X-Tenant-ID` 仍为 **400**。
  - **外部 DID 停用通告**：上述原验真**成功之后**，再按当前租户同
    `did` 查询 `POST /v1/trust/dids/deactivate-sync` 登记的停用通告；
    命中时返回 **HTTP 200**、键序 `valid,reason`，值为
    `false`、`"外部DID已停用：<通告 reason>"`；未命中维持原结果
    （成功仍为 `{"valid":true}`）。查询为只读：不登记资源、不写历史
    或审计；跨租户通告互不可见，结论随状态文件重启稳定。

  ```bash
  curl -X POST localhost:8080/v1/trust/dids/verify-document \
    -d '{"document":{ ...GET /v1/dids/{did}/document 返回的整个文档对象... }}'
  ```
- `POST /v1/trust/dids/deactivate-sync` 登记**外部 DID 停用通告**：
  外部系统对其 DID 停用后，将带 ES256 签名的通告提交给本租户，供
  `POST /v1/trust/dids/verify-document` 在原验真成功后拦截。通告按
  租户与 `did` 隔离持久化，不读取本地 DID 注册表，其他 HTTP 与 CLI
  行为完全不变。
  - 请求体必须**恰含** `body`（JSON 对象）与 `signature`（非空字符
    串）；缺失/多余字段、请求体缺失/非法 JSON/非对象一律 **400** 且
    响应仅含非空中文 `{"error": "..."}`。
  - `body` 必须**恰含**四个字段：
    - `did`：**非空字符串**；
    - `key_version`：**非布尔正整数**（布尔、0、负数、字符串均 400）；
    - `reason`：长度 **1–256 个 Unicode 码点**的字符串，且**首尾不
      得含空白**（空串、纯空白、首尾空格/制表符/换行、超长均 400；
      保存原文，不做裁剪）；
    - `deactivated_at`：**UTC 秒精度 Z 格式**
      `YYYY-MM-DDTHH:MM:SSZ`（毫秒、偏移、缺 Z、非法时刻均 400）。
  - 签名规则与其他信任接口一致：**ES256/SHA-256**，64 字节裸
    `R||S` 的**无填充 base64url**，覆盖提交的完整 `body` 按 key
    升序的规范化 JSON（紧凑序列化、UTF-8、嵌套递归排序）。验签公钥
    取**当前租户** `(did, key_version)` 的信任锚点，仅 `active` 的
    P-256 公钥可用。
  - 锚点缺失、已吊销或公钥不可用 → **HTTP 200**
    `{"valid":false,"reason":"锚点不可用"}`；签名编码非法 →
    `reason:"签名格式错误"`；密码学验签失败 →
    `reason:"签名校验失败"`。失败响应键序固定为 `valid,reason`，
    **不写入、不改变任何状态**。
  - 验签通过后按 **(租户, did)** 持久化：
    - **首次接受**：**201**，响应键序恰为
      `valid,did,key_version,reason,deactivated_at`，`valid:true`；
    - **完全重放**（同 did 且 key_version/reason/deactivated_at 完全
      一致）：**200** 返回首次记录，不重复写入；
    - **同 did 已有不同通告**（任一字段不同）：**409** 且响应仅含
      非空中文 `{"error": "..."}`，不写入。
  - 记录与落盘在同一把锁内经**同一次原子写**完成，落盘失败一并
    回滚；通告随状态文件**跨重启保留**。遵守 `X-Tenant-ID` 缺省
    `default`、显式空值 **400** 与跨租户隔离（他租户登记的通告与
    锚点均不可见、不可探测）。

  ```bash
  curl -X POST localhost:8080/v1/trust/dids/deactivate-sync -d '{
    "body": {"did":"did:web:example.com","key_version":1,
             "reason":"机构业务终止","deactivated_at":"2026-09-25T00:00:00Z"},
    "signature":"<base64url R||S>"}'
  ```
- `GET /v1/trust/dids/deactivations` **只读查询外部 DID 停用通告审计
  事件**，与登记端点配套。仅返回当前租户的事件，跨租户互不可见；无任何
  事件也返回 **200 空页**，不因此 404。
  - **追加时机**：通告**首次接受**时与通告记录在**同一把锁内经同一次
    原子写**追加一条事件；完全重放（200）、同 did 异通告冲突（409）、
    锚点不可用/签名格式错误/验签失败（200 `valid:false`）等**一律不
    追加**。批量登记逐项提交，仅批内首次接受的项各自追加，落盘失败仅
    回滚该项。
  - **游标**：`cursor` 为**租户内跨 DID 持久递增正整数**，按首次接受
    顺序单调递增并跨重启稳定；不同租户各自从 1 计起，且该游标空间与
    DID/密钥/锚点等其他历史**完全隔离**。
  - **旧状态兼容**：旧版本状态文件中已存在停用通告但无审计事件列表时，
    加载时按（租户、**`deactivated_at`**、**`did`**）升序为每个缺事件
    的通告稳定补录一条，`cursor` 为该租户内新分配的持久化正整数；补录
    在内存中完成并随下一次原子写一并落盘，**即使加载后无写操作，重启时
    也按相同顺序重建为相同 cursor**（迁移原子、重启不变）。
  - **查询参数仅允许** `limit`、`after`、`did`、`key_version`、`from`、
    `to`，且均**只能出现一次**：
    - `limit` 缺省 **50**，须为 **1–200** 的**非空 ASCII 十进制**整数；
    - `after` 缺省 **0**，须为**非空非负 ASCII 十进制**整数；
    - `did` 提供时须为**非空字符串**（精确匹配）；
    - `key_version` 须为 **ASCII 十进制正整数**（精确匹配）；
    - `from`/`to` 须为 **UTC 秒精度 Z 时间** `YYYY-MM-DDTHH:MM:SSZ`
      （毫秒、偏移、缺 Z、未补零、非法时刻、空白、Unicode 数字均 400），
      对 `deactivated_at` 做**闭区间**过滤，且同时提供时 **`from ≤ to`**。
    - 重复参数、空值、未知参数、布尔词、小数、符号或范围非法一律 **400**
      且响应**恰为**非空中文 `{"error": "..."}`。
  - **过滤后再分页**：先按 `did`、`key_version` 精确过滤及
    `deactivated_at` 闭区间过滤，再取 **`cursor > after`** 按 `cursor`
    升序取至多 `limit` 项。
  - 200 响应**恰含** `events`、`next_after`；每项**恰含** `cursor`
    （整数）、`did`（字符串）、`key_version`（整数）、`reason`（字符串）、
    `deactivated_at`（字符串）。**空页 `next_after` 等于 `after`**，否则
    取本页末项的 `cursor`。
  - 该接口为纯只读查询，**不记审计**、不触发落盘；`X-Tenant-ID` 缺省
    `default`、显式空值 **400**；登记、验真与 CLI 等其他 HTTP 行为均
    保持不变。

  ```bash
  curl -H 'X-Tenant-ID: acme' \
    'localhost:8080/v1/trust/dids/deactivations?limit=50&after=0'
  curl 'localhost:8080/v1/trust/dids/deactivations?did=did:web:example.com&key_version=1&from=2026-01-01T00:00:00Z&to=2026-12-31T00:00:00Z'
  ```
- `GET /v1/trust/dids/deactivations/export` **确定性 NDJSON 导出外部 DID
  停用通告审计事件**，与查询端点共用过滤规则，额外支持**快照续传**：
  同一 `snapshot` 的续页天然排除快照之后新登记的事件，跨重启字节一致。
  - **查询参数仅允许** `limit`、`after`、`snapshot`、`did`、`key_version`、
    `from`、`to`，且均**只能出现一次**：
    - `limit` 缺省 **1000**，须为 **1–10000** 的**非空 ASCII 十进制**整数；
    - `after` 缺省 **0**，须为**非空非负 ASCII 十进制**整数；
    - `snapshot` 缺省为**请求开始时原子读取的本租户最大 cursor**（无事件
      为 0）；显式提供时须为**非负 ASCII 十进制**整数且**不超过当时最大
      值**；
    - `did`、`key_version`、`from`、`to` 校验与查询端点完全一致。
    - 重复参数、空值、未知参数、布尔词、小数、符号或范围非法一律 **400**
      且响应**恰为**非空中文 `{"error": "..."}`。
  - **过滤后再分页**：先按 `did`、`key_version` 精确过滤及
    `deactivated_at` 闭区间过滤，再取 **`after < cursor ≤ snapshot`**
    按 `cursor` 升序的前 `limit` 条。
  - 成功 **200**，`Content-Type: application/x-ndjson; charset=utf-8`；
    响应头 **`X-Snapshot-Cursor`** 为生效快照、**`X-Next-After`** 为末行
    `cursor`（空结果为 `after`）。每行一个事件，键序固定为 `cursor`、
    `did`、`key_version`、`reason`、`deactivated_at`（类型与查询端点
    一致）；**UTF-8 紧凑 JSON、非 ASCII 不转义、字符串按 RFC 8259 最短
    转义、LF 结行（末行亦有 LF）、无 BOM**；空结果为**零字节**。
  - 续页方式：以响应头 `X-Next-After` 作为下一页 `after`，并带上同一
    `snapshot`，即可在事件持续追加时获得确定的分页结果。
  - 该接口为纯只读查询，**不改游标、状态或审计**；`X-Tenant-ID` 缺省
    `default`、显式空值 **400**；其余 HTTP 入口与 CLI 行为均保持不变。

  ```bash
  curl -D - 'localhost:8080/v1/trust/dids/deactivations/export?limit=1000'
  curl 'localhost:8080/v1/trust/dids/deactivations/export?snapshot=42&after=1000&limit=1000'
  ```
- `GET /v1/trust/dids/deactivations/manifest` 为一次确定性导出生成**签名
  摘要清单（manifest）**，供依赖方凭清单校验导出的 NDJSON 内容。与 export
  共用同一套过滤/分页/快照规则与同一字节形状，但 `snapshot` 必填、且另需
  唯一 `signer_did`。
  - **查询参数**：export 七参数 `limit`、`after`、`snapshot`、`did`、
    `key_version`、`from`、`to` 加 `signer_did`，均**只能出现一次**：
    - `snapshot` **必填**：须为**非负 ASCII 十进制**整数且**不超过请求
      开始时本租户最大 cursor**；缺失、空值、负数、小数、空白、布尔词、
      Unicode 数字或越界一律 **400**；
    - `signer_did` 必填且为**非空字符串**，须是**当前租户的活动本地
      DID**（即经 `/v1/dids` 注册、服务端托管当前私钥的 DID）：未知或
      他租户 DID 返回 **404**，已生命周期停用返回 **409**（快照越界等
      **400 判定优先于** 404/409）；
    - 其余参数校验与 export 完全一致（`limit` 缺省 1000、限 1–10000，
      `after` 缺省 0，`did` 非空，`key_version` 为正整数，`from`/`to`
      为 UTC 秒精度 Z 且 `from≤to`；非 ASCII 数字 400）；空值、重复或
      未知参数一律 **400**。
  - **200 响应键序固定**为 `snapshot`、`filters`、`count`、`alg`、
    `digest`、`signer_did`、`key_version`、`signature`：
    - `snapshot` 为生效快照；
    - `filters` 键序固定为 `after`、`limit`、`did`、`key_version`、
      `from`、`to`，**按此顺序记录各参数显式提供时的生效值**（数值/
      字符串），未提供的缺省项一律为 `null`；
    - `count` 为本页事件的**非负整数**行数；
    - `alg` 恒为 `"SHA-256"`；
    - `digest` 为本页 **NDJSON 字节**（与 export 完全相同的 UTF-8 紧凑
      JSON、LF 结行字节，空页为零字节）的 **64 位小写十六进制** SHA-256；
    - `signer_did` 为签名 DID，`key_version` 为其**当前密钥版本**；
    - `signature` 由签名 DID **当前私钥**对**前七键**（不含
      `signature`）的对象按 key 升序规范化 JSON（紧凑、UTF-8、嵌套递归
      排序）做 **ES256** 裸 `R||S` 无填充 base64url 签名，规则与凭证/
      锚点既有签名一致。
  - ECDSA 签名含随机因子，**每次签名字节可变**，但用该 DID 当前版本公钥
    验签的结论**跨重启稳定**；该接口为纯只读，不改游标、状态或审计，遵守
    `X-Tenant-ID` 缺省 `default`、显式空值 400 与租户隔离。
- `POST /v1/trust/dids/deactivations/manifest/verify` 校验清单与其声称的
  NDJSON 导出内容，供跨系统验真；**只读、租户隔离、不记审计**。
  - **外层请求**：体须**恰为** `{"manifest":对象,"ndjson":字符串}`。
    请求体缺失、非法 JSON、非对象、缺 `manifest`/`ndjson`、含多余字段、
    `manifest` 不是对象或 `ndjson` 不是字符串，一律 **400** 且响应仅含
    非空中文 `{"error": "..."}`。
  - 外层合法后**任何失败均 HTTP 200**，返回键序 `valid,reason`，并按以下
    **顺序**短路校验：
    1. **清单结构**：恰含 `snapshot`（非负整数）、`filters`（恰含
       `after`/`limit`/`did`/`key_version`/`from`/`to` 六键，取值类型与
       范围同 GET 规则，缺省可为 `null`，`from≤to`）、`count`（非负
       整数）、`alg`（恰为 `SHA-256`）、`digest`（64 位小写 hex）、
       `signer_did`（非空串）、`key_version`（正整数）、`signature`
       （非空串）。任一不合法 → `reason:"清单非法"`；
    2. **锚点**：按当前租户 `(signer_did, key_version)` 查**信任锚点**，
       仅存在、`active` 且公钥 PEM 可解析才可用，否则
       `reason:"锚点不可用"`（他租户/未知/吊销不可探测）；
    3. **签名格式**：须为 86 字符规范的 64 字节裸 `R||S` 无填充
       base64url，否则 `reason:"签名格式错误"`；
    4. **密码学签名**：用 active 锚点公钥对清单**前七键**规范化 JSON 验
       ES256，失败 `reason:"签名校验失败"`；
    5. **导出内容**：将 `ndjson` 编码为 **UTF-8 字节**，其 SHA-256
       小写 hex 须等于 `digest`，且 LF 行数须等于 `count`，否则
       `reason:"导出内容不匹配"`。
  - 全部通过仅返回 `{"valid":true}`（无其他字段）。GET 与 export 产出的
    `manifest`/NDJSON 可直接配对提交；结论随状态文件**跨重启稳定**，且仅
    使用当前租户锚点。

  ```bash
  # 1) 取签名清单与其对应导出（同一组参数、snapshot 必填）
  curl -H 'X-Tenant-ID: acme' \
    'localhost:8080/v1/trust/dids/deactivations/manifest?snapshot=42&signer_did=did:example:<id>'
  curl -H 'X-Tenant-ID: acme' \
    'localhost:8080/v1/trust/dids/deactivations/export?snapshot=42'
  # 2) 校验
  curl -X POST -H 'X-Tenant-ID: acme' \
    localhost:8080/v1/trust/dids/deactivations/manifest/verify \
    -d '{"manifest":{ ...上一步清单对象... },"ndjson":"<导出的 NDJSON 文本>"}'
  ```
- `POST /v1/trust/dids/deactivations/manifest/verify-batch` 为批量版本：
  请求体必须**恰为** `{"items":[项...]}`，`items` 为 1–100 项的数组，
  每项**恰含** `manifest` 对象与 `ndjson` 字符串；**任何失败均
  HTTP 200**，只读、不写状态/历史/审计。
  - **请求级非法**（空体、非法 JSON、非对象、缺 `items`、含多余字段、
    `items` 非数组、空数组或超过 100 项）统一返回
    `{"results":[],"reason":"请求..."}`（`reason` 以“请求”开头）；
    显式空 `X-Tenant-ID` 仍 **400**。
  - **合法批次**返回 `{"results":[...]}`，长度与顺序与输入一致、逐项
    不短路：项非对象、字段缺失/多余或类型非法按 `清单非法` 处理，其余
    逐项沿用单项验真的五段顺序与五种 `reason`；成功项仅
    `{"valid":true}`，失败项键序 `valid,reason`。

  ```bash
  curl -X POST -H 'X-Tenant-ID: acme' \
    localhost:8080/v1/trust/dids/deactivations/manifest/verify-batch \
    -d '{"items":[{"manifest":{ ...清单对象... },"ndjson":"<NDJSON 文本>"}]}'
  ```
- `POST /v1/trust/presentations/verify` 验证**其他系统生成且未在本租户
  保存的演示**：无需登记本地 DID/凭证/演示，只读、不写凭证/演示/状态/
  历史/审计，跨租户各自使用本租户锚点，重启后结论一致。
  - 请求体必须**恰为** `{"presentation":对象,"challenge":非空字符串}`；
    缺失、多余字段、请求体缺失/非法 JSON/非对象一律按请求错误返回
    HTTP 200 + `{"valid":false,"reason":"请求…"}`。
  - `presentation` 必须**恰为** present 接口返回的**未绑定九字段**演示：
    `presentation_id`、`credential_id`、`issuer_did`（均为非空字符串）、
    `issuer_key_version`（非布尔正整数）、`disclose`（字符串数组）、
    `claims`（对象）、`challenge`、`expires_at`、`proof`（均为非空
    字符串）；缺字段、多余字段、类型非法或出现任何 `holder_*` 字段均
    返回前缀“演示”的原因。请求 `challenge` 必须等于演示对象的
    `challenge`，不一致返回前缀“挑战”的原因。
  - 校验顺序：请求结构 → 演示字段与 challenge → 锚点 → 签名格式 →
    密码学验签 → 期限。锚点按本租户 `(issuer_did, issuer_key_version)`
    查找，仅 `active` 的 P-256 公钥可用：缺失或已吊销返回前缀“锚点”
    的原因。
  - `proof` 为 **ES256/SHA-256**，64 字节裸 `R||S` 的无填充 base64url，
    覆盖对象中**除 `proof` 外全部字段**的递归排序紧凑 JSON；编码非法
    返回前缀“签名格式错误”，验签失败返回前缀“签名校验失败”。
  - `expires_at` 必须为 UTC 秒精度 Z 格式 `YYYY-MM-DDTHH:MM:SSZ`
    （非法返回前缀“演示”的原因）；当前时间达到它时返回
    `{"valid":false,"reason":"演示已过期"}`。成功仅返回
    `{"valid":true}`。
- `POST /v1/trust/presentations/verify-batch` 为批量版本：请求体必须
  **恰为** `{"presentations":[项...]}`，数组非空且不超过 100 项。外层
  缺失、非法 JSON、非对象、字段缺失或多余、`presentations` 非数组、
  空数组或超限，统一 HTTP 200 返回
  `{"results":[],"reason":"请求…"}`；显式空 `X-Tenant-ID` 仍返回 400。
  合法批次按输入顺序逐项处理且**不短路**，每项复用单项协议的两种形态：
  未绑定项恰含 `presentation` 对象与非空 `challenge`（演示出现任何
  `holder_*` 字段即项级失败）；持有者绑定项另须恰含非空
  `source_tenant_id`，演示恰为未绑定九字段加 `holder_did`（非空串）、
  `holder_key_version`（非布尔正整数）、`holder_proof`（非空串），
  继续校验签发者与持有者两类锚点和双签名，
  `source_tenant_id` 作为 holder proof 覆盖对象中的 `tenant_id`。
  字段、挑战、锚点、签名、期限及校验顺序与单项完全一致。
  响应恰为 `{"results":[...]}`，长度和顺序与输入一致：成功项仅
  `{"valid":true}`，失败项恰为
  `{"valid":false,"reason":"非空中文原因"}`。接口纯只读、不消费、不
  登记资源、不写状态/历史/审计，仅使用当前租户锚点，重启后结论稳定。
- `POST /v1/trust/proofs/verify` 验证**未在本租户保存的外部谓词证明**：
  无需登记 DID/凭证/证明，只读、不消费、不写证明/状态/历史/审计，跨租户
  各自使用本租户锚点，重启后结论一致。原本地
  `POST /v1/proofs/{proof_id}/verify` 协议保持不变。
  - 请求体必须**恰含** `proof`（JSON 对象）、`challenge`（非空字符串）、
    `source_tenant_id`（非空字符串）；缺失、多余字段、请求体缺失/非法
    JSON/非对象一律按请求错误返回 HTTP 200 +
    `{"valid":false,"reason":"请求…"}`。
  - `proof` 必须**恰为** prove 响应九字段：`proof_id`、`credential_id`、
    `issuer_did`（均为非空字符串）、`issuer_key_version`（非布尔正整数）、
    `predicates`（非空数组）、`results`（数组）、`challenge`、
    `expires_at`、`proof`（均为非空字符串）；缺字段、多余字段或类型非法
    返回前缀“证明”的原因。请求 `challenge` 必须等于证明对象的
    `challenge`，不一致返回前缀“挑战”的原因。
  - `results` 必须与 `predicates` **等长且仅含布尔值**；**不按 claims
    重算 results**（即使结果与谓词语义相反，签名合法即通过）。
  - `predicates` 每项须**恰含** `path`、`op` 及可选 `value`：
    `op ∈ {exists,eq,gte,lte}`；`exists` **禁止** `value`，其余 op 必填
    `value`；`gte`/`lte` 的 `value` 必须为**非布尔数字**。`path` 须以
    `/` 开头、RFC 6901 转义合法（`~0`/`~1`），且路径**不得重复、不得有
    祖先/后代重叠**；此处**不校验 claims 命中、不判数组索引路径、不校验
    命中值类型**。
  - 校验顺序：请求结构 → 证明字段与挑战 → 锚点 → 签名格式 →
    密码学验签 → 期限。锚点按**当前租户** `(issuer_did,
    issuer_key_version)` 查找，仅 `active` 的 P-256 公钥可用：缺失返回
    前缀“锚点”的原因，已吊销返回前缀“锚点”的吊销原因。
  - 签名为 **ES256/SHA-256**，64 字节裸 `R||S` 的无填充 base64url，覆盖
    证明对象中**除 `proof` 外八字段**并加入
    **`tenant_id=source_tenant_id`** 后的递归排序紧凑 JSON；编码非法返回
    前缀“签名格式错误”，验签失败返回前缀“签名校验失败”。
  - `expires_at` 必须为 UTC 秒精度 Z 格式 `YYYY-MM-DDTHH:MM:SSZ`
    （非法返回前缀“证明”的原因）；当前时间达到它时返回
    `{"valid":false,"reason":"证明已过期"}`。签名等先置失败仍优先返回
    各自原因。成功仅返回 `{"valid":true}`。
- `POST /v1/trust/proofs/verify-batch` 为批量版本，逐项规则与单项
  验真完全一致（证明九字段、predicates/results 结构、挑战、锚点、
  签名与期限判定及原因分类）：
  - 请求体必须**恰为** `{"proofs": [项...]}`；`proofs` 须为
    **非空且不超过 100 项**的数组，每项须恰含 `proof`（对象）、
    `challenge` 与 `source_tenant_id`（非空字符串）。
  - 请求体非法（非法 JSON/非对象、缺或多字段、`proofs` 非数组、
    空数组或超过上限）一律 HTTP 200，返回
    `{"results": [], "reason": "请求…"}`。
  - 请求级合法时按输入**顺序逐项校验、失败不短路**，HTTP 200 返回
    `{"results": [...]}`：长度与顺序与输入一致，成功项为
    `{"valid": true}`，失败项为 `{"valid": false, "reason": "…"}`，
    `reason` 区分请求、证明、挑战、锚点、签名格式错误、签名校验失败
    与过期。
  - 同样只读：不消费、不登记 DID/凭证/证明，不写状态、历史或审计；
    遵守租户缺省 `default`、显式空值 400 与跨租户锚点隔离。
- `POST /v1/trust/credentials/verify-batch` 为批量版本，逐项规则与单项
  验真完全一致（字段、锚点、签名与原因分类）：
  - 请求体必须**恰为** `{"credentials":[项...]}`；`credentials` 须为
    **非空且不超过 100 项**的数组，每项须恰含 `body`（对象）与
    `signature`（非空字符串）。
  - 请求体非法（非法 JSON/非对象、缺或多字段、`credentials` 非数组、
    空数组或超过上限）一律 HTTP 200，返回
    `{"results":[],"reason":"请求…"}`。
  - 请求级合法时按输入**顺序逐项校验、失败不短路**，HTTP 200 返回
    `{"results":[...]}`：长度与顺序与输入一致，成功项为
    `{"valid":true}`，失败项为 `{"valid":false,"reason":"…"}`，
    `reason` 区分请求、凭证、锚点、签名格式错误、签名校验失败。
  - 同样只读：不写凭证、状态或审计；遵守租户缺省 `default`、显式空值
    400 与跨租户锚点隔离。
- `POST /v1/trust/credentials/verify-with-status` 合并**外部凭证验真与
  状态判定**，供依赖方一次调用得到最终结论：
  - 请求体**恰为** `{"body":对象,"signature":非空字符串}`；`body` 字段
    类型、扩展字段、ES256 规范化 JSON 签名（覆盖提交的完整 `body`）、
    `issuer_key_version` 省略按 1 且不注入正文、`expires_at` 规则与
    校验优先级，全部沿用 `/v1/trust/credentials/verify`。请求、凭证、
    锚点、签名格式、签名校验或过期失败，均 **HTTP 200** 返回
    `{"valid":false,"reason":...}`，保持既有的分类措辞与优先级。
  - 验签通过后按**当前租户**的 `(issuer_did, credential_id)` 双键查询
    外部凭证状态同步记录（含他租户未同步在内的未命中不可探测）：
    - **未同步**：`{"valid":false,"reason":"外部凭证状态未同步"}`；
    - **active**：仅 `{"valid":true}`；
    - **revoked**：`{"valid":false,
      "reason":"外部凭证已吊销：<保存的 reason>"}`；同步记录无
      `reason` 时使用“未知原因”；
    - **unknown**：`{"valid":false,"reason":"外部凭证状态未知"}`。
  - **纯只读**：不创建凭证、不修改本地凭证状态、不写同步记录或历史、
    不记审计；遵守 `X-Tenant-ID` 缺省 `default`、显式空值 **400** 与
    租户隔离，结论随状态文件**跨重启持久化**。既有验真、同步与历史
    查询接口协议保持不变。
- `POST /v1/trust/credentials/verify-batch-with-status` 批量合并**外部
  凭证验真与本租户同步状态**，一次调用得到整批最终结论：
  - 请求体**恰为** `{"credentials":[项...]}`，数组须为 **1–100 项**；
    外层缺失、非法 JSON、非对象、字段缺失或多余、`credentials` 非数组、
    空数组或超限，统一 **HTTP 200** 返回
    `{"results":[],"reason":"请求…"}`。
  - 请求级合法时按输入**顺序逐项处理、失败不短路**：每项恰含 `body`
    对象与非空 `signature`，项级结构或类型错误只写入对应结果
    （`valid:false` + “请求”前缀原因），不清空整批；`body` 字段错误
    沿用“凭证”分类，其余验真规则（版本省略按 1、扩展字段参与 ES256
    规范化签名、`expires_at` 与校验优先级）与状态合并约定（未同步 /
    active / revoked / unknown）全部沿用
    `/v1/trust/credentials/verify-with-status`。
  - 返回 `{"results":[...]}`：长度与顺序与输入一致，成功项
    `{"valid":true}`（不含 `reason`），失败项
    `{"valid":false,"reason":"…"}`（非空中文原因）。
  - **纯只读**：不写凭证、状态、历史或审计；遵守 `X-Tenant-ID` 缺省
    `default`、显式空值 **400**、跨租户隔离与重启持久化。
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
    原样保留**，新版本**继承前置版本的 `uses` 用途白名单**（前置无
    `uses` 限制时新版本同为全用途）；响应字段同 GET 元素
    （`{did, public_key, key_version, status, updated_at}`），新建
    **201**、幂等 **200**。
  - 新建与幂等重试均记 `trust.anchor.rotated`（`resource_type` 为
    `trust_anchor`、`resource_id` 为 `<did>#<目标版本>`）；冲突、请求
    校验失败与验签不记。轮换与审计在同一把锁内经同一次原子写落盘，
    落盘失败回滚（版本不新增、事件不记录）；重启后版本、状态与审计保留。
  - 旧版本在被显式吊销前仍可用于验签，新版本同样可验签；跨租户继续
    遵循既有 404（轮换/查询/吊销）或 200/`valid:false`（验签）规则。
- 锚点、状态与审计随状态文件持久化，**跨重启保留**；状态变更与审计
  事件在同一把锁内经同一次原子写落盘，落盘失败回滚（变更不生效、
  事件不记录）。

#### 信任锚点生命周期历史（只读）

`GET /v1/trust/anchors/{did}/history` 只读返回某 DID 锚点版本的
生命周期事件，与注册、轮换、吊销、验真及审计协议完全兼容。

- 200 响应恰含 `did`、`events`、`next_after`；`events` 按 `cursor`
  升序，每项恰含 `key_version`、`action`、`status`、`updated_at`、
  `cursor`。`action` 沿用对应的既有审计动作名：
  - 新版本注册（`POST /v1/trust/anchors` 新建）追加
    `trust.anchor.registered`、`status:"active"`、`updated_at:null`；
  - 轮换目标版本新建追加 `trust.anchor.rotated`、`status:"active"`、
    `updated_at:null`；
  - 版本**首次**吊销追加 `trust.anchor.revoked`、`status:"revoked"`、
    `updated_at` 为首次吊销的 UTC 秒精度 Z 时间。
- **幂等重试与任何失败均不追加**：同 DID/版本同 PEM 的注册重试、
  同前置同 PEM 的轮换重试、重复吊销（这些请求仍按原规则记审计），
  以及 400/404/409 等失败路径都不产生历史事件。
- `cursor` 为**租户内持久化正整数**：同一租户内不同 DID 的锚点事件
  共享同一游标空间，按追加顺序单调递增并跨重启稳定；不同租户各自
  从 1 计起。
- `limit` 缺省 **50**，须为 **1–200** 的 ASCII 十进制整数；`after`
  缺省 **0**，须为**非负** ASCII 十进制整数。二者都**只能出现一次**
  且须为**非空 ASCII 数字**：重复参数、空白、布尔词、小数、符号、
  Unicode 数字等一律 **400**。`after` 排除 `cursor` 不大于其值的
  事件，`next_after` 为本页末项的 `cursor`，**空页等于 `after`**。
- DID 在本租户已存在但无历史时返回**空页**；未知 DID 或访问他租户
  DID 返回 **404**（跨租户不可探测）；显式空 `X-Tenant-ID` 为
  **400**。该接口为纯只读查询，**不记审计**、不触发落盘，锚点列表、
  验真与注册/轮换/吊销的幂等响应均保持不变。
- **旧状态兼容**：旧版本状态文件中锚点版本存在但无生命周期历史时，
  加载时按（租户、DID、版本）稳定顺序补录——每个版本补一条 active
  事件（行含 `from_key_version` 即经轮换创建，补
  `trust.anchor.rotated`；否则补 `trust.anchor.registered`，
  `updated_at` 为 `null`），已吊销版本另补一条
  `trust.anchor.revoked`，`updated_at` 取该版本行的首次吊销时间；
  补录 `cursor` 为该租户内新分配的持久化正整数。兼容项随下一次原子
  写一并落盘，即使加载后无写操作，重启时也按相同顺序重建为**相同
  cursor**。
- 注册/轮换/吊销变更时，**锚点、历史、游标与审计事件在同一把锁内
  经同一次原子写落盘，落盘失败一并回滚**（锚点版本不变、历史不追加、
  游标不前进、审计不记录）。

```bash
curl "localhost:8080/v1/trust/anchors/did:web:example.com/history?limit=50&after=0"
```

#### 信任锚点跨 DID 发现（只读）

`GET /v1/trust/anchors` 在不指定 DID 的情况下，跨本租户全部 DID 只读
发现锚点版本，与既有按 DID 接口
（`GET /v1/trust/anchors/{did}`、`.../history`、注册/轮换/吊销）完全
兼容，路由互不影响。

- 查询参数**仅允许** `limit`、`after`、`status`，出现任何其他参数一律
  **400**；显式空 `X-Tenant-ID` 仍为 **400**。
  - `limit` 缺省 **50**，须为 **1–200** 的 ASCII 十进制整数；
  - `after` 缺省 **0**，须为**非负** ASCII 十进制整数（允许前导零与
    超大整数，按大整数精确处理）；
  - `status` 可省略；提供时只能是 `active` 或 `revoked`。
  - 三个参数都**只能出现一次**且须为**非空 ASCII 数字/合法取值**：
    重复参数、空值、首尾空白、符号（`-1`/`+1`）、小数、布尔词、
    Unicode 数字、`limit` 越界及未知参数一律 **400**。
- 200 响应恰含 `anchors`、`next_after`：
  - `anchors` 每项恰含 `did`、`public_key`、`key_version`、`status`、
    `updated_at`、`cursor`，字段含义与按 DID 列表元素相同，另附
    `cursor`；
  - `cursor` 为 **JSON 正整数**，在**租户内跨 DID 唯一、单调递增并
    持久化**，**复用该版本注册/轮换生命周期历史的 active 事件游标**；
    **吊销不改变 cursor**（吊销版本的 cursor 仍是其 active 事件游标，
    revoked 事件游标不参与发现）；不同租户各自独立。
  - 查询顺序：**先按 `status` 过滤当前版本状态**，再在匹配项中按
    **`cursor > after` 升序**取至多 `limit` 项；
  - `next_after` 为本页末项 `cursor`，**空结果等于 `after`**；租户下
    **无任何锚点也返回 200** 与 `{"anchors":[],"next_after":0}`，
    不返回 404。
- 该接口为**纯只读**：**不记审计**、不触发落盘或迁移重试，分页结论
  随状态文件**跨重启稳定**。
- **旧状态兼容**：加载阶段按 **did 字典序、key_version 升序**为缺失
  active 历史的版本补游标（已吊销版本同样先补其 active 游标，游标
  空间与生命周期历史完全一致）；**已有有效游标一律复用**，不重新
  分配。迁移只在内存中进行并尝试随下一次**原子写**持久化——落盘失败
  不得部分写入；GET **不触发重试**，此后任一次成功的注册/轮换/吊销
  原子写会把迁移结果一并落盘；始终无写操作时，重启按相同顺序重建为
  **相同 cursor**。

```bash
curl "localhost:8080/v1/trust/anchors?limit=50&after=0"
curl "localhost:8080/v1/trust/anchors?status=active&limit=200"
curl "localhost:8080/v1/trust/anchors?status=revoked&after=10"
```

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
curl -X POST localhost:8080/v1/trust/credentials/verify-batch \
  -d '{"credentials":[{"body":{...},"signature":"<base64url R||S>"},
                       {"body":{...},"signature":"<base64url R||S>"}]}'
# 外部谓词证明验真（proof 为 prove 响应九字段；签名覆盖除 proof 外八字段
# 并加入 tenant_id=source_tenant_id 的规范化 JSON）
curl -X POST localhost:8080/v1/trust/proofs/verify \
  -d '{"proof":{ ...prove 接口返回的整个证明对象... },
       "challenge":"<证明的 challenge>","source_tenant_id":"<来源租户>"}'
# 批量外部谓词证明验真（逐项规则同单项，失败不短路）
curl -X POST localhost:8080/v1/trust/proofs/verify-batch \
  -d '{"proofs":[{"proof":{...},"challenge":"...","source_tenant_id":"..."},
                   {"proof":{...},"challenge":"...","source_tenant_id":"..."}]}'
# 批量外部演示验真（逐项可为未绑定或持有者绑定形态，失败不短路；
# 绑定项另含 source_tenant_id，演示含 holder_did/holder_key_version/holder_proof）
curl -X POST localhost:8080/v1/trust/presentations/verify-batch \
  -d '{"presentations":[{"presentation":{ ...present 接口返回的九字段演示... },
                          "challenge":"<演示的 challenge>"},
                         {"presentation":{ ...绑定十二字段演示... },
                          "challenge":"<演示的 challenge>",
                          "source_tenant_id":"<来源租户>"}]}'
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

#### 外部凭证状态批量同步

`POST /v1/trust/credential-status/sync-batch` 在一次请求内按顺序同步多条
外部凭证状态，**逐项复用上面的单项同步规则、失败不短路**。

- 请求体必须**恰为** `{"items":[项,...]}`，`items` 为**非空且不超过
  100 项**的数组。请求体缺失、非法 JSON、非对象、字段缺失或多余、
  `items` 非数组/空数组/超过上限，一律返回 **HTTP 200** 与
  `{"results":[],"reason":"请求..."}`，且**不处理、不写入任何一项**。
- 请求级合法时返回 **HTTP 200** 与 `{"results":[...]}`，`results` 与
  输入 `items` **等长、同序**；每一项独立判定，互不影响。
- **失败项**键序恰为 `valid,http_status,reason`，`reason` 恒为非空中文：
  字段/请求错误 `http_status=400`；同 `updated_at` 内容不同
  `http_status=409`；锚点缺失/吊销、签名格式错误、密码学验签失败
  `http_status=200`（`reason` 前缀依次为“锚点”/“签名格式错误”/
  “签名校验失败”），且该项**不写入、不记审计**。
- **成功项**键序恰为 `valid,http_status,issuer_did,credential_id,status,
  reason,updated_at,issuer_key_version`：首次同步 `http_status=201`，
  相同重放与被忽略的更早日 `http_status=200`（不重复/不记审计），
  `updated_at` 更晚的严格更新 `http_status=200` 并记一次
  `trust.credential.status.synced` 审计。
- 同一批内各项按顺序生效（后项可见前项已落盘的状态）；每个成功项沿用
  单项的状态、历史与审计**同一次原子写**，落盘失败仅回滚该项，跨重启
  保持。批量同步同样不触碰本租户签发凭证的状态。
- `X-Tenant-ID` 缺省 `default`，显式空值在进入批处理前判 **400**；
  所有项仅使用当前租户锚点并按本租户双键隔离。

```bash
curl -X POST localhost:8080/v1/trust/credential-status/sync-batch -d '{
  "items":[
    {"body":{"issuer_did":"did:web:example.com","credential_id":"vc_ext_1",
             "status":"active","updated_at":"2026-09-21T00:00:00Z",
             "issuer_key_version":1},"signature":"<base64url R||S>"},
    {"body":{"issuer_did":"did:web:example.com","credential_id":"vc_ext_2",
             "status":"revoked","updated_at":"2026-09-22T00:00:00Z",
             "issuer_key_version":1,"reason":"持证人违规"},
             "signature":"<base64url R||S>"}]}'
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

### 外部凭证导入与读取

在验真通过后，把**外部凭证原文**（完整 `body` 与 `signature`）持久化到
独立的 `imported_credentials` 命名空间，与本租户签发凭证（`credentials`）、
外部状态同步（`credential_status_sync`）互不影响；按租户与
`(issuer_did, credential_id)` 双键隔离，导入内容**一经保存不可变**。

- `POST /v1/trust/credentials/import` 请求体必须**恰为** `{body, signature}`：
  `body` 为 JSON 对象、`signature` 为非空字符串，规则与
  `/v1/trust/credentials/verify` 完全一致（必含非空字符串
  `credential_id`/`issuer_did`/`subject_did`/`issued_at`、对象 `claims`，
  `issuer_key_version` 可省略按版本 1，其余扩展字段允许且参与签名）。
  请求体缺失/非法 JSON/非对象、字段缺失或多余、`body`/`signature` 类型
  错误、凭证必含字段缺失或类型错误，一律 **400**，响应**仅** `{error}`。
- 签名为 **ES256/SHA-256**、64 字节裸 `R||S` 的无填充 base64url，覆盖
  **完整 `body`**（省略 `issuer_key_version` 时不注入正文）。公钥取本
  租户匹配 `(issuer_did, issuer_key_version)` 且 **active** 的锚点；
  锚点缺失/已吊销、锚点公钥不可用、签名格式错误、密码学验签失败、
  `expires_at` 已到期，均返回 **HTTP 200** 与
  `{"valid":false,"reason":...}`（`reason` 为非空中文，前缀依次为
  **锚点**/**签名格式错误**/**签名校验失败**/“凭证已过期”），且
  **不写入、不记审计**。
- 验签通过后按 `(tenant, issuer_did, credential_id)` 双键持久化：
  - **首次导入**返回 **201**，响应键序恰为
    `imported,issuer_did,credential_id,body,signature`，`imported` 恒为
    `true`，`body`/`signature` 为提交原文；
  - **相同内容重放**（`body` 与 `signature` 全等）返回 **200**，响应体
    与首次完全一致，不替换、**不重复审计**；
  - **不同内容**（`body` 或 `signature` 任一不一致）返回 **409**，响应
    **仅** `{error}`，不写入、不记审计，已保存原文保持不变。
- 首次导入记 `trust.credential.imported`，`resource_type` 为
  `imported_credential`、`resource_id` 为 `<issuer_did>#<credential_id>`；
  保存与审计经同一把锁内**同一次原子写**落盘，失败回滚。
- `GET /v1/trust/credentials/imported/{credential_id}?issuer_did=...`：
  `issuer_did` 查询参数**必须提供且唯一、非空**（缺失/重复/空值
  **400**）；成功 **200**，响应键序恰为
  `issuer_did,credential_id,body,signature`；未导入、**跨租户**或
  `issuer_did` 与保存值不匹配一律 **404**（存在性不可探测）。纯只读，
  不写状态、不记审计；记录随状态文件持久化，**重启后可读**。
- `POST /v1/trust/credentials/imported/{credential_id}/verify?issuer_did=...`
  在服务**重启后重新验证已落盘凭证**，import 与 GET 行为均不改变：
  - `X-Tenant-ID` 缺省 `default`，显式空值在进入处理前判 **400**。
  - `issuer_did` 查询参数**必须提供且唯一、非空**；缺失、重复或空值
    一律 **400**，响应恰为 `{"error":"<非空中文原因>"}`。
  - 请求体**必须恰为 `{}`**：缺失（空体）、非法 JSON、JSON 非对象或含
    任意字段一律 **400** 且仅 `{error}`。
  - 按**当前租户、`issuer_did`、`credential_id`** 双键查找导入记录；
    记录不存在、`issuer_did` 错配或属他租户一律 **404**（跨租户/
    存在性不可探测）。
  - 取存储的 **`body`、`signature` 原文**：`issuer_key_version` 缺省
    按 **1**，用**同 DID/版本且 active** 的本租户锚点公钥，对完整
    `body` 做递归键升序紧凑 UTF-8 JSON 的 **ES256** 验签；签名须为
    **无填充 base64url 的 64 字节裸 `R||S`**。
  - 锚点缺失或 revoked（或锚点公钥不可用）返回 **HTTP 200**、恰为
    `{"valid":false,"reason":"锚点不可用"}`；签名编码非法时 reason
    恰为 **“签名格式错误”**，密码学验签失败时恰为 **“签名校验失败”**；
    `body` 含 `expires_at` 且当前时间达到（`>=`）时恰为 **“凭证已过期”**
    （签名等先置失败优先于过期，与外部凭证验真一致）。验签成功仅返回
    `{"valid":true}`（无其他字段）。
  - 接口为**纯只读**：不写导入记录、状态、历史或审计，不泄露私钥；
    锚点吊销、服务重启以及他租户查询的结论均稳定（他租户恒 404）。

```bash
curl -X POST "/v1/trust/credentials/imported/vc_ext_1/verify?issuer_did=did:web:example.com" \
  -H 'Content-Type: application/json' -d '{}'
```
- `POST /v1/trust/credentials/imported/{credential_id}/verify-with-status?issuer_did=...`
  在重验已落盘凭证的基础上**只读合并本租户同步状态**，import、GET、
  单项重验与 CLI 行为均不改变：
  - 请求级规则与单项重验**完全一致**：`X-Tenant-ID` 缺省 `default`、
    显式空值在进入处理前判 **400**；`issuer_did` 必须唯一、非空，
    缺失/重复/空值 **400** 仅 `{error}`；请求体须恰为 `{}`，空体、
    非法 JSON、非对象或含任意字段 **400** 仅 `{error}`；记录不存在、
    `issuer_did` 错配或属他租户 **404** 仅 `{error}`。
  - 取存储的 **`body`、`signature` 原文**复用单项重验：
    `issuer_key_version` 缺省按 **1**，递归键升序紧凑 UTF-8 JSON 的
    **ES256** 裸 `R||S` 验签。锚点不可用、签名格式错、验签失败、凭证
    过期均 **HTTP 200** 返回 `{"valid":false,"reason":...}`，reason
    恰为“锚点不可用”/“签名格式错误”/“签名校验失败”/“凭证已过期”。
  - 重验成功后按当前租户 `(issuer_did, credential_id)` 双键只读查询
    `credential_status_sync` 同步记录：未同步
    `{"valid":false,"reason":"外部凭证状态未同步"}`；active 仅
    `{"valid":true}`；revoked 为
    `{"valid":false,"reason":"外部凭证已吊销：<保存 reason>"}`，保存
    reason 为空串或缺失时固定“未知原因”；unknown 为
    `{"valid":false,"reason":"外部凭证状态未知"}`。
  - 失败响应键序固定 `valid,reason`；纯只读，不写记录、状态、历史或
    审计；结论随状态文件跨重启稳定，跨租户恒 404。

```bash
curl -X POST "/v1/trust/credentials/imported/vc_ext_1/verify-with-status?issuer_did=did:web:example.com" \
  -H 'Content-Type: application/json' -d '{}'
```
- `X-Tenant-ID` 缺省 `default`，显式空值在进入处理前判 **400**。
- `POST /v1/trust/credentials/imported/verify-batch-with-status`
  **批量重验已导入凭证并合并本租户同步状态**，import、GET、单项重验
  与 CLI 行为均不改变，接口为**纯只读**：
  - `X-Tenant-ID` 缺省 `default`，显式空值在进入处理前判 **400**。
  - 请求体**恰为 `{"items":[项...]}`**：每项须恰含 `issuer_did`、
    `credential_id` 且均为非空字符串；`items` 必须为非空数组且不超过
    **100** 项。请求体缺失、非法 JSON、非对象、字段缺失或多余、
    `items` 非数组/空/超 100 项等请求级错误，一律 **HTTP 200** 返回
    `{"results":[],"reason":"请求..."}`。
  - 合法批次返回 `{"results":[...]}`，与输入**等长同序**、不短路，无
    请求级 `reason`；每项键序固定为 `valid,http_status,reason`。
  - 项非法（非对象、字段缺失或多余、字段非非空字符串）为
    `{"valid":false,"http_status":400,"reason":"请求项非法"}`；记录
    不存在或跨租户（存在性不可探测）为
    `{"valid":false,"http_status":404,"reason":"资源不存在"}`。
  - 找到记录后复用单项重验规则：锚点缺失/吊销、签名格式错、验签
    失败、凭证过期均 `http_status=200`，reason 恰为
    “锚点不可用”/“签名格式错误”/“签名校验失败”/“凭证已过期”。
  - 重验成功后**只读查询**本租户 `credential_status_sync` 同步记录：
    未同步 `false,200,"外部凭证状态未同步"`；active
    `{"valid":true,"http_status":200,"reason":null}`；revoked
    `false,200,"外部凭证已吊销：<保存 reason>"`（空原因用“未知原因”）；
    unknown `false,200,"外部凭证状态未知"`。
  - 不写记录、同步状态、历史或审计；结论随状态文件**跨重启稳定**。

```bash
curl -X POST localhost:8080/v1/trust/credentials/imported/verify-batch-with-status \
  -H 'Content-Type: application/json' \
  -d '{"items":[{"issuer_did":"did:web:example.com","credential_id":"vc_ext_1"}]}'
```

```bash
curl -X POST localhost:8080/v1/trust/credentials/import -d '{
  "body":{"credential_id":"vc_ext_1","issuer_did":"did:web:example.com",
          "subject_did":"did:web:subject","claims":{...},
          "issued_at":"2026-09-21T00:00:00Z","issuer_key_version":1},
  "signature":"<base64url R||S>"}'
curl "localhost:8080/v1/trust/credentials/imported/vc_ext_1?issuer_did=did:web:example.com"
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
  | DID 停用（首次与幂等重试均记） | `did.deactivated` | `did` |
  | 签发凭证 | `credential.issued` | `credential` |
  | 密钥轮换 | `key.rotated` | `did` |
  | 密钥版本吊销（首次与幂等重试均记） | `key.revoked` | `did` |
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
  | 外部凭证首次导入（相同重放、不同内容冲突、锚点/签名失败不记） | `trust.credential.imported` | `imported_credential` |

  信任锚点审计 `resource_id` 为 `<did>#<key_version>`（轮换取目标版本
  `from_key_version+1`）；注册冲突 409、轮换冲突 409/校验失败 400、
  验签（成功或失败）等只读或失败路径不记审计。密钥版本吊销审计
  `resource_id` 同样为 `<did>#<key_version>`；400/404/409 不记。外部凭证状态同步审计
  `resource_id` 为 `<issuer_did>#<credential_id>`；锚点/签名失败、
  400/409、相同重放与更早日均不记。外部凭证导入审计
  `resource_id` 同样为 `<issuer_did>#<credential_id>`；锚点/签名失败、
  400/409 与相同重放不记。

  验签失败、演示已消费、演示过期、凭证过期、凭证/演示吊销判定等**只读或失败
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
python3 tests/did_document_test.py
python3 tests/did_deactivation_test.py
python3 tests/key_revocation_test.py
python3 tests/key_revocation_status_history_test.py
python3 tests/key_lifecycle_history_test.py
python3 tests/credential_status_history_test.py
python3 tests/credential_expiry_test.py
python3 tests/tenant_audit_test.py
python3 tests/trust_anchor_test.py
python3 tests/trust_anchor_rotate_test.py
python3 tests/trust_anchor_history_test.py
python3 tests/predicate_proof_test.py
python3 tests/holder_binding_test.py
python3 tests/trust_credential_verify_test.py
python3 tests/trust_did_document_verify_test.py
python3 tests/trust_did_deactivation_sync_test.py
python3 tests/trust_presentation_verify_test.py
python3 tests/trust_proof_verify_test.py
python3 tests/trust_proof_verify_batch_test.py
python3 tests/trust_credential_verify_with_status_test.py
python3 tests/trust_credential_status_sync_test.py
python3 tests/trust_credential_status_history_test.py
python3 tests/trust_credential_import_test.py
python3 tests/trust_credential_imported_verify_test.py
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
  models.py    DIDRecord / DIDStatusRecord / CredentialRecord / CredentialStatusRecord /
               LocalCredentialStatusHistoryEvent /
               KeyVersionStatusRecord / KeyRevocationEvent /
               KeyLifecycleEvent /
               PresentationRecord / PredicateProofRecord /
               TrustAnchorRecord / CredentialStatusSyncRecord /
               CredentialStatusHistoryEvent / TrustAnchorHistoryEvent /
               AuditEvent 数据模型
  store.py     多租户文件存储（租户分桶、旧格式迁移）、DID 去重、DID
               生命周期停用（终态 deactivated、首次/幂等原子审计、
               轮换/签发/present/prove 409 拦截与验签后停用判定）、密钥
               轮换、DID 旧密钥版本吊销（当前版本 409、重复忽略 reason、
               原子审计与验真端签发/持有者密钥吊销判定）、
               DID 文档只读查询（历史公钥与当前版本私钥证明）、密钥版本
               状态与吊销历史只读查询（租户内持久化游标、旧吊销状态
               加载补兼容事件、追加与分页）、密钥生命周期历史只读查询
               （新建/轮换 active 与首次吊销 revoked、租户内跨 DID
               独立持久化游标并与吊销历史隔离、关联审计同秒、旧状态按
               DID/版本序补 active+revoked 兼容事件、追加与分页）、凭证签发/验签、选择性披露演示（RFC6901 路径校验、
               claims 投影）、谓词证明（谓词校验/求值、results 重算）、
               消费锁内复查过期，信任锚点注册/吊销/验签/
               带前置版本校验的轮换/生命周期历史（租户内跨 DID
               共享持久化游标、旧锚点加载按版本补注册/轮换/吊销事件、
               追加与分页）、跨系统外部凭证验真（含合并同步状态
               的只读判定）、跨系统 DID 文档验真（仅凭提交文档的
               结构/证明/信任判断、active 锚点同 DID 同版本且公钥
               原文匹配、验真成功后查外部 DID 停用通告、只读不登记）、
               外部 DID 停用通告登记（恰含四字段的 body 校验、active
               锚点 ES256 验签、按租户+did 原子持久化、完全重放幂等、
               异通告冲突、失败不写入）、跨系统外部演示验真（未绑定九字段、
               挑战一致性与期限判定）、跨系统外部谓词证明验真
               （九字段与 predicates/results 结构校验、不重算 results、
               tenant_id=source_tenant_id 规范化验签、期限判定，只读不消费）、
               批量跨系统谓词证明验真（逐项复用单项规则、失败不短路、
               只读不消费）、
               外部凭证状态
               同步（双键隔离、严格更新、重放幂等、原子审计）、外部凭证
               状态历史（持久化游标、旧状态兼容补项、追加与查询）、
               本地凭证状态登记/吊销与状态历史（仅首次 active/revoke
               追加、租户内跨凭证共享持久化游标、旧状态加载补兼容事件、
               updated_at/cursor 排序与分页、与状态及审计同锁原子落盘），以及
               全局连续审计事件与状态变更的同一次原子写（失败回滚）
  service.py   标准库 HTTP 路由、X-Tenant-ID 租户解析、/v1/audit、
               /v1/dids/{did}/deactivate、/v1/dids/{did}/status、
               /v1/dids/{did}/document、
               /v1/dids/{did}/keys/{ver}/status、
               /v1/dids/{did}/keys/revocations、
               /v1/dids/{did}/keys/history、
               /v1/credentials/{id}/status/history、
               /v1/trust/anchors/{did}/history、
               /v1/trust/credential-status/{id}/history 与错误映射
  cli.py       did-create / did-show / issue / verify / serve
tests/e2e_test.py                  端到端测试（默认租户，全协议兼容）
tests/did_document_test.py         DID 文档只读接口（字段/升序/不暴露私钥、
                                   document_proof 恒由当前版本签发、version
                                   参数 400/404、租户隔离、只读不审计、
                                   重启验签稳定、旧状态迁移公开版本 1）
tests/did_deactivation_test.py     DID 生命周期停用（空体/{}与恰含 reason、
                                   400/404、首次/幂等返回首次值、active
                                   null/null、did.deactivated 审计与失败不记、
                                   轮换/签发/present/prove 409 不写、验签后
                                   “签发DID已停用”优先于有效期/吊销且失败
                                   不消费、签名失败原分类优先、历史文档/公钥/
                                   凭证仍可读、跨租户隔离、重启稳定、
                                   落盘失败状态与审计共同回滚）
tests/credential_expiry_test.py    凭证有效期（签发 400/不注入/参与签名、
                                   verify 过期原因与优先级/不记审计、演示与
                                   谓词证明拒签不消费、外部凭证验真、重启持久化）
tests/key_revocation_test.py       DID 旧密钥版本吊销（400/404/409、空体/{}
                                   与恰含 reason、首次/幂等返回、key.revoked
                                   审计与失败不记、document 历史保留、凭证/演示/
                                   谓词证明验签后的签发/持有者密钥吊销顺序、
                                   已消费/过期优先、失败不消费、present/prove
                                   400 不留记录、旧凭证按版本 1、租户隔离、
                                   重启保留、落盘失败回滚）
tests/key_revocation_status_history_test.py DID 密钥版本状态与吊销历史
                                   （status active null/null、revoked 首次原因/
                                   时间、路径版本 400、DID/版本/跨租户 404；
                                   历史字段与 cursor 租户内跨 DID 递增、重复与
                                   失败吊销不追加、limit/after 分页与空页保持、
                                   各类非法参数 400、未知/跨租户 404、空 DID
                                   空页、只读不审计、重启 cursor 稳定、旧吊销
                                   状态补兼容事件且无写重启 cursor 稳定、
                                   首次吊销落盘失败状态/历史/游标/审计全回滚）
tests/key_lifecycle_history_test.py DID 密钥生命周期历史（200 恰含
                                   did/events/next_after、事件恰九字段
                                   按 cursor 升序且禁止私钥；新建/轮换
                                   active 与首次吊销 revoked 追加且
                                   updated_at 与审计同秒，重复/失败/
                                   幂等不追加、active 不改写；游标租户内
                                   跨 DID 递增、租户独立且与吊销历史
                                   隔离；limit/after 分页与各类非法参数
                                   400、未知/跨租户 404、空租户头 400、
                                   只读不审计；重启 cursor 稳定；旧状态
                                   按 DID/版本序补 active 后 revoked
                                   （v1 取 created_at、其余 active 与缺
                                   revoked_at 的 revoked 为 null、
                                   audit null）且无写重启 cursor 稳定；
                                   轮换/吊销落盘失败版本/历史/游标/审计
                                   全回滚）
tests/credential_status_history_test.py 本地凭证状态历史（首次 active
                                   与首次 revoke 各追加、重复与失败路径
                                   不追加；active null/null、revoked 裁剪
                                   reason/revoked_at；字段恰含与审计关联、
                                   updated_at/cursor 排序；cursor 租户内跨
                                   凭证递增且租户独立；limit/after 分页、
                                   空页保持与各类非法参数 400；未知/跨租户
                                   404、有凭证无状态空页、显式空租户头 400、
                                   只读不审计；重启 cursor 与审计关联稳定；
                                   旧状态按稳定顺序补兼容事件（audit null）
                                   且无写重启 cursor 稳定；首次 active/revoke
                                   落盘失败状态/历史/游标/审计全回滚）
tests/tenant_audit_test.py         租户隔离 / 审计 / 过期竞态测试
tests/trust_anchor_test.py         信任锚点注册/查询/吊销/验签测试
tests/trust_anchor_rotate_test.py  信任锚点密钥轮换（400/404/409/幂等/审计/重启）
tests/trust_anchor_history_test.py 信任锚点生命周期历史（注册/轮换 active
                                   与首次吊销 revoked 事件、动作名沿用审计、
                                   幂等重试与失败不追加、字段恰含与 cursor
                                   租户内跨 DID 递增、limit/after 分页与
                                   空页保持、各类非法参数 400、未知/跨租户
                                   404、空租户头 400、只读不审计、重启 cursor
                                   稳定、旧状态按版本补注册/轮换/吊销事件且
                                   无写重启 cursor 稳定、落盘失败锚点/历史/
                                   游标/审计共同回滚、列表/验真/幂等响应不变）
tests/predicate_proof_test.py      谓词证明（prove 字段/400/404、verify 消费/
                                   过期/篡改/跨租户/并发/审计/重启）
tests/holder_binding_test.py       演示持有者绑定（未绑定兼容、绑定 201 字段/
                                   holder_proof 外部验真/issuer proof 不变、
                                   holder_binding 非布尔 400、未注册 400、
                                   verify 缺字段/篡改/格式/跨租户/密钥不可用
                                   valid:false 不消费、过期/吊销、持有者密钥
                                   轮换后历史公钥验证、并发仅一次、重启持久化）
tests/trust_credential_verify_test.py  跨系统凭证验真（请求/凭证/锚点/
                                   签名格式/验签分类 reason、省略版本不注入、
                                   扩展字段参与签名、只读不记审计、跨租户/重启）
tests/trust_did_document_verify_test.py 跨系统 DID 文档验真（成功与跨系统
                                   提交原文、请求/文档结构/版本升序无重复/
                                   非布尔正整数/P-256 PEM/禁止私钥/当前版本
                                   最高、锚点缺失/跨租户/吊销/公钥不匹配、
                                   签名格式/验签/证明覆盖范围分类 reason、
                                   显式空租户头 400、只读不审计不登记、
                                   重启结论稳定、既有接口不变）
tests/trust_did_deactivation_sync_test.py 外部 DID 停用通告（请求/body
                                   四字段 400 仅 error、锚点不可用/签名格式
                                   错误/签名校验失败 200 不写入、首次 201
                                   键序、完全重放 200、异通告 409、
                                   verify-document 命中“外部DID已停用”、
                                   跨租户隔离、显式空租户头 400、重启稳定）
tests/trust_did_deactivations_test.py 外部 DID 停用通告审计查询（六参数
                                   严格校验/重复/空值/未知/范围 400 仅
                                   error、首次接受原子追加、重放/失败/冲突
                                   与批量非首次项不追加、did/key_version
                                   精确与 deactivated_at 闭区间过滤、
                                   cursor 升序分页与空页 next_after、
                                   键序与类型、租户隔离、旧通告按
                                   deactivated_at,did 补录、迁移与重启
                                   cursor 稳定）
tests/trust_presentation_verify_test.py 跨系统演示验真（请求/演示字段/holder_*
                                   拒绝/挑战/锚点/签名格式/验签/过期分类 reason、
                                   恰九字段与类型、只读不记审计、跨租户/重启）
tests/trust_proof_verify_test.py   跨系统谓词证明验真（请求/证明九字段/
                                   predicates 与 results 结构、不重算 results、
                                   不校验 claims 命中与数组路径、挑战/锚点/
                                   签名格式/验签 tenant_id/过期分类 reason、
                                   只读不消费不审计、跨租户/重启）
tests/trust_proof_verify_batch_test.py 批量跨系统谓词证明验真（请求级非法
                                   统一 results:[]+请求原因、1–100 项边界、
                                   混合批次逐项分类 reason 不短路、长度顺序
                                   一致、不重算 results、只读不消费不审计、
                                   跨租户/重启结论稳定、单项接口不受影响）
tests/trust_credential_verify_with_status_test.py  外部凭证验真并合并状态
                                   判定（未同步/active/revoked/unknown 四分支、
                                   无 reason 用“未知原因”、验真与过期优先级、
                                   省略版本与扩展字段沿用验真规则、只读不审计
                                   不改同步记录、租户隔离与显式空值 400、重启持久化）
tests/trust_credential_status_sync_test.py  外部凭证状态同步（请求/字段 400、
                                   锚点/签名格式/验签分类 reason、201/200/409、
                                   严格更新与更早日忽略、重放不重复审计、
                                   GET 三字段/404、跨租户双键隔离、不改本地
                                   凭证状态、重启持久化、落盘失败回滚）
tests/trust_credential_status_sync_batch_test.py  外部凭证状态批量同步
                                   （请求级非法 200+results 空+请求原因、
                                   items 1–100、逐项 201/200/400/409/验签
                                   失败不短路、成功/失败键序、同批顺序效应、
                                   results 等长同序、审计计数、租户隔离、
                                   不改本地凭证、重启持久化、落盘失败回滚、
                                   显式空租户 400）
tests/trust_credential_status_history_test.py  外部凭证状态历史（追加规则：
                                   仅首次/严格更新追加，重放/更早/冲突/验签
                                   失败不追加；字段与审计关联、updated_at/
                                   cursor 排序、limit/after 分页与空页保持、
                                   各类非法参数 400、双键 404、租户隔离、
                                   只读不审计、重启 cursor 持久化、旧状态补
                                   兼容项 audit 为 null、落盘失败回滚）
tests/trust_credential_imported_verify_test.py 已导入外部凭证重新验证
                                   （POST .../imported/{id}/verify：
                                   issuer_did 缺/重/空 400、空体/非法 JSON/
                                   非对象/非恰 {} 400、未导入/错配/跨租户
                                   404、显式空租户头 400；存储 body/signature
                                   原文按缺省 v1/指定版本的 active 锚点
                                   ES256 验签，锚点缺失或吊销/签名格式错/
                                   验签失败/过期均 200 且原因恰为锚点不可用/
                                   签名格式错误/签名校验失败/凭证已过期；
                                   成功仅 {valid:true}；只读不记审计、
                                   导入原文不变、轮换/吊销后版本结论稳定、
                                   重启后篡改与过期结论稳定、default 缺省租户）
tests/trust_credential_imported_verify_with_status_test.py 已导入外部凭证
                                   重验并合并同步状态
                                   （POST .../imported/{id}/verify-with-status：
                                   issuer_did 缺/重/空 400、空体/非法 JSON/
                                   非对象/非恰 {} 400、未导入/错配/跨租户
                                   404、显式空租户头 400；复用存储 body/
                                   signature 原文按 active 锚点 ES256 重验，
                                   锚点不可用/签名格式错/验签失败/过期均
                                   200 且原因固定；重验成功后合并同步状态——
                                   未同步/active/revoked（空原因固定未知原因）
                                   /unknown 结论固定；失败键序 valid,reason；
                                   只读不记审计、跨租户隔离、重启结论稳定、
                                   default 缺省租户、单项重验与 CLI 行为不变）
```
