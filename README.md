# SOLOTASK04 可验证凭证后端

要实现一个可验证凭证后端，用 Python 加 cryptography，同时提供 HTTP 服务和命令行入口。DID 注册走 POST /v1/dids，请求体是 JSON，含 method 与 public_key 两个字符串字段，返回 201 与 did 和 public_key，did 形如 did:example 加标识；同一 public_key 再次提交返回其既有 DID；缺少字段返回 400 并说明原因。查询走 GET /v1/dids/{did}，返回 public_key 与 created_at，不存在返回 404。凭证签发走 POST /v1/credentials，请求体是 JSON，含 issuer_did、subject_did 与 claims 对象；用 ES256 对凭证正文签名，签名覆盖正文按 key 升序的规范化 JSON 序列化结果；返回 201 与 credential_id 和 signature；任一 DID 不存在返回 400 并指明是哪一个。查询走 GET /v1/credentials/{credential_id}，返回正文与 signature，不存在返回 404。命令行提供 did-create、did-show、issue 与 verify 四个子命令，verify 用签发者现取的公钥校验，成功输出 true，正文被改动则输出 false 并说明原因。

## 当前状态

上述接口尚未实现。实现完成后，请在此补充安装依赖、启动方式与基础测试命令。
