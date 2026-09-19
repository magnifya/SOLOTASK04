# SOLOTASK04

可验证凭证后端。Python 加 cryptography，对外提供 HTTP 服务与命令行入口，两者能力一致。

## 运行

    python -m app --port <port>      # 启动 HTTP 服务
    python -m app <subcommand>       # 命令行入口，输出单行 JSON

## 公开接口

POST /v1/dids
  请求：method、public_key
  成功：201 -> did（did:example 形式标识）、public_key
  同一公钥重复提交：返回既有 DID
  缺少公钥：400

GET /v1/dids/{did}
  成功：200 -> public_key、created_at
  不存在：404

POST /v1/credentials
  请求：issuer_did、subject_did、claims
  成功：201 -> credential_id、signature
  任一 DID 不存在：400，需指明是哪一个

GET /v1/credentials/{credential_id}
  成功：200 -> 凭证正文、signature
  不存在：404

## 约定

- 凭证正文任一字段被改动后签名校验必须失败
- 校验结论由命令行子命令输出，失败时需说明原因
- 验证方不得依赖本地私有状态，验签所用公钥须现取

## 当前状态

接口尚未实现；实现完成后需在此补充安装依赖、启动方式与基础测试命令。
