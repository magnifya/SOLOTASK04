"""数据模型定义。"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class DIDRecord:
    """一条 DID 注册记录。

    key_mode 目前仅支持 "server"（服务端托管密钥）；key_handle 为注册/轮换
    时提交的句柄；key_version 为当前密钥版本（自 1 起，轮换递增）。
    """

    did: str
    method: str
    public_key: str
    created_at: str
    key_mode: str = "server"
    key_handle: str = ""
    key_version: int = 1


@dataclass
class DIDStatusRecord:
    """一条 DID 生命周期状态记录（active/deactivated）。

    active 时 reason/updated_at 均为 None；deactivated 时 reason 为首次
    停用的裁剪后非空原因（缺省“DID 主动停用”），updated_at 为首次停用
    时间（UTC ISO8601 秒精度 Z 结尾），重复停用保持首次值不变。
    """

    did: str
    status: str
    reason: Optional[str] = None
    updated_at: Optional[str] = None


@dataclass
class KeyVersionStatusRecord:
    """一条 DID 密钥版本吊销记录。

    did 为所属 DID；key_version 为被吊销的历史密钥版本（自 1 起，
    必为旧版本，当前版本不可吊销）；status 恒为 "revoked"；reason 为
    裁剪后非空的吊销原因；updated_at/revoked_at 为首次吊销时间（UTC
    ISO8601 秒精度 Z 结尾）。
    """

    did: str
    key_version: int
    status: str
    reason: str
    updated_at: str


@dataclass
class KeyRevocationEvent:
    """DID 密钥吊销历史中的一条事件（只读吊销历史查询用）。

    按 (租户, did) 归属；仅首次成功吊销追加。cursor 为租户内持久化
    正整数，按追加顺序单调递增；同一租户内不同 DID 的吊销事件共享
    同一游标空间。updated_at 为首次吊销时间（UTC ISO8601 秒精度 Z）。
    """

    key_version: int
    reason: str
    updated_at: str
    cursor: int


@dataclass
class KeyLifecycleEvent:
    """DID 密钥生命周期历史中的一条事件（只读历史查询用）。

    按 (租户, did) 归属；新版本创建追加 active（v1 为 did.created，
    轮换为 key.rotated），首次吊销追加 revoked（key.revoked）；重复、
    失败与幂等请求不追加，active 历史不改写。action 沿用对应审计动作名。
    key_handle/public_key 为该版本的句柄与 P-256 公钥 PEM（绝不包含
    私钥）；updated_at 为 active 的创建/轮换成功时刻或 revoked 的首次
    吊销时间（UTC ISO8601 秒精度 Z），旧状态补录的非 v1 active 为
    None；audit_seq/audit_timestamp 关联产生该事件的审计事件，旧状态
    补录无法追溯时为 None。cursor 为租户内跨 DID 持久递增正整数，与
    吊销历史游标空间相互隔离。
    """

    key_version: int
    key_handle: str
    public_key: str
    action: str
    status: str
    updated_at: Optional[str]
    cursor: int
    audit_seq: Optional[int] = None
    audit_timestamp: Optional[int] = None


@dataclass
class DIDHistoryEvent:
    """DID 生命周期历史中的一条事件（只读历史查询用）。

    按 (租户, did) 归属；注册追加 did.created（active、reason/updated_at
    为 None），首次停用追加 did.deactivated（status=deactivated、reason
    为首次裁剪原因、updated_at 为首次停用 UTC ISO8601 秒精度 Z 时间）。
    同句柄幂等注册、重复停用与失败路径不追加。audit_seq/audit_timestamp
    关联产生该事件的审计事件（did.created / did.deactivated），且
    audit_timestamp 与 updated_at 为同一秒；旧状态补录无法追溯时为 None。
    cursor 为租户内跨 DID 持久递增正整数，独立于密钥等其他历史游标空间。
    """

    action: str
    status: str
    reason: Optional[str]
    updated_at: Optional[str]
    cursor: int
    audit_seq: Optional[int] = None
    audit_timestamp: Optional[int] = None


@dataclass
class CredentialSchemaRecord:
    """一条凭证模式（约束）注册记录（按租户与 issuer_did#schema_id#version 隔离）。

    schema_id 仅含小写字母、数字、下划线或连字符且以字母开头（长度
    1..64）；version 为正整数；issuer_did 为同租户活动 DID；
    claim_types 将 1..100 个 RFC6901 路径（相对 claims，须以 / 开头、
    禁根/数组索引）映射到 string/number/integer/boolean/object/array；
    required_claims 为其键的不重复子集。digest 为注册内容
    {schema_id,version,issuer_did,claim_types,required_claims}
    规范化 JSON 的 SHA-256 小写十六进制，同内容重复注册据此幂等。
    """

    schema_id: str
    version: int
    issuer_did: str
    claim_types: Dict[str, str]
    required_claims: List[str]
    digest: str


@dataclass
class CredentialSchemaStatusRecord:
    """一条凭证模式版本的生命周期状态（按租户与 issuer#schema#version 隔离）。

    status 为 "active"、"deprecated" 或 "revoked"：注册即为 active，
    active 可转 deprecated，active/deprecated 可转 revoked，均不可恢复。
    active 时 reason/updated_at 均为 None；deprecated/revoked 时 reason
    为首次变更的裁剪原因（缺省分别为“模式版本已弃用”“模式版本已吊销”），
    updated_at 为首次变更的 UTC 秒精度 Z 时间（与审计同秒）。
    """

    schema_id: str
    version: int
    issuer_did: str
    status: str
    reason: Optional[str]
    updated_at: Optional[str]


@dataclass
class CredentialSchemaHistoryEvent:
    """模式版本生命周期历史中的一条事件（注册/弃用/吊销）。

    按 cursor 升序；注册事件 action 为 credential.schema.registered、
    status 为 active、reason 为 None；弃用/吊销分别为
    credential.schema.deprecated/revoked。补录事件 audit_seq/
    audit_timestamp 为 None。
    """

    action: str
    status: str
    reason: Optional[str]
    updated_at: Optional[str]
    cursor: int
    audit_seq: Optional[int] = None
    audit_timestamp: Optional[int] = None


@dataclass
class CredentialRecord:
    """一条已签发凭证：正文与其 ES256 签名。"""

    credential_id: str
    body: Dict[str, Any]
    signature: str


@dataclass
class CredentialStatusRecord:
    """凭证状态登记记录。

    status 为 "active"、"suspended" 或 "revoked"；updated_at 为最近
    一次状态登记/变更时间（UTC ISO8601 秒精度 Z），历史无状态凭证查询
    时为 None。suspended 时附带 reason（裁剪后 1..256 码点的暂停原因，
    revoked_at 为 None）；revoked 时附带 reason（裁剪后的吊销原因）与
    revoked_at；active 时 reason/revoked_at 均为 None。
    """

    credential_id: str
    status: str
    updated_at: Optional[str]
    reason: Optional[str] = None
    revoked_at: Optional[str] = None


@dataclass
class PresentationRecord:
    """一条选择性披露演示记录。

    disclose 为命中 claims 的 RFC6901 指针列表（相对 claims，"[]" 时为
    零披露空列表）；projection 为按 disclose 重算出的 claims 投影；
    proof 为覆盖除 proof 外规范化 JSON 的 ES256 签名（base64url 无填充），
    使用凭证签发时 issuer_key_version 对应的历史私钥。
    challenge/expires_at 为防重放字段（旧演示记录没有，为 None）：
    challenge 为挑战串，expires_at 为过期时间（UTC、Z 结尾、秒精度），
    二者均随演示一起签名并持久化。
    """

    presentation_id: str
    credential_id: str
    issuer_did: str
    issuer_key_version: int
    disclose: list
    projection: Dict[str, Any]
    proof: str
    challenge: Optional[str] = None
    expires_at: Optional[str] = None
    # 验证方展示请求模式：request_id 为该演示应答的展示请求标识，
    # 随演示一起被 issuer proof（及绑定时 holder_proof）覆盖并持久化；
    # 非请求模式演示为 None。
    request_id: Optional[str] = None
    # 可选持有者绑定（holder_binding=true 时写入并持久化）：
    # holder_did 为持有者（即凭证 subject_did）；holder_key_version 为
    # 生成绑定时持有者的当前密钥版本；holder_proof 为持有者私钥对
    # （去掉 proof、holder_proof 后的演示对象 + tenant_id）的 ES256
    # 裸 R||S 无填充 base64url 签名。未绑定演示三者均为 None。
    holder_did: Optional[str] = None
    holder_key_version: Optional[int] = None
    holder_proof: Optional[str] = None


@dataclass
class PresentationRequestRecord:
    """一条验证方展示请求记录（按租户隔离）。

    challenge 为验证方给出的非空挑战串；expires_at 为请求过期时间
    （UTC、Z 结尾、秒精度）；disclose 为要求的披露路径（空列表表示
    零披露）；issuer_dids 为限定的签发者 DID 列表（None 表示不限定）；
    holder_binding 为是否要求持有者绑定；status 为 pending/consumed，
    仅验证成功（valid true）时置为 consumed。
    """

    request_id: str
    challenge: str
    expires_at: str
    disclose: list
    issuer_dids: Optional[List[str]]
    holder_binding: bool
    status: str


@dataclass
class MultiPresentationItem:
    """多凭证组合展示中的单个凭证投影项。

    disclose 为命中该凭证 claims 的 RFC6901 指针列表（"[]" 时为零
    披露空列表）；projection 为按 disclose 重算出的 claims 投影；
    proof 为覆盖组合层 challenges/expires_at 与本项投影的签发 ES256
    签名（base64url 无填充），使用该凭证签发时 issuer_key_version
    对应的历史私钥。
    """

    credential_id: str
    issuer_did: str
    issuer_key_version: int
    disclose: list
    projection: Dict[str, Any]
    proof: str


@dataclass
class MultiPresentationRecord:
    """一条多凭证组合展示记录。

    items 为按请求顺序排列的凭证投影项（见 MultiPresentationItem）；
    challenge 为全组合统一挑战串，expires_at 为统一过期时间（UTC、Z
    结尾、秒精度），二者随组合一起被各项签发证明与可选持有者证明
    覆盖并持久化；presentation_id 为 mvp_ 加 32 位小写 hex。

    holder_binding 为 True 时，各凭证 subject_did 必须相同且均为本
    租户已注册 DID，holder_did/holder_key_version/holder_proof 为
    该持有者的统一绑定信息（与单凭证演示同构）；未绑定时三者为 None。
    """

    presentation_id: str
    items: List[MultiPresentationItem]
    challenge: str
    expires_at: str
    holder_did: Optional[str] = None
    holder_key_version: Optional[int] = None
    holder_proof: Optional[str] = None


@dataclass
class PredicateProofRecord:
    """一条谓词证明记录。

    predicates 为原样回显的谓词列表（每项 {path, op[, value]}，路径为
    相对 claims 的 RFC6901 指针）；results 为与 predicates 同序的布尔
    结果；challenge/expires_at 为防重放字段；proof 为覆盖除 proof 外
    字段（含 tenant_id）规范化 JSON 的 ES256 签名（base64url 无填充），
    使用凭证签发时 issuer_key_version 对应的历史私钥。
    """

    proof_id: str
    credential_id: str
    issuer_did: str
    issuer_key_version: int
    predicates: list
    results: list
    challenge: str
    expires_at: str
    proof: str


@dataclass
class TrustAnchorRecord:
    """一条信任锚点记录（按租户隔离）。

    did 为锚点标识；public_key 为注册的 P-256 PEM 公钥；key_version
    为正整数版本；status 为 active/revoked；updated_at 为首次吊销时间
    （UTC ISO8601 秒精度），未吊销时为 None。
    """

    did: str
    public_key: str
    key_version: int
    status: str = "active"
    updated_at: Optional[str] = None


@dataclass
class TrustAnchorHistoryEvent:
    """信任锚点生命周期历史中的一条事件（只读历史查询用）。

    按 (租户, did) 归属；仅新版本注册、轮换目标版本与首次吊销追加。
    action 沿用既有审计动作名（trust.anchor.registered /
    trust.anchor.rotated / trust.anchor.revoked）；status 为追加时的
    版本状态（active/revoked）；active 事件 updated_at 为 None，revoked
    事件为首次吊销时间（UTC ISO8601 秒精度 Z）。cursor 为租户内跨 DID
    共享的持久化正整数，按追加顺序单调递增。
    """

    key_version: int
    action: str
    status: str
    updated_at: Optional[str]
    cursor: int


@dataclass
class TrustAnchorUsesHistoryEvent:
    """信任锚点用途历史中的一条事件（只读历史查询用）。

    按 (租户, did, key_version) 归属：新版本注册/轮换追加 registered/
    rotated（from_uses 为 None、uses 为该版本生效用途，按规范序），实际
    收紧追加 updated（from_uses/uses 分别为变更前后用途数组），幂等、
    冲突、失败与吊销均不追加。updated_at 为变更时刻（UTC ISO8601 秒精度
    Z）；旧锚点加载时补录的 snapshot 事件 from_uses/updated_at 均为
    None、uses 为当前值。cursor 为租户内跨 DID 持久递增正整数，独立于
    其他历史游标空间。
    """

    action: str
    from_uses: Optional[List[str]]
    uses: List[str]
    updated_at: Optional[str]
    cursor: int


@dataclass
class TrustAnchorChangeEvent:
    """可签名信任锚点变更流中的一条事件（只读变更流查询用）。

    按租户归属、跨 DID 共享游标：锚点新版本注册、轮换、首次吊销与实际
    用途收紧分别追加 registered/rotated/revoked/uses.updated；幂等重试、
    冲突与失败路径不追加。事件各字段值均为变更后状态：did/key_version/
    public_key 标识锚点版本，status 为 active/revoked，uses 为变更后
    生效用途（按规范序）。cursor 为租户内跨 DID 持久递增正整数，独立于
    其他历史游标空间。旧状态文件中已有锚点版本但无变更事件的，加载时按
    （租户、did、key_version）稳定补一条 snapshot 事件（取当前状态）。
    """

    cursor: int
    action: str
    did: str
    key_version: int
    public_key: str
    status: str
    uses: List[str]


@dataclass
class TrustAnchorDiscoveryRecord:
    """跨 DID 发现接口中的一条锚点版本（只读发现查询用）。

    在 TrustAnchorRecord 的基础上附带 cursor：cursor 为租户内跨 DID
    唯一、单调递增并持久化的 JSON 正整数，复用该版本注册/轮换历史的
    active 事件游标；吊销不改变 cursor。
    """

    did: str
    public_key: str
    key_version: int
    status: str
    updated_at: Optional[str]
    cursor: int


@dataclass
class CredentialStatusSyncRecord:
    """一条外部凭证状态同步记录（按租户与 issuer_did#credential_id 双键隔离）。

    status 为 active/revoked/unknown/suspended；updated_at 为签发方声明的
    状态时间（UTC ISO8601 秒精度，Z 结尾）；reason 在状态非 active 时可
    携带（active/unknown 时通常为 None；suspended 必带裁剪后 1–256 码点
    的非空原因）。
    """

    issuer_did: str
    credential_id: str
    status: str
    updated_at: str
    issuer_key_version: int
    reason: Optional[str] = None


@dataclass
class DidDeactivationNoticeRecord:
    """一条外部 DID 停用通告（按租户与 did 隔离）。

    仅在通过本租户同 did/版本 active 信任锚点的 ES256 验签后写入；
    key_version 为通告声明的密钥版本，reason 为 1–256 码点且首尾无
    空白的停用原因，deactivated_at 为签发方声明的停用时间（UTC
    ISO8601 秒精度 Z）。同一 (tenant, did) 仅保存首次接受的通告：
    完全重放幂等返回，不同通告一律冲突拒绝。
    """

    did: str
    key_version: int
    reason: str
    deactivated_at: str


@dataclass
class DidDeactivationEvent:
    """外部 DID 停用通告审计历史中的一条事件（只读查询用）。

    按租户归属；仅首次接受通告时追加一条（与通告记录在同一次原子写中
    落盘），完全重放、冲突或锚点/签名失败均不追加。cursor 为租户内跨
    DID 持久递增正整数，按追加顺序单调递增，独立于其他历史游标空间。
    旧状态文件中已存在但无审计历史的通告，加载时按
    (deactivated_at, did) 升序稳定补录，重启后 cursor 不变。
    """

    cursor: int
    did: str
    key_version: int
    reason: str
    deactivated_at: str


@dataclass
class ReceiptConsumptionEvent:
    """验真回执消费历史中的一条事件（只读消费历史查询用）。

    按租户归属、跨验证者共享游标：仅首次成功消费回执时追加一条（与
    消费记录及审计事件在同一次原子写中落盘），重放与验真失败不追加。
    receipt_id 为回执规范化 JSON 字节的 SHA-256 小写 64 位 hex；
    verifier_did/nonce 为该消费的唯一键；consumed_at 为首次消费时间
    （UTC ISO8601 秒精度 Z）。cursor 为租户内跨验证者持久递增正整数，
    独立于其他历史游标空间。旧状态文件中已消费但无消费历史的记录，
    加载时按 (consumed_at, verifier_did, nonce) 升序稳定补录，重启后
    cursor 不变。
    """

    cursor: int
    receipt_id: str
    verifier_did: str
    nonce: str
    consumed_at: str


@dataclass
class CredentialStatusReceiptConsumptionEvent:
    """凭证状态同步签名回执消费历史中的一条事件（只读消费历史查询用）。

    按租户归属、跨验证者共享游标：仅首次成功消费凭证状态回执时追加
    一条（与消费记录及审计事件在同一次原子写中落盘），重放与验真失败
    不追加。receipt_id 为完整 receipt 规范化 JSON 字节的 SHA-256 小写
    64 位 hex；verifier_did/nonce 为该消费的唯一键；consumed_at 为首
    次消费时间（UTC ISO8601 秒精度 Z）。cursor 为租户内跨验证者持久递
    增正整数，独立于其他历史游标空间（含验真回执消费历史）。旧状态文
    件中已消费但无消费历史的记录，加载时按
    (consumed_at, verifier_did, nonce) 升序稳定补录，重启后 cursor 不变。
    """

    cursor: int
    receipt_id: str
    verifier_did: str
    nonce: str
    consumed_at: str


@dataclass
class CredentialStatusSyncReceiptConsumptionEvent:
    """凭证状态回执消费同步进度签名回执消费历史中的一条事件（只读查询用）。

    按租户归属、跨验证者共享游标：仅首次成功消费
    credential-status/receipt-sync/receipt（单条或批量）时追加一条（与消费
    记录及审计事件在同一次原子写中落盘），重放与验真失败不追加。
    receipt_id 为完整 receipt 规范化 JSON 字节的 SHA-256 小写 64 位 hex；
    verifier_did/nonce 为该消费的唯一键；consumed_at 为首次消费时间
    （UTC ISO8601 秒精度 Z）。cursor 为租户内跨验证者持久递增正整数，
    独立于其他历史游标空间（含凭证状态同步签名回执消费历史）。旧状态
    文件中已消费但无消费历史的记录，加载时按
    (consumed_at, verifier_did, nonce) 升序稳定补录，重启后 cursor 不变。
    """

    cursor: int
    receipt_id: str
    verifier_did: str
    nonce: str
    consumed_at: str


@dataclass
class PresentationSyncReceiptConsumptionEvent:
    """演示消费同步进度签名回执消费历史中的一条事件。

    按租户归属、跨验证者共享游标：仅首次成功消费
    presentation-sync/receipt（单条或批量）时追加一条（与消费记录及
    审计事件在同一次原子写中落盘），重放与验真失败不追加。receipt_id
    为完整 receipt 规范化 JSON 字节的 SHA-256 小写 64 位 hex；
    verifier_did/nonce 为该消费的唯一键；consumed_at 为首次消费时间
    （UTC ISO8601 秒精度 Z）。cursor 为租户内跨验证者持久递增正整数，
    独立于其他历史游标空间。旧状态文件中已消费但无消费历史的记录，
    加载时按 (consumed_at, verifier_did, nonce) 升序稳定补录，重启后
    cursor 不变。
    """

    cursor: int
    receipt_id: str
    verifier_did: str
    nonce: str
    consumed_at: str


@dataclass
class TrustPresentationConsumptionEvent:
    """跨系统外部演示消费历史中的一条事件（只读消费历史查询用）。

    仅首次成功消费外部演示时产生（消费标记与
    trust.presentation.consumed 审计在同一次原子写中落盘），重放、
    验真失败与落盘失败均不产生。consumption_id 为消费请求规范化
    JSON 字节的 SHA-256 小写 64 位 hex；issuer_did/presentation_id
    为该消费的唯一键；consumed_at 为首次消费时间（UTC ISO8601 秒
    精度 Z）。cursor 取首次成功消费对应 trust.presentation.consumed
    审计事件的 seq（存储内全局连续正整数，跨租户共享，故租户内递增
    但不一定连续），重启后稳定不变。
    """

    cursor: int
    consumption_id: str
    issuer_did: str
    presentation_id: str
    consumed_at: str


@dataclass
class ImportedCredentialRecord:
    """一条已导入的外部凭证（按租户与 issuer_did#credential_id 双键隔离）。

    仅在通过本租户 active 信任锚点验签后写入；body 为提交的完整凭证
    原文（含扩展字段，不注入缺省的 issuer_key_version），signature 为
    提交时的非空签名串。首次导入后内容不可变：相同内容重放幂等返回，
    不同内容一律冲突拒绝。
    """

    issuer_did: str
    credential_id: str
    body: Dict[str, Any]
    signature: str


@dataclass
class CredentialStatusHistoryEvent:
    """外部凭证状态历史中的一条追加事件（只读查询用）。

    按 (issuer_did, credential_id) 双键归属；cursor 为租户内持久化正整数，
    按追加顺序递增。audit_seq/audit_timestamp 关联产生该状态的同步审计
    事件；无法追溯（旧状态补录的兼容项）时为 None。
    """

    status: str
    reason: Optional[str]
    updated_at: str
    issuer_key_version: int
    cursor: int
    audit_seq: Optional[int] = None
    audit_timestamp: Optional[int] = None


@dataclass
class LocalCredentialStatusHistoryEvent:
    """本租户签发凭证状态历史中的一条事件（只读历史查询用）。

    按 (租户, credential_id) 归属；首次 active 登记、首次 revoke 以及
    每次暂停/恢复状态变更各追加一条，重复登记/吊销、同状态幂等请求与
    失败路径不追加。active（含恢复）事件的 reason/revoked_at 均为
    None；suspended 事件保存裁剪后的暂停原因、revoked_at 为 None；
    revoked 事件保存裁剪后的 reason 与 revoked_at。updated_at 为状态
    变更时间（UTC ISO8601 秒精度 Z）。cursor 为租户内持久化正整数，按
    追加顺序递增，事件按 updated_at 升序、同 updated_at 按 cursor 升序
    排列。audit_seq/audit_timestamp 关联产生该状态变更的审计事件
    （status.updated / credential.revoked）；无法追溯（旧状态补录的
    兼容项）时为 None。
    """

    status: str
    updated_at: str
    cursor: int
    reason: Optional[str] = None
    revoked_at: Optional[str] = None
    audit_seq: Optional[int] = None
    audit_timestamp: Optional[int] = None


@dataclass
class AuditEvent:
    """一条审计事件。

    seq 为存储内全局连续序号（自 1 起，跨租户）；timestamp 为 UTC
    秒级时间戳（整数 Unix 秒）；tenant_id 为事件所属租户；action 为
    点分事件名；resource_type/resource_id 标识被操作资源。
    """

    seq: int
    timestamp: int
    tenant_id: str
    action: str
    resource_type: str
    resource_id: str
