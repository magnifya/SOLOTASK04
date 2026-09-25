"""数据模型定义。"""

from dataclasses import dataclass
from typing import Any, Dict, Optional


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
    # 可选持有者绑定（holder_binding=true 时写入并持久化）：
    # holder_did 为持有者（即凭证 subject_did）；holder_key_version 为
    # 生成绑定时持有者的当前密钥版本；holder_proof 为持有者私钥对
    # （去掉 proof、holder_proof 后的演示对象 + tenant_id）的 ES256
    # 裸 R||S 无填充 base64url 签名。未绑定演示三者均为 None。
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

    status 为 active/revoked/unknown；updated_at 为签发方声明的状态时间
    （UTC ISO8601 秒精度，Z 结尾）；reason 在状态非 active 时可携带
    （active/unknown 时通常为 None）。
    """

    issuer_did: str
    credential_id: str
    status: str
    updated_at: str
    issuer_key_version: int
    reason: Optional[str] = None


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
