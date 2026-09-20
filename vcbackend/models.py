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
class CredentialRecord:
    """一条已签发凭证：正文与其 ES256 签名。"""

    credential_id: str
    body: Dict[str, Any]
    signature: str


@dataclass
class CredentialStatusRecord:
    """凭证状态登记记录。

    status 目前为 "active" 或 "revoked"；updated_at 为首次状态登记时间
    （UTC ISO8601），历史无状态凭证查询时为 None。revoked 时附带
    reason（裁剪后的吊销原因）与 revoked_at。
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
