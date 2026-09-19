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
