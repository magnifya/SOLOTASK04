"""数据模型定义。"""

from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class DIDRecord:
    """一条 DID 注册记录。"""

    did: str
    method: str
    public_key: str
    created_at: str
    key_mode: str = "server"
    key_handle: str = ""
    key_version: int = 1


@dataclass
class CredentialRecord:
    """一条已签发凭证：正文与其 ES256 签名。

    issuer_key_version 为签发时使用的 DID 密钥版本（整数）。
    """

    credential_id: str
    body: Dict[str, Any]
    signature: str
    issuer_key_version: int = 1
