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


@dataclass
class CredentialRecord:
    """一条已签发凭证：正文与其 ES256 签名。"""

    credential_id: str
    body: Dict[str, Any]
    signature: str
