"""文件支撑的内存存储：DID 注册与凭证签发。

状态保存在 JSON 文件中，HTTP 服务与命令行（跨进程）共用同一份状态。
每个 DID 内部持有其 P-256 私钥（演示用途），使服务端签发的 ES256
签名可用该 DID 注册的公钥验真。
"""

import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from . import crypto
from .models import CredentialRecord, DIDRecord

# DID method 标识：小写字母开头，仅含小写字母数字与下划线/连字符
_METHOD_RE = re.compile(r"^[a-z][a-z0-9_-]*$")

DEFAULT_STORE_PATH = os.environ.get(
    "VCBACKEND_STORE", os.path.join(os.getcwd(), ".vcbackend_store.json")
)


class ValidationError(ValueError):
    """输入不合法（映射为 HTTP 400）。"""


class NotFoundError(LookupError):
    """资源不存在（映射为 HTTP 404）。"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


class VCStore:
    """DID 与凭证的存储。"""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or DEFAULT_STORE_PATH
        self._lock = threading.Lock()
        self._dids: Dict[str, Dict[str, Any]] = {}
        self._credentials: Dict[str, Dict[str, Any]] = {}
        self._load()

    # ------------------------------------------------------------------ #
    # 持久化
    # ------------------------------------------------------------------ #
    def _load(self) -> None:
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self._dids = data.get("dids", {})
            self._credentials = data.get("credentials", {})

    def _save_locked(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        tmp = f"{self.path}.tmp.{os.getpid()}.{uuid.uuid4().hex}"
        payload = {
            "dids": self._dids,
            "credentials": self._credentials,
        }
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(tmp, self.path)

    # ------------------------------------------------------------------ #
    # DID
    # ------------------------------------------------------------------ #
    def create_did(
        self,
        method: str,
        public_key: str,
        private_pem: Optional[str] = None,
    ) -> DIDRecord:
        """注册 DID。

        - method/public_key 必须为非空字符串，否则 ValidationError；
        - 同一 public_key 原文再次提交返回既有记录；
        - 新注册使用系统生成的 P-256 密钥对；若调用方提供与 public_key
          匹配的 private_pem（例如 CLI 本地生成密钥对），则原样采用。
        """
        if not isinstance(method, str) or not method:
            raise ValidationError("缺少字段或字段为空: method")
        if not _METHOD_RE.match(method):
            raise ValidationError(
                f"method 非法: {method!r}（需为小写字母开头的小写字母数字/_-串）"
            )
        if not isinstance(public_key, str) or not public_key.strip():
            raise ValidationError("缺少字段或字段为空: public_key")
        public_key = public_key.strip()

        with self._lock:
            existing = self._find_did_by_public_key_locked(public_key)
            if existing is not None:
                return existing

            if private_pem is not None:
                derived = crypto.public_key_pem_from_private(private_pem).strip()
                if derived != public_key:
                    raise ValidationError(
                        "private_key 与 public_key 不配对"
                    )
                priv_pem = private_pem.strip()
                registered_pub = public_key
            else:
                priv_pem = crypto.generate_private_key_pem()
                registered_pub = crypto.public_key_pem_from_private(priv_pem).strip()

            did = f"did:{method}:{uuid.uuid4().hex}"
            created_at = _utc_now()
            self._dids[did] = {
                "method": method,
                "public_key": registered_pub,
                "submitted_public_key": public_key,
                "created_at": created_at,
                "private_key_pem": priv_pem,
            }
            self._save_locked()
            return DIDRecord(
                did=did,
                method=method,
                public_key=registered_pub,
                created_at=created_at,
            )

    def _find_did_by_public_key_locked(self, public_key: str) -> Optional[DIDRecord]:
        for did, rec in self._dids.items():
            if rec.get("public_key") == public_key or rec.get(
                "submitted_public_key"
            ) == public_key:
                return DIDRecord(
                    did=did,
                    method=rec["method"],
                    public_key=rec["public_key"],
                    created_at=rec["created_at"],
                )
        return None

    def get_did(self, did: str) -> DIDRecord:
        """查询 DID；不存在抛 NotFoundError。"""
        with self._lock:
            rec = self._dids.get(did)
            if rec is None:
                raise NotFoundError(f"DID 不存在: {did}")
            return DIDRecord(
                did=did,
                method=rec["method"],
                public_key=rec["public_key"],
                created_at=rec["created_at"],
            )

    def _get_did_row_locked(self, did: str) -> Dict[str, Any]:
        rec = self._dids.get(did)
        if rec is None:
            raise NotFoundError(f"DID 不存在: {did}")
        return rec

    # ------------------------------------------------------------------ #
    # 凭证
    # ------------------------------------------------------------------ #
    def create_credential(
        self,
        issuer_did: str,
        subject_did: str,
        claims: Dict[str, Any],
    ) -> CredentialRecord:
        """校验签发者/持有者 DID，构造正文并以 ES256 签名后保存。"""
        if not isinstance(issuer_did, str) or not issuer_did:
            raise ValidationError("缺少字段或字段为空: issuer_did")
        if not isinstance(subject_did, str) or not subject_did:
            raise ValidationError("缺少字段或字段为空: subject_did")
        if not isinstance(claims, dict):
            raise ValidationError("字段 claims 必须为 JSON 对象")

        with self._lock:
            # 逐个指明不存在的是哪一个 DID
            issuer = self._dids.get(issuer_did)
            if issuer is None:
                raise ValidationError(f"issuer_did 不存在: {issuer_did}")
            subject = self._dids.get(subject_did)
            if subject is None:
                raise ValidationError(f"subject_did 不存在: {subject_did}")

            credential_id = f"vc_{uuid.uuid4().hex}"
            body: Dict[str, Any] = {
                "credential_id": credential_id,
                "issuer_did": issuer_did,
                "subject_did": subject_did,
                "claims": claims,
                "issued_at": _utc_now(),
            }
            signature = crypto.sign(body, issuer["private_key_pem"])
            self._credentials[credential_id] = {
                "body": body,
                "signature": signature,
            }
            self._save_locked()
            return CredentialRecord(
                credential_id=credential_id, body=body, signature=signature
            )

    def get_credential(self, credential_id: str) -> CredentialRecord:
        """查询凭证；不存在抛 NotFoundError。"""
        with self._lock:
            rec = self._credentials.get(credential_id)
            if rec is None:
                raise NotFoundError(f"凭证不存在: {credential_id}")
            return CredentialRecord(
                credential_id=credential_id,
                body=rec["body"],
                signature=rec["signature"],
            )
