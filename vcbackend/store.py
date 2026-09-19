"""文件支撑的内存存储：DID 注册、密钥轮换与凭证签发/验签。

状态保存在 JSON 文件中，HTTP 服务与命令行（跨进程）共用同一份状态。
每个 DID 内部持有其各版本 P-256 私钥（演示用途），使服务端签发的
ES256 签名可用该 DID 登记的公钥验真。

密钥模型（key_mode="server"）：
- 注册时提交的 public_key 仅作为非空、非 PEM 的字符串句柄；
- 系统为句柄铸造 P-256 密钥对，公钥 PEM 登记入库并可轮换；
- 公钥按版本保存在 public_key_history 中，轮换原子递增 key_version；
- 凭证正文记录签发时的整数 issuer_key_version，验签时取对应历史公钥。
"""

import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from . import crypto
from .models import CredentialRecord, DIDRecord

# DID method 标识：小写字母开头，仅含小写字母数字与下划线/连字符
_METHOD_RE = re.compile(r"^[a-z][a-z0-9_-]*$")

DEFAULT_STORE_PATH = os.environ.get(
    "VCBACKEND_STORE", os.path.join(os.getcwd(), ".vcbackend_store.json")
)

# 支持的密钥托管模式；缺省（未提交 key_mode）按 server 处理
KEY_MODE_SERVER = "server"
SUPPORTED_KEY_MODES = (KEY_MODE_SERVER,)

_PEM_MARKER = "-----BEGIN"


class ValidationError(ValueError):
    """输入不合法（映射为 HTTP 400）。"""


class NotFoundError(LookupError):
    """资源不存在（映射为 HTTP 404）。"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _validate_handle(handle: Any) -> str:
    """校验密钥句柄：非空字符串、不得为 PEM 文本。"""
    if not isinstance(handle, str) or not handle.strip():
        raise ValidationError("缺少字段或字段为空: public_key")
    handle = handle.strip()
    if _PEM_MARKER in handle:
        raise ValidationError(
            "public_key 必须为非 PEM 的密钥句柄，不能提交 PEM 公钥"
        )
    return handle


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
        with self._lock:
            for did in list(self._dids.keys()):
                self._migrate_did_locked(did, self._dids[did])

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
    # 旧记录迁移
    # ------------------------------------------------------------------ #
    def _migrate_did_locked(self, did: str, rec: Dict[str, Any]) -> bool:
        """把缺少密钥元数据的旧 DID 记录迁移为 server/1 结构。

        历史公钥即原 public_key；句柄取 submitted_public_key，缺省则
        回退为原 public_key。返回是否发生了迁移。
        """
        if "key_version" in rec:
            return False
        public_pem = rec["public_key"]
        handle = rec.get("submitted_public_key") or public_pem
        rec["key_mode"] = KEY_MODE_SERVER
        rec["key_handle"] = handle
        rec["key_version"] = 1
        rec["public_key_history"] = [
            {"version": 1, "handle": handle, "public_key": public_pem}
        ]
        rec["private_keys"] = {"1": rec.get("private_key_pem", "")}
        return True

    def _record_from_row_locked(
        self, did: str, rec: Dict[str, Any]
    ) -> DIDRecord:
        return DIDRecord(
            did=did,
            method=rec["method"],
            public_key=rec["public_key"],
            created_at=rec["created_at"],
            key_mode=rec.get("key_mode", KEY_MODE_SERVER),
            key_handle=rec.get("key_handle", rec.get("submitted_public_key", "")),
            key_version=int(rec.get("key_version", 1)),
        )

    # ------------------------------------------------------------------ #
    # DID
    # ------------------------------------------------------------------ #
    def create_did(
        self,
        method: str,
        public_key: str,
        key_mode: Optional[str] = None,
    ) -> DIDRecord:
        """注册 DID。

        - method 必须合法；public_key 为非空、非 PEM 的密钥句柄；
        - key_mode 缺省或 "server" 合法，其余 ValidationError；
        - 同一句柄再次提交返回既有记录（按提交原文去重）；
        - 新注册由系统铸造 P-256 密钥对，key_version 从 1 开始。
        """
        if not isinstance(method, str) or not method:
            raise ValidationError("缺少字段或字段为空: method")
        if not _METHOD_RE.match(method):
            raise ValidationError(
                f"method 非法: {method!r}（需为小写字母开头的小写字母数字/_-串）"
            )
        handle = _validate_handle(public_key)
        if key_mode is None:
            key_mode = KEY_MODE_SERVER
        if key_mode not in SUPPORTED_KEY_MODES:
            raise ValidationError(
                f"key_mode 非法: {key_mode!r}（仅支持 {KEY_MODE_SERVER!r}）"
            )

        with self._lock:
            existing = self._find_did_by_handle_locked(handle)
            if existing is not None:
                return existing

            priv_pem = crypto.generate_private_key_pem()
            public_pem = crypto.public_key_pem_from_private(priv_pem).strip()

            did = f"did:{method}:{uuid.uuid4().hex}"
            created_at = _utc_now()
            self._dids[did] = {
                "method": method,
                "key_mode": key_mode,
                "key_handle": handle,
                "key_version": 1,
                "public_key": public_pem,
                "public_key_history": [
                    {"version": 1, "handle": handle, "public_key": public_pem}
                ],
                "submitted_public_key": handle,
                "created_at": created_at,
                "private_key_pem": priv_pem,
                "private_keys": {"1": priv_pem},
            }
            self._save_locked()
            return self._record_from_row_locked(did, self._dids[did])

    def _find_did_by_handle_locked(self, handle: str) -> Optional[DIDRecord]:
        for did, rec in self._dids.items():
            self._migrate_did_locked(did, rec)
            if (
                rec.get("key_handle") == handle
                or rec.get("submitted_public_key") == handle
                or rec.get("public_key") == handle
            ):
                return self._record_from_row_locked(did, rec)
        return None

    def get_did(self, did: str) -> DIDRecord:
        """查询 DID；不存在抛 NotFoundError。"""
        with self._lock:
            rec = self._dids.get(did)
            if rec is None:
                raise NotFoundError(f"DID 不存在: {did}")
            self._migrate_did_locked(did, rec)
            return self._record_from_row_locked(did, rec)

    def _get_did_row_locked(self, did: str) -> Dict[str, Any]:
        rec = self._dids.get(did)
        if rec is None:
            raise NotFoundError(f"DID 不存在: {did}")
        self._migrate_did_locked(did, rec)
        return rec

    # ------------------------------------------------------------------ #
    # 密钥轮换
    # ------------------------------------------------------------------ #
    def rotate_key(self, did: str, new_handle: str) -> DIDRecord:
        """为 DID 铸造并启用新版本 P-256 密钥，原子递增并保存公钥历史。

        - DID 不存在抛 NotFoundError；
        - 新句柄非空、非 PEM、不得与历史句柄重复，否则 ValidationError。
        """
        handle = _validate_handle(new_handle)
        with self._lock:
            rec = self._get_did_row_locked(did)
            history = rec.setdefault("public_key_history", [])
            used_handles = {entry.get("handle") for entry in history}
            used_handles.add(rec.get("key_handle"))
            if handle in used_handles:
                raise ValidationError(
                    f"key_handle 与既有句柄重复: {handle!r}"
                )

            priv_pem = crypto.generate_private_key_pem()
            public_pem = crypto.public_key_pem_from_private(priv_pem).strip()
            next_version = int(rec.get("key_version", 1)) + 1

            rec["key_version"] = next_version
            rec["key_handle"] = handle
            rec["public_key"] = public_pem
            rec["private_key_pem"] = priv_pem
            rec.setdefault("private_keys", {})[str(next_version)] = priv_pem
            history.append(
                {
                    "version": next_version,
                    "handle": handle,
                    "public_key": public_pem,
                }
            )
            self._save_locked()
            return self._record_from_row_locked(did, rec)

    def _public_key_for_version_locked(
        self, rec: Dict[str, Any], version: int
    ) -> Optional[str]:
        for entry in rec.get("public_key_history", []):
            if int(entry["version"]) == version:
                return entry["public_key"]
        return None

    # ------------------------------------------------------------------ #
    # 凭证
    # ------------------------------------------------------------------ #
    def create_credential(
        self,
        issuer_did: str,
        subject_did: str,
        claims: Dict[str, Any],
    ) -> CredentialRecord:
        """校验签发者/持有者 DID，构造正文（含 issuer_key_version）并签名保存。"""
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
            self._migrate_did_locked(issuer_did, issuer)
            subject = self._dids.get(subject_did)
            if subject is None:
                raise ValidationError(f"subject_did 不存在: {subject_did}")

            key_version = int(issuer["key_version"])
            credential_id = f"vc_{uuid.uuid4().hex}"
            body: Dict[str, Any] = {
                "credential_id": credential_id,
                "issuer_did": issuer_did,
                "issuer_key_version": key_version,
                "subject_did": subject_did,
                "claims": claims,
                "issued_at": _utc_now(),
            }
            signature = crypto.sign(
                body, issuer["private_keys"][str(key_version)]
            )
            self._credentials[credential_id] = {
                "body": body,
                "signature": signature,
            }
            self._save_locked()
            return CredentialRecord(
                credential_id=credential_id,
                body=body,
                signature=signature,
                issuer_key_version=key_version,
            )

    def get_credential(self, credential_id: str) -> CredentialRecord:
        """查询凭证；不存在抛 NotFoundError。"""
        with self._lock:
            return self._get_credential_locked(credential_id)

    def _get_credential_locked(self, credential_id: str) -> CredentialRecord:
        rec = self._credentials.get(credential_id)
        if rec is None:
            raise NotFoundError(f"凭证不存在: {credential_id}")
        body = rec["body"]
        version = int(body.get("issuer_key_version", 1))
        return CredentialRecord(
            credential_id=credential_id,
            body=body,
            signature=rec["signature"],
            issuer_key_version=version,
        )

    def verify_credential_signature(
        self, credential_id: str, signature: str
    ) -> None:
        """以存储的 credential_id / issuer_did / issuer_key_version 为锚验签。

        取凭证签发时版本对应的 DID 历史公钥校验提交的 signature；
        旧凭证缺 issuer_key_version 时按版本 1 处理。任何不通过均抛
        ValidationError（NotFoundError 表示凭证或签发者不存在）。
        """
        if not isinstance(signature, str) or not signature:
            raise ValidationError("signature 必须为非空字符串")
        with self._lock:
            credential = self._get_credential_locked(credential_id)
            body = credential.body
            issuer_did = body["issuer_did"]
            version = credential.issuer_key_version
            issuer = self._dids.get(issuer_did)
            if issuer is None:
                raise ValidationError(
                    f"凭证锚定的签发者 DID 不存在: {issuer_did}"
                )
            self._migrate_did_locked(issuer_did, issuer)
            public_pem = self._public_key_for_version_locked(issuer, version)
            if public_pem is None:
                raise ValidationError(
                    f"签发者密钥版本 {version} 的公钥已不可用"
                )
            try:
                crypto.verify(body, signature, public_pem)
            except crypto.InvalidSignature as exc:
                detail = str(exc) or "签名与规范化正文不匹配"
                raise ValidationError(f"签名校验失败: {detail}") from exc
            except ValueError as exc:
                raise ValidationError(f"验签公钥不可用: {exc}") from exc
