"""文件支撑的内存存储：DID 注册、密钥轮换与凭证签发/验签。

状态保存在 JSON 文件中，HTTP 服务与命令行（跨进程）共用同一份状态。
每个 DID 内部持有其 P-256 私钥（演示用途），使服务端签发的 ES256
签名可用该 DID 登记的公钥验真。

密钥模型：
- key_mode 目前仅支持 "server"（服务端托管密钥）；
- 每个 DID 维护 key_history：[{version, key_handle, public_key, private_key_pem}]，
  版本自 1 起，轮换时原子递增；新签名用当前版本私钥，验签按
  issuer_key_version 从历史中取对应公钥；
- 旧状态文件里缺少密钥元数据的 DID 在加载时迁移为 server/1，
  历史即原 public_key，句柄取 submitted_public_key 或原 public_key。
"""

import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from . import crypto
from .models import CredentialRecord, DIDRecord

# DID method 标识：小写字母开头，仅含小写字母数字与下划线/连字符
_METHOD_RE = re.compile(r"^[a-z][a-z0-9_-]*$")

# PEM 标记：句柄不允许是 PEM 文本
_PEM_MARKER = "-----BEGIN"

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


def _validate_key_handle(value: Any, field: str) -> str:
    """句柄必须为非空字符串且不是 PEM 文本，返回去空白后的句柄。"""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"缺少字段或字段为空: {field}")
    handle = value.strip()
    if _PEM_MARKER in handle:
        raise ValidationError(f"字段 {field} 必须为句柄，而非 PEM 密钥文本")
    return handle


def _migrate_did_row(rec: Dict[str, Any]) -> Dict[str, Any]:
    """为缺少密钥元数据的旧 DID 记录补齐 server/1 与公钥历史。"""
    if rec.get("key_mode"):
        return rec
    handle = rec.get("submitted_public_key") or rec.get("public_key") or ""
    rec["key_mode"] = "server"
    rec["key_handle"] = handle
    rec["key_version"] = 1
    rec["key_history"] = [
        {
            "version": 1,
            "key_handle": handle,
            "public_key": rec.get("public_key", ""),
            "private_key_pem": rec.get("private_key_pem", ""),
        }
    ]
    return rec


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
            for rec in self._dids.values():
                _migrate_did_row(rec)

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
    @staticmethod
    def _did_record(did: str, rec: Dict[str, Any]) -> DIDRecord:
        return DIDRecord(
            did=did,
            method=rec["method"],
            public_key=rec["public_key"],
            created_at=rec["created_at"],
            key_mode=rec.get("key_mode", "server"),
            key_handle=rec.get("key_handle", ""),
            key_version=int(rec.get("key_version", 1)),
        )

    def create_did(
        self,
        method: str,
        public_key: str,
        key_mode: str = "server",
        private_pem: Optional[str] = None,
    ) -> DIDRecord:
        """注册 DID。

        - method 须合法；public_key 为句柄：非空且非 PEM 文本；
        - key_mode 缺省为 "server"，其余取值一律 ValidationError；
        - 同一句柄再次提交返回既有记录（按提交原文去重）；
        - 新注册使用系统生成的 P-256 密钥对，版本自 1 起并登记公钥历史。
        """
        if not isinstance(method, str) or not method:
            raise ValidationError("缺少字段或字段为空: method")
        if not _METHOD_RE.match(method):
            raise ValidationError(
                f"method 非法: {method!r}（需为小写字母开头的小写字母数字/_-串）"
            )
        if key_mode != "server":
            raise ValidationError(
                f"key_mode 非法: {key_mode!r}（目前仅支持 server）"
            )
        handle = _validate_key_handle(public_key, "public_key")

        with self._lock:
            existing = self._find_did_by_handle_locked(handle)
            if existing is not None:
                return existing

            if private_pem is not None:
                # 调用方自供私钥（如本地生成密钥对）：公钥由私钥导出
                priv_pem = private_pem.strip()
                registered_pub = crypto.public_key_pem_from_private(priv_pem).strip()
            else:
                priv_pem = crypto.generate_private_key_pem()
                registered_pub = crypto.public_key_pem_from_private(priv_pem).strip()

            did = f"did:{method}:{uuid.uuid4().hex}"
            created_at = _utc_now()
            self._dids[did] = {
                "method": method,
                "public_key": registered_pub,
                "submitted_public_key": handle,
                "created_at": created_at,
                "private_key_pem": priv_pem,
                "key_mode": "server",
                "key_handle": handle,
                "key_version": 1,
                "key_history": [
                    {
                        "version": 1,
                        "key_handle": handle,
                        "public_key": registered_pub,
                        "private_key_pem": priv_pem,
                    }
                ],
            }
            self._save_locked()
            return self._did_record(did, self._dids[did])

    def _find_did_by_handle_locked(self, handle: str) -> Optional[DIDRecord]:
        for did, rec in self._dids.items():
            if handle in (rec.get("public_key"), rec.get("submitted_public_key"),
                          rec.get("key_handle")):
                return self._did_record(did, rec)
            for entry in rec.get("key_history", []):
                if entry.get("key_handle") == handle:
                    return self._did_record(did, rec)
        return None

    def _handle_in_use_locked(self, handle: str) -> bool:
        return self._find_did_by_handle_locked(handle) is not None

    def get_did(self, did: str) -> DIDRecord:
        """查询 DID；不存在抛 NotFoundError。"""
        with self._lock:
            rec = self._dids.get(did)
            if rec is None:
                raise NotFoundError(f"DID 不存在: {did}")
            return self._did_record(did, rec)

    def _get_did_row_locked(self, did: str) -> Dict[str, Any]:
        rec = self._dids.get(did)
        if rec is None:
            raise NotFoundError(f"DID 不存在: {did}")
        return rec

    # ------------------------------------------------------------------ #
    # 密钥轮换
    # ------------------------------------------------------------------ #
    def rotate_key(self, did: str, key_handle: str) -> DIDRecord:
        """轮换 DID 密钥：生成新 P-256 密钥对，原子递增版本并登记历史。

        - DID 不存在抛 NotFoundError；
        - key_handle 须为非空、非 PEM 且未被任何 DID 使用过的句柄。
        """
        handle = _validate_key_handle(key_handle, "key_handle")
        with self._lock:
            rec = self._dids.get(did)
            if rec is None:
                raise NotFoundError(f"DID 不存在: {did}")
            if self._handle_in_use_locked(handle):
                raise ValidationError(f"key_handle 已被使用: {handle}")

            priv_pem = crypto.generate_private_key_pem()
            pub_pem = crypto.public_key_pem_from_private(priv_pem).strip()
            new_version = int(rec.get("key_version", 1)) + 1
            history: List[Dict[str, Any]] = rec.setdefault("key_history", [])
            history.append(
                {
                    "version": new_version,
                    "key_handle": handle,
                    "public_key": pub_pem,
                    "private_key_pem": priv_pem,
                }
            )
            rec["key_version"] = new_version
            rec["key_handle"] = handle
            rec["public_key"] = pub_pem
            rec["private_key_pem"] = priv_pem
            self._save_locked()
            return self._did_record(did, rec)

    def _public_key_for_version_locked(
        self, did: str, version: int
    ) -> Optional[str]:
        rec = self._dids.get(did)
        if rec is None:
            return None
        for entry in rec.get("key_history", []):
            if entry.get("version") == version:
                return entry.get("public_key")
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
        """校验签发者/持有者 DID，构造正文（含 issuer_key_version）并签名。"""
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
                "issuer_key_version": int(issuer.get("key_version", 1)),
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

    def verify_credential(
        self,
        credential_id: str,
        body: Dict[str, Any],
        signature: str,
    ) -> Tuple[bool, str]:
        """以存储记录为锚验签：返回 (是否有效, 失败原因)。

        锚定字段为存储的 credential_id、issuer_did、issuer_key_version；
        验签公钥按 issuer_key_version 从签发者公钥历史中取出（旧凭证
        缺版本按 1 处理）。任何失败都返回非空中文原因，绝不抛异常、
        绝不泄露私钥。reason 按类别区分：请求 / 资源 / 锚定 / 签名格式 /
        签名校验 / 密钥。
        """
        if not isinstance(body, dict):
            return False, "请求不合法: 字段 body 必须为 JSON 对象"
        if not isinstance(signature, str) or not signature:
            return False, "请求不合法: 字段 signature 必须为非空字符串"

        with self._lock:
            rec = self._credentials.get(credential_id)
            if rec is None:
                return False, f"凭证不存在: {credential_id}"
            stored_body = rec["body"]

            if body.get("credential_id") != stored_body.get("credential_id"):
                return False, (
                    "锚定校验失败: 正文 credential_id 与存储记录不一致"
                )
            if body.get("issuer_did") != stored_body.get("issuer_did"):
                return False, "锚定校验失败: 正文 issuer_did 与存储记录不一致"
            stored_version = stored_body.get("issuer_key_version", 1)
            if body.get("issuer_key_version", 1) != stored_version:
                return False, (
                    "锚定校验失败: 正文 issuer_key_version 与存储记录不一致"
                )

            issuer_did = stored_body.get("issuer_did")
            public_pem = self._public_key_for_version_locked(
                issuer_did, stored_version
            )

        if not public_pem:
            return False, (
                "历史公钥不可用: 签发者 "
                f"{issuer_did} 密钥版本 {stored_version} 的公钥不存在"
            )
        try:
            crypto.validate_public_key_pem(public_pem)
        except (ValueError, TypeError):
            return False, (
                "历史公钥不可用: 签发者 "
                f"{issuer_did} 密钥版本 {stored_version} 的公钥无法解析"
            )

        try:
            crypto.verify(body, signature, public_pem)
        except crypto.MalformedSignature:
            return False, "签名格式错误: 不是合法的 ES256 签名编码"
        except crypto.InvalidSignature:
            return False, "签名校验失败，正文或签名可能被改动"
        except Exception:  # noqa: BLE001 验签绝不向上抛错或泄露内部细节
            return False, "验签过程发生内部错误"
        return True, ""
