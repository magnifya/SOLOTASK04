"""内存存储：DID 注册表与凭证库。"""

from __future__ import annotations

import hashlib
import threading
import uuid
from datetime import datetime, timezone


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _did_for(method: str, public_key: str) -> str:
    digest = hashlib.sha256(public_key.encode("utf-8")).hexdigest()
    return f"did:{method}:{digest[:16]}"


class DidStore:
    """DID 注册表，按 public_key 去重。

    记录字段：did、method、public_key、created_at，以及仅供服务端签名
    使用的 private_key（可能为 None，不对外返回）。
    """

    def __init__(self) -> None:
        self._by_did: dict[str, dict] = {}
        self._did_by_public_key: dict[str, str] = {}
        self._lock = threading.Lock()

    def register(self, method: str, public_key: str,
                 private_key: str | None = None) -> tuple[dict, bool]:
        """注册 DID，返回 (记录, 是否新建)。同一 public_key 重复提交返回既有记录。"""
        with self._lock:
            existing = self._did_by_public_key.get(public_key)
            if existing is not None:
                return self._by_did[existing], False
            did = _did_for(method, public_key)
            record = {
                "did": did,
                "method": method,
                "public_key": public_key,
                "private_key": private_key,
                "created_at": _now_iso(),
            }
            self._by_did[did] = record
            self._did_by_public_key[public_key] = did
            return record, True

    def reindex(self, record: dict) -> None:
        """记录的 public_key 被更新后，把新公钥也加入 public_key -> did 索引。

        旧公钥的映射保留，保证用原 public_key 重复注册仍返回既有 DID。
        """
        with self._lock:
            self._did_by_public_key[record["public_key"]] = record["did"]

    def get(self, did: str) -> dict | None:
        """按 DID 查询记录，不存在返回 None。"""
        return self._by_did.get(did)


class CredentialStore:
    """凭证库，按 credential_id 索引。

    记录字段：credential_id、body（凭证正文 dict）、signature。
    """

    def __init__(self) -> None:
        self._by_id: dict[str, dict] = {}
        self._lock = threading.Lock()

    def add(self, record: dict) -> None:
        """保存一条凭证记录（含 body 与 signature）。"""
        with self._lock:
            self._by_id[record["credential_id"]] = record

    def get(self, credential_id: str) -> dict | None:
        """按 credential_id 查询，不存在返回 None。"""
        return self._by_id.get(credential_id)


def new_credential_id() -> str:
    return uuid.uuid4().hex


def now_iso() -> str:
    return _now_iso()
