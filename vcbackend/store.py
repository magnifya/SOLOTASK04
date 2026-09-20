"""文件支撑的内存存储：租户隔离、DID/凭证/演示与审计日志。

状态保存在 JSON 文件中，HTTP 服务与命令行（跨进程）共用同一份状态。
每个 DID 内部持有其 P-256 私钥（演示用途），使服务端签发的 ES256
签名可用该 DID 登记的公钥验真。

多租户：
- 状态按租户分桶，tenants[tenant_id] 各持 dids/credentials/
  presentations；同一句柄可在不同租户分别注册，跨租户互不可见，
  访问他租户资源一律按“不存在”处理（HTTP 层映射为 404/400 原协议）；
- 旧版顶层 dids/credentials/presentations 状态文件加载时整体迁移到
  "default" 租户桶。

审计：
- 审计事件存于全局 audit 列表，seq 全局连续自 1 起（跨租户）；
- 每次状态变更与事件追加在同一把锁内完成并通过同一次原子写落盘，
  落盘失败则回滚内存变更（变更不生效、事件不记录）。

密钥模型：
- key_mode 目前仅支持 "server"（服务端托管密钥）；
- 每个 DID 维护 key_history：[{version, key_handle, public_key, private_key_pem}]，
  版本自 1 起，轮换时原子递增；新签名用当前版本私钥，验签按
  issuer_key_version 从历史中取对应公钥；
- 旧状态文件里缺少密钥元数据的 DID 在加载时迁移为 server/1，
  历史即原 public_key，句柄取 submitted_public_key 或原 public_key。

凭证状态（active/revoked）登记在凭证行内，随状态文件持久化；
历史无状态凭证查询时按 active 呈现（updated_at 为空）。
"""

import copy
import json
import os
import re
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from . import crypto
from .models import (
    AuditEvent,
    CredentialRecord,
    CredentialStatusRecord,
    DIDRecord,
    PredicateProofRecord,
    PresentationRecord,
    TrustAnchorRecord,
)

# DID method 标识：小写字母开头，仅含小写字母数字与下划线/连字符
_METHOD_RE = re.compile(r"^[a-z][a-z0-9_-]*$")

# PEM 标记：句柄不允许是 PEM 文本
_PEM_MARKER = "-----BEGIN"

# 缺省租户标识
DEFAULT_TENANT = "default"

DEFAULT_STORE_PATH = os.environ.get(
    "VCBACKEND_STORE", os.path.join(os.getcwd(), ".vcbackend_store.json")
)


class ValidationError(ValueError):
    """输入不合法（映射为 HTTP 400）。"""


class NotFoundError(LookupError):
    """资源不存在（映射为 HTTP 404）。"""


class ConflictError(RuntimeError):
    """资源状态冲突（映射为 HTTP 409），如已吊销凭证再次登记 active。"""


# 吊销时未提供合法 reason 的默认原因
DEFAULT_REVOKE_REASON = "持证人主动吊销"

# 哨兵：调用方未提供 reason 字段（区别于显式传 None 等非法值）
REASON_UNSET = object()

# 哨兵：演示验签请求未提供 challenge 字段（区别于显式传非法值）
CHALLENGE_UNSET = object()

# 演示默认有效期（秒）与允许范围
DEFAULT_EXPIRES_IN = 300
MAX_EXPIRES_IN = 86400

# 审计动作名
AUDIT_DID_CREATED = "did.created"
AUDIT_CREDENTIAL_ISSUED = "credential.issued"
AUDIT_KEY_ROTATED = "key.rotated"
AUDIT_STATUS_UPDATED = "status.updated"
AUDIT_CREDENTIAL_REVOKED = "credential.revoked"
AUDIT_PRESENTATION_CREATED = "presentation.created"
AUDIT_PRESENTATION_CONSUMED = "presentation.consumed"
AUDIT_TRUST_ANCHOR_REGISTERED = "trust.anchor.registered"
AUDIT_TRUST_ANCHOR_REVOKED = "trust.anchor.revoked"
AUDIT_TRUST_ANCHOR_ROTATED = "trust.anchor.rotated"
AUDIT_PROOF_CREATED = "proof.created"
AUDIT_PROOF_CONSUMED = "proof.consumed"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _utc_after(seconds: int) -> str:
    """当前 UTC 时间加 seconds 秒，Z 结尾秒精度。"""
    moment = datetime.now(timezone.utc) + timedelta(seconds=seconds)
    return moment.isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_utc_z(text: str) -> datetime:
    """解析 Z 结尾秒精度 UTC 时间戳为 aware datetime。"""
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )


def _validate_key_handle(value: Any, field: str) -> str:
    """句柄必须为非空字符串且不是 PEM 文本，返回去空白后的句柄。"""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"缺少字段或字段为空: {field}")
    handle = value.strip()
    if _PEM_MARKER in handle:
        raise ValidationError(f"字段 {field} 必须为句柄，而非 PEM 密钥文本")
    return handle


def _parse_pointer(pointer: str, label: str = "disclose") -> Tuple[str, ...]:
    """解析相对 claims 的 RFC6901 JSON Pointer 为 token 元组。

    仅做语法解析：必须为以 "/" 开头的字符串，按 "/" 分段并对
    "~1"/"~0" 反转义（顺序不可颠倒）；根指针 "" 与数组索引语义在
    _resolve_pointer 中按业务规则拒绝。label 为错误措辞中的字段名。
    """
    if not isinstance(pointer, str):
        raise ValidationError(f"{label} 路径必须为字符串")
    if not pointer.startswith("/"):
        raise ValidationError(
            f"{label} 路径非法（须以 / 开头）: {pointer!r}"
        )
    tokens: List[str] = []
    for raw in pointer.split("/")[1:]:
        if "~" in raw:
            # RFC6901：~ 后只能跟 0 或 1，且先还原 ~1 再还原 ~0
            idx = 0
            while idx < len(raw):
                if raw[idx] == "~" and (
                    idx + 1 >= len(raw) or raw[idx + 1] not in "01"
                ):
                    raise ValidationError(
                        f"{label} 路径含非法转义（~ 后须为 0 或 1）: {pointer!r}"
                    )
                idx += 1
        tokens.append(raw.replace("~1", "/").replace("~0", "~"))
    return tuple(tokens)


def _resolve_pointer(
    claims: Dict[str, Any],
    tokens: Tuple[str, ...],
    pointer: str,
    label: str = "disclose",
) -> Any:
    """沿 token 导航 claims 并返回目标值。

    禁根（空 token）、禁数组索引（任一步进入数组）、键不存在或
    经过非对象叶子均按越界/未命中拒绝。
    """
    if not tokens:
        raise ValidationError(f"{label} 不允许根路径（零披露请传空列表）")
    current: Any = claims
    for token in tokens:
        if isinstance(current, list):
            raise ValidationError(
                f"{label} 路径不允许数组索引: {pointer!r}"
            )
        if not isinstance(current, dict) or token not in current:
            raise ValidationError(
                f"{label} 路径越界或未命中 claims 属性: {pointer!r}"
            )
        current = current[token]
    return current


def _validate_disclose(
    claims: Dict[str, Any], disclose: Any
) -> List[Tuple[str, Tuple[str, ...]]]:
    """校验 disclose 列表并返回 (原路径, token 元组) 列表。

    - disclose 必须为列表；元素须为以 / 开头的合法 RFC6901 指针字符串；
    - 路径须命中 claims 属性：禁根、禁数组索引、禁越界；
    - 路径不得重复、不得存在祖先/后代重叠（含已覆盖的深层路径）。
    """
    if not isinstance(disclose, list):
        raise ValidationError("字段 disclose 必须为数组")
    parsed: List[Tuple[str, Tuple[str, ...]]] = []
    seen_tokens: List[Tuple[str, ...]] = []
    for pointer in disclose:
        tokens = _parse_pointer(pointer)
        if tokens in seen_tokens:
            raise ValidationError(f"disclose 路径重复: {pointer!r}")
        for existing in seen_tokens:
            if tokens[: len(existing)] == existing:
                raise ValidationError(
                    f"disclose 路径存在祖先重叠: {pointer!r} 被已选路径覆盖"
                )
            if existing[: len(tokens)] == tokens:
                raise ValidationError(
                    f"disclose 路径存在祖先重叠: 已选路径被 {pointer!r} 覆盖"
                )
        _resolve_pointer(claims, tokens, pointer)
        parsed.append((pointer, tokens))
        seen_tokens.append(tokens)
    return parsed


def _project_claims(
    claims: Dict[str, Any],
    parsed: List[Tuple[str, Tuple[str, ...]]],
) -> Dict[str, Any]:
    """按解析后的路径从 claims 提取投影；路径值整体保留（数组作叶子）。"""
    projection: Dict[str, Any] = {}
    for pointer, tokens in parsed:
        value = _resolve_pointer(claims, tokens, pointer)
        target = projection
        for key in tokens[:-1]:
            target = target.setdefault(key, {})
        target[tokens[-1]] = value
    return projection


# 谓词证明支持的操作符
_PREDICATE_OPS = ("exists", "eq", "gte", "lte")


def _json_exact_equal(left: Any, right: Any) -> bool:
    """JSON 精确相等：布尔与数字不互通（True != 1），其余按值比较。"""
    if isinstance(left, bool) or isinstance(right, bool):
        return (
            isinstance(left, bool)
            and isinstance(right, bool)
            and left == right
        )
    return left == right


def _is_number(value: Any) -> bool:
    """非布尔 JSON 数字（int/float，排除 True/False）。"""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _validate_predicates(
    claims: Dict[str, Any], predicates: Any
) -> Tuple[List[Dict[str, Any]], List[bool]]:
    """校验谓词列表并对 claims 求值，返回 (回显谓词列表, 同序布尔结果)。

    - predicates 必须为非空数组；元素为 {path, op[, value]} 对象，
      op 仅支持 exists/eq/gte/lte；exists 禁带 value，其余必须带 value；
    - path 为相对 claims 的 RFC6901 指针：禁根、禁数组索引、禁越界，
      且列表内不得重复、不得祖先/后代重叠；
    - eq 为精确相等（布尔与数字不互通）；gte/lte 要求谓词 value 与
      claims 命中值均为非布尔数字，否则 ValidationError。
    """
    if not isinstance(predicates, list) or not predicates:
        raise ValidationError("字段 predicates 必须为非空数组")
    echo: List[Dict[str, Any]] = []
    results: List[bool] = []
    seen_tokens: List[Tuple[str, ...]] = []
    for item in predicates:
        if not isinstance(item, dict):
            raise ValidationError("predicates 元素必须为 JSON 对象")
        if "path" not in item:
            raise ValidationError("谓词缺少字段: path")
        if "op" not in item:
            raise ValidationError("谓词缺少字段: op")
        op = item["op"]
        if op not in _PREDICATE_OPS:
            raise ValidationError(
                f"谓词 op 非法: {op!r}（仅支持 exists/eq/gte/lte）"
            )
        if op == "exists":
            extra = sorted(set(item) - {"path", "op"})
            if extra:
                raise ValidationError(
                    f"exists 谓词不允许字段: {', '.join(extra)}"
                )
        else:
            if "value" not in item:
                raise ValidationError(f"{op} 谓词缺少字段: value")
            extra = sorted(set(item) - {"path", "op", "value"})
            if extra:
                raise ValidationError(
                    f"谓词含多余字段: {', '.join(extra)}"
                )
        pointer = item["path"]
        tokens = _parse_pointer(pointer, label="谓词 path")
        if tokens in seen_tokens:
            raise ValidationError(f"谓词 path 重复: {pointer!r}")
        for existing in seen_tokens:
            if tokens[: len(existing)] == existing:
                raise ValidationError(
                    f"谓词 path 存在祖先重叠: {pointer!r} 被已选路径覆盖"
                )
            if existing[: len(tokens)] == tokens:
                raise ValidationError(
                    f"谓词 path 存在祖先重叠: 已选路径被 {pointer!r} 覆盖"
                )
        claim_value = _resolve_pointer(
            claims, tokens, pointer, label="谓词 path"
        )
        seen_tokens.append(tokens)

        if op == "exists":
            result = True
        elif op == "eq":
            result = _json_exact_equal(claim_value, item["value"])
        else:
            if not _is_number(item["value"]):
                raise ValidationError(
                    f"{op} 谓词 value 必须为非布尔数字: {pointer!r}"
                )
            if not _is_number(claim_value):
                raise ValidationError(
                    f"{op} 谓词命中的 claims 值必须为非布尔数字: {pointer!r}"
                )
            if op == "gte":
                result = claim_value >= item["value"]
            else:
                result = claim_value <= item["value"]

        echo_item: Dict[str, Any] = {"path": pointer, "op": op}
        if op != "exists":
            echo_item["value"] = item["value"]
        echo.append(echo_item)
        results.append(result)
    return echo, results



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
    """DID、凭证、演示与审计事件的多租户存储。"""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or DEFAULT_STORE_PATH
        self._lock = threading.Lock()
        # tenant_id -> {"dids": {...}, "credentials": {...},
        #               "presentations": {...}}
        self._tenants: Dict[str, Dict[str, Dict[str, Any]]] = {}
        # 全局审计事件（按追加顺序即 seq 升序）
        self._audit: List[Dict[str, Any]] = []
        self._audit_seq: int = 0
        self._load()

    # ------------------------------------------------------------------ #
    # 持久化
    # ------------------------------------------------------------------ #
    def _load(self) -> None:
        data: Dict[str, Any] = {}
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        if isinstance(data.get("tenants"), dict):
            self._tenants = data["tenants"]
        else:
            # 旧版顶层结构：整体迁入 default 租户桶
            legacy: Dict[str, Any] = {}
            for key in ("dids", "credentials", "presentations"):
                if key in data:
                    legacy[key] = data[key]
            self._tenants = {DEFAULT_TENANT: legacy} if legacy else {}
        self._audit = list(data.get("audit", []))
        if self._audit:
            self._audit_seq = int(
                data.get("audit_seq", self._audit[-1].get("seq", 0))
            )
        else:
            self._audit_seq = int(data.get("audit_seq", 0))
        for bucket in self._tenants.values():
            bucket.setdefault("dids", {})
            bucket.setdefault("credentials", {})
            bucket.setdefault("presentations", {})
            bucket.setdefault("proofs", {})
            bucket.setdefault("trust_anchors", {})
            for rec in bucket["dids"].values():
                _migrate_did_row(rec)

    def _save_locked(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        tmp = f"{self.path}.tmp.{os.getpid()}.{uuid.uuid4().hex}"
        payload = {
            "tenants": self._tenants,
            "audit": self._audit,
            "audit_seq": self._audit_seq,
        }
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(tmp, self.path)

    def _snapshot_locked(self) -> Any:
        """深拷贝当前全部可变状态，供落盘失败时回滚。"""
        return copy.deepcopy((self._tenants, self._audit, self._audit_seq))

    def _restore_locked(self, snapshot: Any) -> None:
        tenants, audit, audit_seq = copy.deepcopy(snapshot)
        self._tenants = tenants
        self._audit = audit
        self._audit_seq = audit_seq

    # ------------------------------------------------------------------ #
    # 租户桶与审计
    # ------------------------------------------------------------------ #
    def _bucket_locked(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        return self._tenants.get(tenant_id)

    def _ensure_bucket_locked(self, tenant_id: str) -> Dict[str, Any]:
        bucket = self._tenants.get(tenant_id)
        if bucket is None:
            bucket = {
                "dids": {},
                "credentials": {},
                "presentations": {},
                "proofs": {},
                "trust_anchors": {},
            }
            self._tenants[tenant_id] = bucket
        return bucket

    def _append_audit_locked(
        self,
        tenant_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
    ) -> Dict[str, Any]:
        """在锁内追加一条审计事件（须与状态变更同一次原子写落盘）。"""
        seq = self._audit_seq + 1
        event = {
            "seq": seq,
            "timestamp": int(time.time()),
            "tenant_id": tenant_id,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
        }
        self._audit.append(event)
        self._audit_seq = seq
        return event

    def list_audit(
        self, tenant_id: str, after: int = 0, limit: int = 50
    ) -> Tuple[List[AuditEvent], int]:
        """查询某租户 seq 严格大于 after 的审计事件，按 seq 升序。

        返回 (事件列表, next_after)；空页 next_after 保持 after。
        """
        with self._lock:
            picked: List[AuditEvent] = []
            for event in self._audit:
                if len(picked) >= limit:
                    break
                if (
                    event.get("tenant_id") == tenant_id
                    and int(event.get("seq", 0)) > after
                ):
                    picked.append(
                        AuditEvent(
                            seq=int(event["seq"]),
                            timestamp=int(event["timestamp"]),
                            tenant_id=event["tenant_id"],
                            action=event["action"],
                            resource_type=event["resource_type"],
                            resource_id=event["resource_id"],
                        )
                    )
            next_after = picked[-1].seq if picked else after
            return picked, next_after

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
        tenant_id: str,
        method: str,
        public_key: str,
        key_mode: str = "server",
        private_pem: Optional[str] = None,
    ) -> DIDRecord:
        """注册 DID。

        - method 须合法；public_key 为句柄：非空且非 PEM 文本；
        - key_mode 缺省为 "server"，其余取值一律 ValidationError；
        - 同一租户内同一句柄再次提交返回既有记录（按提交原文去重），
          同句柄可在不同租户分别注册；
        - 新注册使用系统生成的 P-256 密钥对，版本自 1 起并登记公钥历史；
        - 新建与幂等重试均记 did.created。
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
            bucket = self._ensure_bucket_locked(tenant_id)
            existing = self._find_did_by_handle_locked(bucket, handle)
            snapshot = self._snapshot_locked()
            try:
                if existing is not None:
                    # 幂等成功同样每次记录审计
                    self._append_audit_locked(
                        tenant_id, AUDIT_DID_CREATED, "did", existing.did
                    )
                    self._save_locked()
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
                bucket["dids"][did] = {
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
                self._append_audit_locked(
                    tenant_id, AUDIT_DID_CREATED, "did", did
                )
                self._save_locked()
                return self._did_record(did, bucket["dids"][did])
            except Exception:
                self._restore_locked(snapshot)
                raise

    def _find_did_by_handle_locked(
        self, bucket: Dict[str, Any], handle: str
    ) -> Optional[DIDRecord]:
        for did, rec in bucket["dids"].items():
            if handle in (rec.get("public_key"), rec.get("submitted_public_key"),
                          rec.get("key_handle")):
                return self._did_record(did, rec)
            for entry in rec.get("key_history", []):
                if entry.get("key_handle") == handle:
                    return self._did_record(did, rec)
        return None

    def _handle_in_use_locked(self, bucket: Dict[str, Any], handle: str) -> bool:
        return self._find_did_by_handle_locked(bucket, handle) is not None

    def get_did(self, tenant_id: str, did: str) -> DIDRecord:
        """查询本租户 DID；不存在（含他租户资源）抛 NotFoundError。"""
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            rec = bucket["dids"].get(did) if bucket is not None else None
            if rec is None:
                raise NotFoundError(f"DID 不存在: {did}")
            return self._did_record(did, rec)

    def _get_did_row_locked(
        self, bucket: Dict[str, Any], did: str
    ) -> Dict[str, Any]:
        rec = bucket["dids"].get(did)
        if rec is None:
            raise NotFoundError(f"DID 不存在: {did}")
        return rec

    # ------------------------------------------------------------------ #
    # 密钥轮换
    # ------------------------------------------------------------------ #
    def rotate_key(
        self, tenant_id: str, did: str, key_handle: str
    ) -> DIDRecord:
        """轮换 DID 密钥：生成新 P-256 密钥对，原子递增版本并登记历史。

        - DID 不存在（含他租户资源）抛 NotFoundError；
        - key_handle 须为非空、非 PEM 且未被本租户任何 DID 使用过的句柄；
        - 成功记 key.rotated。
        """
        handle = _validate_key_handle(key_handle, "key_handle")
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            rec = bucket["dids"].get(did) if bucket is not None else None
            if rec is None:
                raise NotFoundError(f"DID 不存在: {did}")
            if self._handle_in_use_locked(bucket, handle):
                raise ValidationError(f"key_handle 已被使用: {handle}")

            snapshot = self._snapshot_locked()
            try:
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
                self._append_audit_locked(
                    tenant_id, AUDIT_KEY_ROTATED, "did", did
                )
                self._save_locked()
                return self._did_record(did, rec)
            except Exception:
                self._restore_locked(snapshot)
                raise

    def _public_key_for_version_locked(
        self, bucket: Dict[str, Any], did: str, version: int
    ) -> Optional[str]:
        rec = bucket["dids"].get(did) if bucket is not None else None
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
        tenant_id: str,
        issuer_did: str,
        subject_did: str,
        claims: Dict[str, Any],
    ) -> CredentialRecord:
        """校验签发者/持有者 DID（限本租户），构造正文并签名，记审计。"""
        if not isinstance(issuer_did, str) or not issuer_did:
            raise ValidationError("缺少字段或字段为空: issuer_did")
        if not isinstance(subject_did, str) or not subject_did:
            raise ValidationError("缺少字段或字段为空: subject_did")
        if not isinstance(claims, dict):
            raise ValidationError("字段 claims 必须为 JSON 对象")

        with self._lock:
            bucket = self._ensure_bucket_locked(tenant_id)
            # 逐个指明不存在的是哪一个 DID（他租户 DID 同样不可见）
            issuer = bucket["dids"].get(issuer_did)
            if issuer is None:
                raise ValidationError(f"issuer_did 不存在: {issuer_did}")
            subject = bucket["dids"].get(subject_did)
            if subject is None:
                raise ValidationError(f"subject_did 不存在: {subject_did}")

            snapshot = self._snapshot_locked()
            try:
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
                bucket["credentials"][credential_id] = {
                    "body": body,
                    "signature": signature,
                }
                self._append_audit_locked(
                    tenant_id, AUDIT_CREDENTIAL_ISSUED,
                    "credential", credential_id,
                )
                self._save_locked()
                return CredentialRecord(
                    credential_id=credential_id, body=body, signature=signature
                )
            except Exception:
                self._restore_locked(snapshot)
                raise

    def get_credential(
        self, tenant_id: str, credential_id: str
    ) -> CredentialRecord:
        """查询本租户凭证；不存在（含他租户资源）抛 NotFoundError。"""
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            rec = (
                bucket["credentials"].get(credential_id)
                if bucket is not None else None
            )
            if rec is None:
                raise NotFoundError(f"凭证不存在: {credential_id}")
            return CredentialRecord(
                credential_id=credential_id,
                body=rec["body"],
                signature=rec["signature"],
            )

    # ------------------------------------------------------------------ #
    # 选择性披露演示
    # ------------------------------------------------------------------ #
    def _private_key_for_version_locked(
        self, bucket: Dict[str, Any], did: str, version: int
    ) -> Optional[str]:
        rec = bucket["dids"].get(did) if bucket is not None else None
        if rec is None:
            return None
        for entry in rec.get("key_history", []):
            if entry.get("version") == version:
                return entry.get("private_key_pem")
        return None

    @staticmethod
    def _presentation_record(row: Dict[str, Any]) -> PresentationRecord:
        return PresentationRecord(
            presentation_id=row["presentation_id"],
            credential_id=row["credential_id"],
            issuer_did=row["issuer_did"],
            issuer_key_version=int(row["issuer_key_version"]),
            disclose=list(row.get("disclose", [])),
            projection=row.get("claims", {}),
            proof=row["proof"],
            challenge=row.get("challenge"),
            expires_at=row.get("expires_at"),
        )

    def create_presentation(
        self,
        tenant_id: str,
        credential_id: str,
        disclose: Any,
        challenge: Optional[str] = None,
        expires_in: Optional[int] = None,
    ) -> PresentationRecord:
        """对本租户已签发凭证生成选择性披露演示并持久化，记审计。

        - 凭证不存在（含他租户资源）抛 NotFoundError；disclose 非法
          （非数组、路径语法/越界/重复/祖先重叠）抛 ValidationError；
          空列表表示零披露；
        - challenge 缺省时生成 32 位小写 hex；expires_in 缺省 300 秒，
          expires_at 为当前 UTC 时间加 expires_in 秒（Z 结尾秒精度）；
        - challenge 与 expires_at 均写入被签名的演示正文并持久化；
        - proof 为 ES256 签名，覆盖除 proof 外按 key 升序规范化 JSON，
          使用凭证 issuer_key_version（旧凭证缺省按 1）对应的历史私钥；
        - presentation_id 为 vp_ 加 32 位小写 hex。
        """
        if challenge is None:
            challenge = uuid.uuid4().hex
        if expires_in is None:
            expires_in = DEFAULT_EXPIRES_IN
        expires_at = _utc_after(expires_in)
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            cred = (
                bucket["credentials"].get(credential_id)
                if bucket is not None else None
            )
            if cred is None:
                raise NotFoundError(f"凭证不存在: {credential_id}")
            stored_body = cred["body"]
            claims = stored_body.get("claims", {})
            if not isinstance(claims, dict):
                raise ValidationError("凭证 claims 不是 JSON 对象，无法披露")

            parsed = _validate_disclose(claims, disclose)
            projection = _project_claims(claims, parsed)

            issuer_did = stored_body["issuer_did"]
            version = int(stored_body.get("issuer_key_version", 1))
            private_pem = self._private_key_for_version_locked(
                bucket, issuer_did, version
            )
            if not private_pem:
                raise ValidationError(
                    "历史私钥不可用: 签发者 "
                    f"{issuer_did} 密钥版本 {version} 的私钥不存在"
                )

            snapshot = self._snapshot_locked()
            try:
                presentation_id = f"vp_{uuid.uuid4().hex}"
                disclose_paths = [pointer for pointer, _ in parsed]
                unsigned: Dict[str, Any] = {
                    "presentation_id": presentation_id,
                    "credential_id": credential_id,
                    "issuer_did": issuer_did,
                    "issuer_key_version": version,
                    "disclose": disclose_paths,
                    "claims": projection,
                    "challenge": challenge,
                    "expires_at": expires_at,
                }
                proof = crypto.sign(unsigned, private_pem)
                row = dict(unsigned)
                row["proof"] = proof
                bucket["presentations"][presentation_id] = row
                self._append_audit_locked(
                    tenant_id, AUDIT_PRESENTATION_CREATED,
                    "presentation", presentation_id,
                )
                self._save_locked()
                return self._presentation_record(row)
            except Exception:
                self._restore_locked(snapshot)
                raise

    def get_presentation(
        self, tenant_id: str, presentation_id: str
    ) -> PresentationRecord:
        """查询本租户演示记录；不存在（含他租户资源）抛 NotFoundError。"""
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            row = (
                bucket["presentations"].get(presentation_id)
                if bucket is not None else None
            )
            if row is None:
                raise NotFoundError(f"演示不存在: {presentation_id}")
            return self._presentation_record(row)

    def verify_presentation(
        self,
        tenant_id: str,
        presentation_id: str,
        presentation: Any,
        challenge: Any = CHALLENGE_UNSET,
    ) -> Tuple[bool, str]:
        """以存储记录为锚校验选择性披露演示，返回 (是否有效, 失败原因)。

        校验顺序：请求 -> 资源 ID -> 绑定（含 challenge）-> 已消费 ->
        过期（当前时间 >= expires_at）-> 投影 -> proof 格式与签名 ->
        吊销。新演示（存储记录含 challenge）要求请求恰含 presentation
        与 challenge，且请求 challenge、演示 challenge 与 proof 覆盖的
        存储 challenge 三者一致；旧演示（无 challenge）只接受恰含
        presentation 的请求，不做挑战、过期与消费检查。

        验签成功后在消费锁内复查已消费/到期/吊销：复查到期即返回
        “演示已过期”，不消费、不记审计；未到期并发验证仅一次成功，
        成功时原子标记已消费并记一次 presentation.consumed（标记与
        事件同一次原子写，失败回滚不记），跨重启保留；已消费优先于
        过期与吊销；签名成功但已吊销返回“凭证已吊销：<原因>”且
        不消费。任何失败均返回非空中文原因，绝不抛异常、不泄露私钥。
        """
        if not isinstance(presentation, dict):
            return False, "请求不合法: 字段 presentation 必须为 JSON 对象"

        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            row = (
                bucket["presentations"].get(presentation_id)
                if bucket is not None else None
            )
            if row is None:
                return False, f"演示不存在: {presentation_id}"

            # 新/旧演示按存储记录是否含 challenge 判定
            is_replay_protected = "challenge" in row
            if is_replay_protected:
                if challenge is CHALLENGE_UNSET:
                    return False, "请求缺少字段: challenge"
            elif challenge is not CHALLENGE_UNSET:
                return False, "请求含多余字段: challenge"

            expected_keys = {
                "presentation_id",
                "credential_id",
                "issuer_did",
                "issuer_key_version",
                "disclose",
                "claims",
                "proof",
            }
            if is_replay_protected:
                expected_keys |= {"challenge", "expires_at"}
            if set(presentation) != expected_keys:
                return False, (
                    "锚定校验失败: presentation 字段集合与存储记录不一致"
                )
            proof = presentation.get("proof")
            if not isinstance(proof, str) or not proof:
                return False, "请求不合法: 字段 proof 必须为非空字符串"
            if presentation.get("presentation_id") != presentation_id:
                return False, (
                    "锚定校验失败: presentation_id 与路径或存储记录不一致"
                )
            if presentation.get("credential_id") != row.get("credential_id"):
                return False, (
                    "锚定校验失败: credential_id 与存储记录不一致"
                )
            if presentation.get("issuer_did") != row.get("issuer_did"):
                return False, "锚定校验失败: issuer_did 与存储记录不一致"
            stored_version = int(row.get("issuer_key_version", 1))
            version_obj = presentation.get("issuer_key_version")
            if (
                not isinstance(version_obj, int)
                or isinstance(version_obj, bool)
                or version_obj != stored_version
            ):
                return False, (
                    "锚定校验失败: issuer_key_version 与存储记录不一致"
                )
            if presentation.get("disclose") != list(row.get("disclose", [])):
                return False, "锚定校验失败: disclose 与存储记录不一致"

            if is_replay_protected:
                # 请求 challenge、演示 challenge 与 proof 覆盖的存储
                # challenge 三者必须一致
                stored_challenge = row.get("challenge")
                if presentation.get("challenge") != stored_challenge:
                    return False, (
                        "锚定校验失败: challenge 与存储记录不一致"
                    )
                if challenge != stored_challenge:
                    return False, (
                        "锚定校验失败: 请求 challenge 与存储记录不一致"
                    )
                if presentation.get("expires_at") != row.get("expires_at"):
                    return False, (
                        "锚定校验失败: expires_at 与存储记录不一致"
                    )
                # 已消费优先于过期与吊销
                if row.get("consumed"):
                    return False, "演示已消费"
                try:
                    expires_at = _parse_utc_z(row["expires_at"])
                except (KeyError, TypeError, ValueError):
                    return False, "验签过程发生内部错误"
                if datetime.now(timezone.utc) >= expires_at:
                    return False, "演示已过期"

            obj_claims = presentation.get("claims")
            if not isinstance(obj_claims, dict):
                return False, "请求不合法: 演示 claims 必须为 JSON 对象"

            credential_id = row["credential_id"]
            issuer_did = row["issuer_did"]
            cred = bucket["credentials"].get(credential_id)
            if cred is None:
                return False, f"凭证不存在: {credential_id}"
            source_claims = cred["body"].get("claims", {})
            credential_status = cred.get("status")
            revoke_reason = cred.get("revoke_reason")

            public_pem = self._public_key_for_version_locked(
                bucket, issuer_did, stored_version
            )

        # 按存储的 disclose 从存储凭证 claims 重算投影并核对
        stored_disclose = list(row.get("disclose", []))
        try:
            parsed_stored = [
                (pointer, _parse_pointer(pointer))
                for pointer in stored_disclose
            ]
            recomputed = _project_claims(source_claims, parsed_stored)
        except ValidationError as exc:
            return False, f"投影重算失败: {exc}"
        if obj_claims != recomputed:
            return False, (
                "锚定校验失败: claims 投影与按存储凭证重算的结果不一致"
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

        unsigned = {
            "presentation_id": presentation_id,
            "credential_id": credential_id,
            "issuer_did": issuer_did,
            "issuer_key_version": stored_version,
            "disclose": list(row.get("disclose", [])),
            "claims": recomputed,
        }
        if is_replay_protected:
            unsigned["challenge"] = row.get("challenge")
            unsigned["expires_at"] = row.get("expires_at")
        try:
            crypto.verify(unsigned, proof, public_pem)
        except crypto.MalformedSignature:
            return False, "签名格式错误: 不是合法的 ES256 签名编码"
        except crypto.InvalidSignature:
            return False, "签名校验失败，演示内容或 proof 可能被改动"
        except Exception:  # noqa: BLE001 验签绝不向上抛错或泄露内部细节
            return False, "验签过程发生内部错误"

        # 签名与锚定均成功后检查凭证状态：已吊销不消费
        if credential_status == "revoked":
            saved_reason = revoke_reason or DEFAULT_REVOKE_REASON
            return False, f"凭证已吊销：{saved_reason}"

        if is_replay_protected:
            # 原子标记已消费：消费锁内复查已消费/到期/吊销，防止
            # “锁外验签期间演示到期仍被消费”的竞态。并发仅一次成功，
            # 跨重启保留；复查到期或已吊销均不消费、不记审计。
            with self._lock:
                bucket = self._bucket_locked(tenant_id)
                row = (
                    bucket["presentations"].get(presentation_id)
                    if bucket is not None else None
                )
                if row is None:
                    return False, f"演示不存在: {presentation_id}"
                if row.get("consumed"):
                    return False, "演示已消费"
                try:
                    expires_at = _parse_utc_z(row["expires_at"])
                except (KeyError, TypeError, ValueError):
                    return False, "验签过程发生内部错误"
                if datetime.now(timezone.utc) >= expires_at:
                    return False, "演示已过期"
                cred = bucket["credentials"].get(credential_id)
                if cred is not None and cred.get("status") == "revoked":
                    saved_reason = (
                        cred.get("revoke_reason") or DEFAULT_REVOKE_REASON
                    )
                    return False, f"凭证已吊销：{saved_reason}"
                snapshot = self._snapshot_locked()
                try:
                    row["consumed"] = True
                    row["consumed_at"] = _utc_now()
                    self._append_audit_locked(
                        tenant_id, AUDIT_PRESENTATION_CONSUMED,
                        "presentation", presentation_id,
                    )
                    self._save_locked()
                except Exception:
                    self._restore_locked(snapshot)
                    return False, "验签过程发生内部错误"
        return True, ""

    # ------------------------------------------------------------------ #
    # 谓词证明
    # ------------------------------------------------------------------ #
    @staticmethod
    def _proof_record(row: Dict[str, Any]) -> PredicateProofRecord:
        return PredicateProofRecord(
            proof_id=row["proof_id"],
            credential_id=row["credential_id"],
            issuer_did=row["issuer_did"],
            issuer_key_version=int(row["issuer_key_version"]),
            predicates=list(row.get("predicates", [])),
            results=list(row.get("results", [])),
            proof=row["proof"],
            challenge=row.get("challenge"),
            expires_at=row.get("expires_at"),
        )

    def create_proof(
        self,
        tenant_id: str,
        credential_id: str,
        predicates: Any,
        challenge: Optional[str] = None,
        expires_in: Optional[int] = None,
    ) -> PredicateProofRecord:
        """对本租户已签发凭证生成谓词证明并持久化，记审计。

        - 凭证不存在（含他租户资源）抛 NotFoundError；predicates 非法
          （非空数组约束、元素结构、路径语法/越界/重复/祖先重叠、
          gte/lte 非数字）抛 ValidationError；
        - challenge 缺省时生成 32 位小写 hex；expires_in 缺省 300 秒，
          expires_at 为当前 UTC 时间加 expires_in 秒（Z 结尾秒精度）；
        - results 为与 predicates 同序的布尔求值结果；
        - proof 为 ES256 签名，覆盖除 proof 外全部字段加 tenant_id 的
          规范化 JSON，使用凭证 issuer_key_version（旧凭证缺省按 1）
          对应的历史私钥；proof_id 为 zp_ 加 32 位小写 hex；
        - 成功记 proof.created（资源类型 predicate_proof）。
        """
        if challenge is None:
            challenge = uuid.uuid4().hex
        if expires_in is None:
            expires_in = DEFAULT_EXPIRES_IN
        expires_at = _utc_after(expires_in)
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            cred = (
                bucket["credentials"].get(credential_id)
                if bucket is not None else None
            )
            if cred is None:
                raise NotFoundError(f"凭证不存在: {credential_id}")
            stored_body = cred["body"]
            claims = stored_body.get("claims", {})
            if not isinstance(claims, dict):
                raise ValidationError("凭证 claims 不是 JSON 对象，无法证明")

            echo, results = _validate_predicates(claims, predicates)

            issuer_did = stored_body["issuer_did"]
            version = int(stored_body.get("issuer_key_version", 1))
            private_pem = self._private_key_for_version_locked(
                bucket, issuer_did, version
            )
            if not private_pem:
                raise ValidationError(
                    "历史私钥不可用: 签发者 "
                    f"{issuer_did} 密钥版本 {version} 的私钥不存在"
                )

            snapshot = self._snapshot_locked()
            try:
                proof_id = f"zp_{uuid.uuid4().hex}"
                unsigned: Dict[str, Any] = {
                    "proof_id": proof_id,
                    "credential_id": credential_id,
                    "issuer_did": issuer_did,
                    "issuer_key_version": version,
                    "predicates": echo,
                    "results": results,
                    "challenge": challenge,
                    "expires_at": expires_at,
                    "tenant_id": tenant_id,
                }
                proof = crypto.sign(unsigned, private_pem)
                row = dict(unsigned)
                row["proof"] = proof
                bucket["proofs"][proof_id] = row
                self._append_audit_locked(
                    tenant_id, AUDIT_PROOF_CREATED,
                    "predicate_proof", proof_id,
                )
                self._save_locked()
                return self._proof_record(row)
            except Exception:
                self._restore_locked(snapshot)
                raise

    def verify_proof(
        self,
        tenant_id: str,
        proof_id: str,
        proof_obj: Any,
        challenge: Any = CHALLENGE_UNSET,
    ) -> Tuple[bool, str]:
        """以存储记录为锚核验谓词证明，返回 (是否有效, 失败原因)。

        校验顺序：请求 -> 资源 -> 绑定（字段集合与各锚定字段，含
        challenge）-> 已消费 -> 过期 -> 结果重算 -> proof 格式与签名
        -> 吊销。任何失败均返回非空中文原因，绝不抛异常、不泄露私钥；
        失败不消费、不记审计。

        验签成功后在消费锁内复查已消费/到期/吊销：复查到期即返回
        “证明已过期”，不消费、不记审计；未到期并发验证仅一次成功，
        成功时原子标记已消费并记一次 proof.consumed（标记与事件同一
        次原子写，失败回滚不记），跨重启保留；已消费优先于过期与
        吊销；签名成功但凭证已吊销返回“凭证已吊销：<原因>”且不消费。
        """
        if not isinstance(proof_obj, dict):
            return False, "请求不合法: 字段 proof 必须为 JSON 对象"
        if challenge is CHALLENGE_UNSET:
            return False, "请求缺少字段: challenge"
        if not isinstance(challenge, str) or not challenge:
            return False, "请求字段 challenge 必须为非空字符串"

        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            row = (
                bucket["proofs"].get(proof_id)
                if bucket is not None else None
            )
            if row is None:
                return False, f"证明不存在: {proof_id}"

            expected_keys = {
                "proof_id",
                "credential_id",
                "issuer_did",
                "issuer_key_version",
                "predicates",
                "results",
                "challenge",
                "expires_at",
                "proof",
            }
            if set(proof_obj) != expected_keys:
                return False, (
                    "锚定校验失败: proof 字段集合与存储记录不一致"
                )
            signature = proof_obj.get("proof")
            if not isinstance(signature, str) or not signature:
                return False, "请求不合法: 字段 proof.proof 必须为非空字符串"
            if proof_obj.get("proof_id") != proof_id:
                return False, (
                    "锚定校验失败: proof_id 与路径或存储记录不一致"
                )
            if proof_obj.get("credential_id") != row.get("credential_id"):
                return False, (
                    "锚定校验失败: credential_id 与存储记录不一致"
                )
            if proof_obj.get("issuer_did") != row.get("issuer_did"):
                return False, "锚定校验失败: issuer_did 与存储记录不一致"
            stored_version = int(row.get("issuer_key_version", 1))
            version_obj = proof_obj.get("issuer_key_version")
            if (
                not isinstance(version_obj, int)
                or isinstance(version_obj, bool)
                or version_obj != stored_version
            ):
                return False, (
                    "锚定校验失败: issuer_key_version 与存储记录不一致"
                )
            if proof_obj.get("predicates") != row.get("predicates"):
                return False, "锚定校验失败: predicates 与存储记录不一致"
            if proof_obj.get("results") != row.get("results"):
                return False, "锚定校验失败: results 与存储记录不一致"
            stored_challenge = row.get("challenge")
            if proof_obj.get("challenge") != stored_challenge:
                return False, "锚定校验失败: challenge 与存储记录不一致"
            if challenge != stored_challenge:
                return False, "锚定校验失败: 请求 challenge 与存储记录不一致"
            if proof_obj.get("expires_at") != row.get("expires_at"):
                return False, "锚定校验失败: expires_at 与存储记录不一致"
            # 已消费优先于过期与吊销
            if row.get("consumed"):
                return False, "证明已消费"
            try:
                expires_at = _parse_utc_z(row["expires_at"])
            except (KeyError, TypeError, ValueError):
                return False, "验签过程发生内部错误"
            if datetime.now(timezone.utc) >= expires_at:
                return False, "证明已过期"

            credential_id = row["credential_id"]
            issuer_did = row["issuer_did"]
            cred = bucket["credentials"].get(credential_id)
            if cred is None:
                return False, f"凭证不存在: {credential_id}"
            source_claims = cred["body"].get("claims", {})
            credential_status = cred.get("status")
            revoke_reason = cred.get("revoke_reason")

            public_pem = self._public_key_for_version_locked(
                bucket, issuer_did, stored_version
            )

        # 按存储的 predicates 从存储凭证 claims 重算结果并核对
        try:
            recomputed_echo, recomputed_results = _validate_predicates(
                source_claims, row.get("predicates", [])
            )
        except ValidationError as exc:
            return False, f"结果重算失败: {exc}"
        if recomputed_echo != row.get("predicates"):
            return False, "结果重算失败: predicates 与存储记录不一致"
        if recomputed_results != row.get("results"):
            return False, (
                "锚定校验失败: results 与按存储凭证重算的结果不一致"
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

        unsigned = {
            "proof_id": proof_id,
            "credential_id": credential_id,
            "issuer_did": issuer_did,
            "issuer_key_version": stored_version,
            "predicates": row.get("predicates"),
            "results": row.get("results"),
            "challenge": row.get("challenge"),
            "expires_at": row.get("expires_at"),
            "tenant_id": tenant_id,
        }
        try:
            crypto.verify(unsigned, signature, public_pem)
        except crypto.MalformedSignature:
            return False, "签名格式错误: 不是合法的 ES256 签名编码"
        except crypto.InvalidSignature:
            return False, "签名校验失败，证明内容或 proof 可能被改动"
        except Exception:  # noqa: BLE001 验签绝不向上抛错或泄露内部细节
            return False, "验签过程发生内部错误"

        # 签名与锚定均成功后检查凭证状态：已吊销不消费
        if credential_status == "revoked":
            saved_reason = revoke_reason or DEFAULT_REVOKE_REASON
            return False, f"凭证已吊销：{saved_reason}"

        # 原子标记已消费：消费锁内复查已消费/到期/吊销，防止
        # “锁外验签期间证明到期仍被消费”的竞态。并发仅一次成功，
        # 跨重启保留；复查到期或已吊销均不消费、不记审计。
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            row = (
                bucket["proofs"].get(proof_id)
                if bucket is not None else None
            )
            if row is None:
                return False, f"证明不存在: {proof_id}"
            if row.get("consumed"):
                return False, "证明已消费"
            try:
                expires_at = _parse_utc_z(row["expires_at"])
            except (KeyError, TypeError, ValueError):
                return False, "验签过程发生内部错误"
            if datetime.now(timezone.utc) >= expires_at:
                return False, "证明已过期"
            cred = bucket["credentials"].get(credential_id)
            if cred is not None and cred.get("status") == "revoked":
                saved_reason = (
                    cred.get("revoke_reason") or DEFAULT_REVOKE_REASON
                )
                return False, f"凭证已吊销：{saved_reason}"
            snapshot = self._snapshot_locked()
            try:
                row["consumed"] = True
                row["consumed_at"] = _utc_now()
                self._append_audit_locked(
                    tenant_id, AUDIT_PROOF_CONSUMED,
                    "predicate_proof", proof_id,
                )
                self._save_locked()
            except Exception:
                self._restore_locked(snapshot)
                return False, "验签过程发生内部错误"
        return True, ""

    # ------------------------------------------------------------------ #
    # 凭证状态与吊销
    # ------------------------------------------------------------------ #
    def set_credential_active(
        self, tenant_id: str, credential_id: str
    ) -> Tuple[CredentialStatusRecord, bool]:
        """登记凭证状态为 active，返回 (状态记录, 是否首次登记)。

        首次登记 201（created=True），重复登记 200（created=False）且
        保持首次 updated_at；已 revoked 返回 ConflictError(409)。
        首次登记与幂等重试均记 status.updated。
        """
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            rec = (
                bucket["credentials"].get(credential_id)
                if bucket is not None else None
            )
            if rec is None:
                raise NotFoundError(f"凭证不存在: {credential_id}")
            current = rec.get("status")
            if current == "revoked":
                raise ConflictError(
                    f"凭证已吊销，不能登记为 active: {credential_id}"
                )
            created = current != "active"
            snapshot = self._snapshot_locked()
            try:
                if created:
                    rec["status"] = "active"
                    rec["status_updated_at"] = _utc_now()
                # 幂等重试（200）同样每次记录审计
                self._append_audit_locked(
                    tenant_id, AUDIT_STATUS_UPDATED,
                    "credential", credential_id,
                )
                self._save_locked()
            except Exception:
                self._restore_locked(snapshot)
                raise
            return (
                CredentialStatusRecord(
                    credential_id=credential_id,
                    status="active",
                    updated_at=rec.get("status_updated_at"),
                ),
                created,
            )

    def get_credential_status(
        self, tenant_id: str, credential_id: str
    ) -> CredentialStatusRecord:
        """查询凭证状态；历史无状态按 active 返回，updated_at 为 None。

        凭证不存在（含他租户资源）抛 NotFoundError。
        """
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            rec = (
                bucket["credentials"].get(credential_id)
                if bucket is not None else None
            )
            if rec is None:
                raise NotFoundError(f"凭证不存在: {credential_id}")
            status = rec.get("status")
            if status is None:
                return CredentialStatusRecord(
                    credential_id=credential_id,
                    status="active",
                    updated_at=None,
                )
            return CredentialStatusRecord(
                credential_id=credential_id,
                status=status,
                updated_at=rec.get("status_updated_at"),
                reason=rec.get("revoke_reason"),
                revoked_at=rec.get("revoked_at"),
            )

    def revoke_credential(
        self,
        tenant_id: str,
        credential_id: str,
        reason: Any = REASON_UNSET,
    ) -> CredentialStatusRecord:
        """吊销凭证；reason 省略（REASON_UNSET）时用默认原因。

        - 凭证不存在（含他租户资源）抛 NotFoundError；
        - 重复吊销时任何 reason（含非法值）均忽略，返回首次吊销结果；
          非法 reason（非字符串或裁剪后为空，含显式 null）仅在首次
          吊销时抛 ValidationError；
        - 保存并返回首尾裁剪后的 reason；
        - 首次吊销与幂等重试均记 credential.revoked。
        """
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            rec = (
                bucket["credentials"].get(credential_id)
                if bucket is not None else None
            )
            if rec is None:
                raise NotFoundError(f"凭证不存在: {credential_id}")
            if rec.get("status") == "revoked":
                snapshot = self._snapshot_locked()
                try:
                    # 幂等成功同样每次记录审计
                    self._append_audit_locked(
                        tenant_id, AUDIT_CREDENTIAL_REVOKED,
                        "credential", credential_id,
                    )
                    self._save_locked()
                except Exception:
                    self._restore_locked(snapshot)
                    raise
                return CredentialStatusRecord(
                    credential_id=credential_id,
                    status="revoked",
                    updated_at=rec.get("status_updated_at"),
                    reason=rec.get("revoke_reason"),
                    revoked_at=rec.get("revoked_at"),
                )

            if reason is REASON_UNSET:
                final_reason = DEFAULT_REVOKE_REASON
            else:
                if not isinstance(reason, str):
                    raise ValidationError("字段 reason 必须为字符串")
                final_reason = reason.strip()
                if not final_reason:
                    raise ValidationError("字段 reason 裁剪后不能为空")

            now = _utc_now()
            snapshot = self._snapshot_locked()
            try:
                rec["status"] = "revoked"
                rec["status_updated_at"] = now
                rec["revoked_at"] = now
                rec["revoke_reason"] = final_reason
                self._append_audit_locked(
                    tenant_id, AUDIT_CREDENTIAL_REVOKED,
                    "credential", credential_id,
                )
                self._save_locked()
            except Exception:
                self._restore_locked(snapshot)
                raise
            return CredentialStatusRecord(
                credential_id=credential_id,
                status="revoked",
                updated_at=now,
                reason=final_reason,
                revoked_at=now,
            )

    def verify_credential(
        self,
        tenant_id: str,
        credential_id: str,
        body: Dict[str, Any],
        signature: str,
    ) -> Tuple[bool, str]:
        """以存储记录为锚验签：返回 (是否有效, 失败原因)。

        锚定字段为存储的 credential_id、issuer_did、issuer_key_version；
        验签公钥按 issuer_key_version 从签发者公钥历史中取出（旧凭证
        缺版本按 1 处理）。资源查找限本租户（他租户凭证按不存在）。
        任何失败都返回非空中文原因，绝不抛异常、绝不泄露私钥。
        reason 按类别区分：请求 / 资源 / 锚定 / 签名格式 / 签名校验 /
        密钥。验签不记审计。
        """
        if not isinstance(body, dict):
            return False, "请求不合法: 字段 body 必须为 JSON 对象"
        if not isinstance(signature, str) or not signature:
            return False, "请求不合法: 字段 signature 必须为非空字符串"

        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            rec = (
                bucket["credentials"].get(credential_id)
                if bucket is not None else None
            )
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
                bucket, issuer_did, stored_version
            )
            # 状态在锚定、签名校验成功后才参与判定；active 或无状态维持结果
            credential_status = rec.get("status")
            revoke_reason = rec.get("revoke_reason")

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

        # 签名、锚定均成功后检查状态：revoked 判 valid:false，
        # active 或历史无状态维持 valid:true
        if credential_status == "revoked":
            saved_reason = revoke_reason or DEFAULT_REVOKE_REASON
            return False, f"凭证已吊销：{saved_reason}"
        return True, ""

    # ------------------------------------------------------------------ #
    # 信任锚点注册表
    # ------------------------------------------------------------------ #
    @staticmethod
    def _trust_anchor_record(did: str, row: Dict[str, Any]) -> TrustAnchorRecord:
        return TrustAnchorRecord(
            did=did,
            public_key=row["public_key"],
            key_version=int(row["key_version"]),
            status=row.get("status", "active"),
            updated_at=row.get("updated_at"),
        )

    @staticmethod
    def _validate_trust_fields(
        did: Any, public_key: Any, key_version: Any
    ) -> Tuple[str, str, int]:
        """校验锚点注册字段：did 非空字符串、公钥为 P-256 PEM、版本为正整数。"""
        if not isinstance(did, str) or not did:
            raise ValidationError("字段 did 必须为非空字符串")
        if not isinstance(public_key, str) or not public_key:
            raise ValidationError("字段 public_key 必须为非空字符串")
        if not isinstance(key_version, int) or isinstance(key_version, bool):
            raise ValidationError("字段 key_version 必须为正整数")
        if key_version < 1:
            raise ValidationError("字段 key_version 必须为正整数")
        try:
            crypto.validate_public_key_pem(public_key)
        except (ValueError, TypeError) as exc:
            raise ValidationError(f"字段 public_key 不是合法的 P-256 PEM: {exc}")
        return did, public_key, key_version

    def register_trust_anchor(
        self,
        tenant_id: str,
        did: Any,
        public_key: Any,
        key_version: Any,
    ) -> Tuple[TrustAnchorRecord, bool]:
        """注册（或幂等重试）信任锚点，返回 (记录, 是否新建)。

        - did 须为非空字符串，public_key 须为可解析的 P-256 PEM，
          key_version 须为非布尔正整数，否则 ValidationError(400)；
        - 同 (did, key_version) 且 PEM 相同：幂等返回既有记录（200），
          每次重试均记 trust.anchor.registered；
        - 同 (did, key_version) 但 PEM 不同：ConflictError(409)，不记审计；
        - 新锚点状态为 active、updated_at 为 None（201）。
        """
        did, public_key, key_version = self._validate_trust_fields(
            did, public_key, key_version
        )
        with self._lock:
            bucket = self._ensure_bucket_locked(tenant_id)
            anchors = bucket["trust_anchors"].setdefault(did, {})
            existing = anchors.get(str(key_version))
            if existing is not None:
                if existing.get("public_key") != public_key:
                    raise ConflictError(
                        f"信任锚点已存在且公钥不同: {did}#{key_version}"
                    )
                snapshot = self._snapshot_locked()
                try:
                    # 幂等重试同样每次记录审计
                    self._append_audit_locked(
                        tenant_id,
                        AUDIT_TRUST_ANCHOR_REGISTERED,
                        "trust_anchor",
                        f"{did}#{key_version}",
                    )
                    self._save_locked()
                except Exception:
                    self._restore_locked(snapshot)
                    raise
                return self._trust_anchor_record(did, existing), False

            snapshot = self._snapshot_locked()
            try:
                row = {
                    "key_version": key_version,
                    "public_key": public_key,
                    "status": "active",
                    "updated_at": None,
                }
                anchors[str(key_version)] = row
                self._append_audit_locked(
                    tenant_id,
                    AUDIT_TRUST_ANCHOR_REGISTERED,
                    "trust_anchor",
                    f"{did}#{key_version}",
                )
                self._save_locked()
                return self._trust_anchor_record(did, row), True
            except Exception:
                self._restore_locked(snapshot)
                raise

    def list_trust_anchors(
        self, tenant_id: str, did: str
    ) -> List[TrustAnchorRecord]:
        """返回本租户指定 DID 的全部锚点版本（按 key_version 升序）。

        DID 未知（含他租户资源）抛 NotFoundError。
        """
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            anchors = (
                bucket["trust_anchors"].get(did)
                if bucket is not None else None
            )
            if not anchors:
                raise NotFoundError(f"信任锚点不存在: {did}")
            rows = sorted(
                anchors.values(), key=lambda row: int(row["key_version"])
            )
            return [self._trust_anchor_record(did, row) for row in rows]

    def revoke_trust_anchor(
        self, tenant_id: str, did: str, key_version: int
    ) -> TrustAnchorRecord:
        """吊销锚点版本；首次与幂等重试均成功，重复吊销保持首次时间。

        - 锚点版本未知（含他租户资源）抛 NotFoundError；
        - 首次吊销置 updated_at 为当前 UTC 秒精度时间并记
          trust.anchor.revoked；重复吊销不变更状态、updated_at 保持
          首次值，但每次均记审计。
        """
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            anchors = (
                bucket["trust_anchors"].get(did)
                if bucket is not None else None
            )
            row = anchors.get(str(key_version)) if anchors is not None else None
            if row is None:
                raise NotFoundError(
                    f"信任锚点不存在: {did}#{key_version}"
                )
            snapshot = self._snapshot_locked()
            try:
                if row.get("status") != "revoked":
                    row["status"] = "revoked"
                    row["updated_at"] = _utc_now()
                # 首次吊销与幂等重试均记审计
                self._append_audit_locked(
                    tenant_id,
                    AUDIT_TRUST_ANCHOR_REVOKED,
                    "trust_anchor",
                    f"{did}#{key_version}",
                )
                self._save_locked()
            except Exception:
                self._restore_locked(snapshot)
                raise
            return self._trust_anchor_record(did, row)

    def verify_trust(
        self,
        tenant_id: str,
        data: Any,
    ) -> Tuple[bool, str]:
        """按 active 锚点公钥验签，返回 (是否有效, 失败原因)。

        请求体须为 JSON 对象，含非空字符串 issuer_did、非布尔正整数
        issuer_key_version 与非空字符串 signature；其余字段作为被签名
        负载参与验签。签名覆盖请求对象去掉 signature 后按 key 升序的
        规范化 JSON（ES256，裸 R||S 的无填充 base64url），公钥取本租户
        匹配 (issuer_did, issuer_key_version) 且状态为 active 的锚点。
        缺失/吊销/验签失败均返回非空中文原因，绝不抛异常、不记审计。
        """
        if not isinstance(data, dict):
            return False, "请求不合法: 请求体必须为 JSON 对象"
        issuer_did = data.get("issuer_did")
        if not isinstance(issuer_did, str) or not issuer_did:
            return False, "请求不合法: 字段 issuer_did 必须为非空字符串"
        key_version = data.get("issuer_key_version")
        if (
            not isinstance(key_version, int)
            or isinstance(key_version, bool)
            or key_version < 1
        ):
            return False, "请求不合法: 字段 issuer_key_version 必须为正整数"
        signature = data.get("signature")
        if not isinstance(signature, str) or not signature:
            return False, "请求不合法: 字段 signature 必须为非空字符串"

        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            anchors = (
                bucket["trust_anchors"].get(issuer_did)
                if bucket is not None else None
            )
            row = (
                anchors.get(str(key_version))
                if anchors is not None else None
            )
            if row is None:
                return False, (
                    f"信任锚点不存在: {issuer_did}#{key_version}"
                )
            status = row.get("status", "active")
            public_pem = row.get("public_key", "")

        if status == "revoked":
            return False, f"信任锚点已吊销: {issuer_did}#{key_version}"

        message = {k: v for k, v in data.items() if k != "signature"}
        try:
            crypto.verify(message, signature, public_pem)
        except crypto.MalformedSignature:
            return False, "签名格式错误: 不是合法的 ES256 签名编码"
        except crypto.InvalidSignature:
            return False, "签名校验失败，负载或签名可能被改动"
        except Exception:  # noqa: BLE001 验签绝不向上抛错或泄露内部细节
            return False, "验签过程发生内部错误"
        return True, ""

    def rotate_trust_anchor(
        self,
        tenant_id: str,
        did: Any,
        from_key_version: Any,
        public_key: Any,
    ) -> Tuple[TrustAnchorRecord, bool]:
        """基于前置版本轮换信任锚点密钥，返回 (新版本记录, 是否新建)。

        请求字段：from_key_version 为非布尔正整数，public_key 为可解析
        的 P-256 PEM；否则 ValidationError(400)。目标版本恒为
        from_key_version + 1。

        - DID 在本租户不存在（含他租户）抛 NotFoundError(404)；
        - 目标版本已存在：
          * 由同一 from_key_version 创建且 PEM 相同 -> 幂等返回既有记录
            （200），每次重试均记 trust.anchor.rotated；即使前置或目标
            后来已吊销也照此幂等；
          * PEM 不同，或 PEM 相同但前置不同 -> ConflictError(409)，
            不记审计；
        - 目标不存在时仅允许前置为本租户当前最高且 active 的版本：
          前置不存在 NotFoundError(404)；前置已吊销或非最高版本
          ValidationError(400)，不改动任何版本、不记审计；
        - 新版本为 active、updated_at 为 None，旧版本状态原样保留；
          轮换与审计在同一把锁内经同一次原子写落盘，失败回滚。
        """
        if not isinstance(did, str) or not did:
            raise ValidationError("路径参数 did 必须为非空字符串")
        if not isinstance(public_key, str) or not public_key:
            raise ValidationError("字段 public_key 必须为非空字符串")
        if (
            not isinstance(from_key_version, int)
            or isinstance(from_key_version, bool)
            or from_key_version < 1
        ):
            raise ValidationError("字段 from_key_version 必须为正整数")
        try:
            crypto.validate_public_key_pem(public_key)
        except (ValueError, TypeError) as exc:
            raise ValidationError(
                f"字段 public_key 不是合法的 P-256 PEM: {exc}"
            )

        target_version = from_key_version + 1
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            anchors = (
                bucket["trust_anchors"].get(did)
                if bucket is not None else None
            )
            if not anchors:
                raise NotFoundError(f"信任锚点不存在: {did}")

            target_row = anchors.get(str(target_version))
            if target_row is not None:
                same_pem = target_row.get("public_key") == public_key
                same_from = (
                    int(target_row.get("from_key_version", -1))
                    == from_key_version
                )
                if same_pem and same_from:
                    snapshot = self._snapshot_locked()
                    try:
                        # 幂等重试同样每次记录审计（前置/目标已吊销亦然）
                        self._append_audit_locked(
                            tenant_id,
                            AUDIT_TRUST_ANCHOR_ROTATED,
                            "trust_anchor",
                            f"{did}#{target_version}",
                        )
                        self._save_locked()
                    except Exception:
                        self._restore_locked(snapshot)
                        raise
                    return self._trust_anchor_record(did, target_row), False
                # 目标已被其他 PEM 或其他前置占用
                raise ConflictError(
                    f"信任锚点目标版本已存在且不可幂等复用: "
                    f"{did}#{target_version}"
                )

            # 目标不存在：前置必须存在、active 且为当前最高版本
            from_row = anchors.get(str(from_key_version))
            if from_row is None:
                raise NotFoundError(
                    f"信任锚点前置版本不存在: {did}#{from_key_version}"
                )
            if from_row.get("status", "active") == "revoked":
                raise ValidationError(
                    "前置版本已吊销，不能作为轮换基准: "
                    f"{did}#{from_key_version}"
                )
            max_version = max(int(version) for version in anchors)
            if from_key_version != max_version:
                raise ValidationError(
                    "from_key_version 不是当前最高 active 版本"
                    f"（当前最高 {max_version}）: {did}#{from_key_version}"
                )

            snapshot = self._snapshot_locked()
            try:
                row = {
                    "key_version": target_version,
                    "public_key": public_key,
                    "status": "active",
                    "updated_at": None,
                    "from_key_version": from_key_version,
                }
                anchors[str(target_version)] = row
                self._append_audit_locked(
                    tenant_id,
                    AUDIT_TRUST_ANCHOR_ROTATED,
                    "trust_anchor",
                    f"{did}#{target_version}",
                )
                self._save_locked()
                return self._trust_anchor_record(did, row), True
            except Exception:
                self._restore_locked(snapshot)
                raise
