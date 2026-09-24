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
    CredentialStatusSyncRecord,
    CredentialStatusHistoryEvent,
    ImportedCredentialRecord,
    LocalCredentialStatusHistoryEvent,
    DIDRecord,
    DIDStatusRecord,
    KeyVersionStatusRecord,
    KeyRevocationEvent,
    KeyLifecycleEvent,
    PredicateProofRecord,
    PresentationRecord,
    TrustAnchorRecord,
    TrustAnchorHistoryEvent,
    TrustAnchorDiscoveryRecord,
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

# 吊销 DID 旧密钥版本时未提供 reason 的默认原因
DEFAULT_KEY_REVOKE_REASON = "密钥版本主动吊销"

# 停用 DID 时未提供 reason 的默认原因
DEFAULT_DID_DEACTIVATE_REASON = "DID 主动停用"

# DID 停用时验签类端点返回的统一中文原因前缀
DID_DEACTIVATED_REASON_PREFIX = "签发DID已停用："

# 凭证（及其演示/谓词证明/外部凭证）到期时的统一中文原因
CREDENTIAL_EXPIRED_REASON = "凭证已过期"

# 重新验证已落盘的导入凭证时的统一中文原因
IMPORTED_ANCHOR_UNAVAILABLE_REASON = "锚点不可用"
IMPORTED_SIGNATURE_MALFORMED_REASON = "签名格式错误"
IMPORTED_SIGNATURE_INVALID_REASON = "签名校验失败"

# 哨兵：调用方未提供 reason 字段（区别于显式传 None 等非法值）
REASON_UNSET = object()

# 哨兵：演示验签请求未提供 challenge 字段（区别于显式传非法值）
CHALLENGE_UNSET = object()

# 哨兵：签发请求未提供 expires_at（区别于显式传 null 等非法值）；
# 未提供时凭证正文不得注入该字段，凭证保持无期限。
EXPIRES_AT_UNSET = object()

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
AUDIT_KEY_REVOKED = "key.revoked"
AUDIT_DID_DEACTIVATED = "did.deactivated"
AUDIT_TRUST_CREDENTIAL_STATUS_SYNCED = "trust.credential.status.synced"
AUDIT_TRUST_CREDENTIAL_IMPORTED = "trust.credential.imported"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _utc_after(seconds: int) -> str:
    """当前 UTC 时间加 seconds 秒，Z 结尾秒精度。"""
    moment = datetime.now(timezone.utc) + timedelta(seconds=seconds)
    return moment.isoformat(timespec="seconds").replace("+00:00", "Z")


def _utc_z_from_unix(ts: int) -> str:
    """Unix 秒转 UTC 秒精度 Z 时间串（与审计 timestamp 严格同秒）。"""
    return datetime.fromtimestamp(int(ts), timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _parse_utc_z(text: str) -> datetime:
    """解析 Z 结尾秒精度 UTC 时间戳为 aware datetime。"""
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )


# 凭证 expires_at 的严格形状：YYYY-MM-DDTHH:MM:SSZ（秒精度、无偏移、
# 无小数秒）；时刻合法性（月/日/时分秒范围）再由 strptime 把关。
_UTC_Z_SHAPE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _validate_future_utc_z(value: Any, field: str) -> str:
    """校验并返回凭证 expires_at：严格 UTC 秒精度 Z 格式且晚于当前时刻。

    - 必须为字符串且形状恰为 YYYY-MM-DDTHH:MM:SSZ（拒绝毫秒、时区
      偏移、空格分隔、非法时刻等）；
    - 必须严格晚于服务接收时刻（相等或更早均拒绝）。
    """
    if not isinstance(value, str) or not _UTC_Z_SHAPE_RE.match(value):
        raise ValidationError(
            f"字段 {field} 必须为 UTC 秒精度 Z 格式"
            "（YYYY-MM-DDTHH:MM:SSZ）"
        )
    try:
        expires_dt = _parse_utc_z(value)
    except ValueError:
        raise ValidationError(
            f"字段 {field} 必须为 UTC 秒精度 Z 格式"
            "（YYYY-MM-DDTHH:MM:SSZ）"
        )
    if expires_dt <= datetime.now(timezone.utc):
        raise ValidationError(f"字段 {field} 必须严格晚于当前时间")
    return value


def _validate_key_handle(value: Any, field: str) -> str:
    """句柄必须为非空字符串且不是 PEM 文本，返回去空白后的句柄。"""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"缺少字段或字段为空: {field}")
    handle = value.strip()
    if _PEM_MARKER in handle:
        raise ValidationError(f"字段 {field} 必须为句柄，而非 PEM 密钥文本")
    return handle


def _is_expired(expires_at: Any) -> bool:
    """凭证正文的 expires_at 已到期（当前时间 >= expires_at）即 True。

    服务端签发的 expires_at 已按严格格式校验；此处为只读判定，缺省
    （无字段/空）视为无期限。任何解析异常都按未到期处理，绝不抛出，
    以免影响锚定/签名等既有分类原因。
    """
    if not isinstance(expires_at, str) or not expires_at:
        return False
    try:
        return datetime.now(timezone.utc) >= _parse_utc_z(expires_at)
    except ValueError:
        return False


def _parse_pointer(pointer: str, label: str = "disclose") -> Tuple[str, ...]:
    """解析相对 claims 的 RFC6901 JSON Pointer 为 token 元组。

    仅做语法解析：必须为以 "/" 开头的字符串，按 "/" 分段并对
    "~1"/"~0" 反转义（顺序不可颠倒）；根指针 "" 与数组索引语义在
    _resolve_pointer 中按业务规则拒绝。label 为报错中的字段名。
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
    return tokens


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


def _is_number(value: Any) -> bool:
    """非布尔数字（bool 是 int 的子类，须显式排除）。"""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _json_equal(left: Any, right: Any) -> bool:
    """JSON 精确相等：布尔与数字不互通，容器递归比较。"""
    if isinstance(left, bool) or isinstance(right, bool):
        return (
            isinstance(left, bool)
            and isinstance(right, bool)
            and left == right
        )
    if _is_number(left) and _is_number(right):
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _json_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _json_equal(a, b) for a, b in zip(left, right)
        )
    return left == right


def _validate_predicates(
    claims: Dict[str, Any], predicates: Any
) -> List[Dict[str, Any]]:
    """校验 predicates 列表并返回原样谓词项列表。

    - predicates 必须为非空数组；元素为恰含 path/op[, value] 的对象；
    - op 仅支持 exists/eq/gte/lte；exists 禁止 value，其余必须有 value；
    - path 为相对 claims 的 RFC6901 指针：禁根、禁数组索引、禁越界，
      不得重复、不得存在祖先/后代重叠；
    - gte/lte 要求谓词 value 与 claims 命中值均为非布尔数字。
    """
    if not isinstance(predicates, list) or not predicates:
        raise ValidationError("字段 predicates 必须为非空数组")
    items: List[Dict[str, Any]] = []
    seen_tokens: List[Tuple[str, ...]] = []
    for item in predicates:
        if not isinstance(item, dict):
            raise ValidationError("predicates 元素必须为 JSON 对象")
        if "path" not in item:
            raise ValidationError("predicates 元素缺少字段: path")
        if "op" not in item:
            raise ValidationError("predicates 元素缺少字段: op")
        extra = sorted(set(item) - {"path", "op", "value"})
        if extra:
            raise ValidationError(
                f"predicates 元素含多余字段: {', '.join(extra)}"
            )
        op = item["op"]
        if op not in _PREDICATE_OPS:
            raise ValidationError(
                f"predicates 元素 op 非法: {op!r}"
                "（仅支持 exists/eq/gte/lte）"
            )
        if op == "exists":
            if "value" in item:
                raise ValidationError(
                    "predicates 元素 op 为 exists 时禁止 value 字段"
                )
        elif "value" not in item:
            raise ValidationError(
                f"predicates 元素 op 为 {op} 时缺少字段: value"
            )
        pointer = item["path"]
        tokens = _parse_pointer(pointer, "predicates")
        if tokens in seen_tokens:
            raise ValidationError(f"predicates 路径重复: {pointer!r}")
        for existing in seen_tokens:
            if tokens[: len(existing)] == existing:
                raise ValidationError(
                    f"predicates 路径存在祖先重叠: {pointer!r} 被已选路径覆盖"
                )
            if existing[: len(tokens)] == tokens:
                raise ValidationError(
                    f"predicates 路径存在祖先重叠: 已选路径被 {pointer!r} 覆盖"
                )
        hit = _resolve_pointer(claims, tokens, pointer, "predicates")
        if op in ("gte", "lte"):
            if not _is_number(item["value"]):
                raise ValidationError(
                    f"predicates 元素 op 为 {op} 时 value 必须为非布尔数字"
                )
            if not _is_number(hit):
                raise ValidationError(
                    f"predicates 元素 op 为 {op} 时 claims 命中值"
                    " 必须为非布尔数字"
                )
        seen_tokens.append(tokens)
        items.append(item)
    return items


def _evaluate_predicates(
    claims: Dict[str, Any], predicates: List[Dict[str, Any]]
) -> List[bool]:
    """对已通过校验的谓词逐项求值，返回同序布尔结果。"""
    results: List[bool] = []
    for item in predicates:
        tokens = _parse_pointer(item["path"], "predicates")
        hit = _resolve_pointer(claims, tokens, item["path"], "predicates")
        op = item["op"]
        if op == "exists":
            results.append(True)
        elif op == "eq":
            results.append(_json_equal(hit, item["value"]))
        elif op == "gte":
            results.append(hit >= item["value"])
        else:  # lte
            results.append(hit <= item["value"])
    return results



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
            bucket.setdefault("credential_status_sync", {})
            bucket.setdefault("imported_credentials", {})
            bucket.setdefault("credential_status_history", {})
            bucket.setdefault("key_revocations", {})
            bucket.setdefault("key_lifecycle", {})
            bucket.setdefault("trust_anchor_history", {})
            bucket.setdefault("local_credential_status_history", {})
            for rec in bucket["dids"].values():
                _migrate_did_row(rec)
        # 外部凭证状态历史游标（租户内持久化正整数，按追加递增）。
        # 旧状态文件无该字段时，从已有历史项的最大 cursor 推导。
        self._history_cursor = int(data.get("credential_status_history_cursor", 0))
        if not self._history_cursor:
            max_cursor = 0
            for bucket in self._tenants.values():
                for entries_by_cred in bucket.get(
                    "credential_status_history", {}
                ).values():
                    for entries in entries_by_cred.values():
                        for event in entries:
                            max_cursor = max(
                                max_cursor, int(event.get("cursor", 0))
                            )
            self._history_cursor = max_cursor
        # DID 密钥吊销历史游标：按租户各自维护的持久化正整数
        # （tenant_id -> cursor），同一租户内不同 DID 的吊销事件共享
        # 该游标空间。旧状态文件无该字段时，从各租户已有吊销历史项的
        # 最大 cursor 推导。
        raw_cursors = data.get("key_revocation_cursors", {})
        self._key_revocation_cursors: Dict[str, int] = {
            str(tenant_id): int(cursor)
            for tenant_id, cursor in raw_cursors.items()
        } if isinstance(raw_cursors, dict) else {}
        for tenant_id, bucket in self._tenants.items():
            max_cursor = self._key_revocation_cursors.get(tenant_id, 0)
            for entries in bucket.get("key_revocations", {}).values():
                for event in entries:
                    max_cursor = max(max_cursor, int(event.get("cursor", 0)))
            self._key_revocation_cursors[tenant_id] = max_cursor
        # DID 密钥生命周期历史游标：按租户各自维护的持久化正整数
        # （tenant_id -> cursor），同一租户内不同 DID 的生命周期事件
        # （did.created/key.rotated/key.revoked）共享该游标空间，但与
        # 密钥吊销历史游标空间相互隔离。旧状态文件无该字段时，从各租户
        # 已有生命周期历史项的最大 cursor 推导。
        raw_lifecycle_cursors = data.get("key_lifecycle_cursors", {})
        self._key_lifecycle_cursors: Dict[str, int] = {
            str(tenant_id): int(cursor)
            for tenant_id, cursor in raw_lifecycle_cursors.items()
        } if isinstance(raw_lifecycle_cursors, dict) else {}
        for tenant_id, bucket in self._tenants.items():
            max_cursor = self._key_lifecycle_cursors.get(tenant_id, 0)
            for entries in bucket.get("key_lifecycle", {}).values():
                for event in entries:
                    max_cursor = max(max_cursor, int(event.get("cursor", 0)))
            self._key_lifecycle_cursors[tenant_id] = max_cursor
        # 信任锚点生命周期历史游标：按租户各自维护的持久化正整数
        # （tenant_id -> cursor），同一租户内不同 DID 的锚点事件共享
        # 该游标空间。旧状态文件无该字段时，从各租户已有锚点历史项的
        # 最大 cursor 推导。
        raw_anchor_cursors = data.get("trust_anchor_history_cursors", {})
        self._trust_anchor_history_cursors: Dict[str, int] = {
            str(tenant_id): int(cursor)
            for tenant_id, cursor in raw_anchor_cursors.items()
        } if isinstance(raw_anchor_cursors, dict) else {}
        for tenant_id, bucket in self._tenants.items():
            max_cursor = self._trust_anchor_history_cursors.get(tenant_id, 0)
            for entries in bucket.get("trust_anchor_history", {}).values():
                for event in entries:
                    max_cursor = max(max_cursor, int(event.get("cursor", 0)))
            self._trust_anchor_history_cursors[tenant_id] = max_cursor
        # 本租户签发凭证状态历史游标：按租户各自维护的持久化正整数
        # （tenant_id -> cursor），同一租户内不同凭证的状态事件共享
        # 该游标空间。旧状态文件无该字段时，从各租户已有历史项的
        # 最大 cursor 推导。
        raw_local_cursors = data.get("local_credential_status_history_cursors", {})
        self._local_credential_status_history_cursors: Dict[str, int] = {
            str(tenant_id): int(cursor)
            for tenant_id, cursor in raw_local_cursors.items()
        } if isinstance(raw_local_cursors, dict) else {}
        for tenant_id, bucket in self._tenants.items():
            max_cursor = self._local_credential_status_history_cursors.get(
                tenant_id, 0
            )
            for entries in bucket.get(
                "local_credential_status_history", {}
            ).values():
                for event in entries:
                    max_cursor = max(max_cursor, int(event.get("cursor", 0)))
            self._local_credential_status_history_cursors[tenant_id] = max_cursor
        # 旧状态文件中已吊销但无历史的密钥版本补一条兼容项（内存态）；
        # 随下一次原子写一并落盘，重启后 cursor 稳定。
        self._backfill_key_revocations_locked()
        # 旧状态文件中已有密钥版本但无生命周期历史的按 DID 序、版本序、
        # 同版本 active 后 revoked 稳定补录（内存态）；重启后 cursor 稳定。
        self._backfill_key_lifecycle_locked()
        # 旧状态文件中已有锚点版本但无生命周期历史的按版本稳定补录
        # （内存态）；随下一次原子写一并落盘，重启后 cursor 稳定。
        self._backfill_trust_anchor_history_locked()
        # 旧状态文件中已有同步状态但无历史的双键补一条兼容项（内存态，
        # audit 字段为 None）；随下一次原子写一并落盘。
        self._backfill_all_history_locked()
        # 旧状态文件中本地凭证已有状态（active/revoked）但无状态历史的
        # 按稳定顺序补兼容项（内存态，audit 字段为 None）。
        self._backfill_local_credential_status_history_locked()

    def _save_locked(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        tmp = f"{self.path}.tmp.{os.getpid()}.{uuid.uuid4().hex}"
        payload = {
            "tenants": self._tenants,
            "audit": self._audit,
            "audit_seq": self._audit_seq,
            "credential_status_history_cursor": self._history_cursor,
            "key_revocation_cursors": self._key_revocation_cursors,
            "key_lifecycle_cursors": self._key_lifecycle_cursors,
            "trust_anchor_history_cursors": self._trust_anchor_history_cursors,
            "local_credential_status_history_cursors": (
                self._local_credential_status_history_cursors
            ),
        }
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(tmp, self.path)

    def _snapshot_locked(self) -> Any:
        """深拷贝当前全部可变状态，供落盘失败时回滚。"""
        return copy.deepcopy(
            (
                self._tenants,
                self._audit,
                self._audit_seq,
                self._history_cursor,
                self._key_revocation_cursors,
                self._key_lifecycle_cursors,
                self._trust_anchor_history_cursors,
                self._local_credential_status_history_cursors,
            )
        )

    def _restore_locked(self, snapshot: Any) -> None:
        (
            tenants,
            audit,
            audit_seq,
            history_cursor,
            key_revocation_cursors,
            key_lifecycle_cursors,
            trust_anchor_history_cursors,
            local_credential_status_history_cursors,
        ) = copy.deepcopy(snapshot)
        self._tenants = tenants
        self._audit = audit
        self._audit_seq = audit_seq
        self._history_cursor = history_cursor
        self._key_revocation_cursors = key_revocation_cursors
        self._key_lifecycle_cursors = key_lifecycle_cursors
        self._trust_anchor_history_cursors = trust_anchor_history_cursors
        self._local_credential_status_history_cursors = (
            local_credential_status_history_cursors
        )

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
                "credential_status_sync": {},
                "imported_credentials": {},
                "credential_status_history": {},
                "key_revocations": {},
                "key_lifecycle": {},
                "trust_anchor_history": {},
                "local_credential_status_history": {},
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
                audit_event = self._append_audit_locked(
                    tenant_id, AUDIT_DID_CREATED, "did", did
                )
                # 生命周期事件的 updated_at 与审计 timestamp 严格同秒。
                created_at = _utc_z_from_unix(audit_event["timestamp"])
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
                # 仅新建追加 active 生命周期事件；幂等重试不追加、不改写。
                lifecycle_entries = (
                    bucket.setdefault("key_lifecycle", {}).setdefault(did, [])
                )
                lifecycle_entries.append(
                    {
                        "key_version": 1,
                        "key_handle": handle,
                        "public_key": registered_pub,
                        "action": AUDIT_DID_CREATED,
                        "status": "active",
                        "updated_at": created_at,
                        "cursor": (
                            self._next_key_lifecycle_cursor_locked(tenant_id)
                        ),
                        "audit_seq": audit_event["seq"],
                        "audit_timestamp": audit_event["timestamp"],
                    }
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

    @staticmethod
    def _is_did_deactivated_locked(rec: Optional[Dict[str, Any]]) -> bool:
        return rec is not None and rec.get("status") == "deactivated"

    # ------------------------------------------------------------------ #
    # DID 生命周期停用
    # ------------------------------------------------------------------ #
    def deactivate_did(
        self,
        tenant_id: str,
        did: str,
        reason: Any = REASON_UNSET,
    ) -> DIDStatusRecord:
        """停用 DID（生命周期终态，不可恢复）。

        - DID 不存在（含他租户资源）抛 NotFoundError（HTTP 404，跨租户
          不可探测）；
        - 重复停用时任何 reason（含非法值）均忽略，返回首次停用结果；
          非法 reason（非字符串或裁剪后为空，含显式 null）仅在首次停用
          时抛 ValidationError（HTTP 400）；
        - 首次停用写入 status="deactivated" 与首次原因/UTC 秒精度 Z 时间；
        - 首次停用与幂等重试均记 did.deactivated（resource_type 为 did、
          resource_id 为 did）；停用状态与审计在同一把锁内经同一次原子
          写落盘，失败回滚（状态不变、事件不记录），重启保留。
        """
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            rec = bucket["dids"].get(did) if bucket is not None else None
            if rec is None:
                raise NotFoundError(f"DID 不存在: {did}")

            if rec.get("status") == "deactivated":
                snapshot = self._snapshot_locked()
                try:
                    # 幂等成功同样每次记录审计；重复请求的 reason 忽略。
                    self._append_audit_locked(
                        tenant_id, AUDIT_DID_DEACTIVATED, "did", did
                    )
                    self._save_locked()
                except Exception:
                    self._restore_locked(snapshot)
                    raise
                return DIDStatusRecord(
                    did=did,
                    status="deactivated",
                    reason=rec["deactivate_reason"],
                    updated_at=rec["deactivated_at"],
                )

            if reason is REASON_UNSET:
                final_reason = DEFAULT_DID_DEACTIVATE_REASON
            else:
                if not isinstance(reason, str):
                    raise ValidationError("字段 reason 必须为字符串")
                final_reason = reason.strip()
                if not final_reason:
                    raise ValidationError("字段 reason 裁剪后不能为空")

            now = _utc_now()
            snapshot = self._snapshot_locked()
            try:
                rec["status"] = "deactivated"
                rec["deactivate_reason"] = final_reason
                rec["deactivated_at"] = now
                self._append_audit_locked(
                    tenant_id, AUDIT_DID_DEACTIVATED, "did", did
                )
                self._save_locked()
            except Exception:
                self._restore_locked(snapshot)
                raise
            return DIDStatusRecord(
                did=did,
                status="deactivated",
                reason=final_reason,
                updated_at=now,
            )

    def get_did_status(self, tenant_id: str, did: str) -> DIDStatusRecord:
        """只读查询 DID 生命周期状态。

        - DID 不存在（含他租户资源）抛 NotFoundError（HTTP 404）；
        - 活动 DID 返回 status="active"、reason/updated_at 均为 None；
        - 停用 DID 返回首次停用的裁剪原因与 UTC 秒精度 Z 时间。
        纯只读：不修改任何状态、不记审计、不触发落盘。
        """
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            rec = bucket["dids"].get(did) if bucket is not None else None
            if rec is None:
                raise NotFoundError(f"DID 不存在: {did}")
            if rec.get("status") == "deactivated":
                return DIDStatusRecord(
                    did=did,
                    status="deactivated",
                    reason=rec.get("deactivate_reason"),
                    updated_at=rec.get("deactivated_at"),
                )
            return DIDStatusRecord(
                did=did, status="active", reason=None, updated_at=None
            )

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
            if rec.get("status") == "deactivated":
                raise ConflictError(f"DID 已停用，不能轮换密钥: {did}")
            if self._handle_in_use_locked(bucket, handle):
                raise ValidationError(f"key_handle 已被使用: {handle}")

            snapshot = self._snapshot_locked()
            try:
                priv_pem = crypto.generate_private_key_pem()
                pub_pem = crypto.public_key_pem_from_private(priv_pem).strip()
                new_version = int(rec.get("key_version", 1)) + 1
                audit_event = self._append_audit_locked(
                    tenant_id, AUDIT_KEY_ROTATED, "did", did
                )
                # 生命周期事件的 updated_at 取轮换成功时刻，与审计同秒。
                rotated_at = _utc_z_from_unix(audit_event["timestamp"])
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
                lifecycle_entries = (
                    bucket.setdefault("key_lifecycle", {}).setdefault(did, [])
                )
                lifecycle_entries.append(
                    {
                        "key_version": new_version,
                        "key_handle": handle,
                        "public_key": pub_pem,
                        "action": AUDIT_KEY_ROTATED,
                        "status": "active",
                        "updated_at": rotated_at,
                        "cursor": (
                            self._next_key_lifecycle_cursor_locked(tenant_id)
                        ),
                        "audit_seq": audit_event["seq"],
                        "audit_timestamp": audit_event["timestamp"],
                    }
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

    @staticmethod
    def _key_history_entry_by_version_locked(
        bucket: Dict[str, Any], did: str, version: int
    ) -> Optional[Dict[str, Any]]:
        """取 DID key_history 中指定版本条目；DID/版本不存在返回 None。"""
        rec = bucket["dids"].get(did) if bucket is not None else None
        if rec is None:
            return None
        for entry in rec.get("key_history", []):
            if int(entry.get("version", 0)) == version:
                return entry
        return None

    def get_did_document(
        self,
        tenant_id: str,
        did: str,
        version: Optional[int] = None,
    ) -> Dict[str, Any]:
        """只读返回 DID 文档（历史公钥）与当前版本私钥的 ES256 证明。

        - DID 不存在（含他租户资源）抛 NotFoundError；
        - verification_methods 按 key_version 升序，每项恰含
          key_version、key_handle、public_key（P-256 PEM），
          绝不包含 private_key；
        - version 提供时仅返回该版本；版本不存在抛 NotFoundError；
          缺省（None）返回全部历史版本；
        - document_proof 始终用 DID 当前版本私钥对除 document_proof 外
          的整个响应对象按规范化 JSON 做 ES256 裸 R||S 无填充 base64url
          签名——即使 version 指向历史版本，证明仍由当前版本密钥重新
          生成；
        - 纯只读：不修改任何状态、不记审计、不触发落盘。文档内容与
          私钥均随状态文件持久化，重启后重新生成的证明验签结论稳定。
        """
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            rec = bucket["dids"].get(did) if bucket is not None else None
            if rec is None:
                raise NotFoundError(f"DID 不存在: {did}")

            history = sorted(
                rec.get("key_history", []),
                key=lambda entry: int(entry.get("version", 0)),
            )
            current_version = int(rec.get("key_version", 1))
            if version is not None:
                history = [
                    entry
                    for entry in history
                    if int(entry.get("version", 0)) == version
                ]
                if not history:
                    raise NotFoundError(
                        f"DID {did} 的密钥版本不存在: {version}"
                    )

            verification_methods = [
                {
                    "key_version": int(entry.get("version", 0)),
                    "key_handle": entry.get("key_handle", ""),
                    "public_key": entry.get("public_key", ""),
                }
                for entry in history
            ]
            document: Dict[str, Any] = {
                "did": did,
                "current_key_version": current_version,
                "verification_methods": verification_methods,
            }
            # 证明恒由当前版本私钥生成（即使请求的是历史版本）。
            current_private_pem = self._private_key_for_version_locked(
                bucket, did, current_version
            )
            if not current_private_pem:
                # 正常不会发生：迁移保证版本 1 存在且当前版本在历史中。
                raise NotFoundError(
                    f"DID {did} 当前版本私钥不可用: {current_version}"
                )
            document["document_proof"] = crypto.sign(
                document, current_private_pem
            )
            return document

    def _key_history_entry_locked(
        self, bucket: Dict[str, Any], did: str, version: int
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """取本租户 DID 行与其 key_history 中指定版本条目。

        DID 不存在（含他租户资源）或版本不在历史中均抛 NotFoundError。
        """
        rec = bucket["dids"].get(did) if bucket is not None else None
        if rec is None:
            raise NotFoundError(f"DID 不存在: {did}")
        for entry in rec.get("key_history", []):
            if int(entry.get("version", 0)) == version:
                return rec, entry
        raise NotFoundError(f"DID {did} 的密钥版本不存在: {version}")

    def revoke_key_version(
        self,
        tenant_id: str,
        did: str,
        key_version: int,
        reason: Any = REASON_UNSET,
    ) -> KeyVersionStatusRecord:
        """吊销 DID 的旧密钥版本。

        - DID 不存在（含他租户资源）或版本不在其 key_history 中均抛
          NotFoundError（HTTP 404，跨租户不可探测）；
        - key_version 为 DID 当前密钥版本时抛 ConflictError（HTTP 409），
          当前版本只能先轮换再吊销；
        - 重复吊销时任何 reason（含非法值）均忽略，返回首次吊销结果；
          非法 reason（非字符串或裁剪后为空，含显式 null）仅在首次
          吊销时抛 ValidationError（HTTP 400）；
        - 吊销标记写入该版本 key_history 条目（status/revoke_reason/
          revoked_at），版本仍保留在 DID 文档历史中；轮换与新签发使用
          当前版本，不受影响；
        - 首次吊销与幂等重试均记 key.revoked（resource_type 为 did、
          resource_id 为 <did>#<version>）；标记与审计在同一把锁内经
          同一次原子写落盘，失败回滚（版本不变、事件不记录），重启保留。
        """
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            rec, entry = self._key_history_entry_locked(
                bucket, did, key_version
            )
            current_version = int(rec.get("key_version", 1))
            if key_version == current_version:
                raise ConflictError(
                    f"当前密钥版本不能吊销，请先轮换: {did}#{key_version}"
                )

            if entry.get("status") == "revoked":
                snapshot = self._snapshot_locked()
                try:
                    # 幂等成功同样每次记录审计；重复请求的 reason 忽略。
                    self._append_audit_locked(
                        tenant_id, AUDIT_KEY_REVOKED,
                        "did", f"{did}#{key_version}",
                    )
                    self._save_locked()
                except Exception:
                    self._restore_locked(snapshot)
                    raise
                return KeyVersionStatusRecord(
                    did=did,
                    key_version=key_version,
                    status="revoked",
                    reason=entry["revoke_reason"],
                    updated_at=entry["revoked_at"],
                )

            if reason is REASON_UNSET:
                final_reason = DEFAULT_KEY_REVOKE_REASON
            else:
                if not isinstance(reason, str):
                    raise ValidationError("字段 reason 必须为字符串")
                final_reason = reason.strip()
                if not final_reason:
                    raise ValidationError("字段 reason 裁剪后不能为空")

            now: Optional[str] = None
            snapshot = self._snapshot_locked()
            try:
                audit_event = self._append_audit_locked(
                    tenant_id, AUDIT_KEY_REVOKED,
                    "did", f"{did}#{key_version}",
                )
                # 吊销标记、两类历史与生命周期事件统一取审计秒，保证
                # updated_at 与 audit_timestamp 严格同秒。
                now = _utc_z_from_unix(audit_event["timestamp"])
                entry["status"] = "revoked"
                entry["revoke_reason"] = final_reason
                entry["revoked_at"] = now
                # 仅首次成功吊销追加吊销历史事件；重复吊销与失败路径均
                # 不会到达此处。吊销标记、历史与审计在同一次原子写落盘。
                revocation_entries = (
                    bucket.setdefault("key_revocations", {})
                    .setdefault(did, [])
                )
                revocation_entries.append(
                    {
                        "key_version": key_version,
                        "reason": final_reason,
                        "updated_at": now,
                        "cursor": (
                            self._next_key_revocation_cursor_locked(tenant_id)
                        ),
                    }
                )
                # 生命周期历史另追加一条 revoked（游标空间与吊销历史
                # 隔离）；重复/失败/幂等不追加，active 历史不改写。
                lifecycle_entries = (
                    bucket.setdefault("key_lifecycle", {}).setdefault(did, [])
                )
                lifecycle_entries.append(
                    {
                        "key_version": key_version,
                        "key_handle": entry.get("key_handle", ""),
                        "public_key": entry.get("public_key", ""),
                        "action": AUDIT_KEY_REVOKED,
                        "status": "revoked",
                        "updated_at": now,
                        "cursor": (
                            self._next_key_lifecycle_cursor_locked(tenant_id)
                        ),
                        "audit_seq": audit_event["seq"],
                        "audit_timestamp": audit_event["timestamp"],
                    }
                )
                self._save_locked()
            except Exception:
                self._restore_locked(snapshot)
                raise
            return KeyVersionStatusRecord(
                did=did,
                key_version=key_version,
                status="revoked",
                reason=final_reason,
                updated_at=now,
            )

    def get_key_version_status(
        self, tenant_id: str, did: str, key_version: int
    ) -> KeyVersionStatusRecord:
        """只读查询 DID 某密钥版本的吊销状态。

        - DID 不存在（含他租户资源）或版本不在其 key_history 中均抛
          NotFoundError（HTTP 404，跨租户不可探测）；
        - active 版本返回 status="active"、reason/updated_at 均为 None；
        - revoked 版本返回首次吊销的原因与 UTC 秒精度 Z 时间。
        纯只读：不修改任何状态、不记审计、不触发落盘。
        """
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            rec, entry = self._key_history_entry_locked(
                bucket, did, key_version
            )
            if entry.get("status") == "revoked":
                return KeyVersionStatusRecord(
                    did=did,
                    key_version=key_version,
                    status="revoked",
                    reason=entry["revoke_reason"],
                    updated_at=entry["revoked_at"],
                )
            return KeyVersionStatusRecord(
                did=did,
                key_version=key_version,
                status="active",
                reason=None,
                updated_at=None,
            )

    def list_key_revocations(
        self,
        tenant_id: str,
        did: str,
        after: int = 0,
        limit: int = 50,
    ) -> Tuple[List[KeyRevocationEvent], int]:
        """只读查询某 DID 的密钥吊销历史，按页返回。

        - DID 在本租户不存在（含他租户）抛 NotFoundError（HTTP 404）；
          DID 存在但从未吊销返回空页；
        - 仅首次成功吊销追加事件（重复吊销与失败不追加），按 cursor
          升序返回；
        - after 排除 cursor 不大于其值的事件，至多返回 limit 项；
        - next_after 为本页末项 cursor，空页保持 after。
        纯只读：不修改任何状态、不记审计、不触发落盘。
        """
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            rec = bucket["dids"].get(did) if bucket is not None else None
            if rec is None:
                raise NotFoundError(f"DID 不存在: {did}")
            entries = sorted(
                (
                    bucket.get("key_revocations", {}).get(did, [])
                ),
                key=lambda event: int(event.get("cursor", 0)),
            )
            picked: List[KeyRevocationEvent] = []
            for row in entries:
                if len(picked) >= limit:
                    break
                cursor = int(row["cursor"])
                if cursor <= after:
                    continue
                picked.append(
                    KeyRevocationEvent(
                        key_version=int(row["key_version"]),
                        reason=row["reason"],
                        updated_at=row["updated_at"],
                        cursor=cursor,
                    )
                )
            next_after = picked[-1].cursor if picked else after
            return picked, next_after

    # ------------------------------------------------------------------ #
    # 凭证
    # ------------------------------------------------------------------ #
    def create_credential(
        self,
        tenant_id: str,
        issuer_did: str,
        subject_did: str,
        claims: Dict[str, Any],
        expires_at: Any = EXPIRES_AT_UNSET,
    ) -> CredentialRecord:
        """校验签发者/持有者 DID（限本租户），构造正文并签名，记审计。

        expires_at 省略（EXPIRES_AT_UNSET）时正文不含该字段，凭证无
        期限；提供时必须为 UTC 秒精度 Z 格式且严格晚于当前时刻，并原样
        写入正文参与 ES256 规范化签名。
        """
        if not isinstance(issuer_did, str) or not issuer_did:
            raise ValidationError("缺少字段或字段为空: issuer_did")
        if not isinstance(subject_did, str) or not subject_did:
            raise ValidationError("缺少字段或字段为空: subject_did")
        if not isinstance(claims, dict):
            raise ValidationError("字段 claims 必须为 JSON 对象")
        raw_expires_at = None
        if expires_at is not EXPIRES_AT_UNSET:
            raw_expires_at = _validate_future_utc_z(expires_at, "expires_at")

        with self._lock:
            bucket = self._ensure_bucket_locked(tenant_id)
            # 逐个指明不存在的是哪一个 DID（他租户 DID 同样不可见）
            issuer = bucket["dids"].get(issuer_did)
            if issuer is None:
                raise ValidationError(f"issuer_did 不存在: {issuer_did}")
            subject = bucket["dids"].get(subject_did)
            if subject is None:
                raise ValidationError(f"subject_did 不存在: {subject_did}")
            # 已停用 DID 不得再作为 issuer 签发凭证：409 且不写记录。
            if issuer.get("status") == "deactivated":
                raise ConflictError(f"签发者 DID 已停用，不能签发凭证: {issuer_did}")

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
                # 仅在请求提供时写入：未提供不得注入字段（旧凭证无期限）。
                if raw_expires_at is not None:
                    body["expires_at"] = raw_expires_at
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
            holder_did=row.get("holder_did"),
            holder_key_version=(
                int(row["holder_key_version"])
                if row.get("holder_key_version") is not None
                else None
            ),
            holder_proof=row.get("holder_proof"),
        )

    def _build_presentation_row_locked(
        self,
        tenant_id: str,
        bucket: Optional[Dict[str, Any]],
        credential_id: str,
        disclose: Any,
        challenge: str,
        expires_at: str,
        holder_binding: bool,
    ) -> Dict[str, Any]:
        """在锁内完成单项演示的全部校验与签名，返回待落盘演示行（不写状态）。

        校验与签名规则与 :meth:`create_presentation` 完全一致：凭证不
        存在（含他租户资源、租户桶缺失）抛 NotFoundError；claims 非对象
        或 disclose 非法（非数组、路径语法/越界/重复/祖先重叠）抛
        ValidationError；签发者 DID 已停用抛 ConflictError；历史私钥缺失
        或签发/持有者当前密钥版本已吊销抛 ValidationError；持有者绑定
        要求 subject_did 为本租户已注册 DID。调用方负责把返回行写入
        presentations 并与审计事件同次原子落盘。
        """
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
        # 签发者 DID 已停用：拒绝生成演示，409 且不留任何记录/审计。
        issuer_rec = bucket["dids"].get(issuer_did)
        if self._is_did_deactivated_locked(issuer_rec):
            raise ConflictError(
                f"签发者 DID 已停用，不能生成演示: {issuer_did}"
            )
        private_pem = self._private_key_for_version_locked(
            bucket, issuer_did, version
        )
        if not private_pem:
            raise ValidationError(
                "历史私钥不可用: 签发者 "
                f"{issuer_did} 密钥版本 {version} 的私钥不存在"
            )
        # 签发密钥版本已吊销：拒绝生成，400 且不留任何记录/审计。
        issuer_entry = self._key_history_entry_by_version_locked(
            bucket, issuer_did, version
        )
        if (
            issuer_entry is not None
            and issuer_entry.get("status") == "revoked"
        ):
            raise ValidationError(
                "签发密钥版本已吊销，不能生成演示: "
                f"{issuer_did}#{version}"
            )

        # 持有者绑定：subject_did 须为本租户已注册 DID，使用其当前
        # 密钥版本私钥签名；未绑定不查询、不注入任何 holder_* 字段。
        holder_did: Optional[str] = None
        holder_key_version: Optional[int] = None
        holder_private_pem: Optional[str] = None
        if holder_binding:
            holder_did = stored_body.get("subject_did")
            if not isinstance(holder_did, str) or not holder_did:
                raise ValidationError(
                    "凭证缺少合法 subject_did，无法进行持有者绑定"
                )
            holder_rec = bucket["dids"].get(holder_did)
            if holder_rec is None:
                raise ValidationError(
                    f"subject_did 不是本租户已注册 DID: {holder_did}"
                )
            holder_key_version = int(holder_rec.get("key_version", 1))
            holder_private_pem = self._private_key_for_version_locked(
                bucket, holder_did, holder_key_version
            )
            if not holder_private_pem:
                raise ValidationError(
                    "持有者当前密钥不可用: 持有者 "
                    f"{holder_did} 密钥版本 {holder_key_version} 的私钥不存在"
                )
            # 绑定的持有者密钥版本已吊销：拒绝生成，400 且不留记录。
            holder_entry = self._key_history_entry_by_version_locked(
                bucket, holder_did, holder_key_version
            )
            if (
                holder_entry is not None
                and holder_entry.get("status") == "revoked"
            ):
                raise ValidationError(
                    "持有者密钥版本已吊销，不能生成绑定演示: "
                    f"{holder_did}#{holder_key_version}"
                )

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
        if holder_binding:
            # holder_proof 覆盖去掉 proof、holder_proof 后的完整
            # 演示对象（含 holder_did/holder_key_version）及
            # tenant_id；issuer proof 覆盖范围保持不变。
            holder_payload = dict(unsigned)
            holder_payload["holder_did"] = holder_did
            holder_payload["holder_key_version"] = holder_key_version
            holder_payload["tenant_id"] = tenant_id
            holder_proof = crypto.sign(
                holder_payload, holder_private_pem
            )
            row["holder_did"] = holder_did
            row["holder_key_version"] = holder_key_version
            row["holder_proof"] = holder_proof
        return row

    def create_presentation(
        self,
        tenant_id: str,
        credential_id: str,
        disclose: Any,
        challenge: Optional[str] = None,
        expires_in: Optional[int] = None,
        holder_binding: bool = False,
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
          issuer proof 的覆盖范围不随持有者绑定改变；
        - holder_binding 为 True 时，凭证 subject_did 必须是本租户已
          注册 DID，否则 ValidationError（400）；额外写入 holder_did
          （即 subject_did）、holder_key_version（持有者当前密钥版本）
          与 holder_proof（持有者当前私钥对“去掉 proof、holder_proof
          后的完整演示对象 + tenant_id”规范化 JSON 的 ES256 签名）。
          未绑定（缺省 False）不注入任何 holder_* 字段，与旧流程完全
          兼容；
        - presentation_id 为 vp_ 加 32 位小写 hex。
        """
        if challenge is None:
            challenge = uuid.uuid4().hex
        if expires_in is None:
            expires_in = DEFAULT_EXPIRES_IN
        expires_at = _utc_after(expires_in)
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            # 构建行为纯校验与签名，不改变任何状态；失败直接抛出，不做
            # 快照恢复，保持调用方可见的租户桶对象引用稳定。
            row = self._build_presentation_row_locked(
                tenant_id, bucket, credential_id, disclose,
                challenge, expires_at, holder_binding,
            )
            snapshot = self._snapshot_locked()
            try:
                presentation_id = row["presentation_id"]
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

    def create_presentations_batch(
        self,
        tenant_id: str,
        credential_id: str,
        items: List[Dict[str, Any]],
    ) -> List[PresentationRecord]:
        """在同一凭证上原子批量生成 1..50 条选择性披露演示。

        items 为已通过请求级结构校验的项列表（每项为恰含 disclose 及
        可选 challenge、expires_in、holder_binding 的对象，字段语义
        校验在本方法内逐项完成，与单项 present 完全一致）。所有项在同
        一把锁、同一个快照事务内顺序构建：任一项失败（未知凭证 404、
        disclose/字段非法 400、签发者停用 409、密钥吊销等）即整体回滚，
        此前已构建的演示行与审计事件全部不落盘，对外表现为“非法不写
        入”。全部项构建成功后统一写入 presentations 并为每条演示各记
        一条 presentation.created 审计，与记录同次原子落盘，落盘失败
        同样整体回滚。返回与 items 等长、同序的演示记录。
        """
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            # 构建阶段为纯校验与签名，不改变任何状态：任一项失败即直接
            # 抛出，此前构建的行尚未写入，天然“非法不写入”，也无需回滚。
            built: List[Dict[str, Any]] = []
            for item in items:
                challenge = item.get("challenge")
                if challenge is None:
                    challenge = uuid.uuid4().hex
                expires_in = item.get("expires_in")
                if expires_in is None:
                    expires_in = DEFAULT_EXPIRES_IN
                expires_at = _utc_after(expires_in)
                row = self._build_presentation_row_locked(
                    tenant_id,
                    bucket,
                    credential_id,
                    item["disclose"],
                    challenge,
                    expires_at,
                    bool(item.get("holder_binding", False)),
                )
                built.append(row)
            # 全部项校验与签名通过后才统一写入并记审计、落盘；记录与
            # 审计同次原子提交，落盘失败整体回滚。
            snapshot = self._snapshot_locked()
            try:
                for row in built:
                    presentation_id = row["presentation_id"]
                    bucket["presentations"][presentation_id] = row
                    self._append_audit_locked(
                        tenant_id, AUDIT_PRESENTATION_CREATED,
                        "presentation", presentation_id,
                    )
                self._save_locked()
                return [self._presentation_record(row) for row in built]
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
            # 持有者绑定演示按存储记录是否含 holder_did 判定（绑定演示
            # 一定也是防重放新演示）。
            is_holder_bound = "holder_did" in row
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
            if is_holder_bound:
                expected_keys |= {
                    "holder_did",
                    "holder_key_version",
                    "holder_proof",
                }
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

            if is_holder_bound:
                # holder 字段与存储记录逐一锚定；holder_proof 还须为
                # 非空字符串（holder_did 必须等于凭证 subject_did 的
                # 进一步绑定在生成时已保证，此处再与存储行核对）。
                if presentation.get("holder_did") != row.get("holder_did"):
                    return False, (
                        "锚定校验失败: holder_did 与存储记录不一致"
                    )
                stored_holder_version = row.get("holder_key_version")
                holder_version_obj = presentation.get("holder_key_version")
                if (
                    not isinstance(holder_version_obj, int)
                    or isinstance(holder_version_obj, bool)
                    or holder_version_obj != stored_holder_version
                ):
                    return False, (
                        "锚定校验失败: holder_key_version 与存储记录不一致"
                    )
                holder_proof = presentation.get("holder_proof")
                if not isinstance(holder_proof, str) or not holder_proof:
                    return False, (
                        "请求不合法: 字段 holder_proof 必须为非空字符串"
                    )

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
            credential_expires_at = cred["body"].get("expires_at")

            public_pem = self._public_key_for_version_locked(
                bucket, issuer_did, stored_version
            )
            issuer_entry = self._key_history_entry_by_version_locked(
                bucket, issuer_did, stored_version
            )
            issuer_key_revoked = (
                issuer_entry is not None
                and issuer_entry.get("status") == "revoked"
            )
            issuer_key_revoke_reason = (
                issuer_entry.get("revoke_reason")
                if issuer_entry is not None
                else None
            )
            # 签发者 DID 停用状态在锚定与双签名成功后判定；锁内捕获。
            issuer_did_row = bucket["dids"].get(issuer_did)
            issuer_did_deactivated = self._is_did_deactivated_locked(
                issuer_did_row
            )
            issuer_did_deactivate_reason = (
                issuer_did_row.get("deactivate_reason")
                if issuer_did_row is not None
                else None
            )

            # 持有者绑定：holder_did 必须等于凭证正文 subject_did，且
            # 持有者为本租户已注册 DID，按 holder_key_version 从其公钥
            # 历史中取历史公钥（轮换后仍可验证；公钥缺失则判密钥不可用）。
            holder_did_value: Optional[str] = None
            holder_version_value: Optional[int] = None
            holder_public_pem: Optional[str] = None
            holder_key_revoked = False
            holder_key_revoke_reason: Optional[str] = None
            if is_holder_bound:
                holder_did_value = row.get("holder_did")
                subject_did = cred["body"].get("subject_did")
                if holder_did_value != subject_did:
                    return False, (
                        "锚定校验失败: holder_did 与凭证 subject_did 不一致"
                    )
                holder_rec = bucket["dids"].get(holder_did_value)
                if holder_rec is None:
                    return False, (
                        f"持有者 DID 不存在: {holder_did_value}"
                    )
                holder_version_value = int(
                    row.get("holder_key_version", 0)
                )
                holder_public_pem = self._public_key_for_version_locked(
                    bucket, holder_did_value, holder_version_value
                )
                holder_entry = self._key_history_entry_by_version_locked(
                    bucket, holder_did_value, holder_version_value
                )
                holder_key_revoked = (
                    holder_entry is not None
                    and holder_entry.get("status") == "revoked"
                )
                holder_key_revoke_reason = (
                    holder_entry.get("revoke_reason")
                    if holder_entry is not None
                    else None
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

        # issuer proof 验签成功后检查签发密钥版本是否已吊销（优先于
        # 持有者校验、凭证有效期与凭证吊销）。
        if issuer_key_revoked:
            saved_reason = (
                issuer_key_revoke_reason or DEFAULT_KEY_REVOKE_REASON
            )
            return False, f"签发密钥已吊销：{saved_reason}"

        # 双签名锚定的 issuer 侧已通过：签发者 DID 已停用则 valid:false，
        # 优先于持有者校验、凭证有效期与凭证吊销（只读，不消费）。
        if issuer_did_deactivated:
            saved_reason = (
                issuer_did_deactivate_reason
                or DEFAULT_DID_DEACTIVATE_REASON
            )
            return False, f"{DID_DEACTIVATED_REASON_PREFIX}{saved_reason}"

        if is_holder_bound:
            # 持有者第二签名：覆盖去掉 proof、holder_proof 后的完整演示
            # 对象（此处与 issuer proof 覆盖对象同构，另含 holder_did、
            # holder_key_version）及 tenant_id，按规范化 JSON/UTF-8 验签；
            # 公钥按 holder_key_version 取持有者历史公钥，轮换后仍可验证。
            if not holder_public_pem:
                return False, (
                    "历史公钥不可用: 持有者 "
                    f"{holder_did_value} 密钥版本 "
                    f"{holder_version_value} 的公钥不存在"
                )
            try:
                crypto.validate_public_key_pem(holder_public_pem)
            except (ValueError, TypeError):
                return False, (
                    "历史公钥不可用: 持有者 "
                    f"{holder_did_value} 密钥版本 "
                    f"{holder_version_value} 的公钥无法解析"
                )
            holder_unsigned = dict(unsigned)
            holder_unsigned["holder_did"] = holder_did_value
            holder_unsigned["holder_key_version"] = holder_version_value
            holder_unsigned["tenant_id"] = tenant_id
            try:
                crypto.verify(
                    holder_unsigned, holder_proof, holder_public_pem
                )
            except crypto.MalformedSignature:
                return False, (
                    "签名格式错误: holder_proof 不是合法的 ES256 签名编码"
                )
            except crypto.InvalidSignature:
                return False, (
                    "签名校验失败: holder_proof 与持有者历史公钥不匹配，"
                    "持有者绑定内容可能被改动"
                )
            except Exception:  # noqa: BLE001 验签绝不向上抛错
                return False, "验签过程发生内部错误"

            # 持有者 proof 验签成功后检查持有者密钥版本是否已吊销
            # （优先于凭证有效期与凭证吊销）。
            if holder_key_revoked:
                saved_reason = (
                    holder_key_revoke_reason or DEFAULT_KEY_REVOKE_REASON
                )
                return False, f"持有者密钥已吊销：{saved_reason}"

        # 签名与锚定均成功后检查凭证有效期：凭证已到期直接拒绝，不消费
        if _is_expired(credential_expires_at):
            return False, CREDENTIAL_EXPIRED_REASON

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
                # 锁内复查密钥版本吊销状态（防锁外验签期间被吊销的竞态）：
                # 签发密钥优先于持有者密钥，二者均优先于凭证有效期/吊销。
                issuer_entry_now = self._key_history_entry_by_version_locked(
                    bucket, issuer_did, stored_version
                )
                if (
                    issuer_entry_now is not None
                    and issuer_entry_now.get("status") == "revoked"
                ):
                    saved_reason = (
                        issuer_entry_now.get("revoke_reason")
                        or DEFAULT_KEY_REVOKE_REASON
                    )
                    return False, f"签发密钥已吊销：{saved_reason}"
                # 锁内复查签发者 DID 停用状态（防锁外验签期间被停用的
                # 竞态）：停用不消费，优先于有效期/凭证吊销。
                issuer_row_now = bucket["dids"].get(issuer_did)
                if self._is_did_deactivated_locked(issuer_row_now):
                    saved_reason = (
                        issuer_row_now.get("deactivate_reason")
                        or DEFAULT_DID_DEACTIVATE_REASON
                    )
                    return False, (
                        f"{DID_DEACTIVATED_REASON_PREFIX}{saved_reason}"
                    )
                if is_holder_bound and holder_did_value is not None:
                    holder_entry_now = (
                        self._key_history_entry_by_version_locked(
                            bucket,
                            holder_did_value,
                            holder_version_value,
                        )
                    )
                    if (
                        holder_entry_now is not None
                        and holder_entry_now.get("status") == "revoked"
                    ):
                        saved_reason = (
                            holder_entry_now.get("revoke_reason")
                            or DEFAULT_KEY_REVOKE_REASON
                        )
                        return False, f"持有者密钥已吊销：{saved_reason}"
                if cred is not None and _is_expired(
                    cred["body"].get("expires_at")
                ):
                    return False, CREDENTIAL_EXPIRED_REASON
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
            challenge=row["challenge"],
            expires_at=row["expires_at"],
            proof=row["proof"],
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
          （非非空数组、元素字段/op/路径/数值问题）抛 ValidationError；
        - challenge 缺省时生成 32 位小写 hex；expires_in 缺省 300 秒，
          expires_at 为当前 UTC 时间加 expires_in 秒（Z 结尾秒精度）；
        - results 为与 predicates 同序的布尔求值结果；
        - proof 为 ES256 签名，覆盖除 proof 外字段（含 tenant_id）按
          key 升序规范化 JSON，使用凭证 issuer_key_version（旧凭证缺省
          按 1）对应的历史私钥；
        - proof_id 为 zp_ 加 32 位小写 hex；成功记 proof.created。
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
                raise ValidationError("凭证 claims 不是 JSON 对象，无法生成谓词证明")

            items = _validate_predicates(claims, predicates)
            results = _evaluate_predicates(claims, items)

            issuer_did = stored_body["issuer_did"]
            version = int(stored_body.get("issuer_key_version", 1))
            # 签发者 DID 已停用：拒绝生成谓词证明，409 且不留记录/审计。
            issuer_rec = bucket["dids"].get(issuer_did)
            if self._is_did_deactivated_locked(issuer_rec):
                raise ConflictError(
                    f"签发者 DID 已停用，不能生成谓词证明: {issuer_did}"
                )
            private_pem = self._private_key_for_version_locked(
                bucket, issuer_did, version
            )
            if not private_pem:
                raise ValidationError(
                    "历史私钥不可用: 签发者 "
                    f"{issuer_did} 密钥版本 {version} 的私钥不存在"
                )
            # 签发密钥版本已吊销：拒绝生成，400 且不留任何记录/审计。
            issuer_entry = self._key_history_entry_by_version_locked(
                bucket, issuer_did, version
            )
            if (
                issuer_entry is not None
                and issuer_entry.get("status") == "revoked"
            ):
                raise ValidationError(
                    "签发密钥版本已吊销，不能生成谓词证明: "
                    f"{issuer_did}#{version}"
                )

            snapshot = self._snapshot_locked()
            try:
                proof_id = f"zp_{uuid.uuid4().hex}"
                unsigned: Dict[str, Any] = {
                    "proof_id": proof_id,
                    "credential_id": credential_id,
                    "issuer_did": issuer_did,
                    "issuer_key_version": version,
                    "predicates": copy.deepcopy(items),
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
        proof: Any,
        challenge: Any = CHALLENGE_UNSET,
    ) -> Tuple[bool, str]:
        """以存储记录为锚校验谓词证明，返回 (是否有效, 失败原因)。

        校验顺序：请求 -> 资源 ID -> 绑定（字段集合与各锚定字段、
        请求 challenge、证明 challenge 与 proof 覆盖的存储 challenge
        三者一致）-> 已消费（优先于过期）-> 过期（当前时间 >=
        expires_at）-> 按存储凭证 claims 与存储 predicates 重算
        results 并核对 -> proof 格式与签名。验签成功后在消费锁内
        复查已消费/到期：复查到期即返回“证明已过期”，不消费、不记
        审计；未到期并发验证仅一次成功，成功时原子标记已消费并记一次
        proof.consumed（同一次原子写，失败回滚），跨重启保留。
        任何失败均返回非空中文原因，绝不抛异常、不泄露私钥。
        """
        if not isinstance(proof, dict):
            return False, "请求不合法: 字段 proof 必须为 JSON 对象"

        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            row = (
                bucket["proofs"].get(proof_id)
                if bucket is not None else None
            )
            if row is None:
                return False, f"证明不存在: {proof_id}"

            if challenge is CHALLENGE_UNSET:
                return False, "请求缺少字段: challenge"

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
            if set(proof) != expected_keys:
                return False, (
                    "锚定校验失败: proof 字段集合与存储记录不一致"
                )
            signature = proof.get("proof")
            if not isinstance(signature, str) or not signature:
                return False, "请求不合法: 字段 proof 必须为非空字符串"
            if proof.get("proof_id") != proof_id:
                return False, (
                    "锚定校验失败: proof_id 与路径或存储记录不一致"
                )
            if proof.get("credential_id") != row.get("credential_id"):
                return False, (
                    "锚定校验失败: credential_id 与存储记录不一致"
                )
            if proof.get("issuer_did") != row.get("issuer_did"):
                return False, "锚定校验失败: issuer_did 与存储记录不一致"
            stored_version = int(row.get("issuer_key_version", 1))
            version_obj = proof.get("issuer_key_version")
            if (
                not isinstance(version_obj, int)
                or isinstance(version_obj, bool)
                or version_obj != stored_version
            ):
                return False, (
                    "锚定校验失败: issuer_key_version 与存储记录不一致"
                )
            if not _json_equal(
                proof.get("predicates"), row.get("predicates", [])
            ):
                return False, "锚定校验失败: predicates 与存储记录不一致"

            # 请求 challenge、证明 challenge 与 proof 覆盖的存储
            # challenge 三者必须一致
            stored_challenge = row.get("challenge")
            if proof.get("challenge") != stored_challenge:
                return False, (
                    "锚定校验失败: challenge 与存储记录不一致"
                )
            if challenge != stored_challenge:
                return False, (
                    "锚定校验失败: 请求 challenge 与存储记录不一致"
                )
            if proof.get("expires_at") != row.get("expires_at"):
                return False, (
                    "锚定校验失败: expires_at 与存储记录不一致"
                )
            # 已消费优先于过期
            if row.get("consumed"):
                return False, "证明已消费"
            try:
                expires_at = _parse_utc_z(row["expires_at"])
            except (KeyError, TypeError, ValueError):
                return False, "验签过程发生内部错误"
            if datetime.now(timezone.utc) >= expires_at:
                return False, "证明已过期"

            obj_results = proof.get("results")
            if not isinstance(obj_results, list):
                return False, "请求不合法: 证明 results 必须为数组"

            credential_id = row["credential_id"]
            issuer_did = row["issuer_did"]
            cred = bucket["credentials"].get(credential_id)
            if cred is None:
                return False, f"凭证不存在: {credential_id}"
            source_claims = cred["body"].get("claims", {})
            credential_expires_at = cred["body"].get("expires_at")

            public_pem = self._public_key_for_version_locked(
                bucket, issuer_did, stored_version
            )
            issuer_entry = self._key_history_entry_by_version_locked(
                bucket, issuer_did, stored_version
            )
            issuer_key_revoked = (
                issuer_entry is not None
                and issuer_entry.get("status") == "revoked"
            )
            issuer_key_revoke_reason = (
                issuer_entry.get("revoke_reason")
                if issuer_entry is not None
                else None
            )
            # 签发者 DID 停用状态在锚定与签名成功后判定；锁内捕获。
            issuer_did_row = bucket["dids"].get(issuer_did)
            issuer_did_deactivated = self._is_did_deactivated_locked(
                issuer_did_row
            )
            issuer_did_deactivate_reason = (
                issuer_did_row.get("deactivate_reason")
                if issuer_did_row is not None
                else None
            )

        # 按存储的 predicates 从存储凭证 claims 重算结果并核对
        stored_predicates = list(row.get("predicates", []))
        try:
            recomputed = _evaluate_predicates(source_claims, stored_predicates)
        except ValidationError as exc:
            return False, f"结果重算失败: {exc}"
        if not _json_equal(obj_results, recomputed):
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
            "predicates": stored_predicates,
            "results": recomputed,
            "challenge": row.get("challenge"),
            "expires_at": row.get("expires_at"),
            "tenant_id": row.get("tenant_id", tenant_id),
        }
        try:
            crypto.verify(unsigned, signature, public_pem)
        except crypto.MalformedSignature:
            return False, "签名格式错误: 不是合法的 ES256 签名编码"
        except crypto.InvalidSignature:
            return False, "签名校验失败，证明内容或 proof 可能被改动"
        except Exception:  # noqa: BLE001 验签绝不向上抛错或泄露内部细节
            return False, "验签过程发生内部错误"

        # 验签成功后检查签发密钥版本是否已吊销（优先于凭证有效期）。
        if issuer_key_revoked:
            saved_reason = (
                issuer_key_revoke_reason or DEFAULT_KEY_REVOKE_REASON
            )
            return False, f"签发密钥已吊销：{saved_reason}"

        # 锚定与签名均成功后检查签发者 DID 是否已停用：valid:false，
        # 优先于凭证有效期（只读判定，不消费）。
        if issuer_did_deactivated:
            saved_reason = (
                issuer_did_deactivate_reason
                or DEFAULT_DID_DEACTIVATE_REASON
            )
            return False, f"{DID_DEACTIVATED_REASON_PREFIX}{saved_reason}"

        # 绑定与签名均成功后检查凭证有效期：凭证已到期直接拒绝，不消费、
        # 不记消费审计（自身绑定/签名失败仍优先返回原分类原因）。
        if _is_expired(credential_expires_at):
            return False, CREDENTIAL_EXPIRED_REASON

        # 原子标记已消费：消费锁内复查已消费/到期，并发仅一次成功，
        # 跨重启保留；复查到期不消费、不记审计。
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
            # 锁内复查签发密钥吊销状态（防锁外验签期间被吊销的竞态）。
            issuer_entry_now = self._key_history_entry_by_version_locked(
                bucket, issuer_did, stored_version
            )
            if (
                issuer_entry_now is not None
                and issuer_entry_now.get("status") == "revoked"
            ):
                saved_reason = (
                    issuer_entry_now.get("revoke_reason")
                    or DEFAULT_KEY_REVOKE_REASON
                )
                return False, f"签发密钥已吊销：{saved_reason}"
            # 锁内复查签发者 DID 停用状态（防锁外验签期间被停用的竞态）：
            # 停用不消费，优先于凭证有效期。
            issuer_row_now = bucket["dids"].get(issuer_did)
            if self._is_did_deactivated_locked(issuer_row_now):
                saved_reason = (
                    issuer_row_now.get("deactivate_reason")
                    or DEFAULT_DID_DEACTIVATE_REASON
                )
                return False, (
                    f"{DID_DEACTIVATED_REASON_PREFIX}{saved_reason}"
                )
            cred = bucket["credentials"].get(credential_id)
            if cred is not None and _is_expired(cred["body"].get("expires_at")):
                return False, CREDENTIAL_EXPIRED_REASON
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
    def _local_credential_history_entries_locked(
        self, bucket: Dict[str, Any], credential_id: str
    ) -> List[Dict[str, Any]]:
        """取（并按需建立）某本地凭证的状态历史事件列表。"""
        history = bucket.setdefault("local_credential_status_history", {})
        return history.setdefault(credential_id, [])

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
                event = self._append_audit_locked(
                    tenant_id, AUDIT_STATUS_UPDATED,
                    "credential", credential_id,
                )
                if created:
                    # 仅首次 active 登记追加状态历史事件（与状态、游标、
                    # 审计同一次原子写）；重复登记不追加。
                    entries = self._local_credential_history_entries_locked(
                        bucket, credential_id
                    )
                    entries.append(
                        {
                            "status": "active",
                            "reason": None,
                            "updated_at": rec["status_updated_at"],
                            "revoked_at": None,
                            "cursor": (
                                self._next_local_credential_status_cursor_locked(
                                    tenant_id
                                )
                            ),
                            "audit_seq": int(event["seq"]),
                            "audit_timestamp": int(event["timestamp"]),
                        }
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

    def list_credential_status_history(
        self,
        tenant_id: str,
        credential_id: str,
        after: int = 0,
        limit: int = 50,
    ) -> Tuple[List[LocalCredentialStatusHistoryEvent], int]:
        """只读查询某本地凭证的状态历史，按页返回。

        - 凭证在本租户不存在（含他租户）抛 NotFoundError（HTTP 404，
          跨租户不可探测）；凭证存在但从未登记状态返回空页；
        - 事件按 updated_at 升序、同一 updated_at 按 cursor 升序排列；
        - 排除 cursor 不大于 after 的项，至多返回 limit 项；
        - next_after 为本页末项 cursor，空页保持 after。

        audit_seq 为 None 的兼容项（旧状态补录，无法追溯状态变更审计）
        仍照常按 updated_at/cursor 返回与分页。纯只读：不修改任何状态、
        不记审计、不触发落盘。
        """
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            rec = (
                bucket["credentials"].get(credential_id)
                if bucket is not None else None
            )
            if rec is None:
                raise NotFoundError(f"凭证不存在: {credential_id}")
            entries = list(
                bucket.get("local_credential_status_history", {})
                .get(credential_id, [])
            )

            def sort_key(row: Dict[str, Any]) -> Tuple[datetime, int]:
                return (
                    _parse_utc_z(row["updated_at"]),
                    int(row["cursor"]),
                )

            ordered = sorted(entries, key=sort_key)
            picked: List[LocalCredentialStatusHistoryEvent] = []
            for row in ordered:
                if len(picked) >= limit:
                    break
                cursor = int(row["cursor"])
                if cursor <= after:
                    continue
                picked.append(
                    LocalCredentialStatusHistoryEvent(
                        status=row["status"],
                        updated_at=row["updated_at"],
                        cursor=cursor,
                        reason=row.get("reason"),
                        revoked_at=row.get("revoked_at"),
                        audit_seq=(
                            int(row["audit_seq"])
                            if row.get("audit_seq") is not None
                            else None
                        ),
                        audit_timestamp=(
                            int(row["audit_timestamp"])
                            if row.get("audit_timestamp") is not None
                            else None
                        ),
                    )
                )
            next_after = picked[-1].cursor if picked else after
            return picked, next_after

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
                event = self._append_audit_locked(
                    tenant_id, AUDIT_CREDENTIAL_REVOKED,
                    "credential", credential_id,
                )
                # 仅首次吊销追加状态历史事件（与状态、游标、审计同一次
                # 原子写）；重复吊销走上方幂等分支，不追加。
                entries = self._local_credential_history_entries_locked(
                    bucket, credential_id
                )
                entries.append(
                    {
                        "status": "revoked",
                        "reason": final_reason,
                        "updated_at": now,
                        "revoked_at": now,
                        "cursor": (
                            self._next_local_credential_status_cursor_locked(
                                tenant_id
                            )
                        ),
                        "audit_seq": int(event["seq"]),
                        "audit_timestamp": int(event["timestamp"]),
                    }
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
            issuer_entry = self._key_history_entry_by_version_locked(
                bucket, issuer_did, stored_version
            )
            # 签发者 DID 的停用判定在锚定与验签成功后进行；锁内捕获状态。
            issuer_row = (
                bucket["dids"].get(issuer_did)
                if issuer_did is not None
                else None
            )
            issuer_did_deactivated = self._is_did_deactivated_locked(
                issuer_row
            )
            issuer_did_deactivate_reason = (
                issuer_row.get("deactivate_reason")
                if issuer_row is not None
                else None
            )
            # 签发密钥版本的吊销判定在验签成功后进行；锁内捕获状态。
            issuer_key_revoked = (
                issuer_entry is not None
                and issuer_entry.get("status") == "revoked"
            )
            issuer_key_revoke_reason = (
                issuer_entry.get("revoke_reason") if issuer_entry is not None else None
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

        # 验签成功后按“签发密钥 -> 签发者 DID 停用 -> 有效期 -> 凭证吊销”
        # 顺序判定：签发密钥版本被吊销时 valid:false，沿用原分类协议。
        if issuer_key_revoked:
            saved_reason = issuer_key_revoke_reason or DEFAULT_KEY_REVOKE_REASON
            return False, f"签发密钥已吊销：{saved_reason}"

        # 锚定与签名均成功后检查签发者 DID 是否已停用：valid:false，
        # 优先于凭证有效期与凭证吊销（只读判定，不记审计）。
        if issuer_did_deactivated:
            saved_reason = (
                issuer_did_deactivate_reason
                or DEFAULT_DID_DEACTIVATE_REASON
            )
            return False, f"{DID_DEACTIVATED_REASON_PREFIX}{saved_reason}"

        # 签名、锚定均成功后检查有效期：当前时间 >= expires_at 判
        # valid:false（只读，不记审计）；无 expires_at 的旧凭证无期限。
        # 其余失败（请求/资源/锚定/签名）已在上方优先返回原分类原因。
        if _is_expired(stored_body.get("expires_at")):
            return False, CREDENTIAL_EXPIRED_REASON

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
                # 仅新版本注册追加 active 生命周期事件；同 DID/版本同
                # PEM 的幂等重试不追加。锚点、历史、游标与审计同一次
                # 原子写落盘。
                history_entries = (
                    bucket.setdefault("trust_anchor_history", {})
                    .setdefault(did, [])
                )
                history_entries.append(
                    {
                        "key_version": key_version,
                        "action": AUDIT_TRUST_ANCHOR_REGISTERED,
                        "status": "active",
                        "updated_at": None,
                        "cursor": (
                            self._next_trust_anchor_cursor_locked(tenant_id)
                        ),
                    }
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
                first_revoke = row.get("status") != "revoked"
                if first_revoke:
                    now = _utc_now()
                    row["status"] = "revoked"
                    row["updated_at"] = now
                # 首次吊销与幂等重试均记审计
                self._append_audit_locked(
                    tenant_id,
                    AUDIT_TRUST_ANCHOR_REVOKED,
                    "trust_anchor",
                    f"{did}#{key_version}",
                )
                # 仅首次吊销追加 revoked 生命周期事件（updated_at 为首次
                # 吊销 UTC 秒精度 Z 时间）；幂等重试不追加。锚点、历史、
                # 游标与审计同一次原子写落盘。
                if first_revoke:
                    history_entries = (
                        bucket.setdefault("trust_anchor_history", {})
                        .setdefault(did, [])
                    )
                    history_entries.append(
                        {
                            "key_version": key_version,
                            "action": AUDIT_TRUST_ANCHOR_REVOKED,
                            "status": "revoked",
                            "updated_at": now,
                            "cursor": (
                                self._next_trust_anchor_cursor_locked(
                                    tenant_id
                                )
                            ),
                        }
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

    def verify_trust_credential(
        self,
        tenant_id: str,
        data: Any,
    ) -> Tuple[bool, str]:
        """验证未在本租户签发或存储的外部凭证，返回 (是否有效, 失败原因)。

        校验顺序：请求结构 -> 凭证字段 -> 锚点 -> 签名格式 -> 密码学验签。
        - 请求体须恰含 body（对象）与 signature（非空字符串），其余字段
          （含缺失、多余字段、非对象）均按请求错误；
        - body 须含 credential_id/issuer_did/subject_did/claims/issued_at，
          依次为非空字符串、非空字符串、非空字符串、对象、非空字符串；
          issuer_key_version 可省略（按版本 1 查锚点且不得注入签名正文），
          提供时须为非布尔正整数；其他扩展字段允许且全部参与签名；
        - 锚点按本租户 (issuer_did, 版本) 查找，仅 active 的 P-256 公钥
          可用，缺失或 revoked 失败；
        - 签名为 ES256/SHA-256，64 字节裸 R||S 的无填充 base64url，覆盖
          完整 body（递归排序紧凑 JSON）。
        只读：不登记 DID/凭证，不写凭证、状态或审计，绝不向上抛异常。
        """
        # 1. 请求结构
        if not isinstance(data, dict):
            return False, "请求不合法: 请求体必须为 JSON 对象"
        if set(data) != {"body", "signature"}:
            missing = [f for f in ("body", "signature") if f not in data]
            if missing:
                return False, f"请求缺少字段: {', '.join(missing)}"
            extra = sorted(set(data) - {"body", "signature"})
            return False, f"请求含多余字段: {', '.join(extra)}"
        body = data["body"]
        signature = data["signature"]
        if not isinstance(body, dict):
            return False, "请求不合法: 字段 body 必须为 JSON 对象"
        if not isinstance(signature, str) or not signature:
            return False, "请求不合法: 字段 signature 必须为非空字符串"

        # 2. 凭证字段
        required_str = (
            "credential_id",
            "issuer_did",
            "subject_did",
            "issued_at",
        )
        for field in required_str:
            if field not in body:
                return False, f"凭证缺少字段: {field}"
            value = body[field]
            if not isinstance(value, str) or not value:
                return False, f"凭证字段 {field} 必须为非空字符串"
        if "claims" not in body:
            return False, "凭证缺少字段: claims"
        if not isinstance(body["claims"], dict):
            return False, "凭证字段 claims 必须为 JSON 对象"
        key_version = 1
        if "issuer_key_version" in body:
            version_obj = body["issuer_key_version"]
            if (
                not isinstance(version_obj, int)
                or isinstance(version_obj, bool)
                or version_obj < 1
            ):
                return False, "凭证字段 issuer_key_version 必须为正整数"
            key_version = version_obj
        issuer_did = body["issuer_did"]

        # 3. 锚点：本租户 (issuer_did, 版本)，仅 active 的 P-256 公钥
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
            public_pem = row.get("public_key", "") if row is not None else ""
            status = row.get("status", "active") if row is not None else None
        if row is None:
            return False, (
                f"锚点不存在: {issuer_did}#{key_version}"
            )
        if status == "revoked":
            return False, f"锚点已吊销: {issuer_did}#{key_version}"
        try:
            crypto.validate_public_key_pem(public_pem)
        except (ValueError, TypeError):
            return False, (
                f"锚点公钥不可用: {issuer_did}#{key_version} 不是合法 P-256 公钥"
            )

        # 4/5. 签名格式与密码学验签：签名覆盖完整 body 的规范化 JSON。
        # 省略 issuer_key_version 时不得向签名正文注入该字段。
        try:
            crypto.verify(body, signature, public_pem)
        except crypto.MalformedSignature:
            return False, "签名格式错误: 不是合法的 ES256 签名编码"
        except crypto.InvalidSignature:
            return False, "签名校验失败，凭证正文或签名可能被改动"
        except Exception:  # noqa: BLE001 验签绝不向上抛错或泄露内部细节
            return False, "签名校验失败: 验签过程发生内部错误"

        # 6. 有效期：仅在请求 body 提供 expires_at 时检查（缺失保持兼容，
        # 无期限）。须为 UTC 秒精度 Z 格式；当前时间 >= expires_at 判
        # 到期。只读，不写任何状态、不记审计。
        if "expires_at" in body:
            expires_value = body["expires_at"]
            if (
                not isinstance(expires_value, str)
                or not _UTC_Z_SHAPE_RE.match(expires_value)
            ):
                return False, (
                    "凭证字段 expires_at 必须为 UTC 秒精度 Z 格式"
                    "（YYYY-MM-DDTHH:MM:SSZ）"
                )
            try:
                expires_dt = _parse_utc_z(expires_value)
            except ValueError:
                return False, (
                    "凭证字段 expires_at 必须为 UTC 秒精度 Z 格式"
                    "（YYYY-MM-DDTHH:MM:SSZ）"
                )
            if datetime.now(timezone.utc) >= expires_dt:
                return False, CREDENTIAL_EXPIRED_REASON
        return True, ""

    def verify_trust_credential_with_status(
        self,
        tenant_id: str,
        data: Any,
    ) -> Tuple[bool, str]:
        """外部凭证验真并合并本地同步状态判定（只读）。

        先按 :meth:`verify_trust_credential` 的全部规则完成外部凭证验真
        （请求结构 → 凭证字段 → 锚点 → 签名格式 → 密码学验签 →
        expires_at），失败原样返回 ``(False, 原因)``，保持既有优先级与
        中文原因分类；签名覆盖请求提交的完整 ``body``，省略
        ``issuer_key_version`` 时按版本 1 且不注入正文。

        验签通过后按当前租户 ``(issuer_did, credential_id)`` 双键只读
        查询 ``credential_status_sync`` 同步记录：
          - 未同步（含属他租户）：``(False, "外部凭证状态未同步")``；
          - active：``(True, "")``；
          - revoked：``(False, "外部凭证已吊销：<保存的 reason>")``，
            保存记录无 reason 时用“未知原因”；
          - unknown：``(False, "外部凭证状态未知")``。

        纯只读：不创建凭证、不修改本地状态、不写同步记录、不记审计。
        """
        valid, reason = self.verify_trust_credential(tenant_id, data)
        if not valid:
            return False, reason

        body = data["body"]
        issuer_did = body["issuer_did"]
        credential_id = body["credential_id"]
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            row = None
            if bucket is not None:
                row = (
                    bucket.get("credential_status_sync", {})
                    .get(issuer_did, {})
                    .get(credential_id)
                )
        if row is None:
            return False, "外部凭证状态未同步"
        status = row.get("status")
        if status == "active":
            return True, ""
        if status == "revoked":
            saved_reason = row.get("reason")
            if not saved_reason:
                saved_reason = "未知原因"
            return False, f"外部凭证已吊销：{saved_reason}"
        # status 仅可能为 active/revoked/unknown（同步入口已约束）。
        return False, "外部凭证状态未知"

    def verify_trust_credentials_batch(
        self,
        tenant_id: str,
        data: Any,
    ) -> Tuple[bool, str, List[Dict[str, Any]]]:
        """批量验证外部凭证，返回 (请求是否合法, 请求级原因, 逐项结果)。

        请求体须恰为 ``{"credentials": [项...]}``：数组非空且不超过 100
        项。请求级结构不合法（非对象、字段缺失或多余、credentials 非数组、
        空数组或超过上限）时返回 ``(False, "请求...", [])``，由调用方回
        ``{"results": [], "reason": ...}``。

        请求级合法时逐项复用 :meth:`verify_trust_credential`（与单项接口
        完全一致的字段、锚点、签名规则），按输入顺序收集结果，失败不短
        路：成功项 ``{"valid": true}``，失败项
        ``{"valid": false, "reason": ...}``，原因前缀依次为“请求”/“凭证”
        /“锚点”/“签名格式错误”/“签名校验失败”。只读，不写任何状态、不记
        审计。
        """
        if not isinstance(data, dict):
            return False, "请求不合法: 请求体必须为 JSON 对象", []
        if set(data) != {"credentials"}:
            missing = [f for f in ("credentials",) if f not in data]
            if missing:
                return False, (
                    f"请求缺少字段: {', '.join(missing)}"
                ), []
            extra = sorted(set(data) - {"credentials"})
            return False, f"请求含多余字段: {', '.join(extra)}", []
        credentials = data["credentials"]
        if not isinstance(credentials, list):
            return False, "请求不合法: 字段 credentials 必须为数组", []
        if not credentials:
            return False, "请求不合法: credentials 数组不能为空", []
        if len(credentials) > 100:
            return False, (
                f"请求不合法: credentials 数组不能超过 100 项（当前 {len(credentials)} 项）"
            ), []

        results: List[Dict[str, Any]] = []
        for item in credentials:  # 顺序校验，失败不短路
            valid, reason = self.verify_trust_credential(tenant_id, item)
            if valid:
                results.append({"valid": True})
            else:
                results.append(
                    {"valid": False, "reason": reason or "验签失败"}
                )
        return True, "", results

    def verify_trust_credentials_batch_with_status(
        self,
        tenant_id: str,
        data: Any,
    ) -> Tuple[bool, str, List[Dict[str, Any]]]:
        """批量验证外部凭证并合并本租户同步状态，返回
        (请求是否合法, 请求级原因, 逐项结果)。

        请求级结构与 :meth:`verify_trust_credentials_batch` 完全一致：
        请求体须恰为 ``{"credentials": [项...]}``，数组非空且不超过 100
        项；不合法时返回 ``(False, "请求...", [])``，由调用方回
        ``{"results": [], "reason": ...}``。

        请求级合法时逐项复用 :meth:`verify_trust_credential_with_status`
        （与单项验真一致的字段、锚点、签名、expires_at 规则，验签通过后
        只读合并本租户 ``(issuer_did, credential_id)`` 同步状态），按输入
        顺序收集结果，失败不短路：成功项 ``{"valid": true}``，失败项
        ``{"valid": false, "reason": ...}``。只读，不写凭证、状态、同步
        记录、历史或审计。
        """
        if not isinstance(data, dict):
            return False, "请求不合法: 请求体必须为 JSON 对象", []
        if set(data) != {"credentials"}:
            missing = [f for f in ("credentials",) if f not in data]
            if missing:
                return False, (
                    f"请求缺少字段: {', '.join(missing)}"
                ), []
            extra = sorted(set(data) - {"credentials"})
            return False, f"请求含多余字段: {', '.join(extra)}", []
        credentials = data["credentials"]
        if not isinstance(credentials, list):
            return False, "请求不合法: 字段 credentials 必须为数组", []
        if not credentials:
            return False, "请求不合法: credentials 数组不能为空", []
        if len(credentials) > 100:
            return False, (
                f"请求不合法: credentials 数组不能超过 100 项（当前 {len(credentials)} 项）"
            ), []

        results = []
        for item in credentials:  # 顺序校验，失败不短路
            valid, reason = self.verify_trust_credential_with_status(
                tenant_id, item
            )
            if valid:
                results.append({"valid": True})
            else:
                results.append(
                    {"valid": False, "reason": reason or "验签失败"}
                )
        return True, "", results

    def verify_trust_presentation(
        self,
        tenant_id: str,
        data: Any,
        allow_holder_bound: bool = True,
    ) -> Tuple[bool, str]:
        """验证未在本租户保存的外部选择性披露演示，返回 (是否有效, 失败原因)。

        支持两种形态：
        - 未绑定：请求恰含 presentation、challenge；演示恰为九字段
          （presentation_id、credential_id、issuer_did、issuer_key_version、
          disclose、claims、challenge、expires_at、proof），出现任何
          holder_* 字段即失败；
        - 持有者绑定：请求恰含 presentation、challenge 及非空字符串
          source_tenant_id；演示恰为九字段外加 holder_did（非空字符串）、
          holder_key_version（正整数）、holder_proof（非空字符串）。
          仅当 ``allow_holder_bound`` 为真时允许；单项接口与批量接口
          逐项均接受两种形态（未绑定项出现 source_tenant_id 以外的多余
          字段仍失败，绑定项须恰含 source_tenant_id）。

        校验顺序：请求结构 -> 演示字段与 challenge -> 签发者锚点与签名 ->
        持有者锚点与签名（仅绑定）-> 期限。
        - 请求 challenge 须等于演示 challenge；
        - 锚点按本租户 (did, key_version) 查找，仅 active 的 P-256 公钥
          可用，缺失或 revoked 失败；签发者与持有者分别匹配各自 DID/版本；
        - issuer proof 为 ES256/SHA-256，64 字节裸 R||S 的无填充
          base64url，覆盖范围沿用本地绑定演示：去掉 proof 与全部
          holder_* 字段后的八个字段；
        - holder_proof 同为 ES256，覆盖去掉 proof、holder_proof 的绑定
          对象（八字段加 holder_did、holder_key_version），并加入
          tenant_id=source_tenant_id 后按规范化 JSON 验签；
        - expires_at 须为 UTC 秒精度 Z 格式，当前时间达到它即过期。
        只读：不登记 DID/凭证/演示，不写状态、历史或审计，绝不向上抛异常。
        """
        # 1. 请求结构：未绑定恰含 presentation/challenge；绑定另含
        # 非空字符串 source_tenant_id。
        if not isinstance(data, dict):
            return False, "请求不合法: 请求体必须为 JSON 对象"
        is_holder_bound = (
            allow_holder_bound and "source_tenant_id" in data
        )
        allowed_fields = {"presentation", "challenge"}
        if is_holder_bound:
            allowed_fields.add("source_tenant_id")
        if set(data) != allowed_fields:
            missing = [
                f for f in ("presentation", "challenge") if f not in data
            ]
            if missing:
                return False, f"请求缺少字段: {', '.join(missing)}"
            extra = sorted(set(data) - allowed_fields)
            return False, f"请求含多余字段: {', '.join(extra)}"
        presentation = data["presentation"]
        request_challenge = data["challenge"]
        if not isinstance(presentation, dict):
            return False, "请求不合法: 字段 presentation 必须为 JSON 对象"
        if not isinstance(request_challenge, str) or not request_challenge:
            return False, "请求不合法: 字段 challenge 必须为非空字符串"
        source_tenant_id: Optional[str] = None
        if is_holder_bound:
            source_value = data["source_tenant_id"]
            if not isinstance(source_value, str) or not source_value:
                return False, (
                    "请求不合法: 字段 source_tenant_id 必须为非空字符串"
                )
            source_tenant_id = source_value

        # 2. 演示字段与 challenge：未绑定恰为九字段（出现 holder_* 即
        # 失败）；绑定恰为九字段外加 holder_did/holder_key_version/
        # holder_proof，字段类型沿用本地绑定演示。
        required_fields = {
            "presentation_id",
            "credential_id",
            "issuer_did",
            "issuer_key_version",
            "disclose",
            "claims",
            "challenge",
            "expires_at",
            "proof",
        }
        if is_holder_bound:
            required_fields |= {
                "holder_did",
                "holder_key_version",
                "holder_proof",
            }
        else:
            holder_fields = sorted(
                key for key in presentation if key.startswith("holder_")
            )
            if holder_fields:
                return False, (
                    "演示字段不合法: 不得包含持有者绑定字段 "
                    f"{', '.join(holder_fields)}"
                )
        if set(presentation) != required_fields:
            missing = sorted(required_fields - set(presentation))
            if missing:
                return False, f"演示缺少字段: {', '.join(missing)}"
            extra = sorted(set(presentation) - required_fields)
            return False, f"演示含多余字段: {', '.join(extra)}"
        for field in ("presentation_id", "credential_id", "issuer_did"):
            value = presentation[field]
            if not isinstance(value, str) or not value:
                return False, f"演示字段 {field} 必须为非空字符串"
        key_version = presentation["issuer_key_version"]
        if (
            not isinstance(key_version, int)
            or isinstance(key_version, bool)
            or key_version < 1
        ):
            return False, "演示字段 issuer_key_version 必须为正整数"
        disclose = presentation["disclose"]
        if not isinstance(disclose, list) or any(
            not isinstance(item, str) for item in disclose
        ):
            return False, "演示字段 disclose 必须为字符串数组"
        if not isinstance(presentation["claims"], dict):
            return False, "演示字段 claims 必须为 JSON 对象"
        for field in ("challenge", "expires_at", "proof"):
            value = presentation[field]
            if not isinstance(value, str) or not value:
                return False, f"演示字段 {field} 必须为非空字符串"
        holder_did_value: Optional[str] = None
        holder_version_value: Optional[int] = None
        holder_proof_value: Optional[str] = None
        if is_holder_bound:
            holder_did_value = presentation["holder_did"]
            if not isinstance(holder_did_value, str) or not holder_did_value:
                return False, "演示字段 holder_did 必须为非空字符串"
            holder_version_value = presentation["holder_key_version"]
            if (
                not isinstance(holder_version_value, int)
                or isinstance(holder_version_value, bool)
                or holder_version_value < 1
            ):
                return False, "演示字段 holder_key_version 必须为正整数"
            holder_proof_value = presentation["holder_proof"]
            if not isinstance(holder_proof_value, str) or not holder_proof_value:
                return False, "演示字段 holder_proof 必须为非空字符串"
        if request_challenge != presentation["challenge"]:
            return False, "挑战不匹配: 请求 challenge 与演示 challenge 不一致"

        # 3. 锚点：本租户 (issuer_did, issuer_key_version)，仅 active。
        issuer_did = presentation["issuer_did"]
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
            public_pem = row.get("public_key", "") if row is not None else ""
            status = row.get("status", "active") if row is not None else None
        if row is None:
            return False, f"锚点不存在: {issuer_did}#{key_version}"
        if status == "revoked":
            return False, f"锚点已吊销: {issuer_did}#{key_version}"
        try:
            crypto.validate_public_key_pem(public_pem)
        except (ValueError, TypeError):
            return False, (
                f"锚点公钥不可用: {issuer_did}#{key_version} 不是合法 P-256 公钥"
            )

        # 4/5. 签名格式与密码学验签：issuer proof 覆盖范围沿用本地绑定
        # 演示——去掉 proof 及全部 holder_* 字段后的八个字段（未绑定
        # 演示本就不含 holder_*，即去掉 proof 的全部字段）。
        proof = presentation["proof"]
        message = {
            k: v
            for k, v in presentation.items()
            if k != "proof" and not k.startswith("holder_")
        }
        try:
            crypto.verify(message, proof, public_pem)
        except crypto.MalformedSignature:
            return False, "签名格式错误: 不是合法的 ES256 签名编码"
        except crypto.InvalidSignature:
            return False, "签名校验失败，演示内容或签名可能被改动"
        except Exception:  # noqa: BLE001 验签绝不向上抛错或泄露内部细节
            return False, "签名校验失败: 验签过程发生内部错误"

        # 5b. 持有者绑定：持有者锚点按本租户 (holder_did,
        # holder_key_version) 查找，仅 active；holder_proof 覆盖去掉
        # proof、holder_proof 的绑定对象（含 holder_did、
        # holder_key_version）并加入 tenant_id=source_tenant_id 后
        # 规范化验签。跨租户只用验证租户锚点，不访问来源租户任何数据。
        if is_holder_bound:
            with self._lock:
                bucket = self._bucket_locked(tenant_id)
                holder_anchors = (
                    bucket["trust_anchors"].get(holder_did_value)
                    if bucket is not None else None
                )
                holder_row = (
                    holder_anchors.get(str(holder_version_value))
                    if holder_anchors is not None else None
                )
                holder_public_pem = (
                    holder_row.get("public_key", "")
                    if holder_row is not None else ""
                )
                holder_status = (
                    holder_row.get("status", "active")
                    if holder_row is not None else None
                )
            holder_ref = f"{holder_did_value}#{holder_version_value}"
            if holder_row is None:
                return False, f"持有者锚点不存在: {holder_ref}"
            if holder_status == "revoked":
                return False, f"持有者锚点已吊销: {holder_ref}"
            try:
                crypto.validate_public_key_pem(holder_public_pem)
            except (ValueError, TypeError):
                return False, (
                    f"持有者锚点公钥不可用: {holder_ref} 不是合法 P-256 公钥"
                )
            holder_message = dict(message)
            holder_message["holder_did"] = holder_did_value
            holder_message["holder_key_version"] = holder_version_value
            holder_message["tenant_id"] = source_tenant_id
            try:
                crypto.verify(
                    holder_message, holder_proof_value, holder_public_pem
                )
            except crypto.MalformedSignature:
                return False, (
                    "签名格式错误: holder_proof 不是合法的 ES256 签名编码"
                )
            except crypto.InvalidSignature:
                return False, (
                    "签名校验失败: holder_proof 与持有者锚点公钥不匹配，"
                    "持有者绑定内容可能被改动"
                )
            except Exception:  # noqa: BLE001 验签绝不向上抛错
                return False, "签名校验失败: 验签过程发生内部错误"

        # 6. 期限：expires_at 须为 UTC 秒精度 Z 格式；当前时间达到它即
        # 过期。只读，不写任何状态、不记审计。
        expires_value = presentation["expires_at"]
        if (
            not isinstance(expires_value, str)
            or not _UTC_Z_SHAPE_RE.match(expires_value)
        ):
            return False, (
                "演示字段 expires_at 必须为 UTC 秒精度 Z 格式"
                "（YYYY-MM-DDTHH:MM:SSZ）"
            )
        try:
            expires_dt = _parse_utc_z(expires_value)
        except ValueError:
            return False, (
                "演示字段 expires_at 必须为 UTC 秒精度 Z 格式"
                "（YYYY-MM-DDTHH:MM:SSZ）"
            )
        if datetime.now(timezone.utc) >= expires_dt:
            return False, "演示已过期"
        return True, ""

    def verify_trust_presentations_batch(
        self,
        tenant_id: str,
        data: Any,
    ) -> Tuple[bool, str, List[Dict[str, Any]]]:
        """批量验证外部选择性披露演示，返回
        (请求是否合法, 请求级原因, 逐项结果)。

        请求体须恰为 ``{"presentations": [项...]}``：数组非空且不超过
        100 项。请求级结构不合法（非对象、字段缺失或多余、presentations
        非数组、空数组或超过上限）时返回 ``(False, "请求...", [])``，由
        调用方回 ``{"results": [], "reason": ...}``。

        请求级合法时逐项复用 :meth:`verify_trust_presentation` 的完整
        形态（单项协议的字段、挑战、锚点、签名与期限规则），按输入顺序
        收集结果，失败不短路：未绑定项须恰含 presentation（对象）与非空
        challenge，演示须为未绑定九字段，出现任何 holder_* 字段即失败；
        持有者绑定项另须恰含非空字符串 source_tenant_id，演示须恰为
        九字段外加 holder_did（非空字符串）、holder_key_version（正整数）
        与 holder_proof（非空字符串），并继续校验签发者与持有者两类
        锚点和双签名，source_tenant_id 作为 holder proof 覆盖对象中的
        tenant_id。成功项 ``{"valid": true}``，失败项
        ``{"valid": false, "reason": ...}``。纯只读：不消费、不登记
        资源，不写状态、历史或审计，仅使用当前租户锚点。
        """
        if not isinstance(data, dict):
            return False, "请求不合法: 请求体必须为 JSON 对象", []
        if set(data) != {"presentations"}:
            missing = [f for f in ("presentations",) if f not in data]
            if missing:
                return False, (
                    f"请求缺少字段: {', '.join(missing)}"
                ), []
            extra = sorted(set(data) - {"presentations"})
            return False, f"请求含多余字段: {', '.join(extra)}", []
        presentations = data["presentations"]
        if not isinstance(presentations, list):
            return False, "请求不合法: 字段 presentations 必须为数组", []
        if not presentations:
            return False, "请求不合法: presentations 数组不能为空", []
        if len(presentations) > 100:
            return False, (
                "请求不合法: presentations 数组不能超过 100 项"
                f"（当前 {len(presentations)} 项）"
            ), []

        results: List[Dict[str, Any]] = []
        for item in presentations:  # 顺序校验，失败不短路
            valid, reason = self.verify_trust_presentation(
                tenant_id, item, allow_holder_bound=True
            )
            if valid:
                results.append({"valid": True})
            else:
                results.append(
                    {"valid": False, "reason": reason or "验签失败"}
                )
        return True, "", results

    def verify_trust_presentation_with_status(
        self,
        tenant_id: str,
        data: Any,
    ) -> Tuple[bool, str]:
        """外部演示验真并合并本地同步状态判定（只读）。

        先按 :meth:`verify_trust_presentation` 的全部规则完成验真
        （未绑定与持有者绑定两种形态：请求结构 → 演示字段与挑战 →
        签发者锚点与签名 → 持有者锚点与签名（仅绑定）→ 期限），失败
        原样返回 ``(False, 原因)``，保持既有优先级与中文原因分类。

        验真通过后按当前租户 ``(issuer_did, credential_id)`` 双键只读
        查询 ``credential_status_sync`` 同步记录（取自演示对象）：
          - 未同步（含属他租户）：``(False, "外部凭证状态未同步")``；
          - active：``(True, "")``；
          - revoked：``(False, "外部凭证已吊销：<保存的 reason>")``，
            保存记录无 reason 时用“未知原因”；
          - unknown：``(False, "外部凭证状态未知")``。

        纯只读：不消费、不登记任何资源、不写状态/历史/审计。
        """
        valid, reason = self.verify_trust_presentation(
            tenant_id, data, allow_holder_bound=True
        )
        if not valid:
            return False, reason

        presentation = data["presentation"]
        issuer_did = presentation["issuer_did"]
        credential_id = presentation["credential_id"]
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            row = None
            if bucket is not None:
                row = (
                    bucket.get("credential_status_sync", {})
                    .get(issuer_did, {})
                    .get(credential_id)
                )
        if row is None:
            return False, "外部凭证状态未同步"
        status = row.get("status")
        if status == "active":
            return True, ""
        if status == "revoked":
            saved_reason = row.get("reason")
            if not saved_reason:
                saved_reason = "未知原因"
            return False, f"外部凭证已吊销：{saved_reason}"
        # status 仅可能为 active/revoked/unknown（同步入口已约束）。
        return False, "外部凭证状态未知"

    def verify_trust_presentations_batch_with_status(
        self,
        tenant_id: str,
        data: Any,
    ) -> Tuple[bool, str, List[Dict[str, Any]]]:
        """批量验证外部演示并合并本租户同步状态，返回
        (请求是否合法, 请求级原因, 逐项结果)。

        请求级结构与 :meth:`verify_trust_presentations_batch` 完全一致：
        请求体须恰为 ``{"presentations": [项...]}``，数组非空且不超过
        100 项；不合法时返回 ``(False, "请求...", [])``，由调用方回
        ``{"results": [], "reason": ...}``。

        请求级合法时逐项复用 :meth:`verify_trust_presentation_with_status`
        （未绑定与持有者绑定两种形态的字段、挑战、双锚点双签名与期限
        规则，验真通过后只读合并本租户 ``(issuer_did, credential_id)``
        同步状态），按输入顺序收集结果，失败不短路：成功项
        ``{"valid": true}``，失败项 ``{"valid": false, "reason": ...}``。
        纯只读：不消费、不登记任何资源、不写状态/历史/审计。
        """
        if not isinstance(data, dict):
            return False, "请求不合法: 请求体必须为 JSON 对象", []
        if set(data) != {"presentations"}:
            missing = [f for f in ("presentations",) if f not in data]
            if missing:
                return False, (
                    f"请求缺少字段: {', '.join(missing)}"
                ), []
            extra = sorted(set(data) - {"presentations"})
            return False, f"请求含多余字段: {', '.join(extra)}", []
        presentations = data["presentations"]
        if not isinstance(presentations, list):
            return False, "请求不合法: 字段 presentations 必须为数组", []
        if not presentations:
            return False, "请求不合法: presentations 数组不能为空", []
        if len(presentations) > 100:
            return False, (
                "请求不合法: presentations 数组不能超过 100 项"
                f"（当前 {len(presentations)} 项）"
            ), []

        results: List[Dict[str, Any]] = []
        for item in presentations:  # 顺序校验，失败不短路
            valid, reason = self.verify_trust_presentation_with_status(
                tenant_id, item
            )
            if valid:
                results.append({"valid": True})
            else:
                results.append(
                    {"valid": False, "reason": reason or "验签失败"}
                )
        return True, "", results

    def verify_trust_proof(
        self,
        tenant_id: str,
        data: Any,
    ) -> Tuple[bool, str]:
        """验证未在本租户保存的外部谓词证明，返回 (是否有效, 失败原因)。

        请求体须恰含 proof（对象）、challenge（非空字符串）与
        source_tenant_id（非空字符串）。proof 须恰为 prove 响应九字段：
        proof_id、credential_id、issuer_did（非空字符串）、
        issuer_key_version（非布尔正整数）、predicates、results、
        challenge/expires_at/proof（非空字符串）。results 与 predicates
        等长且仅含布尔；请求 challenge 须等于证明对象 challenge。
        predicates 项须恰含 path、op 及可选 value；op 限
        exists/eq/gte/lte，exists 禁 value，其余必填 value，gte/lte 的
        value 为非布尔数字；path 须以 / 开头、RFC6901 转义合法且无重复
        或祖先重叠（不校验 claims 命中、数组路径或命中值类型，也不重算
        results）。

        校验顺序：请求 -> 证明字段与挑战 -> 锚点 -> 签名格式 ->
        ES256 验签（覆盖除 proof 外八字段并加入
        tenant_id=source_tenant_id 的规范化 JSON）-> 期限。锚点按当前
        租户 (issuer_did, issuer_key_version) 查找，仅 active 的 P-256
        公钥可用。expires_at 须为 UTC 秒精度 Z 格式，到期返回
        “证明已过期”。只读：不消费、不登记任何资源、不写状态/历史/审计，
        绝不向上抛异常。
        """
        # 1. 请求结构：恰含 proof、challenge、source_tenant_id。
        if not isinstance(data, dict):
            return False, "请求不合法: 请求体必须为 JSON 对象"
        request_fields = {"proof", "challenge", "source_tenant_id"}
        if set(data) != request_fields:
            missing = sorted(request_fields - set(data))
            if missing:
                return False, f"请求缺少字段: {', '.join(missing)}"
            extra = sorted(set(data) - request_fields)
            return False, f"请求含多余字段: {', '.join(extra)}"
        proof = data["proof"]
        request_challenge = data["challenge"]
        source_tenant_id = data["source_tenant_id"]
        if not isinstance(proof, dict):
            return False, "请求不合法: 字段 proof 必须为 JSON 对象"
        if not isinstance(request_challenge, str) or not request_challenge:
            return False, "请求不合法: 字段 challenge 必须为非空字符串"
        if not isinstance(source_tenant_id, str) or not source_tenant_id:
            return False, (
                "请求不合法: 字段 source_tenant_id 必须为非空字符串"
            )

        # 2. 证明字段与挑战。
        required_fields = {
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
        if set(proof) != required_fields:
            missing = sorted(required_fields - set(proof))
            if missing:
                return False, f"证明缺少字段: {', '.join(missing)}"
            extra = sorted(set(proof) - required_fields)
            return False, f"证明含多余字段: {', '.join(extra)}"
        for field in ("proof_id", "credential_id", "issuer_did"):
            value = proof[field]
            if not isinstance(value, str) or not value:
                return False, f"证明字段 {field} 必须为非空字符串"
        key_version = proof["issuer_key_version"]
        if (
            not isinstance(key_version, int)
            or isinstance(key_version, bool)
            or key_version < 1
        ):
            return False, "证明字段 issuer_key_version 必须为正整数"
        predicates = proof["predicates"]
        if not isinstance(predicates, list) or not predicates:
            return False, "证明字段 predicates 必须为非空数组"
        seen_tokens: List[Tuple[str, ...]] = []
        for item in predicates:
            if not isinstance(item, dict):
                return False, "证明 predicates 元素必须为 JSON 对象"
            if set(item) - {"path", "op", "value"}:
                extra = sorted(set(item) - {"path", "op", "value"})
                return False, (
                    f"证明 predicates 元素含多余字段: {', '.join(extra)}"
                )
            if "path" not in item:
                return False, "证明 predicates 元素缺少字段: path"
            if "op" not in item:
                return False, "证明 predicates 元素缺少字段: op"
            op = item["op"]
            if op not in _PREDICATE_OPS:
                return False, (
                    f"证明 predicates 元素 op 非法: {op!r}"
                    "（仅支持 exists/eq/gte/lte）"
                )
            if op == "exists":
                if "value" in item:
                    return False, (
                        "证明 predicates 元素 op 为 exists 时禁止 value 字段"
                    )
            elif "value" not in item:
                return False, (
                    f"证明 predicates 元素 op 为 {op} 时缺少字段: value"
                )
            elif op in ("gte", "lte") and not _is_number(item["value"]):
                return False, (
                    f"证明 predicates 元素 op 为 {op} 时 value 必须为非布尔数字"
                )
            # 仅做指针语法与重叠校验：不查 claims 命中、不判数组路径。
            try:
                tokens = _parse_pointer(item["path"], "证明 predicates")
            except ValidationError as exc:
                return False, str(exc)
            if tokens in seen_tokens:
                return False, (
                    f"证明 predicates 路径重复: {item['path']!r}"
                )
            for existing in seen_tokens:
                if tokens[: len(existing)] == existing:
                    return False, (
                        "证明 predicates 路径存在祖先重叠: "
                        f"{item['path']!r} 被已选路径覆盖"
                    )
                if existing[: len(tokens)] == tokens:
                    return False, (
                        "证明 predicates 路径存在祖先重叠: "
                        f"已选路径被 {item['path']!r} 覆盖"
                    )
            seen_tokens.append(tokens)
        results = proof["results"]
        if not isinstance(results, list) or len(results) != len(predicates):
            return False, (
                "证明字段 results 必须为与 predicates 等长的数组"
            )
        if any(not isinstance(item, bool) for item in results):
            return False, "证明字段 results 仅能包含布尔值"
        for field in ("challenge", "expires_at", "proof"):
            value = proof[field]
            if not isinstance(value, str) or not value:
                return False, f"证明字段 {field} 必须为非空字符串"
        if request_challenge != proof["challenge"]:
            return False, "挑战不匹配: 请求 challenge 与证明 challenge 不一致"

        # 3. 锚点：当前租户 (issuer_did, issuer_key_version)，仅 active。
        issuer_did = proof["issuer_did"]
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
            public_pem = row.get("public_key", "") if row is not None else ""
            status = row.get("status", "active") if row is not None else None
        if row is None:
            return False, f"锚点不存在: {issuer_did}#{key_version}"
        if status == "revoked":
            return False, f"锚点已吊销: {issuer_did}#{key_version}"
        try:
            crypto.validate_public_key_pem(public_pem)
        except (ValueError, TypeError):
            return False, (
                f"锚点公钥不可用: {issuer_did}#{key_version} 不是合法 P-256 公钥"
            )

        # 4/5. 签名格式与密码学验签：覆盖除 proof 外八字段，并加入
        # tenant_id=source_tenant_id 后按规范化 JSON 验签。
        signature = proof["proof"]
        message = {k: v for k, v in proof.items() if k != "proof"}
        message["tenant_id"] = source_tenant_id
        try:
            crypto.verify(message, signature, public_pem)
        except crypto.MalformedSignature:
            return False, "签名格式错误: 不是合法的 ES256 签名编码"
        except crypto.InvalidSignature:
            return False, "签名校验失败，证明内容或签名可能被改动"
        except Exception:  # noqa: BLE001 验签绝不向上抛错或泄露内部细节
            return False, "签名校验失败: 验签过程发生内部错误"

        # 6. 期限：expires_at 须为 UTC 秒精度 Z 格式；当前时间达到它即
        # 过期。只读，不消费、不写任何状态、不记审计。
        expires_value = proof["expires_at"]
        if not _UTC_Z_SHAPE_RE.match(expires_value):
            return False, (
                "证明字段 expires_at 必须为 UTC 秒精度 Z 格式"
                "（YYYY-MM-DDTHH:MM:SSZ）"
            )
        try:
            expires_dt = _parse_utc_z(expires_value)
        except ValueError:
            return False, (
                "证明字段 expires_at 必须为 UTC 秒精度 Z 格式"
                "（YYYY-MM-DDTHH:MM:SSZ）"
            )
        if datetime.now(timezone.utc) >= expires_dt:
            return False, "证明已过期"
        return True, ""

    def verify_trust_proof_with_status(
        self,
        tenant_id: str,
        data: Any,
    ) -> Tuple[bool, str]:
        """外部谓词证明验真并合并本地同步状态判定（只读）。

        先按 :meth:`verify_trust_proof` 的全部规则完成验真（请求结构 →
        证明字段与挑战 → 锚点 → 签名格式 → ES256 验签 → 期限），失败
        原样返回 ``(False, 原因)``，保持既有优先级与中文原因分类。

        验真通过后按当前租户 ``(issuer_did, credential_id)`` 双键只读
        查询 ``credential_status_sync`` 同步记录：
          - 未同步（含属他租户）：``(False, "外部凭证状态未同步")``；
          - active：``(True, "")``；
          - revoked：``(False, "外部凭证已吊销：<保存的 reason>")``，
            保存记录无 reason 时用“未知原因”；
          - unknown：``(False, "外部凭证状态未知")``。

        纯只读：不消费、不登记任何资源、不写状态/历史/审计。
        """
        valid, reason = self.verify_trust_proof(tenant_id, data)
        if not valid:
            return False, reason

        proof = data["proof"]
        issuer_did = proof["issuer_did"]
        credential_id = proof["credential_id"]
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            row = None
            if bucket is not None:
                row = (
                    bucket.get("credential_status_sync", {})
                    .get(issuer_did, {})
                    .get(credential_id)
                )
        if row is None:
            return False, "外部凭证状态未同步"
        status = row.get("status")
        if status == "active":
            return True, ""
        if status == "revoked":
            saved_reason = row.get("reason")
            if not saved_reason:
                saved_reason = "未知原因"
            return False, f"外部凭证已吊销：{saved_reason}"
        # status 仅可能为 active/revoked/unknown（同步入口已约束）。
        return False, "外部凭证状态未知"

    def verify_trust_proofs_batch(
        self,
        tenant_id: str,
        data: Any,
    ) -> Tuple[bool, str, List[Dict[str, Any]]]:
        """批量验证外部谓词证明，返回 (请求是否合法, 请求级原因, 逐项结果)。

        请求体须恰为 ``{"proofs": [项...]}``：数组非空且不超过 100 项。
        请求级结构不合法（非对象、字段缺失或多余、proofs 非数组、空数组
        或超过上限）时返回 ``(False, "请求...", [])``，由调用方回
        ``{"results": [], "reason": ...}``。

        请求级合法时逐项复用 :meth:`verify_trust_proof`（与单项接口完全
        一致的请求、证明字段、挑战、锚点、签名与期限规则），按输入顺序
        收集结果，失败不短路：成功项 ``{"valid": true}``，失败项
        ``{"valid": false, "reason": ...}``。只读，不消费、不登记任何
        资源、不写状态/历史/审计。
        """
        if not isinstance(data, dict):
            return False, "请求不合法: 请求体必须为 JSON 对象", []
        if set(data) != {"proofs"}:
            missing = [f for f in ("proofs",) if f not in data]
            if missing:
                return False, (
                    f"请求缺少字段: {', '.join(missing)}"
                ), []
            extra = sorted(set(data) - {"proofs"})
            return False, f"请求含多余字段: {', '.join(extra)}", []
        proofs = data["proofs"]
        if not isinstance(proofs, list):
            return False, "请求不合法: 字段 proofs 必须为数组", []
        if not proofs:
            return False, "请求不合法: proofs 数组不能为空", []
        if len(proofs) > 100:
            return False, (
                f"请求不合法: proofs 数组不能超过 100 项（当前 {len(proofs)} 项）"
            ), []

        results: List[Dict[str, Any]] = []
        for item in proofs:  # 顺序校验，失败不短路
            valid, reason = self.verify_trust_proof(tenant_id, item)
            if valid:
                results.append({"valid": True})
            else:
                results.append(
                    {"valid": False, "reason": reason or "验签失败"}
                )
        return True, "", results

    def verify_trust_proofs_batch_with_status(
        self,
        tenant_id: str,
        data: Any,
    ) -> Tuple[bool, str, List[Dict[str, Any]]]:
        """批量验证外部谓词证明并合并本租户同步状态，返回
        (请求是否合法, 请求级原因, 逐项结果)。

        请求级结构与 :meth:`verify_trust_proofs_batch` 完全一致：请求体
        须恰为 ``{"proofs": [项...]}``，数组非空且不超过 100 项；不合法
        时返回 ``(False, "请求...", [])``，由调用方回
        ``{"results": [], "reason": ...}``。

        请求级合法时逐项复用 :meth:`verify_trust_proof_with_status`
        （与单项验真一致的请求、证明字段、挑战、锚点、签名与期限规则，
        验真通过后只读合并本租户 ``(issuer_did, credential_id)`` 同步
        状态），按输入顺序收集结果，失败不短路：成功项
        ``{"valid": true}``，失败项 ``{"valid": false, "reason": ...}``。
        只读，不消费、不登记任何资源、不写状态/历史/审计。
        """
        if not isinstance(data, dict):
            return False, "请求不合法: 请求体必须为 JSON 对象", []
        if set(data) != {"proofs"}:
            missing = [f for f in ("proofs",) if f not in data]
            if missing:
                return False, (
                    f"请求缺少字段: {', '.join(missing)}"
                ), []
            extra = sorted(set(data) - {"proofs"})
            return False, f"请求含多余字段: {', '.join(extra)}", []
        proofs = data["proofs"]
        if not isinstance(proofs, list):
            return False, "请求不合法: 字段 proofs 必须为数组", []
        if not proofs:
            return False, "请求不合法: proofs 数组不能为空", []
        if len(proofs) > 100:
            return False, (
                f"请求不合法: proofs 数组不能超过 100 项（当前 {len(proofs)} 项）"
            ), []

        results: List[Dict[str, Any]] = []
        for item in proofs:  # 顺序校验，失败不短路
            valid, reason = self.verify_trust_proof_with_status(
                tenant_id, item
            )
            if valid:
                results.append({"valid": True})
            else:
                results.append(
                    {"valid": False, "reason": reason or "验签失败"}
                )
        return True, "", results

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
                # 仅轮换目标新版本追加 active 事件；同前置同 PEM 的幂等
                # 重试不追加。锚点、历史、游标与审计同一次原子写落盘。
                history_entries = (
                    bucket.setdefault("trust_anchor_history", {})
                    .setdefault(did, [])
                )
                history_entries.append(
                    {
                        "key_version": target_version,
                        "action": AUDIT_TRUST_ANCHOR_ROTATED,
                        "status": "active",
                        "updated_at": None,
                        "cursor": (
                            self._next_trust_anchor_cursor_locked(tenant_id)
                        ),
                    }
                )
                self._save_locked()
                return self._trust_anchor_record(did, row), True
            except Exception:
                self._restore_locked(snapshot)
                raise

    # ------------------------------------------------------------------ #
    # 外部凭证状态同步
    # ------------------------------------------------------------------ #
    @staticmethod
    def _sync_status_record(
        issuer_did: str, credential_id: str, row: Dict[str, Any]
    ) -> CredentialStatusSyncRecord:
        return CredentialStatusSyncRecord(
            issuer_did=issuer_did,
            credential_id=credential_id,
            status=row["status"],
            updated_at=row["updated_at"],
            issuer_key_version=int(row["issuer_key_version"]),
            reason=row.get("reason"),
        )

    def _history_entries_locked(
        self, bucket: Dict[str, Any], issuer_did: str, credential_id: str
    ) -> List[Dict[str, Any]]:
        """取（并按需建立）某双键的历史事件列表。"""
        history = bucket.setdefault("credential_status_history", {})
        return history.setdefault(issuer_did, {}).setdefault(credential_id, [])

    def _next_history_cursor_locked(self) -> int:
        """分配下一个持久化历史游标（正整数，按追加递增）。"""
        self._history_cursor += 1
        return self._history_cursor

    def _next_key_revocation_cursor_locked(self, tenant_id: str) -> int:
        """分配租户内下一个持久化密钥吊销游标（正整数，按追加递增）。"""
        cursor = self._key_revocation_cursors.get(tenant_id, 0) + 1
        self._key_revocation_cursors[tenant_id] = cursor
        return cursor

    def _backfill_key_revocations_locked(self) -> None:
        """加载迁移：为旧状态文件中已吊销但无历史的版本补兼容项。

        对每个租户的每个 DID，按 key_history 中被标记为 revoked 但在
        key_revocations 历史中没有对应事件的版本，按版本升序补录一条
        内容取自吊销标记（revoke_reason/revoked_at）的兼容项，cursor
        为该租户内新分配的持久化正整数。仅在内存中补录：随下一次原子
        写一并落盘；若无写操作，重启时按相同（租户、DID、版本）顺序
        重建，cursor 稳定。
        """
        for tenant_id in sorted(self._tenants):
            bucket = self._tenants[tenant_id]
            history_map = bucket.setdefault("key_revocations", {})
            dids = bucket.get("dids", {})
            for did in sorted(dids):
                rec = dids[did]
                revoked_versions = sorted(
                    int(entry.get("version", 0))
                    for entry in rec.get("key_history", [])
                    if entry.get("status") == "revoked"
                )
                if not revoked_versions:
                    continue
                entries = history_map.setdefault(did, [])
                known = {int(event.get("key_version", 0)) for event in entries}
                for version in revoked_versions:
                    if version in known:
                        continue
                    entry = None
                    for item in rec.get("key_history", []):
                        if int(item.get("version", 0)) == version:
                            entry = item
                            break
                    if entry is None:
                        continue
                    entries.append(
                        {
                            "key_version": version,
                            "reason": entry.get(
                                "revoke_reason", DEFAULT_KEY_REVOKE_REASON
                            ),
                            "updated_at": entry.get("revoked_at"),
                            "cursor": (
                                self._next_key_revocation_cursor_locked(
                                    tenant_id
                                )
                            ),
                        }
                    )
                entries.sort(
                    key=lambda event: int(event.get("key_version", 0))
                )

    def _next_key_lifecycle_cursor_locked(self, tenant_id: str) -> int:
        """分配租户内下一个持久化密钥生命周期游标（正整数，递增）。

        与密钥吊销历史游标（_key_revocation_cursors）相互隔离：同一租户
        内不同 DID 的 did.created/key.rotated/key.revoked 生命周期事件
        共享本游标空间。
        """
        cursor = self._key_lifecycle_cursors.get(tenant_id, 0) + 1
        self._key_lifecycle_cursors[tenant_id] = cursor
        return cursor

    def _backfill_key_lifecycle_locked(self) -> None:
        """加载迁移：为旧状态文件补齐密钥生命周期历史（内存态）。

        对每个租户按 DID 字典序、DID 内 key_history 版本升序，为缺少
        生命周期历史的版本补录：
        - 每个版本先补一条 active：版本 1 的 action 为 did.created、
          updated_at 取 DID created_at；其余版本 action 为 key.rotated、
          updated_at 为 None（轮换时刻无法追溯）；
        - 已吊销版本再补一条 revoked（key.revoked），updated_at 取该版本
          revoked_at，缺失时为 None。
        同版本顺序固定为 active 先、revoked 后。补录项的
        audit_seq/audit_timestamp 均为 None（无法追溯原始审计），cursor
        为该租户内新分配的持久化正整数。仅在内存中补录：随下一次原子写
        一并落盘；若无写操作，重启时按相同（租户、DID、版本、动作）
        顺序重建，cursor 稳定。
        """
        for tenant_id in sorted(self._tenants):
            bucket = self._tenants[tenant_id]
            history_map = bucket.setdefault("key_lifecycle", {})
            dids = bucket.get("dids", {})
            for did in sorted(dids):
                rec = dids[did]
                entries = history_map.setdefault(did, [])
                known = {
                    (int(event.get("key_version", 0)), event.get("action"))
                    for event in entries
                }
                key_history = sorted(
                    rec.get("key_history", []),
                    key=lambda item: int(item.get("version", 0)),
                )
                for item in key_history:
                    version = int(item.get("version", 0))
                    active_action = (
                        AUDIT_DID_CREATED
                        if version == 1
                        else AUDIT_KEY_ROTATED
                    )
                    if (version, active_action) not in known:
                        active_updated_at = (
                            rec.get("created_at")
                            if version == 1
                            else None
                        )
                        entries.append(
                            {
                                "key_version": version,
                                "key_handle": item.get("key_handle", ""),
                                "public_key": item.get("public_key", ""),
                                "action": active_action,
                                "status": "active",
                                "updated_at": active_updated_at,
                                "cursor": (
                                    self._next_key_lifecycle_cursor_locked(
                                        tenant_id
                                    )
                                ),
                                "audit_seq": None,
                                "audit_timestamp": None,
                            }
                        )
                        known.add((version, active_action))
                    if (
                        item.get("status") == "revoked"
                        and (version, AUDIT_KEY_REVOKED) not in known
                    ):
                        entries.append(
                            {
                                "key_version": version,
                                "key_handle": item.get("key_handle", ""),
                                "public_key": item.get("public_key", ""),
                                "action": AUDIT_KEY_REVOKED,
                                "status": "revoked",
                                "updated_at": item.get("revoked_at"),
                                "cursor": (
                                    self._next_key_lifecycle_cursor_locked(
                                        tenant_id
                                    )
                                ),
                                "audit_seq": None,
                                "audit_timestamp": None,
                            }
                        )
                        known.add((version, AUDIT_KEY_REVOKED))
                entries.sort(key=lambda event: int(event.get("cursor", 0)))

    def list_key_lifecycle(
        self,
        tenant_id: str,
        did: str,
        after: int = 0,
        limit: int = 50,
    ) -> Tuple[List[KeyLifecycleEvent], int]:
        """只读查询某 DID 的密钥生命周期历史，按页返回。

        - DID 在本租户不存在（含他租户）抛 NotFoundError（HTTP 404）；
          DID 存在但无历史返回空页；
        - 事件按 cursor 升序；after 排除 cursor 不大于其值的事件，至多
          返回 limit 项；
        - next_after 为本页末项 cursor，空页保持 after。
        纯只读：不修改任何状态、不记审计、不触发落盘；事件仅含公钥，
        绝不暴露私钥。
        """
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            rec = bucket["dids"].get(did) if bucket is not None else None
            if rec is None:
                raise NotFoundError(f"DID 不存在: {did}")
            entries = sorted(
                bucket.get("key_lifecycle", {}).get(did, []),
                key=lambda event: int(event.get("cursor", 0)),
            )
            picked: List[KeyLifecycleEvent] = []
            for row in entries:
                if len(picked) >= limit:
                    break
                cursor = int(row["cursor"])
                if cursor <= after:
                    continue
                picked.append(
                    KeyLifecycleEvent(
                        key_version=int(row["key_version"]),
                        key_handle=row.get("key_handle", ""),
                        public_key=row.get("public_key", ""),
                        action=row["action"],
                        status=row["status"],
                        updated_at=row.get("updated_at"),
                        cursor=cursor,
                        audit_seq=row.get("audit_seq"),
                        audit_timestamp=row.get("audit_timestamp"),
                    )
                )
            next_after = picked[-1].cursor if picked else after
            return picked, next_after

    def _next_trust_anchor_cursor_locked(self, tenant_id: str) -> int:
        """分配租户内下一个持久化锚点历史游标（正整数，按追加递增）。"""
        cursor = self._trust_anchor_history_cursors.get(tenant_id, 0) + 1
        self._trust_anchor_history_cursors[tenant_id] = cursor
        return cursor

    def _backfill_trust_anchor_history_locked(self) -> None:
        """加载迁移：为缺生命周期历史的旧锚点版本按版本稳定补录。

        对每个租户的每个 DID，按 key_version 升序检查 trust_anchors 中
        的每个版本行：
        - 缺 active 事件时补一条：经轮换创建（行含 from_key_version）补
          trust.anchor.rotated，否则补 trust.anchor.registered，
          status=active、updated_at=None；
        - 已吊销且缺 revoked 事件时再补一条 trust.anchor.revoked，
          status=revoked，updated_at 取版本行首次吊销时间。
        补录 cursor 为该租户内新分配的持久化正整数。仅在内存中补录：
        随下一次原子写一并落盘；若无写操作，重启时按相同（租户、DID、
        版本、动作）顺序重建，cursor 稳定。
        """
        for tenant_id in sorted(self._tenants):
            bucket = self._tenants[tenant_id]
            history_map = bucket.setdefault("trust_anchor_history", {})
            anchors_map = bucket.get("trust_anchors", {})
            for did in sorted(anchors_map):
                rows = anchors_map[did]
                entries = history_map.setdefault(did, [])
                known = {
                    (int(event.get("key_version", 0)), event.get("action"))
                    for event in entries
                }
                for version in sorted(int(ver) for ver in rows):
                    row = rows[str(version)]
                    active_action = (
                        AUDIT_TRUST_ANCHOR_ROTATED
                        if row.get("from_key_version") is not None
                        else AUDIT_TRUST_ANCHOR_REGISTERED
                    )
                    if (version, active_action) not in known:
                        entries.append(
                            {
                                "key_version": version,
                                "action": active_action,
                                "status": "active",
                                "updated_at": None,
                                "cursor": (
                                    self._next_trust_anchor_cursor_locked(
                                        tenant_id
                                    )
                                ),
                            }
                        )
                        known.add((version, active_action))
                    if (
                        row.get("status", "active") == "revoked"
                        and (version, AUDIT_TRUST_ANCHOR_REVOKED) not in known
                    ):
                        entries.append(
                            {
                                "key_version": version,
                                "action": AUDIT_TRUST_ANCHOR_REVOKED,
                                "status": "revoked",
                                "updated_at": row.get("updated_at"),
                                "cursor": (
                                    self._next_trust_anchor_cursor_locked(
                                        tenant_id
                                    )
                                ),
                            }
                        )
                        known.add((version, AUDIT_TRUST_ANCHOR_REVOKED))
                entries.sort(
                    key=lambda event: int(event.get("cursor", 0))
                )

    def list_trust_anchor_history(
        self,
        tenant_id: str,
        did: str,
        after: int = 0,
        limit: int = 50,
    ) -> Tuple[List[TrustAnchorHistoryEvent], int]:
        """只读查询某 DID 的信任锚点生命周期历史，按页返回。

        - DID 在本租户不存在（含他租户）抛 NotFoundError（HTTP 404）；
          DID 存在但无历史返回空页；
        - 事件按 cursor 升序；after 排除 cursor 不大于其值的事件，至多
          返回 limit 项；
        - next_after 为本页末项 cursor，空页保持 after。
        纯只读：不修改任何状态、不记审计、不触发落盘。
        """
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            anchors = (
                bucket.get("trust_anchors", {}).get(did)
                if bucket is not None else None
            )
            if not anchors:
                raise NotFoundError(f"信任锚点不存在: {did}")
            entries = sorted(
                bucket.get("trust_anchor_history", {}).get(did, []),
                key=lambda event: int(event.get("cursor", 0)),
            )
            picked: List[TrustAnchorHistoryEvent] = []
            for row in entries:
                if len(picked) >= limit:
                    break
                cursor = int(row["cursor"])
                if cursor <= after:
                    continue
                picked.append(
                    TrustAnchorHistoryEvent(
                        key_version=int(row["key_version"]),
                        action=row["action"],
                        status=row["status"],
                        updated_at=row.get("updated_at"),
                        cursor=cursor,
                    )
                )
            next_after = picked[-1].cursor if picked else after
            return picked, next_after

    def list_trust_anchor_entries(
        self,
        tenant_id: str,
        after: int = 0,
        limit: int = 50,
        status: Optional[str] = None,
    ) -> Tuple[List[TrustAnchorDiscoveryRecord], int]:
        """跨 DID 只读发现本租户锚点版本，按页返回。

        - status 给定时先按当前状态（active/revoked）过滤，省略则全部；
        - 每项 cursor 复用该版本注册/轮换历史的 active 事件游标，租户内
          跨 DID 唯一、单调递增；吊销不改变 cursor；
        - 再按 cursor > after 升序取至多 limit 项；
        - next_after 为本页末项 cursor，空页保持 after。
        纯只读：不修改任何状态、不记审计、不触发落盘。无锚点的租户
        返回空页（不抛 404）。
        """
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            candidates: List[Tuple[int, str, Dict[str, Any]]] = []
            if bucket is not None:
                anchors_map = bucket.get("trust_anchors", {})
                history_map = bucket.get("trust_anchor_history", {})
                for did, versions in anchors_map.items():
                    # 版本 -> active 生命周期事件游标（注册/轮换）。
                    active_cursor: Dict[int, int] = {}
                    for event in history_map.get(did, []):
                        if event.get("status") == "active":
                            active_cursor[int(event["key_version"])] = int(
                                event["cursor"]
                            )
                    for version_raw, row in versions.items():
                        version = int(version_raw)
                        current_status = row.get("status", "active")
                        if status is not None and current_status != status:
                            continue
                        cursor = active_cursor.get(version)
                        if cursor is None:
                            # 加载迁移已保证存在；防御性跳过异常数据。
                            continue
                        if cursor <= after:
                            continue
                        candidates.append((cursor, did, row))
            candidates.sort(key=lambda item: item[0])
            picked_rows = candidates[:limit]
            picked: List[TrustAnchorDiscoveryRecord] = [
                TrustAnchorDiscoveryRecord(
                    did=did,
                    public_key=row["public_key"],
                    key_version=int(row["key_version"]),
                    status=row.get("status", "active"),
                    updated_at=row.get("updated_at"),
                    cursor=cursor,
                )
                for cursor, did, row in picked_rows
            ]
            next_after = picked[-1].cursor if picked else after
            return picked, next_after

    def _backfill_all_history_locked(self) -> None:
        """加载迁移：为缺历史的旧同步状态补一条兼容项（内存态）。

        对每个租户内存在当前同步状态行、但该双键无任何历史项的旧状态，
        按 (租户, issuer_did, credential_id) 的稳定顺序补录一条内容取自
        旧状态行的兼容项：cursor 为新分配的持久化正整数，
        audit_seq/audit_timestamp 均为 None（无法追溯同步事件）。

        仅在内存中补录：兼容项随下一次任意原子写一并落盘；若此后无写
        操作则重启时按相同顺序重建（加载顺序由 sort_keys 落盘决定，
        cursor 稳定）。严格更新在追加新事件前，旧状态的兼容项已存在。
        """
        for tenant_id in sorted(self._tenants):
            bucket = self._tenants[tenant_id]
            history = bucket.setdefault("credential_status_history", {})
            for issuer_did in sorted(bucket.get("credential_status_sync", {})):
                issuer_rows = bucket["credential_status_sync"][issuer_did]
                issuer_history = history.setdefault(issuer_did, {})
                for credential_id in sorted(issuer_rows):
                    entries = issuer_history.setdefault(credential_id, [])
                    if entries:
                        continue
                    old_row = issuer_rows[credential_id]
                    entries.append(
                        {
                            "status": old_row["status"],
                            "reason": old_row.get("reason"),
                            "updated_at": old_row["updated_at"],
                            "issuer_key_version": int(
                                old_row["issuer_key_version"]
                            ),
                            "cursor": self._next_history_cursor_locked(),
                            "audit_seq": None,
                            "audit_timestamp": None,
                        }
                    )

    def _next_local_credential_status_cursor_locked(
        self, tenant_id: str
    ) -> int:
        """分配租户内下一个持久化凭证状态历史游标（正整数，递增）。"""
        cursor = (
            self._local_credential_status_history_cursors.get(tenant_id, 0)
            + 1
        )
        self._local_credential_status_history_cursors[tenant_id] = cursor
        return cursor

    def _backfill_local_credential_status_history_locked(self) -> None:
        """加载迁移：为有状态但无历史的本地凭证补一条兼容项（内存态）。

        对每个租户内已有状态行（status 为 active/revoked）、但该凭证
        没有任何状态历史项的旧状态，按 (租户, credential_id) 的稳定顺序
        补录一条内容取自状态行的兼容事件：active 事件 reason/revoked_at
        为 None；revoked 事件保存裁剪 reason 与 revoked_at；cursor 为该
        租户内新分配的持久化正整数，audit_seq/audit_timestamp 均为 None
        （无法追溯原始审计事件）。

        仅在内存中补录：兼容项随下一次任意原子写一并落盘；若此后无写
        操作则重启时按相同顺序重建，cursor 稳定。
        """
        for tenant_id in sorted(self._tenants):
            bucket = self._tenants[tenant_id]
            history = bucket.setdefault(
                "local_credential_status_history", {}
            )
            for credential_id in sorted(bucket.get("credentials", {})):
                rec = bucket["credentials"][credential_id]
                status = rec.get("status")
                if status not in ("active", "revoked"):
                    continue
                entries = history.setdefault(credential_id, [])
                if entries:
                    continue
                if status == "revoked":
                    reason = rec.get("revoke_reason")
                    revoked_at = rec.get("revoked_at")
                else:
                    reason = None
                    revoked_at = None
                entries.append(
                    {
                        "status": status,
                        "reason": reason,
                        "updated_at": rec.get("status_updated_at"),
                        "revoked_at": revoked_at,
                        "cursor": (
                            self._next_local_credential_status_cursor_locked(
                                tenant_id
                            )
                        ),
                        "audit_seq": None,
                        "audit_timestamp": None,
                    }
                )

    @staticmethod
    def _imported_credential_record(
        issuer_did: str, credential_id: str, row: Dict[str, Any]
    ) -> ImportedCredentialRecord:
        return ImportedCredentialRecord(
            issuer_did=issuer_did,
            credential_id=credential_id,
            body=row["body"],
            signature=row["signature"],
        )

    @staticmethod
    def _credential_body_field_error(
        body: Any,
    ) -> Tuple[Optional[str], int]:
        """校验外部凭证 body 字段，返回 (中文错误原因, 锚点版本)。

        规则与 :meth:`verify_trust_credential` 的凭证字段部分完全一致：
        body 须含 credential_id/issuer_did/subject_did/issued_at 非空
        字符串、claims 对象；issuer_key_version 可省略（按版本 1），
        提供时须为非布尔正整数。通过时错误原因为 None。
        """
        if not isinstance(body, dict):
            return "字段 body 必须为 JSON 对象", 1
        required_str = (
            "credential_id",
            "issuer_did",
            "subject_did",
            "issued_at",
        )
        for field in required_str:
            if field not in body:
                return f"凭证缺少字段: {field}", 1
            value = body[field]
            if not isinstance(value, str) or not value:
                return f"凭证字段 {field} 必须为非空字符串", 1
        if "claims" not in body:
            return "凭证缺少字段: claims", 1
        if not isinstance(body["claims"], dict):
            return "凭证字段 claims 必须为 JSON 对象", 1
        key_version = 1
        if "issuer_key_version" in body:
            version_obj = body["issuer_key_version"]
            if (
                not isinstance(version_obj, int)
                or isinstance(version_obj, bool)
                or version_obj < 1
            ):
                return "凭证字段 issuer_key_version 必须为正整数", 1
            key_version = version_obj
        return None, key_version

    def import_trust_credential(
        self,
        tenant_id: str,
        data: Any,
    ) -> Dict[str, Any]:
        """导入一条外部凭证，返回结果字典。

        请求结构与凭证字段规则同 :meth:`verify_trust_credential`，但错误
        分类不同：
          - 请求/字段非法（非对象、字段缺失或多余、body 非对象、signature
            非空字符串、凭证必含字段缺失或类型错误、issuer_key_version
            非法）一律抛 ValidationError（HTTP 400）；
          - 锚点缺失/非 active、锚点公钥不可用、签名格式错误、密码学验签
            失败、凭证已过期均返回 ``{"valid": False, "reason": ...}``
            （非空中文原因），不写入、不记审计；
          - 验签通过后按 (tenant, issuer_did, credential_id) 持久化完整
            body 原文与 signature：首次导入 201 并记
            trust.credential.imported；相同内容重放 200、不替换、不重复
            审计；不同内容（body 或 signature 不一致）抛 ConflictError
            （HTTP 409），不写入。状态与审计同一次原子写，失败回滚。
        """
        # ---- 请求结构（错误 -> 400）----
        if not isinstance(data, dict):
            raise ValidationError("请求体必须为 JSON 对象")
        if set(data) != {"body", "signature"}:
            missing = [f for f in ("body", "signature") if f not in data]
            if missing:
                raise ValidationError(f"缺少字段: {', '.join(missing)}")
            extra = sorted(set(data) - {"body", "signature"})
            raise ValidationError(f"多余字段: {', '.join(extra)}")
        body = data["body"]
        signature = data["signature"]
        if not isinstance(signature, str) or not signature:
            raise ValidationError("字段 signature 必须为非空字符串")

        # ---- 凭证字段（错误 -> 400）----
        field_error, key_version = self._credential_body_field_error(body)
        if field_error is not None:
            raise ValidationError(field_error)
        issuer_did = body["issuer_did"]
        credential_id = body["credential_id"]

        # ---- 锚点（缺失/非 active -> 200 valid:false，不写入）----
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            anchors = (
                bucket["trust_anchors"].get(issuer_did)
                if bucket is not None
                else None
            )
            anchor_row = (
                anchors.get(str(key_version))
                if anchors is not None
                else None
            )
            public_pem = (
                anchor_row.get("public_key", "")
                if anchor_row is not None
                else ""
            )
            anchor_status = (
                anchor_row.get("status", "active")
                if anchor_row is not None
                else None
            )
        if anchor_row is None:
            return {
                "valid": False,
                "reason": f"锚点不存在: {issuer_did}#{key_version}",
            }
        if anchor_status == "revoked":
            return {
                "valid": False,
                "reason": f"锚点已吊销: {issuer_did}#{key_version}",
            }
        try:
            crypto.validate_public_key_pem(public_pem)
        except (ValueError, TypeError):
            return {
                "valid": False,
                "reason": (
                    f"锚点公钥不可用: {issuer_did}#{key_version}"
                    " 不是合法 P-256 公钥"
                ),
            }

        # ---- 签名（覆盖完整 body 的规范化 JSON）----
        try:
            crypto.verify(body, signature, public_pem)
        except crypto.MalformedSignature:
            return {
                "valid": False,
                "reason": "签名格式错误: 不是合法的 ES256 签名编码",
            }
        except crypto.InvalidSignature:
            return {
                "valid": False,
                "reason": "签名校验失败，凭证正文或签名可能被改动",
            }
        except Exception:  # noqa: BLE001 验签绝不向上抛错或泄露内部细节
            return {"valid": False, "reason": "签名校验失败: 验签过程发生内部错误"}

        # ---- 有效期（规则同 verify：仅 body 提供 expires_at 时检查）----
        if "expires_at" in body:
            expires_value = body["expires_at"]
            if (
                not isinstance(expires_value, str)
                or not _UTC_Z_SHAPE_RE.match(expires_value)
            ):
                return {
                    "valid": False,
                    "reason": (
                        "凭证字段 expires_at 必须为 UTC 秒精度 Z 格式"
                        "（YYYY-MM-DDTHH:MM:SSZ）"
                    ),
                }
            try:
                expires_dt = _parse_utc_z(expires_value)
            except ValueError:
                return {
                    "valid": False,
                    "reason": (
                        "凭证字段 expires_at 必须为 UTC 秒精度 Z 格式"
                        "（YYYY-MM-DDTHH:MM:SSZ）"
                    ),
                }
            if datetime.now(timezone.utc) >= expires_dt:
                return {"valid": False, "reason": CREDENTIAL_EXPIRED_REASON}

        # ---- 持久化（双键隔离、重放幂等、内容冲突、原子审计）----
        with self._lock:
            bucket = self._ensure_bucket_locked(tenant_id)
            issuer_map = bucket.setdefault(
                "imported_credentials", {}
            ).setdefault(issuer_did, {})
            existing = issuer_map.get(credential_id)
            if existing is not None:
                if (
                    existing.get("body") == body
                    and existing.get("signature") == signature
                ):
                    # 相同内容重放：200、不替换、不重复审计
                    return {
                        "valid": True,
                        "status_code": 200,
                        "record": self._imported_credential_record(
                            issuer_did, credential_id, existing
                        ),
                    }
                # 不同内容：冲突，不写入、不记审计
                raise ConflictError(
                    "外部凭证已导入且内容不同: "
                    f"{issuer_did}#{credential_id}"
                )

            new_row = {"body": copy.deepcopy(body), "signature": signature}
            snapshot = self._snapshot_locked()
            try:
                issuer_map[credential_id] = new_row
                self._append_audit_locked(
                    tenant_id,
                    AUDIT_TRUST_CREDENTIAL_IMPORTED,
                    "imported_credential",
                    f"{issuer_did}#{credential_id}",
                )
                self._save_locked()
            except Exception:
                self._restore_locked(snapshot)
                raise
            return {
                "valid": True,
                "status_code": 201,
                "record": self._imported_credential_record(
                    issuer_did, credential_id, new_row
                ),
            }

    def import_trust_credentials_batch(
        self,
        tenant_id: str,
        items: List[Any],
    ) -> List[Dict[str, Any]]:
        """批量导入外部凭证，逐项复用 :meth:`import_trust_credential`。

        请求级结构（items 字段存在性、数组类型、1..50 长度）由服务层
        校验；此处逐项处理、失败不短路，结果与输入等长同序：

          - 项非对象或字段非法（缺/多字段、signature 非空字符串、凭证
            必含字段缺失或类型错误、issuer_key_version 非法）->
            ``imported:false, http_status:400``，reason 前缀“请求”；
          - 锚点缺失/非 active、锚点公钥不可用、签名格式错误、密码学
            验签失败、expires_at 非法或凭证已过期 ->
            ``imported:false, http_status:200``，reason 沿用单项导入
            措辞（含“凭证字段 expires_at...”与“凭证已过期”）；
          - 同双键不同内容（body 或 signature 不一致）->
            ``imported:false, http_status:409``，reason 前缀“冲突”；
          - 成功 -> ``imported:true``，首次 201、同内容重放 200，键序
            imported,http_status,issuer_did,credential_id,body,
            signature。

        批内同键同内容首 201 后 200、异内容 409（逐项即时落盘，后续
        项可见前项结果）。失败项不写入、不审计；成功项记录与
        trust.credential.imported 审计同一次原子写，失败回滚。
        """
        results: List[Dict[str, Any]] = []
        for item in items:  # 顺序处理，失败不短路
            try:
                result = self.import_trust_credential(tenant_id, item)
            except ValidationError as exc:
                reason = str(exc)
                if not reason.startswith("请求"):
                    reason = f"请求不合法: {reason}"
                results.append(
                    {
                        "imported": False,
                        "http_status": 400,
                        "reason": reason,
                    }
                )
                continue
            except ConflictError as exc:
                results.append(
                    {
                        "imported": False,
                        "http_status": 409,
                        "reason": f"冲突: {exc}",
                    }
                )
                continue
            if not result.get("valid"):
                results.append(
                    {
                        "imported": False,
                        "http_status": 200,
                        "reason": result.get("reason") or "验签失败",
                    }
                )
                continue
            record = result["record"]
            results.append(
                {
                    "imported": True,
                    "http_status": result["status_code"],
                    "issuer_did": record.issuer_did,
                    "credential_id": record.credential_id,
                    "body": record.body,
                    "signature": record.signature,
                }
            )
        return results

    def get_imported_credential(
        self, tenant_id: str, issuer_did: str, credential_id: str
    ) -> ImportedCredentialRecord:
        """查询已导入的外部凭证原文与签名。

        按本租户 (issuer_did, credential_id) 双键查找；未导入、属他租户
        或 issuer_did 不匹配均抛 NotFoundError（HTTP 404，跨租户/存在性
        不可探测）。
        """
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            row = None
            if bucket is not None:
                row = (
                    bucket.get("imported_credentials", {})
                    .get(issuer_did, {})
                    .get(credential_id)
                )
            if row is None:
                raise NotFoundError(
                    "外部凭证未导入: "
                    f"{issuer_did}#{credential_id}"
                )
            return self._imported_credential_record(
                issuer_did, credential_id, row
            )

    def verify_imported_credential(
        self,
        tenant_id: str,
        issuer_did: str,
        credential_id: str,
    ) -> Tuple[bool, str]:
        """重新验证一条已落盘的导入凭证，返回 (是否有效, 失败原因)。

        按本租户 (issuer_did, credential_id) 双键取出存储的 body 与
        signature 原文；未导入、issuer_did 不匹配或属他租户均抛
        NotFoundError（HTTP 404，存在性不可探测）。issuer_key_version
        取存储 body 的值，缺失时按版本 1；锚点按本租户
        (issuer_did, 版本) 查找，仅 active 锚点可用：

          - 锚点缺失或已吊销（或公钥不可用）->
            (False, "锚点不可用")；
          - 签名非无填充 base64url 的 64 字节裸 R||S ->
            (False, "签名格式错误")；
          - ES256 密码学验签失败（覆盖 body 递归键升序紧凑 UTF-8 JSON）
            -> (False, "签名校验失败")；
          - body 含 expires_at 且当前时间已达到 ->
            (False, "凭证已过期")；
          - 成功 -> (True, "")。

        纯只读：不写记录、状态、历史或审计，绝不向上抛内部异常；
        结论随状态文件跨重启稳定。
        """
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            row = None
            if bucket is not None:
                row = (
                    bucket.get("imported_credentials", {})
                    .get(issuer_did, {})
                    .get(credential_id)
                )
            if row is None:
                raise NotFoundError(
                    "外部凭证未导入: "
                    f"{issuer_did}#{credential_id}"
                )
            body = copy.deepcopy(row["body"])
            signature = row["signature"]
            key_version = 1
            version_obj = body.get("issuer_key_version") if isinstance(
                body, dict
            ) else None
            if isinstance(version_obj, int) and not isinstance(
                version_obj, bool
            ):
                key_version = version_obj
            anchors = bucket["trust_anchors"].get(issuer_did)
            anchor_row = (
                anchors.get(str(key_version))
                if anchors is not None else None
            )
            public_pem = (
                anchor_row.get("public_key", "")
                if anchor_row is not None else ""
            )
            anchor_status = (
                anchor_row.get("status", "active")
                if anchor_row is not None else None
            )

        # 锚点：缺失或 revoked（含公钥不可用）统一为“锚点不可用”
        if anchor_row is None or anchor_status == "revoked":
            return False, IMPORTED_ANCHOR_UNAVAILABLE_REASON
        try:
            crypto.validate_public_key_pem(public_pem)
        except (ValueError, TypeError):
            return False, IMPORTED_ANCHOR_UNAVAILABLE_REASON

        # 签名格式与密码学验签：签名覆盖存储 body 原文的规范化 JSON，
        # 省略 issuer_key_version 时不注入该字段。
        try:
            crypto.verify(body, signature, public_pem)
        except crypto.MalformedSignature:
            return False, IMPORTED_SIGNATURE_MALFORMED_REASON
        except crypto.InvalidSignature:
            return False, IMPORTED_SIGNATURE_INVALID_REASON
        except Exception:  # noqa: BLE001 验签绝不向上抛错或泄露内部细节
            return False, IMPORTED_SIGNATURE_INVALID_REASON

        # 有效期：body 含 expires_at 且当前时间达到（>=）判到期
        if isinstance(body, dict) and "expires_at" in body:
            expires_value = body["expires_at"]
            try:
                if not isinstance(expires_value, str) or not (
                    _UTC_Z_SHAPE_RE.match(expires_value)
                ):
                    raise ValueError
                expires_dt = _parse_utc_z(expires_value)
            except ValueError:
                # 存储记录均经导入验签，正常不会到达；防御性归为过期判定。
                return False, CREDENTIAL_EXPIRED_REASON
            if datetime.now(timezone.utc) >= expires_dt:
                return False, CREDENTIAL_EXPIRED_REASON
        return True, ""

    def verify_imported_credential_with_status(
        self,
        tenant_id: str,
        issuer_did: str,
        credential_id: str,
    ) -> Tuple[bool, str]:
        """重验一条已落盘导入凭证并合并本租户同步状态（只读）。

        先按 :meth:`verify_imported_credential` 的全部规则重验存储的
        body 与 signature（未导入、issuer_did 错配或属他租户同样抛
        NotFoundError；锚点、签名格式、密码学验签、过期结论原样返回，
        原因恰为“锚点不可用”/“签名格式错误”/“签名校验失败”/
        “凭证已过期”）。

        重验通过后按当前租户 ``(issuer_did, credential_id)`` 双键只读
        查询 ``credential_status_sync`` 同步记录：
          - 未同步（含属他租户）：``(False, "外部凭证状态未同步")``；
          - active：``(True, "")``；
          - revoked：``(False, "外部凭证已吊销：<保存的 reason>")``，
            保存记录无 reason 或 reason 为空串时用“未知原因”；
          - unknown：``(False, "外部凭证状态未知")``。

        纯只读：不写记录、状态、历史或审计，结论随状态文件跨重启稳定。
        """
        valid, reason = self.verify_imported_credential(
            tenant_id, issuer_did, credential_id
        )
        if not valid:
            return False, reason

        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            row = None
            if bucket is not None:
                row = (
                    bucket.get("credential_status_sync", {})
                    .get(issuer_did, {})
                    .get(credential_id)
                )
        if row is None:
            return False, "外部凭证状态未同步"
        status = row.get("status")
        if status == "active":
            return True, ""
        if status == "revoked":
            saved_reason = row.get("reason")
            if not saved_reason:
                saved_reason = "未知原因"
            return False, f"外部凭证已吊销：{saved_reason}"
        # status 仅可能为 active/revoked/unknown（同步入口已约束）。
        return False, "外部凭证状态未知"

    def verify_imported_credentials_batch_with_status(
        self,
        tenant_id: str,
        data: Any,
    ) -> Tuple[bool, str, List[Dict[str, Any]]]:
        """批量重验已导入外部凭证并合并本租户同步状态，返回
        (请求是否合法, 请求级原因, 逐项结果)。

        请求体须恰为 ``{"items": [项...]}``：数组非空且不超过 100 项。
        请求级结构不合法（非对象、字段缺失或多余、items 非数组、空数组
        或超过上限）时返回 ``(False, "请求...", [])``，由调用方回
        ``{"results": [], "reason": ...}``。

        请求级合法时逐项处理，失败不短路。每项须恰含 issuer_did、
        credential_id，且均为非空字符串，否则该项为
        ``{"valid": False, "http_status": 400, "reason": "请求项非法"}``。
        合法项先按本租户 (issuer_did, credential_id) 双键查导入记录：
        未导入或属他租户为
        ``{"valid": False, "http_status": 404, "reason": "资源不存在"}``；
        找到后复用 :meth:`verify_imported_credential` 的重验规则，锚点
        缺失/吊销、签名格式错、验签失败、过期的 http_status 均为 200，
        reason 与单项重验一致。重验成功后只读查询本租户
        ``credential_status_sync`` 同步记录（不随凭证导入创建）：
          - 未同步：(False, 200, "外部凭证状态未同步")；
          - active：(True, 200, None)；
          - revoked：(False, 200, "外部凭证已吊销：<保存 reason>")，
            reason 为空时用“未知原因”；
          - unknown：(False, 200, "外部凭证状态未知")。
        每项结果键序固定为 valid、http_status、reason。纯只读：不写
        记录、状态、历史或审计，结论随状态文件跨重启稳定。
        """
        if not isinstance(data, dict):
            return False, "请求不合法: 请求体必须为 JSON 对象", []
        if set(data) != {"items"}:
            missing = [f for f in ("items",) if f not in data]
            if missing:
                return False, (
                    f"请求缺少字段: {', '.join(missing)}"
                ), []
            extra = sorted(set(data) - {"items"})
            return False, f"请求含多余字段: {', '.join(extra)}", []
        items = data["items"]
        if not isinstance(items, list):
            return False, "请求不合法: 字段 items 必须为数组", []
        if not items:
            return False, "请求不合法: items 数组不能为空", []
        if len(items) > 100:
            return False, (
                f"请求不合法: items 数组不能超过 100 项（当前 {len(items)} 项）"
            ), []

        def item_result(
            valid: bool, http_status: int, reason: Any
        ) -> Dict[str, Any]:
            # 键序固定：valid、http_status、reason。
            return {
                "valid": valid,
                "http_status": http_status,
                "reason": reason,
            }

        results: List[Dict[str, Any]] = []
        for item in items:  # 顺序校验，失败不短路
            # 每项须恰含 issuer_did、credential_id，均为非空字符串。
            if (
                not isinstance(item, dict)
                or set(item) != {"issuer_did", "credential_id"}
                or not isinstance(item["issuer_did"], str)
                or not item["issuer_did"]
                or not isinstance(item["credential_id"], str)
                or not item["credential_id"]
            ):
                results.append(item_result(False, 400, "请求项非法"))
                continue

            issuer_did = item["issuer_did"]
            credential_id = item["credential_id"]
            with self._lock:
                bucket = self._bucket_locked(tenant_id)
                row = None
                if bucket is not None:
                    row = (
                        bucket.get("imported_credentials", {})
                        .get(issuer_did, {})
                        .get(credential_id)
                    )
            if row is None:
                # 记录不存在或跨租户：存在性不可探测。
                results.append(item_result(False, 404, "资源不存在"))
                continue

            try:
                valid, reason = self.verify_imported_credential(
                    tenant_id, issuer_did, credential_id
                )
            except NotFoundError:
                results.append(item_result(False, 404, "资源不存在"))
                continue
            except Exception:  # noqa: BLE001 验签绝不暴露内部细节
                results.append(
                    item_result(False, 200, "签名校验失败")
                )
                continue
            if not valid:
                results.append(item_result(False, 200, reason))
                continue

            with self._lock:
                bucket = self._bucket_locked(tenant_id)
                status_row = None
                if bucket is not None:
                    status_row = (
                        bucket.get("credential_status_sync", {})
                        .get(issuer_did, {})
                        .get(credential_id)
                    )
            if status_row is None:
                results.append(
                    item_result(False, 200, "外部凭证状态未同步")
                )
                continue
            status = status_row.get("status")
            if status == "active":
                results.append(item_result(True, 200, None))
            elif status == "revoked":
                saved_reason = status_row.get("reason")
                if not saved_reason:
                    saved_reason = "未知原因"
                results.append(
                    item_result(
                        False, 200, f"外部凭证已吊销：{saved_reason}"
                    )
                )
            else:
                # status 仅可能为 active/revoked/unknown（同步入口已约束）。
                results.append(
                    item_result(False, 200, "外部凭证状态未知")
                )
        return True, "", results

    def sync_credential_status(
        self,
        tenant_id: str,
        data: Any,
    ) -> Dict[str, Any]:
        """同步一条外部凭证状态，返回结果字典。

        请求体须恰含 body（JSON 对象）与 signature（非空字符串）；
        body 须恰含 issuer_did、credential_id、status、updated_at、
        issuer_key_version，并可选 reason：
          - issuer_did/credential_id/status/updated_at 为非空字符串；
          - status 仅 active、revoked、unknown；
          - issuer_key_version 为非布尔正整数；
          - updated_at 为 UTC 秒精度 Z 格式（YYYY-MM-DDTHH:MM:SSZ）；
          - reason 提供时须为非空字符串。
        任何请求/字段非法均抛 ValidationError（HTTP 400）。

        签名覆盖 body 的规范化 JSON，用本租户 (issuer_did,
        issuer_key_version) 的 active 信任锚点公钥验签。锚点缺失/吊销、
        签名格式错误、密码学验签失败均不抛异常、不写入、不记审计，返回
        {"valid": False, "reason": ...}（reason 前缀依次为
        “锚点”/“签名格式错误”/“签名校验失败”）。

        验签通过后按 (issuer_did, credential_id) 双键在本租户内持久化：
          - 首次同步 201；
          - 相同内容（同 updated_at 且 status/version/reason 相同）重放
            200，不替换、不重复审计；
          - updated_at 严格更新才替换（200 并记审计）；更早或相等内容
            时间但内容不同的处理见下；
          - 同 updated_at 但内容不同抛 ConflictError（409），不写入。
        成功变更（首次或严格更新）记 trust.credential.status.synced，
        resource_id 为 issuer_did#credential_id；状态与审计同一次原子写，
        失败回滚。绝不改动本租户既有凭证状态。
        """
        # ---- 请求结构（错误 -> 400）----
        if not isinstance(data, dict):
            raise ValidationError("请求体必须为 JSON 对象")
        if set(data) != {"body", "signature"}:
            missing = [f for f in ("body", "signature") if f not in data]
            if missing:
                raise ValidationError(f"缺少字段: {', '.join(missing)}")
            extra = sorted(set(data) - {"body", "signature"})
            raise ValidationError(f"多余字段: {', '.join(extra)}")
        body = data["body"]
        signature = data["signature"]
        if not isinstance(body, dict):
            raise ValidationError("字段 body 必须为 JSON 对象")
        if not isinstance(signature, str) or not signature:
            raise ValidationError("字段 signature 必须为非空字符串")

        # ---- body 字段（错误 -> 400）----
        required = (
            "issuer_did",
            "credential_id",
            "status",
            "updated_at",
            "issuer_key_version",
        )
        for field in required:
            if field not in body:
                raise ValidationError(f"body 缺少字段: {field}")
        extra = sorted(set(body) - set(required) - {"reason"})
        if extra:
            raise ValidationError(f"body 含多余字段: {', '.join(extra)}")
        issuer_did = body["issuer_did"]
        credential_id = body["credential_id"]
        status = body["status"]
        updated_at = body["updated_at"]
        key_version = body["issuer_key_version"]
        for name, value in (
            ("issuer_did", issuer_did),
            ("credential_id", credential_id),
            ("status", status),
            ("updated_at", updated_at),
        ):
            if not isinstance(value, str) or not value:
                raise ValidationError(
                    f"body 字段 {name} 必须为非空字符串"
                )
        if status not in ("active", "revoked", "unknown"):
            raise ValidationError(
                "body 字段 status 仅支持 active、revoked、unknown"
            )
        if not isinstance(key_version, int) or isinstance(
            key_version, bool
        ) or key_version < 1:
            raise ValidationError(
                "body 字段 issuer_key_version 必须为非布尔正整数"
            )
        try:
            incoming_dt = _parse_utc_z(updated_at)
        except (TypeError, ValueError):
            raise ValidationError(
                "body 字段 updated_at 必须为 UTC 秒精度 Z 格式"
                "（YYYY-MM-DDTHH:MM:SSZ）"
            )
        reason: Optional[str] = None
        if "reason" in body:
            reason = body["reason"]
            if not isinstance(reason, str) or not reason:
                raise ValidationError("body 字段 reason 必须为非空字符串")

        # ---- 锚点（缺失/吊销 -> 200 valid:false，且不写入）----
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            anchors = (
                bucket["trust_anchors"].get(issuer_did)
                if bucket is not None
                else None
            )
            anchor_row = (
                anchors.get(str(key_version))
                if anchors is not None
                else None
            )
            public_pem = (
                anchor_row.get("public_key", "")
                if anchor_row is not None
                else ""
            )
            anchor_status = (
                anchor_row.get("status", "active")
                if anchor_row is not None
                else None
            )
        if anchor_row is None:
            return {
                "valid": False,
                "reason": f"锚点不存在: {issuer_did}#{key_version}",
            }
        if anchor_status == "revoked":
            return {
                "valid": False,
                "reason": f"锚点已吊销: {issuer_did}#{key_version}",
            }
        try:
            crypto.validate_public_key_pem(public_pem)
        except (ValueError, TypeError):
            return {
                "valid": False,
                "reason": (
                    f"锚点公钥不可用: {issuer_did}#{key_version}"
                    " 不是合法 P-256 公钥"
                ),
            }

        # ---- 签名（覆盖 body 的规范化 JSON）----
        try:
            crypto.verify(body, signature, public_pem)
        except crypto.MalformedSignature:
            return {
                "valid": False,
                "reason": "签名格式错误: 不是合法的 ES256 签名编码",
            }
        except crypto.InvalidSignature:
            return {
                "valid": False,
                "reason": "签名校验失败，状态正文或签名可能被改动",
            }
        except Exception:  # noqa: BLE001 验签绝不向上抛错或泄露内部细节
            return {"valid": False, "reason": "签名校验失败: 验签过程发生内部错误"}

        # ---- 持久化（双键隔离、严格更新、重放幂等、原子审计）----
        with self._lock:
            bucket = self._ensure_bucket_locked(tenant_id)
            sync_map = bucket.setdefault("credential_status_sync", {})
            issuer_map = sync_map.setdefault(issuer_did, {})
            existing = issuer_map.get(credential_id)
            if existing is not None:
                existing_dt = _parse_utc_z(existing["updated_at"])
                if incoming_dt == existing_dt:
                    identical = (
                        existing.get("status") == status
                        and int(existing.get("issuer_key_version"))
                        == key_version
                        and existing.get("reason") == reason
                    )
                    if identical:
                        # 相同重放：200、不替换、不重复审计
                        return {
                            "valid": True,
                            "status_code": 200,
                            "record": self._sync_status_record(
                                issuer_did, credential_id, existing
                            ),
                        }
                    # 同时间不同内容：冲突，不写入、不记审计
                    raise ConflictError(
                        "凭证状态 updated_at 相同但内容不同: "
                        f"{issuer_did}#{credential_id}@{updated_at}"
                    )
                if incoming_dt < existing_dt:
                    # 更早的状态：忽略，保持既有值，200 且不记审计
                    return {
                        "valid": True,
                        "status_code": 200,
                        "record": self._sync_status_record(
                            issuer_did, credential_id, existing
                        ),
                    }

            # 首次同步（201）或严格更新（200）：替换状态、记审计、追加
            # 历史，三者在同一次原子写落盘（失败一并回滚）。重放、更早
            # 日期、同时间冲突均在上方提前返回，不会追加历史。
            created = existing is None
            new_row = {
                "status": status,
                "updated_at": updated_at,
                "issuer_key_version": key_version,
                "reason": reason,
            }
            snapshot = self._snapshot_locked()
            try:
                issuer_map[credential_id] = new_row
                event = self._append_audit_locked(
                    tenant_id,
                    AUDIT_TRUST_CREDENTIAL_STATUS_SYNCED,
                    "trust_credential_status",
                    f"{issuer_did}#{credential_id}",
                )
                entries = self._history_entries_locked(
                    bucket, issuer_did, credential_id
                )
                entries.append(
                    {
                        "status": status,
                        "reason": reason,
                        "updated_at": updated_at,
                        "issuer_key_version": key_version,
                        "cursor": self._next_history_cursor_locked(),
                        "audit_seq": int(event["seq"]),
                        "audit_timestamp": int(event["timestamp"]),
                    }
                )
                self._save_locked()
            except Exception:
                self._restore_locked(snapshot)
                raise
            return {
                "valid": True,
                "status_code": 201 if created else 200,
                "record": self._sync_status_record(
                    issuer_did, credential_id, new_row
                ),
            }

    def sync_credential_status_batch(
        self,
        tenant_id: str,
        data: Any,
    ) -> Tuple[bool, str, List[Dict[str, Any]]]:
        """批量同步外部凭证状态，返回 (请求是否合法, 请求级原因, 逐项结果)。

        请求体须恰为 ``{"items": [项...]}``：数组非空且不超过 100 项。
        请求级结构不合法（非对象、字段缺失或多余、items 非数组、空数组或
        超过上限）时返回 ``(False, "请求...", [])``，由调用方回
        ``{"results": [], "reason": ...}``；请求级非法不写任何状态。

        请求级合法时逐项复用 :meth:`sync_credential_status` 的完整单项
        规则（body 字段、锚点、签名、双键严格更新/重放/冲突与原子落盘），
        按输入顺序收集结果，**失败不短路**：某项的字段错误、锚点/签名
        失败或同秒冲突均不影响其余项。每项失败结果键序为
        ``valid,http_status,reason``（字段错误 400、同秒冲突 409、锚点/
        签名失败 200，reason 恒为非空中文）；成功结果键序为
        ``valid,http_status,issuer_did,credential_id,status,reason,
        updated_at,issuer_key_version``（首次 201，重放/更早日 200，
        严格更新 200 并记审计）。每个成功项沿用单项的状态/历史/审计
        同次原子写，落盘失败回滚该项，跨重启保持。results 与输入等长、
        同序。
        """
        if not isinstance(data, dict):
            return False, "请求不合法: 请求体必须为 JSON 对象", []
        if set(data) != {"items"}:
            if "items" not in data:
                return False, "请求缺少字段: items", []
            extra = sorted(set(data) - {"items"})
            return False, f"请求含多余字段: {', '.join(extra)}", []
        items = data["items"]
        if not isinstance(items, list):
            return False, "请求不合法: 字段 items 必须为数组", []
        if not items:
            return False, "请求不合法: items 数组不能为空", []
        if len(items) > 100:
            return False, (
                f"请求不合法: items 数组不能超过 100 项（当前 {len(items)} 项）"
            ), []

        results: List[Dict[str, Any]] = []
        for item in items:  # 顺序处理，失败不短路
            try:
                result = self.sync_credential_status(tenant_id, item)
            except ValidationError as exc:
                results.append(
                    {"valid": False, "http_status": 400, "reason": str(exc)}
                )
                continue
            except ConflictError as exc:
                results.append(
                    {"valid": False, "http_status": 409, "reason": str(exc)}
                )
                continue
            if not result.get("valid"):
                results.append(
                    {
                        "valid": False,
                        "http_status": 200,
                        "reason": result.get("reason") or "验签失败",
                    }
                )
                continue
            record = result["record"]
            results.append(
                {
                    "valid": True,
                    "http_status": result["status_code"],
                    "issuer_did": record.issuer_did,
                    "credential_id": record.credential_id,
                    "status": record.status,
                    "reason": record.reason,
                    "updated_at": record.updated_at,
                    "issuer_key_version": record.issuer_key_version,
                }
            )
        return True, "", results

    def get_synced_credential_status(
        self, tenant_id: str, issuer_did: str, credential_id: str
    ) -> CredentialStatusSyncRecord:
        """查询已同步的外部凭证状态。

        按本租户 (issuer_did, credential_id) 双键查找；未同步或属他租户
        均抛 NotFoundError（HTTP 404，跨租户不可探测）。
        """
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            row = None
            if bucket is not None:
                row = (
                    bucket.get("credential_status_sync", {})
                    .get(issuer_did, {})
                    .get(credential_id)
                )
            if row is None:
                raise NotFoundError(
                    "外部凭证状态未同步: "
                    f"{issuer_did}#{credential_id}"
                )
            return self._sync_status_record(issuer_did, credential_id, row)

    def list_synced_credential_status_history(
        self,
        tenant_id: str,
        issuer_did: str,
        credential_id: str,
        after: int = 0,
        limit: int = 50,
    ) -> Tuple[List[CredentialStatusHistoryEvent], int]:
        """查询某双键外部凭证的状态历史（只读），按页返回。

        - 双键在本租户未同步（含他租户）抛 NotFoundError（HTTP 404）；
        - 历史按 updated_at 升序、同 updated_at 按 cursor 升序排列；
        - 排除 cursor 不大于 after 的项，至多返回 limit 项；
        - next_after 为本页末项 cursor，空页保持 after。

        audit_seq 为 None 的兼容项（旧状态补录，无法追溯同步事件）
        仍照常按 cursor 返回。
        """
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            current_row = None
            entries: List[Dict[str, Any]] = []
            if bucket is not None:
                current_row = (
                    bucket.get("credential_status_sync", {})
                    .get(issuer_did, {})
                    .get(credential_id)
                )
                entries = list(
                    bucket.get("credential_status_history", {})
                    .get(issuer_did, {})
                    .get(credential_id, [])
                )
            if current_row is None:
                raise NotFoundError(
                    "外部凭证状态未同步: "
                    f"{issuer_did}#{credential_id}"
                )

            def sort_key(row: Dict[str, Any]) -> Tuple[datetime, int]:
                return (
                    _parse_utc_z(row["updated_at"]),
                    int(row["cursor"]),
                )

            ordered = sorted(entries, key=sort_key)
            picked: List[CredentialStatusHistoryEvent] = []
            for row in ordered:
                if len(picked) >= limit:
                    break
                cursor = int(row["cursor"])
                if cursor <= after:
                    continue
                picked.append(
                    CredentialStatusHistoryEvent(
                        status=row["status"],
                        reason=row.get("reason"),
                        updated_at=row["updated_at"],
                        issuer_key_version=int(row["issuer_key_version"]),
                        cursor=cursor,
                        audit_seq=(
                            int(row["audit_seq"])
                            if row.get("audit_seq") is not None
                            else None
                        ),
                        audit_timestamp=(
                            int(row["audit_timestamp"])
                            if row.get("audit_timestamp") is not None
                            else None
                        ),
                    )
                )
            next_after = picked[-1].cursor if picked else after
            return picked, next_after

    def verify_trust_did_document(
        self,
        tenant_id: str,
        data: Any,
    ) -> Tuple[bool, str]:
        """跨系统 DID 文档验真（只读），返回 (是否有效, 失败原因)。

        使未在本租户注册 DID 的系统仅凭提交的 DID 文档完成结构、证明与
        信任判断。校验顺序：请求结构 -> 文档字段/结构 -> 锚点 ->
        签名格式 -> 密码学验签。

        - 请求体须恰含 document（JSON 对象）；缺失、多余字段、非法
          JSON/非对象由 HTTP 层与这里统一归为“请求”类原因；
        - document 须恰含 did（非空字符串）、current_key_version（非
          布尔正整数）、verification_methods（数组）、document_proof
          （非空字符串）；方法按 key_version 严格升序且无重复，每项
          恰含 key_version（非布尔正整数）、key_handle（非空字符串）、
          public_key（可解析 P-256 公钥 PEM），文档任何位置不得出现
          私钥；current_key_version 必须等于最高方法版本；
        - 锚点按当前租户 (did, current_key_version) 查找，仅 active 且
          公钥与文档最高版本 public_key 原文完全匹配的锚点可用；
        - document_proof 为 ES256 裸 R||S 无填充 base64url，覆盖除
          document_proof 外整个文档的递归排序紧凑 JSON。

        纯只读：不登记资源、不写状态/历史/审计，绝不向上抛异常；跨
        租户各自使用本租户锚点，结论随状态文件重启后稳定。
        """
        # 1. 请求结构：恰含 document，且为 JSON 对象
        if not isinstance(data, dict):
            return False, "请求不合法: 请求体必须为 JSON 对象"
        if set(data) != {"document"}:
            if "document" not in data:
                return False, "请求缺少字段: document"
            extra = sorted(set(data) - {"document"})
            return False, f"请求含多余字段: {', '.join(extra)}"
        document = data["document"]
        if not isinstance(document, dict):
            return False, "请求不合法: 字段 document 必须为 JSON 对象"

        # 2. 文档顶层字段：恰含四项
        required = (
            "did",
            "current_key_version",
            "verification_methods",
            "document_proof",
        )
        missing = [f for f in required if f not in document]
        if missing:
            return False, f"DID文档缺少字段: {', '.join(missing)}"
        extra = sorted(set(document) - set(required))
        if extra:
            return False, f"DID文档含多余字段: {', '.join(extra)}"

        did = document["did"]
        if not isinstance(did, str) or not did:
            return False, "DID文档字段 did 必须为非空字符串"

        current_version = document["current_key_version"]
        if (
            not isinstance(current_version, int)
            or isinstance(current_version, bool)
            or current_version < 1
        ):
            return False, "DID文档字段 current_key_version 必须为非布尔正整数"

        proof = document["document_proof"]
        if not isinstance(proof, str) or not proof:
            return False, "DID文档字段 document_proof 必须为非空字符串"

        methods = document["verification_methods"]
        if not isinstance(methods, list):
            return False, "DID文档字段 verification_methods 必须为数组"
        if not methods:
            return False, "DID文档 verification_methods 必须为非空数组"

        # 3. 逐个校验验证方法：恰含三字段、类型、P-256 公钥 PEM、无私钥
        method_fields = {"key_version", "key_handle", "public_key"}
        parsed_versions: List[int] = []
        highest_public_pem = ""
        for index, method in enumerate(methods):
            label = f"第 {index + 1} 个验证方法"
            if not isinstance(method, dict):
                return False, f"DID文档{label}必须为 JSON 对象"
            m_missing = [f for f in method_fields if f not in method]
            if m_missing:
                return False, (
                    f"DID文档{label}缺少字段: {', '.join(m_missing)}"
                )
            m_extra = sorted(set(method) - method_fields)
            if m_extra:
                return False, (
                    f"DID文档{label}含多余字段: {', '.join(m_extra)}"
                )
            version = method["key_version"]
            if (
                not isinstance(version, int)
                or isinstance(version, bool)
                or version < 1
            ):
                return False, (
                    f"DID文档{label}的 key_version 必须为非布尔正整数"
                )
            handle = method["key_handle"]
            if not isinstance(handle, str) or not handle:
                return False, (
                    f"DID文档{label}的 key_handle 必须为非空字符串"
                )
            public_pem = method["public_key"]
            if not isinstance(public_pem, str) or not public_pem:
                return False, (
                    f"DID文档{label}的 public_key 必须为非空字符串 PEM"
                )
            try:
                crypto.validate_public_key_pem(public_pem)
            except (ValueError, TypeError):
                return False, (
                    f"DID文档{label}的 public_key 不是合法的 P-256 公钥 PEM"
                )
            parsed_versions.append(version)

        # 文档任何位置都不得携带私钥（PKCS8/PKCS1/SEC1 私钥 PEM 标记）
        try:
            serialized = json.dumps(document, ensure_ascii=False)
        except (TypeError, ValueError):
            return False, "DID文档含无法序列化的内容"
        if "PRIVATE KEY-----" in serialized:
            return False, "DID文档不得包含私钥"

        # 4. 版本须按升序严格递增（无重复）；当前版本须对应最高版本
        if any(
            parsed_versions[i] >= parsed_versions[i + 1]
            for i in range(len(parsed_versions) - 1)
        ):
            return False, (
                "DID文档 verification_methods 必须按 key_version 升序"
                "且不得重复"
            )
        highest_version = parsed_versions[-1]
        if current_version != highest_version:
            return False, (
                "DID文档 current_key_version 必须对应最高密钥版本"
            )
        highest_public_pem = methods[-1]["public_key"]

        # 5. 锚点：当前租户同 DID、同版本、active 且公钥原文完全匹配
        with self._lock:
            bucket = self._bucket_locked(tenant_id)
            anchors = (
                bucket["trust_anchors"].get(did)
                if bucket is not None else None
            )
            row = (
                anchors.get(str(current_version))
                if anchors is not None else None
            )
            anchor_public_pem = (
                row.get("public_key", "") if row is not None else ""
            )
            anchor_status = (
                row.get("status", "active") if row is not None else None
            )
        if row is None:
            return False, f"锚点不存在: {did}#{current_version}"
        if anchor_status == "revoked":
            return False, f"锚点已吊销: {did}#{current_version}"
        if anchor_public_pem != highest_public_pem:
            return False, (
                f"锚点公钥与文档当前版本公钥不匹配: {did}#{current_version}"
            )

        # 6. 签名格式与密码学验签：证明覆盖除 document_proof 外的整个文档
        unsigned = {k: v for k, v in document.items() if k != "document_proof"}
        try:
            crypto.verify(unsigned, proof, anchor_public_pem)
        except crypto.MalformedSignature:
            return False, "签名格式错误: 不是合法的 ES256 签名编码"
        except crypto.InvalidSignature:
            return False, "签名校验失败，DID 文档或证明可能被改动"
        except Exception:  # noqa: BLE001 验签绝不向上抛错或泄露内部细节
            return False, "签名校验失败: 验签过程发生内部错误"
        return True, ""

    def verify_trust_did_documents_batch(
        self,
        tenant_id: str,
        data: Any,
    ) -> Tuple[bool, str, List[Dict[str, Any]]]:
        """批量验真未在本租户登记的外部 DID 文档（只读），返回
        (请求是否合法, 请求级原因, 逐项结果)。

        请求体须恰为 ``{"documents": [文档...]}``：数组非空且不超过
        100 项。请求级结构不合法（非对象、字段缺失或多余、documents
        非数组、空数组或超过上限）时返回 ``(False, "请求...", [])``，
        由调用方回 ``{"results": [], "reason": ...}``。

        请求级合法时逐项复用 :meth:`verify_trust_did_document` 的完整
        规则（文档结构、锚点、签名格式与密码学验签），按输入顺序收集
        结果，失败不短路：每项包装为 ``{"document": 项}`` 走单项协议，
        成功项 ``{"valid": true}``，失败项
        ``{"valid": false, "reason": ...}``。纯只读：不登记资源、不写
        状态、历史或审计，仅使用当前租户锚点。
        """
        if not isinstance(data, dict):
            return False, "请求不合法: 请求体必须为 JSON 对象", []
        if set(data) != {"documents"}:
            if "documents" not in data:
                return False, "请求缺少字段: documents", []
            extra = sorted(set(data) - {"documents"})
            return False, f"请求含多余字段: {', '.join(extra)}", []
        documents = data["documents"]
        if not isinstance(documents, list):
            return False, "请求不合法: 字段 documents 必须为数组", []
        if not documents:
            return False, "请求不合法: documents 数组不能为空", []
        if len(documents) > 100:
            return False, (
                "请求不合法: documents 数组不能超过 100 项"
                f"（当前 {len(documents)} 项）"
            ), []

        results: List[Dict[str, Any]] = []
        for document in documents:  # 顺序校验，失败不短路
            valid, reason = self.verify_trust_did_document(
                tenant_id, {"document": document}
            )
            if valid:
                results.append({"valid": True})
            else:
                results.append(
                    {"valid": False, "reason": reason or "DID 文档验真失败"}
                )
        return True, "", results

