"""HTTP 服务：基于标准库 http.server。

路由：
  POST /v1/dids                           注册 DID
  GET  /v1/dids/{did}                     查询 DID
  POST /v1/dids/{did}/deactivate          停用 DID（首次/幂等均 200）
  GET  /v1/dids/{did}/status              查询 DID 生命周期状态（只读）
  GET  /v1/dids/{did}/history             查询 DID 注册与停用历史（只读）
  GET  /v1/dids/{did}/document            查询 DID 文档（历史公钥，只读）
  POST /v1/dids/{did}/keys/rotate         轮换 DID 密钥
  POST /v1/dids/{did}/keys/{ver}/revoke   吊销 DID 旧密钥版本
  GET  /v1/dids/{did}/keys/{ver}/status   查询 DID 密钥版本吊销状态（只读）
  GET  /v1/dids/{did}/keys/revocations    查询 DID 密钥吊销历史（只读）
GET  /v1/dids/{did}/keys/history        查询 DID 密钥生命周期历史（只读）
  POST /v1/credentials                    签发凭证
  GET  /v1/credentials/{credential_id}    查询凭证
  PUT  /v1/credentials/{credential_id}/status   登记 active（首次 201/重复 200）或暂停/恢复 suspended（200）
  GET  /v1/credentials/{credential_id}/status   查询状态（无状态按 active）
  GET  /v1/credentials/{credential_id}/status/history  查询凭证状态历史（只读）
  POST /v1/credentials/{credential_id}/revoke   吊销凭证
  POST /v1/credentials/{credential_id}/verify  以存储记录为锚验签
  POST /v1/credentials/{credential_id}/present 生成选择性披露演示
  POST /v1/credentials/{credential_id}/present-batch 原子批量生成选择性披露演示
  POST /v1/presentations/{presentation_id}/verify  以存储记录为锚校验演示
  POST /v1/credentials/{credential_id}/prove    生成谓词证明
  POST /v1/proofs/{proof_id}/verify             以存储记录为锚校验谓词证明
  POST /v1/trust/anchors                  注册信任锚点（同 DID/版本同 PEM 且 uses 相同幂等；可选 uses 用途白名单）
  GET  /v1/trust/anchor-changes           可签名信任锚点变更流（?after=&signer_did=，只读）
  GET  /v1/trust/ac-proof                  锚点变更 Merkle 包含证明（?cursor=&snapshot=&signer_did=，只读）
  POST /v1/trust/ac-proof                  校验锚点变更证明（结构/锚点/签名/包含路径，不依赖本地事件）
  POST /v1/trust/ac-proof/verify-batch     批量校验锚点变更证明（批初锚点快照、逐项不短路，只读）
  POST /v1/trust/anchor-changes/verify    跨系统信任锚点变更流只读验真（不依赖本地事件）
  POST /v1/trust/anchor-changes/sync      跨系统信任锚点变更流同步接收（验真、检查点防重放，原子落盘不审计）
  GET  /v1/trust/anchor-changes/sync-history  查询锚点变更同步页历史（?signer_did=&limit=&after=，只读）
  GET  /v1/trust/anchor-changes/synced-state  锚点变更同步时点汇聚状态视图（?signer_did=&at=&limit=&after=，只读）
  GET  /v1/trust/anchors                  跨 DID 只读发现锚点版本（?limit=&after=&status=）
  POST /v1/trust/anchors/{did}/rotate     带前置版本校验的密钥轮换（继承前置 uses）
  GET  /v1/trust/anchors/{did}            查询 DID 的全部锚点版本
  GET  /v1/trust/anchors/{did}/history    查询信任锚点生命周期历史（只读）
  GET  /v1/trust/anchors/{did}/{key_version}/uses  查询锚点版本用途白名单（只读）
  PUT  /v1/trust/anchors/{did}/{key_version}/uses  收紧锚点版本用途白名单（真子集，幂等）
  GET  /v1/trust/anchors/{did}/{key_version}/uses/history  查询锚点版本用途历史（只读）
  PUT  /v1/trust/anchors/{did}/{key_version}/status  吊销锚点版本
  GET  /v1/trust/anchors/snapshot      本租户锚点签名快照（?signer_did=，只读）
  POST /v1/trust/anchors/snapshot/verify  校验锚点快照签名（只读）
  POST /v1/trust/verify                   用 active 锚点公钥验签
  POST /v1/trust/credentials/verify       跨系统凭证验真（无需登记 DID/凭证）
  POST /v1/trust/credentials/verify-synced  以同步锚点验真外部凭证（只读）
  POST /v1/trust/credentials/verify-synced-with-status  同步锚点验真外部凭证并合并请求初始状态快照（只读）
  POST /v1/trust/credentials/verify-synced-batch  批量以同步锚点快照验真外部凭证（只读）
  POST /v1/trust/credentials/verify-synced-batch-with-status  批量同步锚点验真并合并批初状态快照（只读）
  POST /v1/trust/credentials/verify-receipt  跨系统凭证验真签名回执（只读）
  POST /v1/trust/credentials/receipt/verify  校验验真签名回执（只读）
  POST /v1/trust/credentials/receipt/consume  消费验真签名回执（防重放，首次落盘并审计）
  POST /v1/trust/credentials/receipt/consume-batch  批量消费验真签名回执（逐项不短路，防重放）
  GET  /v1/trust/credentials/receipt/consumptions  查询验真回执消费历史（只读）
  GET  /v1/trust/credentials/receipt/consumptions/export  确定性 NDJSON 导出回执消费历史（快照续传，只读）
  GET  /v1/trust/credentials/receipt/consumptions/manifest 回执消费历史导出清单（签名摘要，只读）
  POST /v1/trust/credentials/receipt/consumptions/manifest/verify 校验回执消费历史清单与 NDJSON 内容（只读）
  POST /v1/trust/receipt-sync 同步外系统回执消费历史（清单验真、检查点防重放，原子落盘不审计）
  POST /v1/trust/receipt-sync-batch 批量同步外系统回执消费历史（逐项不短路，原子落盘不审计）
  POST /v1/trust/credentials/import       导入外部凭证（active 锚点验签后持久化）
  POST /v1/trust/credentials/import-batch 批量导入外部凭证（逐项不短路）
  GET  /v1/trust/credentials/imported/{credential_id}  读取已导入的外部凭证（?issuer_did=）
  POST /v1/trust/credentials/imported/{credential_id}/verify  重启后重新验证已落盘凭证（?issuer_did=，只读）
  POST /v1/trust/credentials/imported/{credential_id}/verify-with-status  重验已导入凭证并合并同步状态（?issuer_did=，只读）
  POST /v1/trust/credentials/imported/verify-batch-with-status 批量重验已导入凭证并合并同步状态（只读）
  POST /v1/trust/dids/verify-document     跨系统 DID 文档验真（仅凭提交文档，只读）
  POST /v1/trust/dids/verify-document-batch 批量跨系统 DID 文档验真（不短路，只读）
  POST /v1/trust/dids/deactivate-sync     登记外部 DID 停用通告（active 锚点验签）
  POST /v1/trust/dids/deactivate-sync-batch 批量登记外部 DID 停用通告（逐项不短路）
  GET  /v1/trust/dids/deactivations       查询外部 DID 停用通告审计事件（只读）
  GET  /v1/trust/dids/deactivations/export 确定性 NDJSON 导出停用通告（快照续传，只读）
  GET  /v1/trust/dids/deactivations/manifest 停用通告导出清单（签名摘要，只读）
  POST /v1/trust/dids/deactivations/manifest/verify 校验停用通告清单与 NDJSON 内容（只读）
  POST /v1/trust/dids/deactivations/manifest/verify-batch 批量校验清单与 NDJSON（只读）
  POST /v1/trust/presentations/verify     跨系统演示验真（无需登记 DID/凭证/演示）
  POST /v1/trust/presentations/verify-synced  以同步锚点验真未绑定外部演示（只读）
  POST /v1/trust/presentations/verify-synced-with-status  同步锚点验真未绑定/持有者绑定演示并合并请求初始状态快照（只读）
  POST /v1/trust/presentations/verify-synced-batch  批量以同步锚点快照验真未绑定演示（只读）
  POST /v1/trust/presentations/verify-synced-batch-with-status  批量同步锚点验真演示并合并批初状态快照（只读）
  POST /v1/trust/presentations/verify-batch 批量跨系统演示验真（仅未绑定形态，不消费）
  POST /v1/trust/presentations/verify-with-status 外部演示验真并合并同步状态（只读）
  POST /v1/trust/presentations/verify-batch-with-status 批量演示验真并合并同步状态（只读）
  POST /v1/trust/proofs/verify            跨系统谓词证明验真（无需登记 DID/凭证/证明，不消费）
  POST /v1/trust/proofs/verify-synced     以同步锚点验真外部谓词证明（只读）
  POST /v1/trust/proofs/verify-synced-with-status  同步锚点验真谓词证明并合并请求初始状态快照（只读）
  POST /v1/trust/proofs/verify-synced-batch  批量以同步锚点快照验真外部谓词证明（只读）
  POST /v1/trust/proofs/verify-synced-batch-with-status  批量同步锚点验真谓词证明并合并批初状态快照（只读）
  POST /v1/trust/proofs/verify-batch      批量跨系统谓词证明验真（兼容单项规则，不消费）
  POST /v1/trust/credentials/verify-batch 批量跨系统凭证验真（兼容单项规则）
  POST /v1/trust/credentials/verify-with-status 外部凭证验真并合并同步状态（只读）
  POST /v1/trust/credentials/verify-batch-with-status 批量验真并合并同步状态（只读）
  POST /v1/trust/credential-status/sync   同步外部凭证状态（active 锚点验签）
  POST /v1/trust/credential-status/sync-batch 批量同步外部凭证状态（逐项不短路）
  GET  /v1/trust/credential-status/{id}   查询已同步的外部凭证状态
  GET  /v1/trust/credential-status/{id}/history  查询外部凭证状态历史（只读）
  GET  /v1/audit                          查询本租户审计事件

多租户：所有 /v1 请求取 X-Tenant-ID 头，缺省为 "default"；显式
提供时须非空，否则 400。DID、凭证、演示、key_handle 均按租户隔离，
跨租户访问一律按不存在处理（沿用 404/400 协议）。

错误映射：ValidationError -> 400，NotFoundError -> 404，ConflictError -> 409。
例外：凭证与演示验签端点对一切“验签失败”都返回 200 +
{"valid": false, "reason": ...}；非法租户头在进入验签流程前判 400。
"""

import errno
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

from . import crypto
from .store import (
    CHALLENGE_UNSET,
    ConflictError,
    DEFAULT_TENANT,
    EXPIRES_AT_UNSET,
    NotFoundError,
    PresentationRecord,
    REASON_UNSET,
    StorageError,
    TRUST_ANCHOR_CHANGE_REGISTERED,
    TRUST_ANCHOR_CHANGE_ROTATED,
    TRUST_ANCHOR_CHANGE_REVOKED,
    TRUST_ANCHOR_CHANGE_SNAPSHOT,
    TRUST_ANCHOR_CHANGE_USES_UPDATED,
    TRUST_ANCHOR_USES,
    USES_UNSET,
    ValidationError,
    VCStore,
)


def _json_dumps(payload: Any) -> bytes:
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


def _deactivation_event_obj(event: Any) -> Dict[str, Any]:
    return {
        "cursor": event.cursor,
        "did": event.did,
        "key_version": event.key_version,
        "reason": event.reason,
        "deactivated_at": event.deactivated_at,
    }


def _deactivation_ndjson_bytes(events: Any) -> bytes:
    """按导出端点的确定性规则将事件编码为 NDJSON 字节。

    每行键序固定为 cursor、did、key_version、reason、deactivated_at，
    UTF-8 紧凑 JSON、非 ASCII 不转义、LF 结行（末行亦有 LF）；空列表
    为零字节。digest 与导出内容必须共用本函数以保证字节一致。
    """
    return "".join(
        json.dumps(
            _deactivation_event_obj(event),
            ensure_ascii=False,
            separators=(",", ":"),
        )
        + "\n"
        for event in events
    ).encode("utf-8")


def _receipt_consumption_event_obj(event: Any) -> Dict[str, Any]:
    return {
        "cursor": event.cursor,
        "receipt_id": event.receipt_id,
        "verifier_did": event.verifier_did,
        "nonce": event.nonce,
        "consumed_at": event.consumed_at,
    }


def _receipt_consumption_ndjson_bytes(events: Any) -> bytes:
    """按消费历史导出端点的确定性规则将事件编码为 NDJSON 字节。

    每行键序固定为 cursor、receipt_id、verifier_did、nonce、consumed_at，
    UTF-8 紧凑 JSON、非 ASCII 不转义、LF 结行（末行亦有 LF）；空列表
    为零字节。
    """
    return "".join(
        json.dumps(
            _receipt_consumption_event_obj(event),
            ensure_ascii=False,
            separators=(",", ":"),
        )
        + "\n"
        for event in events
    ).encode("utf-8")


def _parse_nonneg_int(raw: str, field: str) -> int:
    """解析非负整数字符串：仅接受 ASCII 十进制数字。

    拒绝符号/小数/空白/布尔词，也拒绝 Unicode 数字（如阿拉伯-印度数字）。
    """
    if (
        not isinstance(raw, str)
        or not raw
        or any(ch < "0" or ch > "9" for ch in raw)
    ):
        raise ValidationError(f"查询参数 {field} 必须为非负整数")
    return int(raw)


def _parse_positive_int(raw: str, field: str) -> int:
    """解析正整数字符串：仅接受非全零的 ASCII 十进制数字串。

    拒绝空值、符号/小数/空白/布尔词与 Unicode 数字（如阿拉伯-印度数字），
    也拒绝 "0" 等非正整数。
    """
    if (
        not isinstance(raw, str)
        or not raw
        or any(ch < "0" or ch > "9" for ch in raw)
    ):
        raise ValidationError(f"查询参数 {field} 必须为 ASCII 十进制正整数")
    value = int(raw)
    if value < 1:
        raise ValidationError(f"查询参数 {field} 必须为正整数")
    return value


# 查询参数中 UTC 秒精度 Z 时间的严格形状（定宽补零、无小数、无偏移）。
_UTC_Z_QUERY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

# SHA-256 摘要的 64 位小写十六进制串。
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

# 跨系统信任锚点变更流验真：事件结构与动作名沿用 GET
# /v1/trust/anchor-changes 响应协议。
_ANCHOR_CHANGES_RESPONSE_KEYS = (
    "events",
    "next_after",
    "signer_did",
    "signer_key_version",
    "signature",
)
_ANCHOR_CHANGE_EVENT_KEYS = (
    "cursor",
    "action",
    "did",
    "key_version",
    "public_key",
    "status",
    "uses",
)
_ANCHOR_CHANGE_ACTIONS = frozenset(
    {
        TRUST_ANCHOR_CHANGE_REGISTERED,
        TRUST_ANCHOR_CHANGE_ROTATED,
        TRUST_ANCHOR_CHANGE_REVOKED,
        TRUST_ANCHOR_CHANGE_USES_UPDATED,
        TRUST_ANCHOR_CHANGE_SNAPSHOT,
    }
)
_ANCHOR_CHANGES_MAX_EVENTS = 200

# GET /v1/trust/ac-proof 锚点变更证明响应协议。
_ANCHOR_PROOF_RESPONSE_KEYS = (
    "event",
    "snapshot",
    "root",
    "path",
    "signer_did",
    "signer_key_version",
    "signature",
)
# 签名覆盖前六键（不含 signature）。
_ANCHOR_PROOF_SIGNED_KEYS = _ANCHOR_PROOF_RESPONSE_KEYS[:6]
# Merkle 路径单项键序 side、hash。
_ANCHOR_PROOF_PATH_ITEM_KEYS = ("side", "hash")
_ANCHOR_PROOF_SIDES = frozenset({"left", "right"})


def _parse_utc_z_query(raw: str, field: str) -> str:
    """校验并返回查询参数中的 UTC 秒精度 Z 时间串。

    仅接受形如 YYYY-MM-DDTHH:MM:SSZ 的合法时刻（拒绝空白、毫秒、时区
    偏移、缺 Z、未补零、非法月/日/时分秒与 Unicode 数字），返回原文
    （定宽 Z 串按字典序比较与时间先后一致）。
    """
    if (
        not isinstance(raw, str)
        or not _UTC_Z_QUERY_RE.match(raw)
    ):
        raise ValidationError(
            f"查询参数 {field} 必须为 UTC 秒精度 Z 时间"
            "（YYYY-MM-DDTHH:MM:SSZ）"
        )
    try:
        datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except (ValueError, TypeError):
        raise ValidationError(
            f"查询参数 {field} 必须为 UTC 秒精度 Z 时间"
            "（YYYY-MM-DDTHH:MM:SSZ）"
        )
    return raw


def _anchor_change_event_obj(event: Any) -> Dict[str, Any]:
    """锚点变更事件按变更流协议构造固定键序对象。"""
    return {
        "cursor": event.cursor,
        "action": event.action,
        "did": event.did,
        "key_version": event.key_version,
        "public_key": event.public_key,
        "status": event.status,
        "uses": event.uses,
    }


def _anchor_proof_leaf_hash(event_obj: Dict[str, Any]) -> str:
    """叶哈希 = SHA-256(0x00 || 事件规范 JSON 的 UTF-8)，返回小写 hex。"""
    return hashlib.sha256(
        b"\x00" + crypto.canonicalize(event_obj)
    ).hexdigest()


def _anchor_proof_parent_hash(left_hex: str, right_hex: str) -> str:
    """父哈希 = SHA-256(0x01 || 左 || 右)，左右为 32 字节摘要，返回小写 hex。"""
    return hashlib.sha256(
        b"\x01" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)
    ).hexdigest()


def _anchor_proof_build(
    leaf_hashes: List[str], index: int
) -> Tuple[str, List[Dict[str, str]]]:
    """以 cursor 升序叶序列对 index 处目标建 Merkle 包含证明。

    奇数层复制末项；返回 (root, path)，path 自叶向根，每项
    {"side": 兄弟所在侧, "hash": 兄弟哈希}。单叶时 root 即叶哈希、
    path 为空。
    """
    path: List[Dict[str, str]] = []
    level = list(leaf_hashes)
    current = index
    while len(level) > 1:
        if len(level) % 2 == 1:
            # 奇数末项复制后再配对。
            level.append(level[-1])
        if current % 2 == 0:
            path.append({"side": "right", "hash": level[current + 1]})
        else:
            path.append({"side": "left", "hash": level[current - 1]})
        next_level = [
            _anchor_proof_parent_hash(level[pos], level[pos + 1])
            for pos in range(0, len(level), 2)
        ]
        level = next_level
        current //= 2
    return level[0], path


def _anchor_proof_recompute_root(
    event_obj: Dict[str, Any], path: List[Dict[str, str]]
) -> str:
    """按 path 自叶向根重算 root（与建树同一叶/父哈希规则）。"""
    current = _anchor_proof_leaf_hash(event_obj)
    for item in path:
        sibling = item["hash"]
        if item["side"] == "left":
            current = _anchor_proof_parent_hash(sibling, current)
        else:
            current = _anchor_proof_parent_hash(current, sibling)
    return current


def build_handler(store: VCStore) -> type:
    """构造绑定给定 store 的请求处理器类。"""

    class Handler(BaseHTTPRequestHandler):
        server_version = "VCBackend/0.1"

        # ------------------------------------------------------------ #
        # 响应工具
        # ------------------------------------------------------------ #
        def _send_json(self, status: int, payload: Any) -> None:
            body = _json_dumps(payload)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_error(self, status: int, message: str) -> None:
            self._send_json(status, {"error": message})

        def _send_invalid(self, reason: str) -> None:
            """verify 端点统一失败响应：HTTP 200 + valid:false + 中文原因。"""
            self._send_json(200, {"valid": False, "reason": reason})

        def _tenant_id(self) -> str:
            """解析 X-Tenant-ID：缺省 default；显式空串 400。"""
            raw = self.headers.get("X-Tenant-ID")
            if raw is None:
                return DEFAULT_TENANT
            if raw == "":
                raise ValidationError("X-Tenant-ID 不能为空")
            return raw

        def _read_json(self) -> Dict[str, Any]:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                data = json.loads(raw.decode("utf-8")) if raw else None
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValidationError(f"请求体不是合法 JSON: {exc}") from exc
            if not isinstance(data, dict):
                raise ValidationError("请求体必须为 JSON 对象")
            return data

        def _read_optional_json(self) -> Dict[str, Any]:
            """读取可选请求体：空体等价于 {}，非空时须为 JSON 对象。"""
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            if not raw:
                return {}
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValidationError(f"请求体不是合法 JSON: {exc}") from exc
            if not isinstance(data, dict):
                raise ValidationError("请求体必须为 JSON 对象")
            return data

        # ------------------------------------------------------------ #
        # 路由
        # ------------------------------------------------------------ #
        def do_POST(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
            try:
                parsed = urlparse(self.path)
                path = parsed.path.rstrip("/") or "/"
                parsed_query = parsed.query
                if not path.startswith("/v1"):
                    self._send_error(404, f"无此路径: {path}")
                    return
                tenant = self._tenant_id()
                if path == "/v1/dids":
                    self._post_dids(tenant)
                elif path == "/v1/credentials":
                    self._post_credentials(tenant)
                elif path.startswith("/v1/dids/") and path.endswith(
                    "/keys/rotate"
                ):
                    did = unquote(
                        path[len("/v1/dids/") : -len("/keys/rotate")]
                    )
                    self._post_rotate_key(tenant, did)
                elif path.startswith("/v1/dids/") and "/keys/" in path and path.endswith(
                    "/revoke"
                ):
                    middle = path[len("/v1/dids/") : -len("/revoke")]
                    did_raw, sep, version_raw = middle.partition("/keys/")
                    did = unquote(did_raw)
                    key_version = unquote(version_raw) if sep else ""
                    self._post_revoke_key(tenant, did, key_version)
                elif path.startswith("/v1/dids/") and path.endswith(
                    "/deactivate"
                ):
                    did = unquote(
                        path[len("/v1/dids/") : -len("/deactivate")]
                    )
                    self._post_deactivate_did(tenant, did)
                elif path.startswith("/v1/credentials/") and path.endswith(
                    "/revoke"
                ):
                    credential_id = unquote(
                        path[len("/v1/credentials/") : -len("/revoke")]
                    )
                    self._post_revoke_credential(tenant, credential_id)
                elif path.startswith("/v1/credentials/") and path.endswith(
                    "/verify"
                ):
                    credential_id = unquote(
                        path[len("/v1/credentials/") : -len("/verify")]
                    )
                    self._post_verify_credential(
                        tenant, credential_id
                    )
                elif path.startswith("/v1/credentials/") and path.endswith(
                    "/present"
                ):
                    credential_id = unquote(
                        path[len("/v1/credentials/") : -len("/present")]
                    )
                    self._post_present(tenant, credential_id)
                elif path.startswith("/v1/credentials/") and path.endswith(
                    "/present-batch"
                ):
                    credential_id = unquote(
                        path[len("/v1/credentials/") : -len("/present-batch")]
                    )
                    self._post_present_batch(tenant, credential_id)
                elif path.startswith("/v1/credentials/") and path.endswith(
                    "/prove"
                ):
                    credential_id = unquote(
                        path[len("/v1/credentials/") : -len("/prove")]
                    )
                    self._post_prove(tenant, credential_id)
                elif path.startswith("/v1/proofs/") and path.endswith(
                    "/verify"
                ):
                    proof_id = unquote(
                        path[len("/v1/proofs/") : -len("/verify")]
                    )
                    self._post_verify_proof(tenant, proof_id)
                elif path.startswith("/v1/presentations/") and path.endswith(
                    "/verify"
                ):
                    presentation_id = unquote(
                        path[len("/v1/presentations/") : -len("/verify")]
                    )
                    self._post_verify_presentation(
                        tenant, presentation_id
                    )
                elif path == "/v1/trust/anchors":
                    self._post_trust_anchors(tenant)
                elif path == "/v1/trust/anchors/snapshot/verify":
                    self._post_trust_anchor_snapshot_verify(tenant)
                elif path == "/v1/trust/anchor-changes/verify":
                    self._post_trust_anchor_changes_verify(tenant)
                elif path == "/v1/trust/ac-proof":
                    self._post_trust_ac_proof(tenant)
                elif path == "/v1/trust/ac-proof/verify-batch":
                    self._post_trust_ac_proof_verify_batch(tenant)
                elif path == "/v1/trust/anchor-changes/sync":
                    self._post_trust_anchor_changes_sync(tenant)
                elif path.startswith("/v1/trust/anchors/") and path.endswith(
                    "/rotate"
                ):
                    did = unquote(
                        path[len("/v1/trust/anchors/") : -len("/rotate")]
                    )
                    self._post_trust_anchor_rotate(tenant, did)
                elif path == "/v1/trust/dids/verify-document":
                    self._post_trust_dids_verify_document(tenant)
                elif path == "/v1/trust/dids/verify-document-batch":
                    self._post_trust_dids_verify_document_batch(tenant)
                elif path == "/v1/trust/dids/deactivate-sync":
                    self._post_trust_dids_deactivate_sync(tenant)
                elif path == "/v1/trust/dids/deactivate-sync-batch":
                    self._post_trust_dids_deactivate_sync_batch(tenant)
                elif path == "/v1/trust/dids/deactivations/manifest/verify":
                    self._post_trust_did_deactivations_manifest_verify(tenant)
                elif (
                    path
                    == "/v1/trust/dids/deactivations/manifest/verify-batch"
                ):
                    self._post_trust_did_deactivations_manifest_verify_batch(
                        tenant
                    )
                elif path == "/v1/trust/verify":
                    self._post_trust_verify(tenant)
                elif path == "/v1/trust/credentials/verify":
                    self._post_trust_credentials_verify(tenant)
                elif path == "/v1/trust/credentials/verify-synced":
                    self._post_trust_credentials_verify_synced(tenant)
                elif (
                    path
                    == "/v1/trust/credentials/verify-synced-with-status"
                ):
                    self._post_trust_credentials_verify_synced_with_status(
                        tenant
                    )
                elif path == "/v1/trust/credentials/verify-synced-batch":
                    self._post_trust_credentials_verify_synced_batch(tenant)
                elif (
                    path
                    == "/v1/trust/credentials/verify-synced-batch-with-status"
                ):
                    self._post_trust_credentials_verify_synced_batch_with_status(
                        tenant
                    )
                elif path == "/v1/trust/credentials/verify-receipt":
                    self._post_trust_credentials_verify_receipt(tenant)
                elif path == "/v1/trust/credentials/receipt/verify":
                    self._post_trust_credentials_receipt_verify(tenant)
                elif path == "/v1/trust/credentials/receipt/consume":
                    self._post_trust_credentials_receipt_consume(tenant)
                elif path == "/v1/trust/credentials/receipt/consume-batch":
                    self._post_trust_credentials_receipt_consume_batch(
                        tenant
                    )
                elif (
                    path
                    == "/v1/trust/credentials/receipt/consumptions/manifest"
                    "/verify"
                ):
                    self._post_trust_credential_receipt_consumptions_manifest_verify(
                        tenant
                    )
                elif path == "/v1/trust/receipt-sync":
                    self._post_trust_receipt_sync(tenant)
                elif path == "/v1/trust/receipt-sync-batch":
                    self._post_trust_receipt_sync_batch(tenant)
                elif path == "/v1/trust/credentials/import":
                    self._post_trust_credentials_import(tenant)
                elif path == "/v1/trust/credentials/import-batch":
                    self._post_trust_credentials_import_batch(tenant)
                elif path == "/v1/trust/credentials/imported/verify-batch-with-status":
                    self._post_trust_imported_credentials_verify_batch_with_status(
                        tenant
                    )
                elif path.startswith(
                    "/v1/trust/credentials/imported/"
                ) and path.endswith("/verify-with-status"):
                    credential_id = unquote(
                        path[
                            len("/v1/trust/credentials/imported/")
                            : -len("/verify-with-status")
                        ]
                    )
                    self._post_trust_imported_credential_verify_with_status(
                        tenant, credential_id, parsed_query
                    )
                elif path.startswith(
                    "/v1/trust/credentials/imported/"
                ) and path.endswith("/verify"):
                    credential_id = unquote(
                        path[
                            len("/v1/trust/credentials/imported/")
                            : -len("/verify")
                        ]
                    )
                    self._post_trust_imported_credential_verify(
                        tenant, credential_id, parsed_query
                    )
                elif path == "/v1/trust/presentations/verify":
                    self._post_trust_presentations_verify(tenant)
                elif path == "/v1/trust/presentations/verify-synced":
                    self._post_trust_presentations_verify_synced(tenant)
                elif (
                    path
                    == "/v1/trust/presentations/verify-synced-with-status"
                ):
                    self._post_trust_presentations_verify_synced_with_status(
                        tenant
                    )
                elif path == "/v1/trust/presentations/verify-synced-batch":
                    self._post_trust_presentations_verify_synced_batch(tenant)
                elif (
                    path
                    == "/v1/trust/presentations/verify-synced-batch-with-status"
                ):
                    self._post_trust_presentations_verify_synced_batch_with_status(
                        tenant
                    )
                elif path == "/v1/trust/presentations/verify-batch":
                    self._post_trust_presentations_verify_batch(tenant)
                elif path == "/v1/trust/presentations/verify-with-status":
                    self._post_trust_presentations_verify_with_status(tenant)
                elif path == "/v1/trust/presentations/verify-batch-with-status":
                    self._post_trust_presentations_verify_batch_with_status(
                        tenant
                    )
                elif path == "/v1/trust/proofs/verify":
                    self._post_trust_proofs_verify(tenant)
                elif path == "/v1/trust/proofs/verify-synced":
                    self._post_trust_proofs_verify_synced(tenant)
                elif path == "/v1/trust/proofs/verify-synced-with-status":
                    self._post_trust_proofs_verify_synced_with_status(tenant)
                elif path == "/v1/trust/proofs/verify-synced-batch":
                    self._post_trust_proofs_verify_synced_batch(tenant)
                elif (
                    path
                    == "/v1/trust/proofs/verify-synced-batch-with-status"
                ):
                    self._post_trust_proofs_verify_synced_batch_with_status(
                        tenant
                    )
                elif path == "/v1/trust/proofs/verify-batch":
                    self._post_trust_proofs_verify_batch(tenant)
                elif path == "/v1/trust/proofs/verify-with-status":
                    self._post_trust_proofs_verify_with_status(tenant)
                elif path == "/v1/trust/proofs/verify-batch-with-status":
                    self._post_trust_proofs_verify_batch_with_status(tenant)
                elif path == "/v1/trust/credentials/verify-batch":
                    self._post_trust_credentials_verify_batch(tenant)
                elif path == "/v1/trust/credentials/verify-batch-with-status":
                    self._post_trust_credentials_verify_batch_with_status(
                        tenant
                    )
                elif path == "/v1/trust/credentials/verify-with-status":
                    self._post_trust_credentials_verify_with_status(tenant)
                elif path == "/v1/trust/credential-status/sync":
                    self._post_trust_credential_status_sync(tenant)
                elif path == "/v1/trust/credential-status/sync-batch":
                    self._post_trust_credential_status_sync_batch(tenant)
                else:
                    self._send_error(404, f"无此路径: {path}")
            except ValidationError as exc:
                self._send_error(400, str(exc))
            except ConflictError as exc:
                self._send_error(409, str(exc))
            except NotFoundError as exc:
                self._send_error(404, str(exc))
            except Exception as exc:  # noqa: BLE001
                self._send_error(500, f"服务器内部错误: {exc}")

        def do_PUT(self) -> None:  # noqa: N802
            try:
                path = urlparse(self.path).path.rstrip("/") or "/"
                if not path.startswith("/v1"):
                    self._send_error(404, f"无此路径: {path}")
                    return
                tenant = self._tenant_id()
                if path.startswith("/v1/credentials/") and path.endswith(
                    "/status"
                ):
                    credential_id = unquote(
                        path[len("/v1/credentials/") : -len("/status")]
                    )
                    self._put_credential_status(tenant, credential_id)
                elif path.startswith("/v1/trust/anchors/") and path.endswith(
                    "/status"
                ):
                    rest = path[len("/v1/trust/anchors/") : -len("/status")]
                    did, sep, version_raw = rest.rpartition("/")
                    if not sep or not did:
                        self._send_error(404, f"无此路径: {path}")
                    else:
                        self._put_trust_anchor_status(
                            tenant, unquote(did), unquote(version_raw)
                        )
                elif path.startswith("/v1/trust/anchors/") and path.endswith(
                    "/uses"
                ):
                    rest = path[len("/v1/trust/anchors/") : -len("/uses")]
                    did, sep, version_raw = rest.rpartition("/")
                    if not sep or not did:
                        self._send_error(404, f"无此路径: {path}")
                    else:
                        self._put_trust_anchor_uses(
                            tenant, unquote(did), unquote(version_raw)
                        )
                else:
                    self._send_error(404, f"无此路径: {path}")
            except ValidationError as exc:
                self._send_error(400, str(exc))
            except ConflictError as exc:
                self._send_error(409, str(exc))
            except NotFoundError as exc:
                self._send_error(404, str(exc))
            except Exception as exc:  # noqa: BLE001
                self._send_error(500, f"服务器内部错误: {exc}")

        def do_GET(self) -> None:  # noqa: N802
            try:
                parsed = urlparse(self.path)
                path = parsed.path.rstrip("/") or "/"
                if path in ("/health", "/healthz"):
                    self._send_json(200, {"status": "ok"})
                    return
                if not path.startswith("/v1"):
                    self._send_error(404, f"无此路径: {path}")
                    return
                # 仅 /v1 路由受租户头约束
                tenant = self._tenant_id()
                if path == "/v1/audit":
                    self._get_audit(tenant, parsed.query)
                elif path.startswith("/v1/dids/") and path.endswith(
                    "/document"
                ):
                    did = unquote(
                        path[len("/v1/dids/") : -len("/document")]
                    )
                    self._get_did_document(tenant, did, parsed.query)
                elif path.startswith("/v1/dids/") and "/keys/" in path and (
                    path.endswith("/status")
                    or path.endswith("/keys/revocations")
                    or path.endswith("/keys/history")
                ):
                    middle = path[len("/v1/dids/") :]
                    did_raw, sep, rest = middle.partition("/keys/")
                    did = unquote(did_raw)
                    if rest == "revocations":
                        self._get_key_revocations(
                            tenant, did, parsed.query
                        )
                    elif rest == "history":
                        self._get_key_history(
                            tenant, did, parsed.query
                        )
                    else:
                        key_version = unquote(
                            rest[: -len("/status")]
                        )
                        self._get_key_version_status(
                            tenant, did, key_version
                        )
                elif path.startswith("/v1/dids/") and path.endswith("/status"):
                    did = unquote(
                        path[len("/v1/dids/") : -len("/status")]
                    )
                    self._get_did_status(tenant, did)
                elif path.startswith("/v1/dids/") and path.endswith("/history"):
                    did = unquote(
                        path[len("/v1/dids/") : -len("/history")]
                    )
                    self._get_did_history(tenant, did, parsed.query)
                elif path.startswith("/v1/dids/"):
                    self._get_did(tenant, unquote(path[len("/v1/dids/") :]))
                elif path.startswith("/v1/credentials/") and path.endswith(
                    "/status/history"
                ):
                    credential_id = unquote(
                        path[
                            len("/v1/credentials/") : -len("/status/history")
                        ]
                    )
                    self._get_credential_status_history(
                        tenant, credential_id, parsed.query
                    )
                elif path.startswith("/v1/credentials/") and path.endswith(
                    "/status"
                ):
                    credential_id = unquote(
                        path[len("/v1/credentials/") : -len("/status")]
                    )
                    self._get_credential_status(tenant, credential_id)
                elif path.startswith("/v1/credentials/"):
                    self._get_credential(
                        tenant, unquote(path[len("/v1/credentials/") :])
                    )
                elif path == "/v1/trust/anchors":
                    self._get_trust_anchor_discovery(tenant, parsed.query)
                elif path == "/v1/trust/anchor-changes":
                    self._get_trust_anchor_changes(tenant, parsed.query)
                elif path == "/v1/trust/ac-proof":
                    self._get_trust_ac_proof(tenant, parsed.query)
                elif path == "/v1/trust/anchor-changes/sync-history":
                    self._get_trust_anchor_changes_sync_history(
                        tenant, parsed.query
                    )
                elif path == "/v1/trust/anchor-changes/synced-state":
                    self._get_trust_anchor_changes_synced_state(
                        tenant, parsed.query
                    )
                elif path == "/v1/trust/anchors/snapshot":
                    self._get_trust_anchor_snapshot(tenant, parsed.query)
                elif path == "/v1/trust/dids/deactivations":
                    self._get_trust_did_deactivations(tenant, parsed.query)
                elif path == "/v1/trust/credentials/receipt/consumptions":
                    self._get_trust_credential_receipt_consumptions(
                        tenant, parsed.query
                    )
                elif (
                    path
                    == "/v1/trust/credentials/receipt/consumptions/export"
                ):
                    self._get_trust_credential_receipt_consumptions_export(
                        tenant, parsed.query
                    )
                elif (
                    path
                    == "/v1/trust/credentials/receipt/consumptions/manifest"
                ):
                    self._get_trust_credential_receipt_consumptions_manifest(
                        tenant, parsed.query
                    )
                elif path == "/v1/trust/dids/deactivations/manifest":
                    self._get_trust_did_deactivations_manifest(
                        tenant, parsed.query
                    )
                elif path == "/v1/trust/dids/deactivations/export":
                    self._get_trust_did_deactivations_export(
                        tenant, parsed.query
                    )
                elif path.startswith(
                    "/v1/trust/credentials/imported/"
                ):
                    credential_id = unquote(
                        path[
                            len("/v1/trust/credentials/imported/") :
                        ]
                    )
                    self._get_trust_imported_credential(
                        tenant, credential_id, parsed.query
                    )
                elif path.startswith("/v1/trust/anchors/") and path.endswith(
                    "/uses/history"
                ):
                    rest = path[
                        len("/v1/trust/anchors/") : -len("/uses/history")
                    ]
                    did_raw, sep, version_raw = rest.rpartition("/")
                    if not sep or not did_raw:
                        self._send_error(404, f"无此路径: {path}")
                    else:
                        self._get_trust_anchor_uses_history(
                            tenant,
                            unquote(did_raw),
                            unquote(version_raw),
                            parsed.query,
                        )
                elif path.startswith("/v1/trust/anchors/") and path.endswith(
                    "/history"
                ):
                    did = unquote(
                        path[
                            len("/v1/trust/anchors/") : -len("/history")
                        ]
                    )
                    self._get_trust_anchor_history(
                        tenant, did, parsed.query
                    )
                elif path.startswith("/v1/trust/anchors/") and path.endswith(
                    "/uses"
                ):
                    rest = path[len("/v1/trust/anchors/") : -len("/uses")]
                    did_raw, sep, version_raw = rest.rpartition("/")
                    if not sep or not did_raw:
                        self._send_error(404, f"无此路径: {path}")
                    else:
                        self._get_trust_anchor_uses(
                            tenant, unquote(did_raw), unquote(version_raw)
                        )
                elif path.startswith("/v1/trust/anchors/"):
                    did = unquote(path[len("/v1/trust/anchors/") :])
                    self._get_trust_anchors(tenant, did)
                elif path.startswith("/v1/trust/credential-status/") and path.endswith(
                    "/history"
                ):
                    credential_id = unquote(
                        path[
                            len("/v1/trust/credential-status/") : -len(
                                "/history"
                            )
                        ]
                    )
                    self._get_trust_credential_status_history(
                        tenant, credential_id, parsed.query
                    )
                elif path.startswith("/v1/trust/credential-status/"):
                    credential_id = unquote(
                        path[len("/v1/trust/credential-status/") :]
                    )
                    self._get_trust_credential_status(
                        tenant, credential_id, parsed.query
                    )
                else:
                    self._send_error(404, f"无此路径: {path}")
            except ValidationError as exc:
                self._send_error(400, str(exc))
            except ConflictError as exc:
                self._send_error(409, str(exc))
            except NotFoundError as exc:
                self._send_error(404, str(exc))
            except Exception as exc:  # noqa: BLE001
                self._send_error(500, f"服务器内部错误: {exc}")

        # ------------------------------------------------------------ #
        # 处理函数
        # ------------------------------------------------------------ #
        def _require_fields(
            self, data: Dict[str, Any], fields: Tuple[str, ...]
        ) -> None:
            for field in fields:
                if field not in data:
                    raise ValidationError(f"缺少字段: {field}")
                value = data[field]
                if not isinstance(value, str) or not value:
                    raise ValidationError(
                        f"字段 {field} 必须为非空字符串"
                    )

        @staticmethod
        def _did_payload(record: Any) -> Dict[str, Any]:
            return {
                "did": record.did,
                "public_key": record.public_key,
                "key_mode": record.key_mode,
                "key_handle": record.key_handle,
                "key_version": record.key_version,
            }

        def _post_dids(self, tenant: str) -> None:
            data = self._read_json()
            self._require_fields(data, ("method", "public_key"))
            key_mode = data.get("key_mode", "server")
            record = store.create_did(
                tenant, data["method"], data["public_key"], key_mode=key_mode
            )
            self._send_json(201, self._did_payload(record))

        def _get_did(self, tenant: str, did: str) -> None:
            record = store.get_did(tenant, did)
            payload = self._did_payload(record)
            payload["created_at"] = record.created_at
            self._send_json(200, payload)

        def _post_deactivate_did(self, tenant: str, did: str) -> None:
            # POST /v1/dids/{did}/deactivate：
            # 请求体仅允许空体、{} 或恰含可选 reason；reason 提供时由
            # store 在确认非重复停用后校验（字符串裁剪后非空，否则 400），
            # 重复停用时任何 reason（含非法值）均忽略并返回首次结果。
            # 未知或他租户 DID 404。首次停用 200，响应恰含 did、
            # status:"deactivated"、reason、updated_at。
            if not did:
                raise ValidationError("路径缺少 did")
            data = self._read_optional_json()
            if data:
                extra = sorted(set(data) - {"reason"})
                if extra:
                    raise ValidationError(f"多余字段: {', '.join(extra)}")
                if "reason" not in data:
                    raise ValidationError("请求体非空时必须恰含字段: reason")
            reason = (
                data["reason"] if data and "reason" in data else REASON_UNSET
            )
            record = store.deactivate_did(tenant, did, reason)
            self._send_json(
                200,
                {
                    "did": record.did,
                    "status": record.status,
                    "reason": record.reason,
                    "updated_at": record.updated_at,
                },
            )

        def _get_did_status(self, tenant: str, did: str) -> None:
            # GET /v1/dids/{did}/status：只读 DID 生命周期状态。
            # 活动 DID 返回 status:"active" 且 reason、updated_at 为
            # null；停用后返回首次原因与 UTC 秒精度 Z 时间。未知或他
            # 租户 DID 404。纯只读：不改变状态与审计。
            if not did:
                raise ValidationError("路径缺少 did")
            record = store.get_did_status(tenant, did)
            self._send_json(
                200,
                {
                    "did": record.did,
                    "status": record.status,
                    "reason": record.reason,
                    "updated_at": record.updated_at,
                },
            )

        def _get_did_history(
            self, tenant: str, did: str, query: str
        ) -> None:
            # GET /v1/dids/{did}/history?limit=&after=：只读 DID 注册与
            # 停用历史。响应恰含 did、events、next_after；事件恰含
            # action、status、reason、updated_at、audit_seq、
            # audit_timestamp、cursor，按 cursor 升序。查询参数仅允许
            # limit、after：limit 缺省 50，须为 1..200 的非空 ASCII 十
            # 进制整数；after 缺省 0，须为非空非负 ASCII 十进制整数；
            # 重复/空白/符号/小数/布尔词/Unicode 数字/未知参数均 400。
            # 未知或他租户 DID 404；已有 DID 无历史返回空页，空页
            # next_after 保持 after。纯只读：不写任何状态、不记审计。
            if not did:
                raise ValidationError("路径缺少 did")
            params = parse_qs(query, keep_blank_values=True)
            unknown = sorted(set(params) - {"limit", "after"})
            if unknown:
                raise ValidationError(
                    f"不支持的查询参数: {', '.join(unknown)}"
                )

            limit_values = params.get("limit")
            if limit_values is not None:
                if len(limit_values) != 1:
                    raise ValidationError("查询参数 limit 只能提供一次")
                limit = _parse_nonneg_int(limit_values[0], "limit")
                if not 1 <= limit <= 200:
                    raise ValidationError(
                        "查询参数 limit 须在 1 到 200 之间"
                    )
            else:
                limit = 50

            after_values = params.get("after")
            if after_values is not None:
                if len(after_values) != 1:
                    raise ValidationError("查询参数 after 只能提供一次")
                after = _parse_nonneg_int(after_values[0], "after")
            else:
                after = 0

            events, next_after = store.list_did_history(
                tenant, did, after, limit
            )
            self._send_json(
                200,
                {
                    "did": did,
                    "events": [
                        {
                            "action": event.action,
                            "status": event.status,
                            "reason": event.reason,
                            "updated_at": event.updated_at,
                            "audit_seq": event.audit_seq,
                            "audit_timestamp": event.audit_timestamp,
                            "cursor": event.cursor,
                        }
                        for event in events
                    ],
                    "next_after": next_after,
                },
            )

        def _get_did_document(
            self, tenant: str, did: str, query: str
        ) -> None:
            # GET /v1/dids/{did}/document[?version=N]：只读 DID 文档。
            # version 可选且只能出现一次；提供时须为 ASCII 十进制正整数
            # （缺失参数走全量历史；空值、重复、符号、小数、Unicode 数字
            # 一律 400）。版本不存在或 DID 未知（含他租户）404。
            # 纯只读：不改变状态与审计。
            if not did:
                raise ValidationError("路径缺少 did")
            params = parse_qs(query, keep_blank_values=True)
            version_values = params.get("version")
            version: Optional[int] = None
            if version_values is not None:
                if len(version_values) != 1:
                    raise ValidationError("查询参数 version 只能提供一次")
                version = _parse_positive_int(
                    version_values[0], "version"
                )
            payload = store.get_did_document(tenant, did, version=version)
            self._send_json(200, payload)

        def _get_key_version_status(
            self, tenant: str, did: str, key_version: str
        ) -> None:
            # GET /v1/dids/{did}/keys/{key_version}/status：只读密钥版本
            # 吊销状态。key_version 须为 ASCII 十进制正整数（空值、0、
            # 符号/小数/空白/布尔词/字母/Unicode 数字一律 400）；DID 或
            # 版本不存在（含他租户）404。active 返回 reason/updated_at
            # 均为 null；revoked 返回首次原因与 UTC 秒精度 Z 时间。
            # 纯只读：不改变状态与审计。
            if (
                not key_version
                or any(ch < "0" or ch > "9" for ch in key_version)
                or int(key_version) < 1
            ):
                raise ValidationError(
                    "路径参数 key_version 必须为 ASCII 十进制正整数"
                )
            record = store.get_key_version_status(
                tenant, did, int(key_version)
            )
            self._send_json(
                200,
                {
                    "did": record.did,
                    "key_version": record.key_version,
                    "status": record.status,
                    "reason": record.reason,
                    "updated_at": record.updated_at,
                },
            )

        def _get_key_revocations(
            self, tenant: str, did: str, query: str
        ) -> None:
            # GET /v1/dids/{did}/keys/revocations?limit=&after=：只读
            # 密钥吊销历史。limit 缺省 50，须为 1..200 的 ASCII 十进制
            # 整数；after 缺省 0，须为非负 ASCII 十进制整数；重复/空白/
            # 布尔词/小数/符号/Unicode 数字一律 400。未知或他租户 DID
            # 404；已有 DID 无历史返回空页，空页 next_after 保持 after。
            # 纯只读：不写任何状态、不记审计。
            if not did:
                raise ValidationError("路径缺少 did")
            params = parse_qs(query, keep_blank_values=True)

            limit_values = params.get("limit")
            if limit_values is not None:
                if len(limit_values) != 1:
                    raise ValidationError("查询参数 limit 只能提供一次")
                limit = _parse_nonneg_int(limit_values[0], "limit")
                if not 1 <= limit <= 200:
                    raise ValidationError(
                        "查询参数 limit 须在 1 到 200 之间"
                    )
            else:
                limit = 50

            after_values = params.get("after")
            if after_values is not None:
                if len(after_values) != 1:
                    raise ValidationError("查询参数 after 只能提供一次")
                after = _parse_nonneg_int(after_values[0], "after")
            else:
                after = 0

            events, next_after = store.list_key_revocations(
                tenant, did, after, limit
            )
            self._send_json(
                200,
                {
                    "did": did,
                    "events": [
                        {
                            "key_version": event.key_version,
                            "reason": event.reason,
                            "updated_at": event.updated_at,
                            "cursor": event.cursor,
                        }
                        for event in events
                    ],
                    "next_after": next_after,
                },
            )

        def _get_key_history(
            self, tenant: str, did: str, query: str
        ) -> None:
            # GET /v1/dids/{did}/keys/history?limit=&after=：只读密钥
            # 生命周期历史。响应恰含 did、events、next_after；事件恰含
            # key_version、key_handle、public_key、action、status、
            # updated_at、audit_seq、audit_timestamp、cursor，按 cursor
            # 升序；仅含公钥，绝不暴露私钥。分页参数规则沿用
            # keys/revocations：limit 缺省 50、须 1..200 的 ASCII 十进制
            # 整数；after 缺省 0、须非负；重复/空白/布尔词/小数/符号/
            # Unicode 数字一律 400。未知或他租户 DID 404；已有 DID 无
            # 历史返回空页，空页 next_after 保持 after。纯只读：不写
            # 任何状态、不记审计。
            if not did:
                raise ValidationError("路径缺少 did")
            params = parse_qs(query, keep_blank_values=True)

            limit_values = params.get("limit")
            if limit_values is not None:
                if len(limit_values) != 1:
                    raise ValidationError("查询参数 limit 只能提供一次")
                limit = _parse_nonneg_int(limit_values[0], "limit")
                if not 1 <= limit <= 200:
                    raise ValidationError(
                        "查询参数 limit 须在 1 到 200 之间"
                    )
            else:
                limit = 50

            after_values = params.get("after")
            if after_values is not None:
                if len(after_values) != 1:
                    raise ValidationError("查询参数 after 只能提供一次")
                after = _parse_nonneg_int(after_values[0], "after")
            else:
                after = 0

            events, next_after = store.list_key_lifecycle(
                tenant, did, after, limit
            )
            self._send_json(
                200,
                {
                    "did": did,
                    "events": [
                        {
                            "key_version": event.key_version,
                            "key_handle": event.key_handle,
                            "public_key": event.public_key,
                            "action": event.action,
                            "status": event.status,
                            "updated_at": event.updated_at,
                            "audit_seq": event.audit_seq,
                            "audit_timestamp": event.audit_timestamp,
                            "cursor": event.cursor,
                        }
                        for event in events
                    ],
                    "next_after": next_after,
                },
            )

        def _post_rotate_key(self, tenant: str, did: str) -> None:
            data = self._read_json()
            self._require_fields(data, ("key_handle",))
            record = store.rotate_key(tenant, did, data["key_handle"])
            self._send_json(200, self._did_payload(record))

        def _post_revoke_key(
            self, tenant: str, did: str, key_version: str
        ) -> None:
            # POST /v1/dids/{did}/keys/{key_version}/revoke：
            # key_version 须为 ASCII 十进制正整数，否则 400；DID 或版本
            # 不存在（含他租户）404；当前版本 409。请求体空体或 {} 表示
            # 省略 reason；非空时必须恰含 reason，其值由 store 在确认非
            # 重复吊销后校验（字符串裁剪后非空，否则 400），重复吊销时
            # 任何 reason（含非法值）均忽略并返回首次结果。
            if (
                not key_version
                or any(ch < "0" or ch > "9" for ch in key_version)
                or int(key_version) < 1
            ):
                raise ValidationError("路径参数 key_version 必须为 ASCII 十进制正整数")
            data = self._read_optional_json()
            if data:
                extra = sorted(set(data) - {"reason"})
                if extra:
                    raise ValidationError(f"多余字段: {', '.join(extra)}")
                if "reason" not in data:
                    raise ValidationError("请求体非空时必须恰含字段: reason")
            reason = data["reason"] if data and "reason" in data else REASON_UNSET
            record = store.revoke_key_version(
                tenant, did, int(key_version), reason
            )
            self._send_json(
                200,
                {
                    "did": record.did,
                    "key_version": record.key_version,
                    "status": record.status,
                    "reason": record.reason,
                    "updated_at": record.updated_at,
                },
            )

        def _post_credentials(self, tenant: str) -> None:
            data = self._read_json()
            self._require_fields(data, ("issuer_did", "subject_did"))
            if "claims" not in data:
                raise ValidationError("缺少字段: claims")
            if not isinstance(data["claims"], dict):
                raise ValidationError("字段 claims 必须为 JSON 对象")
            # expires_at 可选：提供时必须为 UTC 秒精度 Z 格式且严格晚于
            # 当前时刻（否则 400）；未提供传哨兵，正文不注入该字段，
            # 凭证保持无期限。
            expires_at = (
                data["expires_at"] if "expires_at" in data else EXPIRES_AT_UNSET
            )
            record = store.create_credential(
                tenant,
                data["issuer_did"],
                data["subject_did"],
                data["claims"],
                expires_at=expires_at,
            )
            self._send_json(
                201,
                {
                    "credential_id": record.credential_id,
                    "signature": record.signature,
                    "issuer_key_version": record.body["issuer_key_version"],
                },
            )

        def _get_credential(self, tenant: str, credential_id: str) -> None:
            record = store.get_credential(tenant, credential_id)
            self._send_json(
                200,
                {
                    "credential_id": record.credential_id,
                    "body": record.body,
                    "signature": record.signature,
                },
            )

        @staticmethod
        def _status_payload(record: Any) -> Dict[str, Any]:
            return {
                "credential_id": record.credential_id,
                "status": record.status,
                "updated_at": record.updated_at,
            }

        def _put_credential_status(
            self, tenant: str, credential_id: str
        ) -> None:
            # 请求体必须恰为 {"status": "active"} 或
            # {"status": "suspended", "reason": "原因"}：缺字段、取值
            # 非法、多余字段一律 400；reason 须为字符串且首尾裁剪后为
            # 1..256 个 Unicode 码点，否则 400。
            data = self._read_json()
            if "status" not in data:
                raise ValidationError("缺少字段: status")
            status = data["status"]
            if status == "active":
                extra = sorted(set(data) - {"status"})
                if extra:
                    raise ValidationError(
                        f"多余字段: {', '.join(extra)}"
                    )
                record, created = store.set_credential_status(
                    tenant, credential_id, "active"
                )
            elif status == "suspended":
                extra = sorted(set(data) - {"status", "reason"})
                if extra:
                    raise ValidationError(
                        f"多余字段: {', '.join(extra)}"
                    )
                if "reason" not in data:
                    raise ValidationError("缺少字段: reason")
                reason = data["reason"]
                if not isinstance(reason, str):
                    raise ValidationError("字段 reason 必须为字符串")
                reason = reason.strip()
                if not reason:
                    raise ValidationError("字段 reason 裁剪后不能为空")
                if len(reason) > 256:
                    raise ValidationError(
                        "字段 reason 裁剪后须为 1 到 256 个 Unicode 码点"
                    )
                record, created = store.set_credential_status(
                    tenant, credential_id, "suspended", reason=reason
                )
            else:
                raise ValidationError(
                    "字段 status 非法: "
                    f"{status!r}（仅支持 active、suspended）"
                )
            # 无状态首次登记 active 为 201；暂停/恢复转换与同状态幂等
            # 均为 200（幂等保持首次 updated_at）。
            self._send_json(
                201 if created else 200, self._status_payload(record)
            )

        def _get_credential_status(
            self, tenant: str, credential_id: str
        ) -> None:
            # 历史无状态按 active 返回，updated_at 为 null
            record = store.get_credential_status(tenant, credential_id)
            self._send_json(200, self._status_payload(record))

        def _get_credential_status_history(
            self, tenant: str, credential_id: str, query: str
        ) -> None:
            # GET /v1/credentials/{credential_id}/status/history
            # ?limit=&after=：只读本地凭证状态历史。响应恰含
            # credential_id、events、next_after；事件按 updated_at
            # 升序、同值按 cursor 升序，每项恰含 status、reason、
            # updated_at、revoked_at、audit_seq、audit_timestamp、
            # cursor。未知或他租户凭证 404；有凭证无状态返回空页。
            # limit 缺省 50，须为 1..200 的 ASCII 十进制整数；after
            # 缺省 0，须为非负 ASCII 十进制整数；重复/空白/布尔词/
            # 小数/符号/Unicode 数字一律 400。空页 next_after 保持
            # after。纯只读：不写任何状态、不记审计。
            if not credential_id:
                raise ValidationError("路径缺少 credential_id")
            params = parse_qs(query, keep_blank_values=True)

            limit_values = params.get("limit")
            if limit_values is not None:
                if len(limit_values) != 1:
                    raise ValidationError("查询参数 limit 只能提供一次")
                limit = _parse_nonneg_int(limit_values[0], "limit")
                if not 1 <= limit <= 200:
                    raise ValidationError(
                        "查询参数 limit 须在 1 到 200 之间"
                    )
            else:
                limit = 50

            after_values = params.get("after")
            if after_values is not None:
                if len(after_values) != 1:
                    raise ValidationError("查询参数 after 只能提供一次")
                after = _parse_nonneg_int(after_values[0], "after")
            else:
                after = 0

            events, next_after = store.list_credential_status_history(
                tenant, credential_id, after, limit
            )
            self._send_json(
                200,
                {
                    "credential_id": credential_id,
                    "events": [
                        {
                            "status": event.status,
                            "reason": event.reason,
                            "updated_at": event.updated_at,
                            "revoked_at": event.revoked_at,
                            "audit_seq": event.audit_seq,
                            "audit_timestamp": event.audit_timestamp,
                            "cursor": event.cursor,
                        }
                        for event in events
                    ],
                    "next_after": next_after,
                },
            )

        def _post_revoke_credential(
            self, tenant: str, credential_id: str
        ) -> None:
            # reason 可省略（请求体亦可整个缺省）；已吊销时任何 reason
            # 均忽略并返回首次结果，非法 reason 仅首次请求 400。
            data = self._read_optional_json()
            # 省略 reason 时传哨兵走默认原因；提供时透传原值，非法
            # reason 的 400 判定由 store 在确认非重复吊销后做出
            # （已吊销时任何 reason 均忽略，含非法值）。
            reason = data["reason"] if "reason" in data else REASON_UNSET
            record = store.revoke_credential(tenant, credential_id, reason)
            self._send_json(
                200,
                {
                    "credential_id": record.credential_id,
                    "status": record.status,
                    "reason": record.reason,
                    "revoked_at": record.revoked_at,
                    "updated_at": record.updated_at,
                },
            )

        def _post_verify_credential(
            self, tenant: str, credential_id: str
        ) -> None:
            # verify 端点的公开错误协议：任何“验签失败”都返回 200 +
            # {"valid": false, "reason": "<非空中文原因>"}，绝不返回
            # 404/500，也不泄露私钥或堆栈。reason 按类别措辞：
            # 请求层（请求*）、资源（凭证不存在）、锚定、签名、密钥。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except (ValueError, TypeError):
                self._send_invalid("请求体缺失或长度声明非法")
                return
            except Exception:  # noqa: BLE001
                self._send_invalid("请求体读取失败")
                return
            if not raw:
                self._send_invalid("请求体缺失")
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._send_invalid("请求体不是合法 UTF-8 文本")
                return
            except json.JSONDecodeError:
                self._send_invalid("请求体不是合法 JSON")
                return
            if not isinstance(data, dict):
                self._send_invalid("请求体必须为 JSON 对象")
                return
            if "body" not in data:
                self._send_invalid("请求缺少字段: body")
                return
            if not isinstance(data["body"], dict):
                self._send_invalid("请求字段 body 必须为 JSON 对象")
                return
            if "signature" not in data:
                self._send_invalid("请求缺少字段: signature")
                return
            if not isinstance(data["signature"], str) or not data["signature"]:
                self._send_invalid("请求字段 signature 必须为非空字符串")
                return

            try:
                valid, reason = store.verify_credential(
                    tenant, credential_id, data["body"], data["signature"]
                )
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_invalid("验签过程发生内部错误")
                return
            payload: Dict[str, Any] = {"valid": valid}
            if not valid:
                payload["reason"] = reason or "验签失败"
            self._send_json(200, payload)

        @staticmethod
        def _presentation_payload(
            record: PresentationRecord,
        ) -> Dict[str, Any]:
            """按对外契约的固定键序组装演示对象。

            未绑定恰为九字段；持有者绑定在末尾追加 holder_did、
            holder_key_version、holder_proof。
            """
            payload: Dict[str, Any] = {
                "presentation_id": record.presentation_id,
                "credential_id": record.credential_id,
                "issuer_did": record.issuer_did,
                "issuer_key_version": record.issuer_key_version,
                "disclose": record.disclose,
                "claims": record.projection,
                "challenge": record.challenge,
                "expires_at": record.expires_at,
                "proof": record.proof,
            }
            # 仅持有者绑定演示返回 holder_did、holder_key_version、
            # holder_proof；未绑定响应字段集合与旧流程完全一致。
            if record.holder_did is not None:
                payload["holder_did"] = record.holder_did
                payload["holder_key_version"] = (
                    record.holder_key_version
                )
                payload["holder_proof"] = record.holder_proof
            return payload

        @staticmethod
        def _validate_present_item(
            item: Any, index: int
        ) -> Dict[str, Any]:
            """校验单个演示生成项，返回透传给 store 的关键字参数。

            规则与单项 present 完全一致：项须为对象，恰含 disclose 及
            可选 challenge、expires_in、holder_binding；challenge 为非空
            字符串且按 Unicode 码点不超过 256；expires_in 为非布尔整数
            且在 1..86400；holder_binding 为布尔。index 为从 0 起的项
            序号，错误信息带从 1 起的中文项号。
            """
            where = f"第 {index + 1} 项"
            if not isinstance(item, dict):
                raise ValidationError(f"{where}必须为 JSON 对象")
            if "disclose" not in item:
                raise ValidationError(f"{where}缺少字段: disclose")
            extra = sorted(
                set(item)
                - {"disclose", "challenge", "expires_in", "holder_binding"}
            )
            if extra:
                raise ValidationError(
                    f"{where}含多余字段: {', '.join(extra)}"
                )
            kwargs: Dict[str, Any] = {"disclose": item["disclose"]}
            if "challenge" in item:
                challenge = item["challenge"]
                if not isinstance(challenge, str) or not challenge:
                    raise ValidationError(
                        f"{where}字段 challenge 必须为非空字符串"
                    )
                if len(challenge) > 256:
                    raise ValidationError(
                        f"{where}字段 challenge 按 Unicode 码点不能超过 256"
                    )
                kwargs["challenge"] = challenge
            if "expires_in" in item:
                expires_in = item["expires_in"]
                if not isinstance(expires_in, int) or isinstance(
                    expires_in, bool
                ):
                    raise ValidationError(
                        f"{where}字段 expires_in 必须为整数"
                    )
                if not 1 <= expires_in <= 86400:
                    raise ValidationError(
                        f"{where}字段 expires_in 须在 1 到 86400 之间"
                    )
                kwargs["expires_in"] = expires_in
            if "holder_binding" in item:
                holder_binding = item["holder_binding"]
                if not isinstance(holder_binding, bool):
                    raise ValidationError(
                        f"{where}字段 holder_binding 必须为布尔值"
                    )
                kwargs["holder_binding"] = holder_binding
            return kwargs

        def _post_present(self, tenant: str, credential_id: str) -> None:
            # 请求体必须恰为 {"disclose": [...]} 加可选 challenge、
            # expires_in：缺失 disclose、类型非法、重复路径或祖先重叠、
            # 多余字段一律 400；未知凭证 404；空列表表示零披露。
            # challenge 须为非空字符串且按 Unicode 码点不超过 256，
            # 缺省生成 32 位小写 hex；expires_in 须为非布尔整数且
            # 在 1..86400 之间，缺省 300。成功 201 返回演示记录。
            data = self._read_json()
            if "disclose" not in data:
                raise ValidationError("缺少字段: disclose")
            extra = sorted(
                set(data)
                - {"disclose", "challenge", "expires_in", "holder_binding"}
            )
            if extra:
                raise ValidationError(f"多余字段: {', '.join(extra)}")
            challenge = None
            if "challenge" in data:
                challenge = data["challenge"]
                if not isinstance(challenge, str) or not challenge:
                    raise ValidationError("字段 challenge 必须为非空字符串")
                if len(challenge) > 256:
                    raise ValidationError(
                        "字段 challenge 按 Unicode 码点不能超过 256"
                    )
            expires_in = None
            if "expires_in" in data:
                expires_in = data["expires_in"]
                if not isinstance(expires_in, int) or isinstance(
                    expires_in, bool
                ):
                    raise ValidationError("字段 expires_in 必须为整数")
                if not 1 <= expires_in <= 86400:
                    raise ValidationError(
                        "字段 expires_in 须在 1 到 86400 之间"
                    )
            # holder_binding 可选：必须为布尔，缺省 false；为 true 时
            # subject_did 须是本租户已注册 DID（否则由 store 判 400）。
            holder_binding = False
            if "holder_binding" in data:
                holder_binding = data["holder_binding"]
                if not isinstance(holder_binding, bool):
                    raise ValidationError("字段 holder_binding 必须为布尔值")
            record = store.create_presentation(
                tenant,
                credential_id,
                data["disclose"],
                challenge=challenge,
                expires_in=expires_in,
                holder_binding=holder_binding,
            )
            self._send_json(201, self._presentation_payload(record))

        def _post_present_batch(
            self, tenant: str, credential_id: str
        ) -> None:
            # 批量选择性披露演示：请求体须恰为
            # {"presentations": [项...]}，数组非空且不超过 50 项。
            # 外层缺失/非数组/空/超限、项非对象、缺 disclose 或多余
            # 字段、challenge/expires_in/holder_binding 类型或范围非法
            # 一律 400 且不写入任何记录；路径凭证未知（含他租户）404；
            # 任一项在 store 内失败（disclose 越界/重复/祖先重叠、绑定
            # subject 非本租户 DID、密钥吊销等）整体回滚，已构建项与
            # 审计均不落盘。成功 201 返回 {"presentations": [...]}，
            # 与输入等长、同序，项键序与单项 present 完全一致。
            data = self._read_json()
            if "presentations" not in data:
                raise ValidationError("缺少字段: presentations")
            extra = sorted(set(data) - {"presentations"})
            if extra:
                raise ValidationError(f"多余字段: {', '.join(extra)}")
            items = data["presentations"]
            if not isinstance(items, list):
                raise ValidationError("字段 presentations 必须为数组")
            if not items:
                raise ValidationError("presentations 数组不能为空")
            if len(items) > 50:
                raise ValidationError(
                    "presentations 数组不能超过 50 项"
                    f"（当前 {len(items)} 项）"
                )
            kwargs_list = [
                self._validate_present_item(item, index)
                for index, item in enumerate(items)
            ]
            records = store.create_presentations_batch(
                tenant, credential_id, kwargs_list
            )
            self._send_json(
                201,
                {
                    "presentations": [
                        self._presentation_payload(record)
                        for record in records
                    ]
                },
            )

        def _post_verify_presentation(
            self, tenant: str, presentation_id: str
        ) -> None:
            # 与凭证 verify 相同的公开错误协议：任何“验签失败”都返回
            # 200 + {"valid": false, "reason": "<非空中文原因>"}，绝不
            # 返回 404/500。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except (ValueError, TypeError):
                self._send_invalid("请求体缺失或长度声明非法")
                return
            except Exception:  # noqa: BLE001
                self._send_invalid("请求体读取失败")
                return
            if not raw:
                self._send_invalid("请求体缺失")
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._send_invalid("请求体不是合法 UTF-8 文本")
                return
            except json.JSONDecodeError:
                self._send_invalid("请求体不是合法 JSON")
                return
            if not isinstance(data, dict):
                self._send_invalid("请求体必须为 JSON 对象")
                return
            if "presentation" not in data:
                self._send_invalid("请求缺少字段: presentation")
                return
            extra = sorted(set(data) - {"presentation", "challenge"})
            if extra:
                self._send_invalid(f"请求含多余字段: {', '.join(extra)}")
                return
            challenge = CHALLENGE_UNSET
            if "challenge" in data:
                challenge = data["challenge"]
                if not isinstance(challenge, str) or not challenge:
                    self._send_invalid(
                        "请求字段 challenge 必须为非空字符串"
                    )
                    return

            try:
                valid, reason = store.verify_presentation(
                    tenant, presentation_id, data["presentation"], challenge
                )
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_invalid("验签过程发生内部错误")
                return
            payload: Dict[str, Any] = {"valid": valid}
            if not valid:
                payload["reason"] = reason or "验签失败"
            self._send_json(200, payload)

        # ------------------------------------------------------------ #
        # 谓词证明
        # ------------------------------------------------------------ #
        def _post_prove(self, tenant: str, credential_id: str) -> None:
            # 请求体必须恰为 {"predicates": [...]} 加可选 challenge、
            # expires_in：缺失/空 predicates、元素字段或 op 非法、路径
            # 重复或祖先重叠、多余字段一律 400；未知凭证 404。
            # challenge 须为非空字符串且按 Unicode 码点不超过 256，
            # 缺省生成 32 位小写 hex；expires_in 须为非布尔整数且
            # 在 1..86400 之间，缺省 300。成功 201 返回证明记录。
            data = self._read_json()
            if "predicates" not in data:
                raise ValidationError("缺少字段: predicates")
            extra = sorted(set(data) - {"predicates", "challenge", "expires_in"})
            if extra:
                raise ValidationError(f"多余字段: {', '.join(extra)}")
            challenge = None
            if "challenge" in data:
                challenge = data["challenge"]
                if not isinstance(challenge, str) or not challenge:
                    raise ValidationError("字段 challenge 必须为非空字符串")
                if len(challenge) > 256:
                    raise ValidationError(
                        "字段 challenge 按 Unicode 码点不能超过 256"
                    )
            expires_in = None
            if "expires_in" in data:
                expires_in = data["expires_in"]
                if not isinstance(expires_in, int) or isinstance(
                    expires_in, bool
                ):
                    raise ValidationError("字段 expires_in 必须为整数")
                if not 1 <= expires_in <= 86400:
                    raise ValidationError(
                        "字段 expires_in 须在 1 到 86400 之间"
                    )
            record = store.create_proof(
                tenant,
                credential_id,
                data["predicates"],
                challenge=challenge,
                expires_in=expires_in,
            )
            self._send_json(
                201,
                {
                    "proof_id": record.proof_id,
                    "credential_id": record.credential_id,
                    "issuer_did": record.issuer_did,
                    "issuer_key_version": record.issuer_key_version,
                    "predicates": record.predicates,
                    "results": record.results,
                    "challenge": record.challenge,
                    "expires_at": record.expires_at,
                    "proof": record.proof,
                },
            )

        def _post_verify_proof(self, tenant: str, proof_id: str) -> None:
            # 与凭证/演示 verify 相同的公开错误协议：任何“验签失败”都
            # 返回 200 + {"valid": false, "reason": "<非空中文原因>"}，
            # 绝不返回 404/500。失败不消费；并发仅一次成功并持久化。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except (ValueError, TypeError):
                self._send_invalid("请求体缺失或长度声明非法")
                return
            except Exception:  # noqa: BLE001
                self._send_invalid("请求体读取失败")
                return
            if not raw:
                self._send_invalid("请求体缺失")
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._send_invalid("请求体不是合法 UTF-8 文本")
                return
            except json.JSONDecodeError:
                self._send_invalid("请求体不是合法 JSON")
                return
            if not isinstance(data, dict):
                self._send_invalid("请求体必须为 JSON 对象")
                return
            if "proof" not in data:
                self._send_invalid("请求缺少字段: proof")
                return
            extra = sorted(set(data) - {"proof", "challenge"})
            if extra:
                self._send_invalid(f"请求含多余字段: {', '.join(extra)}")
                return
            challenge = CHALLENGE_UNSET
            if "challenge" in data:
                challenge = data["challenge"]
                if not isinstance(challenge, str) or not challenge:
                    self._send_invalid(
                        "请求字段 challenge 必须为非空字符串"
                    )
                    return

            try:
                valid, reason = store.verify_proof(
                    tenant, proof_id, data["proof"], challenge
                )
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_invalid("验签过程发生内部错误")
                return
            payload: Dict[str, Any] = {"valid": valid}
            if not valid:
                payload["reason"] = reason or "验签失败"
            self._send_json(200, payload)

        # ------------------------------------------------------------ #
        # 信任锚点
        # ------------------------------------------------------------ #
        @staticmethod
        def _trust_anchor_payload(record: Any) -> Dict[str, Any]:
            return {
                "did": record.did,
                "public_key": record.public_key,
                "key_version": record.key_version,
                "status": record.status,
                "updated_at": record.updated_at,
            }

        def _post_trust_anchors(self, tenant: str) -> None:
            # 字段依次为：did 非空字符串、public_key 为 P-256 PEM、
            # key_version 为非布尔正整数；uses 可省略（全用途），提供时
            # 须为非空无重复字符串数组、取值限且按规范序 generic、vc、
            # vp、proof、did、status、deactivation；多余字段一律 400。
            data = self._read_json()
            self._require_fields(data, ("did", "public_key"))
            if "key_version" not in data:
                raise ValidationError("缺少字段: key_version")
            extra = sorted(
                set(data) - {"did", "public_key", "key_version", "uses"}
            )
            if extra:
                raise ValidationError(f"多余字段: {', '.join(extra)}")
            record, created = store.register_trust_anchor(
                tenant,
                data["did"],
                data["public_key"],
                data["key_version"],
                data["uses"] if "uses" in data else USES_UNSET,
            )
            # 新建 201；同 DID/版本同 PEM 且 uses 相同的幂等重试 200；
            # PEM 或 uses 不同由 store 抛 ConflictError -> 409。
            self._send_json(
                201 if created else 200,
                self._trust_anchor_payload(record),
            )

        def _get_trust_anchors(self, tenant: str, did: str) -> None:
            # 返回该 DID 的全部锚点版本；未知 DID（含他租户）404。
            records = store.list_trust_anchors(tenant, did)
            self._send_json(
                200, [self._trust_anchor_payload(r) for r in records]
            )

        def _get_trust_anchor_uses(
            self, tenant: str, did: str, key_version: str
        ) -> None:
            # GET /v1/trust/anchors/{did}/{key_version}/uses：只读返回
            # 锚点版本的用途白名单。路径 key_version 须为 ASCII 十进制
            # 正整数，否则 400；未知或他租户锚点 404。200 按键序恰返
            # did、key_version、uses；uses 按规范序，省略注册或旧记录
            # 为全用途。纯只读：不写任何状态、不记审计。
            if (
                not key_version
                or any(ch < "0" or ch > "9" for ch in key_version)
                or int(key_version) < 1
            ):
                raise ValidationError("路径参数 key_version 必须为正整数")
            uses = store.get_trust_anchor_uses(tenant, did, int(key_version))
            self._send_json(
                200,
                {
                    "did": did,
                    "key_version": int(key_version),
                    "uses": uses,
                },
            )

        def _get_trust_anchor_uses_history(
            self, tenant: str, did: str, key_version: str, query: str
        ) -> None:
            # GET /v1/trust/anchors/{did}/{key_version}/uses/history?
            # limit=&after=：只读锚点版本用途历史。路径 key_version 须为
            # ASCII 十进制正整数，否则 400；查询参数仅允许 limit、after：
            # limit 缺省 50、须为 1..200 的非空 ASCII 十进制整数；after
            # 缺省 0、须为非空非负 ASCII 十进制整数；重复/未知参数一律
            # 400。未知或他租户锚点 404。200 按序恰返 did、key_version、
            # events、next_after；事件按 cursor 升序，键序恰为 cursor、
            # action、from_uses、uses、updated_at；空页 next_after 保持
            # after。纯只读：不写任何状态、不记审计。
            if (
                not key_version
                or any(ch < "0" or ch > "9" for ch in key_version)
                or int(key_version) < 1
            ):
                raise ValidationError("路径参数 key_version 必须为正整数")
            if not did:
                raise ValidationError("路径缺少 did")
            params = parse_qs(query, keep_blank_values=True)
            unknown = sorted(set(params) - {"limit", "after"})
            if unknown:
                raise ValidationError(
                    f"不支持的查询参数: {', '.join(unknown)}"
                )

            limit_values = params.get("limit")
            if limit_values is not None:
                if len(limit_values) != 1:
                    raise ValidationError("查询参数 limit 只能提供一次")
                limit = _parse_nonneg_int(limit_values[0], "limit")
                if not 1 <= limit <= 200:
                    raise ValidationError(
                        "查询参数 limit 须在 1 到 200 之间"
                    )
            else:
                limit = 50

            after_values = params.get("after")
            if after_values is not None:
                if len(after_values) != 1:
                    raise ValidationError("查询参数 after 只能提供一次")
                after = _parse_nonneg_int(after_values[0], "after")
            else:
                after = 0

            events, next_after = store.list_trust_anchor_uses_history(
                tenant, did, int(key_version), after, limit
            )
            self._send_json(
                200,
                {
                    "did": did,
                    "key_version": int(key_version),
                    "events": [
                        {
                            "cursor": event.cursor,
                            "action": event.action,
                            "from_uses": event.from_uses,
                            "uses": event.uses,
                            "updated_at": event.updated_at,
                        }
                        for event in events
                    ],
                    "next_after": next_after,
                },
            )

        def _get_trust_anchor_history(
            self, tenant: str, did: str, query: str
        ) -> None:
            # GET /v1/trust/anchors/{did}/history?limit=&after=：只读
            # 信任锚点生命周期历史。limit 缺省 50，须为 1..200 的 ASCII
            # 十进制整数；after 缺省 0，须为非负 ASCII 十进制整数；
            # 重复/空白/布尔词/小数/符号/Unicode 数字一律 400。未知或
            # 他租户 DID 404；已有 DID 无历史返回空页，空页 next_after
            # 保持 after。纯只读：不写任何状态、不记审计。
            if not did:
                raise ValidationError("路径缺少 did")
            params = parse_qs(query, keep_blank_values=True)

            limit_values = params.get("limit")
            if limit_values is not None:
                if len(limit_values) != 1:
                    raise ValidationError("查询参数 limit 只能提供一次")
                limit = _parse_nonneg_int(limit_values[0], "limit")
                if not 1 <= limit <= 200:
                    raise ValidationError(
                        "查询参数 limit 须在 1 到 200 之间"
                    )
            else:
                limit = 50

            after_values = params.get("after")
            if after_values is not None:
                if len(after_values) != 1:
                    raise ValidationError("查询参数 after 只能提供一次")
                after = _parse_nonneg_int(after_values[0], "after")
            else:
                after = 0

            events, next_after = store.list_trust_anchor_history(
                tenant, did, after, limit
            )
            self._send_json(
                200,
                {
                    "did": did,
                    "events": [
                        {
                            "key_version": event.key_version,
                            "action": event.action,
                            "status": event.status,
                            "updated_at": event.updated_at,
                            "cursor": event.cursor,
                        }
                        for event in events
                    ],
                    "next_after": next_after,
                },
            )

        def _get_trust_anchor_discovery(self, tenant: str, query: str) -> None:
            # GET /v1/trust/anchors?limit=&after=&status=：跨 DID 只读
            # 发现。查询参数仅允许 limit、after、status：limit 缺省 50、
            # 须为 1..200 的 ASCII 十进制整数；after 缺省 0、须为非负
            # ASCII 十进制整数；status 可省略，提供时只能为 active 或
            # revoked。重复参数、空值、空白、符号、小数、布尔词、Unicode
            # 数字、越界及未知参数一律 400。响应恰含 anchors、next_after；
            # 每项恰含 did、public_key、key_version、status、updated_at、
            # cursor。先按 status 过滤，再按 cursor>after 升序取至多
            # limit；空结果 next_after 等于 after，无锚点也返回 200 空
            # 数组。纯只读：不写任何状态、不记审计。
            params = parse_qs(query, keep_blank_values=True)
            unknown = sorted(set(params) - {"limit", "after", "status"})
            if unknown:
                raise ValidationError(
                    f"不支持的查询参数: {', '.join(unknown)}"
                )

            limit_values = params.get("limit")
            if limit_values is not None:
                if len(limit_values) != 1:
                    raise ValidationError("查询参数 limit 只能提供一次")
                limit = _parse_nonneg_int(limit_values[0], "limit")
                if not 1 <= limit <= 200:
                    raise ValidationError(
                        "查询参数 limit 须在 1 到 200 之间"
                    )
            else:
                limit = 50

            after_values = params.get("after")
            if after_values is not None:
                if len(after_values) != 1:
                    raise ValidationError("查询参数 after 只能提供一次")
                after = _parse_nonneg_int(after_values[0], "after")
            else:
                after = 0

            status_values = params.get("status")
            status: Optional[str] = None
            if status_values is not None:
                if len(status_values) != 1:
                    raise ValidationError("查询参数 status 只能提供一次")
                if status_values[0] not in ("active", "revoked"):
                    raise ValidationError(
                        "查询参数 status 仅支持 active 或 revoked"
                    )
                status = status_values[0]

            anchors, next_after = store.list_trust_anchor_entries(
                tenant, after, limit, status
            )
            self._send_json(
                200,
                {
                    "anchors": [
                        {
                            "did": record.did,
                            "public_key": record.public_key,
                            "key_version": record.key_version,
                            "status": record.status,
                            "updated_at": record.updated_at,
                            "cursor": record.cursor,
                        }
                        for record in anchors
                    ],
                    "next_after": next_after,
                },
            )

        def _get_trust_anchor_changes(self, tenant: str, query: str) -> None:
            # GET /v1/trust/anchor-changes?after=&signer_did=：只读返回本
            # 租户可签名信任锚点变更流。查询参数仅允许唯一 after 与唯一
            # 非空 signer_did；after 缺省 0、须为非负 ASCII 十进制整数；
            # 缺失/空值/重复/空白/符号/小数/布尔词/Unicode 数字/未知参数
            # 一律 400 且仅 {"error": 非空中文}。签名 DID 未知（含他租户）
            # 404、已停用 409。200 键序 events、next_after、signer_did、
            # signer_key_version、signature；events 按 cursor 升序取
            # cursor>after 的至多 200 项，每项键序 cursor、action、did、
            # key_version、public_key、status、uses；空页 next_after=after，
            # 否则取页末 cursor。signature 由签名 DID 当前私钥对前四键
            # 递归键升序紧凑 UTF-8 JSON 做 ES256 裸 R||S 无填充 base64url
            # 签名。纯只读：不写状态、不记审计。
            params = parse_qs(query, keep_blank_values=True)
            unknown = sorted(set(params) - {"after", "signer_did"})
            if unknown:
                raise ValidationError(
                    f"不支持的查询参数: {', '.join(unknown)}"
                )

            after_values = params.get("after")
            if after_values is not None:
                if len(after_values) != 1:
                    raise ValidationError("查询参数 after 只能提供一次")
                after = _parse_nonneg_int(after_values[0], "after")
            else:
                after = 0

            signer_values = params.get("signer_did")
            if signer_values is None:
                raise ValidationError("查询参数 signer_did 必填")
            if len(signer_values) != 1:
                raise ValidationError("查询参数 signer_did 只能提供一次")
            signer_did = signer_values[0]
            if not signer_did:
                raise ValidationError(
                    "查询参数 signer_did 必须为非空字符串"
                )

            # 签名 DID 须为本租户活动本地 DID：未知（含他租户）404、
            # 已停用 409。
            signer_key_version, private_pem = (
                store.get_trust_anchor_snapshot_signer(tenant, signer_did)
            )
            events, next_after = store.list_trust_anchor_changes(
                tenant, after, 200
            )
            event_objs = [
                {
                    "cursor": event.cursor,
                    "action": event.action,
                    "did": event.did,
                    "key_version": event.key_version,
                    "public_key": event.public_key,
                    "status": event.status,
                    "uses": event.uses,
                }
                for event in events
            ]
            signed = {
                "events": event_objs,
                "next_after": next_after,
                "signer_did": signer_did,
                "signer_key_version": signer_key_version,
            }
            signature = crypto.sign(signed, private_pem)
            payload = dict(signed)
            payload["signature"] = signature
            self._send_json(200, payload)

        def _get_trust_ac_proof(self, tenant: str, query: str) -> None:
            # GET /v1/trust/ac-proof?cursor=&snapshot=&signer_did=：为指定
            # 锚点变更事件生成 Merkle 包含证明。查询参数仅允许唯一
            # cursor、snapshot、signer_did；cursor、snapshot 均为 ASCII
            # 十进制正整数且 cursor<=snapshot<=本租户最大游标；signer_did
            # 唯一非空。缺失/空值/重复/空白/符号/小数/布尔词/Unicode
            # 数字/未知参数/越界一律 400 且仅 {"error": 非空中文}。签名
            # DID 未知（含他租户）404、已停用 409；cursor 事件在 snapshot
            # 前缀内不存在 404。
            #
            # 以 cursor 升序的 snapshot 前缀（cursor<=snapshot 的全部事
            # 件）建树：叶=SHA-256(0x00||事件规范JSON UTF-8)，父=
            # SHA-256(0x01||左||右)，奇数末项复制。200 键序 event、
            # snapshot、root、path、signer_did、signer_key_version、
            # signature；event 沿用变更流事件协议；root 为 64 位小写 hex；
            # path 自叶向根，项键序 side、hash，side 限 left/right，hash
            # 同 root 格式；signature 由签名 DID 当前私钥对前六键规范化
            # JSON 做 ES256 裸 R||S 无填充 base64url。纯只读：不写状态、
            # 不记审计。
            params = parse_qs(query, keep_blank_values=True)
            unknown = sorted(
                set(params) - {"cursor", "snapshot", "signer_did"}
            )
            if unknown:
                raise ValidationError(
                    f"不支持的查询参数: {', '.join(unknown)}"
                )

            def _single(name: str) -> str:
                values = params.get(name)
                if values is None:
                    raise ValidationError(f"查询参数 {name} 必填")
                if len(values) != 1:
                    raise ValidationError(
                        f"查询参数 {name} 只能提供一次"
                    )
                return values[0]

            cursor = _parse_positive_int(_single("cursor"), "cursor")
            snapshot = _parse_positive_int(_single("snapshot"), "snapshot")
            if cursor > snapshot:
                raise ValidationError(
                    "查询参数 cursor 不得大于 snapshot"
                )
            signer_did = _single("signer_did")
            if not signer_did:
                raise ValidationError(
                    "查询参数 signer_did 必须为非空字符串"
                )

            # 先做 snapshot 越界校验（400 优先于签名 DID 的 404/409）。
            store.validate_anchor_change_snapshot(tenant, snapshot)

            # 签名 DID 须为本租户活动本地 DID（沿用变更流入口）：未知
            # （含他租户）404、已停用 409；先于事件存在性 404。
            signer_key_version, private_pem = (
                store.get_trust_anchor_snapshot_signer(tenant, signer_did)
            )

            target, prefix = store.get_anchor_change_proof_prefix(
                tenant, cursor, snapshot
            )
            if target is None:
                raise NotFoundError("锚点变更事件不存在")

            event_obj = _anchor_change_event_obj(target)
            leaf_hashes = [
                _anchor_proof_leaf_hash(_anchor_change_event_obj(event))
                for event in prefix
            ]
            index = next(
                pos
                for pos, event in enumerate(prefix)
                if event.cursor == cursor
            )
            root, path = _anchor_proof_build(leaf_hashes, index)
            signed = {
                "event": event_obj,
                "snapshot": snapshot,
                "root": root,
                "path": path,
                "signer_did": signer_did,
                "signer_key_version": signer_key_version,
            }
            signature = crypto.sign(signed, private_pem)
            proof = dict(signed)
            proof["signature"] = signature
            self._send_json(200, proof)

        def _anchor_proof_is_well_formed(self, proof: Any) -> bool:
            # 证明结构校验（“证明非法”）：proof 恰含 GET
            # /v1/trust/ac-proof 响应的七键；event 沿用变更流事件协议；
            # snapshot/signer_key_version 为非布尔正整数；root/hash 为 64
            # 位小写 hex；path 为 list，项恰含 side、hash，side 限
            # left/right；signer_did、signature 非空字符串。
            if not isinstance(proof, dict):
                return False
            if set(proof) != set(_ANCHOR_PROOF_RESPONSE_KEYS):
                return False

            event = proof["event"]
            if not isinstance(event, dict):
                return False
            if set(event) != set(_ANCHOR_CHANGE_EVENT_KEYS):
                return False
            event_cursor = event["cursor"]
            if (
                not isinstance(event_cursor, int)
                or isinstance(event_cursor, bool)
                or event_cursor < 1
            ):
                return False
            if event["action"] not in _ANCHOR_CHANGE_ACTIONS:
                return False
            if not isinstance(event["did"], str) or not event["did"]:
                return False
            key_version = event["key_version"]
            if (
                not isinstance(key_version, int)
                or isinstance(key_version, bool)
                or key_version < 1
            ):
                return False
            if (
                not isinstance(event["public_key"], str)
                or not event["public_key"]
            ):
                return False
            if event["status"] not in ("active", "revoked"):
                return False
            uses = event["uses"]
            if not isinstance(uses, list) or not uses:
                return False
            if any(
                not isinstance(use, str) or use not in TRUST_ANCHOR_USES
                for use in uses
            ):
                return False
            if len(set(uses)) != len(uses) or list(uses) != sorted(
                uses, key=TRUST_ANCHOR_USES.index
            ):
                return False

            snapshot = proof["snapshot"]
            if (
                not isinstance(snapshot, int)
                or isinstance(snapshot, bool)
                or snapshot < event_cursor
            ):
                return False
            root = proof["root"]
            if not (
                isinstance(root, str) and _SHA256_HEX_RE.fullmatch(root)
            ):
                return False
            path = proof["path"]
            if not isinstance(path, list):
                return False
            for item in path:
                if not isinstance(item, dict):
                    return False
                if set(item) != set(_ANCHOR_PROOF_PATH_ITEM_KEYS):
                    return False
                if item["side"] not in _ANCHOR_PROOF_SIDES:
                    return False
                item_hash = item["hash"]
                if not (
                    isinstance(item_hash, str)
                    and _SHA256_HEX_RE.fullmatch(item_hash)
                ):
                    return False
            signer_did = proof["signer_did"]
            if not isinstance(signer_did, str) or not signer_did:
                return False
            signer_key_version = proof["signer_key_version"]
            if (
                not isinstance(signer_key_version, int)
                or isinstance(signer_key_version, bool)
                or signer_key_version < 1
            ):
                return False
            signature = proof["signature"]
            if not isinstance(signature, str) or not signature:
                return False
            return True

        def _verify_anchor_proof_item(
            self,
            tenant: str,
            proof: Any,
            anchor_keys: Optional[Dict[Tuple[str, int], str]] = None,
        ) -> Optional[str]:
            # 锚点变更证明验真：按序返回失败原因（证明非法 -> 锚点不可
            # 用 -> 签名格式错误 -> 签名校验失败 -> 包含证明校验失败），
            # 成功返回 None。不依赖本地事件、纯只读、不记审计。
            # anchor_keys 为批初原子快照（(signer_did, 版本) -> 公钥
            # PEM，仅含 active 且含 generic 用途的锚点）；缺省时逐项实
            # 时查询本租户锚点。
            # 阶段一：proof 结构与事件协议
            if not self._anchor_proof_is_well_formed(proof):
                return "证明非法"

            signer_did = proof["signer_did"]
            signer_key_version = proof["signer_key_version"]

            # 阶段二：本租户同 signer_did/版本且含 generic 用途的
            # active 信任锚点
            if anchor_keys is None:
                public_pem = store.get_active_trust_anchor_public_key(
                    tenant,
                    signer_did,
                    signer_key_version,
                    required_use="generic",
                )
            else:
                public_pem = anchor_keys.get(
                    (signer_did, signer_key_version)
                )
            if public_pem is None:
                return "锚点不可用"
            try:
                crypto.validate_public_key_pem(public_pem)
            except (ValueError, TypeError):
                return "锚点不可用"

            # 阶段三：签名格式（ES256 裸 R||S 无填充 base64url）
            signature = proof["signature"]
            try:
                crypto.validate_signature_format_strict(signature)
            except crypto.MalformedSignature:
                return "签名格式错误"

            # 阶段四：密码学验签，覆盖 proof 除 signature 外六键的规范
            # 化 JSON
            signed = {
                key: proof[key] for key in _ANCHOR_PROOF_SIGNED_KEYS
            }
            try:
                crypto.verify(signed, signature, public_pem)
            except crypto.MalformedSignature:
                return "签名格式错误"
            except crypto.InvalidSignature:
                return "签名校验失败"
            except Exception:  # noqa: BLE001 验签绝不向上抛错或泄露细节
                return "签名校验失败"

            # 阶段五：按 path 自叶向根重算 root，须与签名所护 root 一致
            try:
                recomputed = _anchor_proof_recompute_root(
                    proof["event"], proof["path"]
                )
            except (ValueError, TypeError):
                return "包含证明校验失败"
            if recomputed != proof["root"]:
                return "包含证明校验失败"
            return None

        def _post_trust_ac_proof(self, tenant: str) -> None:
            # POST /v1/trust/ac-proof：校验锚点变更证明，不依赖本地事
            # 件。请求体须恰含 proof（JSON 对象），否则 400 且仅
            # {"error": 非空中文}；proof 须恰含 event、snapshot、root、
            # path、signer_did、signer_key_version、signature 七键。外层
            # 合法后任何失败均 HTTP 200，按键序返回
            # {"valid":false,"reason":...}，原因依次为证明非法 -> 锚点
            # 不可用（本租户同 signer_did/版本且含 generic 用途的 active
            # 锚点）-> 签名格式错误 -> 签名校验失败 -> 包含证明校验失败
            # （按 path 重算 root 不符）。成功仅 {"valid":true}。纯只
            # 读、租户隔离、不记审计。
            data = self._read_json()
            if set(data) != {"proof"}:
                if "proof" not in data:
                    raise ValidationError("请求缺少字段: proof")
                extra = sorted(set(data) - {"proof"})
                raise ValidationError(
                    f"请求含多余字段: {', '.join(extra)}"
                )
            proof = data["proof"]
            if not isinstance(proof, dict):
                raise ValidationError(
                    "请求不合法: 字段 proof 必须为 JSON 对象"
                )
            reason = self._verify_anchor_proof_item(tenant, proof)
            if reason is not None:
                self._send_json(200, {"valid": False, "reason": reason})
                return
            self._send_json(200, {"valid": True})

        def _post_trust_ac_proof_verify_batch(self, tenant: str) -> None:
            # POST /v1/trust/ac-proof/verify-batch：批量校验锚点变更证
            # 明（只读）。请求体须恰为 {"items": [证明...]}，数组限
            # 1–100 项；空体、非法 JSON、非对象、键集错误、items 非数
            # 组/空/超限均 HTTP 200 且按键序恰返
            # {"results": [], "reason": "请求非法"}。合法批次原子读取
            # 批初本租户信任锚点快照，逐项不短路，results 等长同序；
            # 并发吊销或用途收紧不得令同批观察到混合状态。每项须为
            # POST /v1/trust/ac-proof 的 proof 对象，逐项复用单项校验
            # 顺序与五类原因；成功项仅 {"valid": true}，失败项键序
            # valid、reason。顶层 HTTP 200 且仅含 results。不依赖变更
            # 事件，不写状态、游标或审计。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except Exception:  # noqa: BLE001 请求非法统一 200 处理
                self._send_json(
                    200, {"results": [], "reason": "请求非法"}
                )
                return
            if not raw:
                self._send_json(
                    200, {"results": [], "reason": "请求非法"}
                )
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(
                    200, {"results": [], "reason": "请求非法"}
                )
                return
            if (
                not isinstance(data, dict)
                or set(data) != {"items"}
                or not isinstance(data["items"], list)
                or not data["items"]
                or len(data["items"]) > 100
            ):
                self._send_json(
                    200, {"results": [], "reason": "请求非法"}
                )
                return
            items = data["items"]

            # 批初原子快照：仅取 active 且含 generic 用途的锚点，同批
            # 各项据此解析，不受并发吊销/用途收紧影响。
            snapshot = store.list_trust_anchor_snapshot(tenant)
            anchor_keys = {
                (row["did"], row["key_version"]): row["public_key"]
                for row in snapshot
                if row["status"] == "active" and "generic" in row["uses"]
            }

            results: List[Dict[str, Any]] = []
            for item in items:  # 顺序校验，失败不短路
                reason = self._verify_anchor_proof_item(
                    tenant, item, anchor_keys=anchor_keys
                )
                if reason is None:
                    results.append({"valid": True})
                else:
                    results.append({"valid": False, "reason": reason})
            self._send_json(200, {"results": results})

        def _anchor_changes_is_well_formed(
            self, changes: Any, after: Any
        ) -> bool:
            # 变更流结构校验（“变更流非法”）：changes 恰含 GET
            # /v1/trust/anchor-changes 响应的五键，字段协议沿用该入口；
            # events 至多 200 项、cursor 严格递增且均大于外层 after；
            # 非空时 next_after 等于末项 cursor，空时等于 after。
            if not isinstance(changes, dict):
                return False
            if set(changes) != set(_ANCHOR_CHANGES_RESPONSE_KEYS):
                return False
            events = changes["events"]
            if not isinstance(events, list):
                return False
            if len(events) > _ANCHOR_CHANGES_MAX_EVENTS:
                return False
            previous_cursor = after
            for event in events:
                if not isinstance(event, dict):
                    return False
                if set(event) != set(_ANCHOR_CHANGE_EVENT_KEYS):
                    return False
                cursor = event["cursor"]
                if (
                    not isinstance(cursor, int)
                    or isinstance(cursor, bool)
                    or cursor <= previous_cursor
                ):
                    return False
                if event["action"] not in _ANCHOR_CHANGE_ACTIONS:
                    return False
                if not isinstance(event["did"], str) or not event["did"]:
                    return False
                key_version = event["key_version"]
                if (
                    not isinstance(key_version, int)
                    or isinstance(key_version, bool)
                    or key_version < 1
                ):
                    return False
                if (
                    not isinstance(event["public_key"], str)
                    or not event["public_key"]
                ):
                    return False
                if event["status"] not in ("active", "revoked"):
                    return False
                uses = event["uses"]
                if not isinstance(uses, list) or not uses:
                    return False
                if any(
                    not isinstance(use, str) or use not in TRUST_ANCHOR_USES
                    for use in uses
                ):
                    return False
                if len(set(uses)) != len(uses) or list(uses) != sorted(
                    uses, key=TRUST_ANCHOR_USES.index
                ):
                    return False
                previous_cursor = cursor
            next_after = changes["next_after"]
            if (
                not isinstance(next_after, int)
                or isinstance(next_after, bool)
                or next_after < 0
            ):
                return False
            expected_next_after = (
                events[-1]["cursor"] if events else after
            )
            if next_after != expected_next_after:
                return False
            signer_did = changes["signer_did"]
            if not isinstance(signer_did, str) or not signer_did:
                return False
            signer_key_version = changes["signer_key_version"]
            if (
                not isinstance(signer_key_version, int)
                or isinstance(signer_key_version, bool)
                or signer_key_version < 1
            ):
                return False
            signature = changes["signature"]
            if not isinstance(signature, str) or not signature:
                return False
            return True

        def _verify_anchor_changes_item(
            self, tenant: str, changes: Any, after: int
        ) -> Optional[str]:
            # 变更流验真：按序返回失败原因（变更流非法 -> 锚点不可用 ->
            # 签名格式错误 -> 签名校验失败），成功返回 None。纯只读，
            # 不依赖本地事件。
            # 阶段一：changes 结构与事件协议
            if not self._anchor_changes_is_well_formed(changes, after):
                return "变更流非法"

            signer_did = changes["signer_did"]
            signer_key_version = changes["signer_key_version"]

            # 阶段二：本租户同 signer_did/版本且含 generic 用途的
            # active 信任锚点
            public_pem = store.get_active_trust_anchor_public_key(
                tenant,
                signer_did,
                signer_key_version,
                required_use="generic",
            )
            if public_pem is None:
                return "锚点不可用"
            try:
                crypto.validate_public_key_pem(public_pem)
            except (ValueError, TypeError):
                return "锚点不可用"

            # 阶段三：签名格式（ES256 裸 R||S 无填充 base64url）
            signature = changes["signature"]
            try:
                crypto.validate_signature_format_strict(signature)
            except crypto.MalformedSignature:
                return "签名格式错误"

            # 阶段四：密码学验签，覆盖 changes 除 signature 外四键的
            # 规范化 JSON
            signed = {
                key: changes[key]
                for key in _ANCHOR_CHANGES_RESPONSE_KEYS[:4]
            }
            try:
                crypto.verify(signed, signature, public_pem)
            except crypto.MalformedSignature:
                return "签名格式错误"
            except crypto.InvalidSignature:
                return "签名校验失败"
            except Exception:  # noqa: BLE001 验签绝不向上抛错或泄露细节
                return "签名校验失败"
            return None

        def _read_anchor_changes_request(self) -> Tuple[Dict[str, Any], int]:
            # /v1/trust/anchor-changes/verify 与 /sync 共用的请求体
            # 协议：恰含 changes（JSON 对象）、after（非布尔非负整数），
            # 否则 400 且仅 {"error": 非空中文}。
            data = self._read_json()
            if set(data) != {"changes", "after"}:
                missing = [f for f in ("changes", "after") if f not in data]
                if missing:
                    raise ValidationError(
                        f"请求缺少字段: {', '.join(missing)}"
                    )
                extra = sorted(set(data) - {"changes", "after"})
                raise ValidationError(f"请求含多余字段: {', '.join(extra)}")
            changes = data["changes"]
            if not isinstance(changes, dict):
                raise ValidationError(
                    "请求不合法: 字段 changes 必须为 JSON 对象"
                )
            after = data["after"]
            if (
                not isinstance(after, int)
                or isinstance(after, bool)
                or after < 0
            ):
                raise ValidationError(
                    "请求不合法: 字段 after 必须为非布尔非负整数"
                )
            return changes, after

        def _post_trust_anchor_changes_verify(self, tenant: str) -> None:
            # POST /v1/trust/anchor-changes/verify：跨系统信任锚点变更
            # 流只读验真，不依赖本地事件。请求体须恰含 changes（JSON
            # 对象）、after（非布尔非负整数），否则 400 且仅
            # {"error": 非空中文}。外层合法后任何失败均 HTTP 200，按键
            # 序返回 {"valid":false,"reason":...}，原因依次为变更流非法
            # -> 锚点不可用（本租户同 signer_did/版本且含 generic 用途
            # 的 active 锚点）-> 签名格式错误 -> 签名校验失败。成功仅
            # {"valid":true}。纯只读：不写状态、游标或审计；租户头缺省
            # default、显式空值 400 并隔离，重启稳定。
            changes, after = self._read_anchor_changes_request()
            reason = self._verify_anchor_changes_item(tenant, changes, after)
            if reason is not None:
                self._send_json(200, {"valid": False, "reason": reason})
                return
            self._send_json(200, {"valid": True})

        def _post_trust_anchor_changes_sync(self, tenant: str) -> None:
            # POST /v1/trust/anchor-changes/sync：跨系统信任锚点变更流
            # 的同步接收与防重放检查点，验真通过的变更页按来源可靠落盘。
            # 1) 请求体协议与 /verify 完全一致：恰含 changes（JSON 对
            #    象）、after（非布尔非负整数），缺失/非法 JSON/非对象/
            #    键集或类型错误均 400 且仅 {"error": 非空中文}；
            # 2) 完整复用 /verify 的变更流结构、锚点用途、签名格式、
            #    验签顺序及四类失败响应（200 + valid:false），失败不
            #    写入任何状态；
            # 3) 验真成功后以 (租户, signer_did) 为检查点键：首个非空
            #    页须 after=0，续页须等于已存 next_after；同 after 且
            #    changes 递归键升序紧凑 UTF-8 JSON 字节相同为幂等重
            #    放；旧页、跳页或同位异内容均 409 且仅
            #    {"error":"同步游标冲突"}；
            # 4) 首个非空页 201，后续新页 200；重放或空页 200 且不推
            #    进。成功响应键序恰为 valid、signer_did、next_after、
            #    accepted，valid=true；新页 accepted 为 events 长度，
            #    重放或空页为 0；
            # 5) 每个新页将原始 events、changes 规范化字节摘要与检查
            #    点原子落盘；存储失败全部回滚，500 仅
            #    {"error":"存储失败"}；并发同一检查点至多一项推进，
            #    其余按重放或冲突处理，重启后结论不变。同步不记审计。
            changes, after = self._read_anchor_changes_request()
            reason = self._verify_anchor_changes_item(tenant, changes, after)
            if reason is not None:
                self._send_json(200, {"valid": False, "reason": reason})
                return

            signer_did = changes["signer_did"]
            events = changes["events"]
            digest = hashlib.sha256(crypto.canonicalize(changes)).hexdigest()
            try:
                created, next_after, accepted = store.sync_anchor_changes(
                    tenant,
                    signer_did,
                    after,
                    digest,
                    events,
                    changes["next_after"],
                )
            except ConflictError:
                self._send_error(409, "同步游标冲突")
                return
            except StorageError:
                self._send_error(500, "存储失败")
                return
            self._send_json(
                201 if created else 200,
                {
                    "valid": True,
                    "signer_did": signer_did,
                    "next_after": next_after,
                    "accepted": accepted,
                },
            )

        def _get_trust_anchor_changes_sync_history(
            self, tenant: str, query: str
        ) -> None:
            # GET /v1/trust/anchor-changes/sync-history：只读查询某签名
            # 方已落盘的锚点变更同步页历史。
            # 查询参数仅允许 signer_did、limit、after 且均只能出现一次：
            # - signer_did 必填、非空；
            # - limit 缺省 50，须为 1..200 的非空 ASCII 十进制整数；
            # - after 缺省 0，须为非空非负 ASCII 十进制整数。
            # 空值、重复、符号、Unicode 数字、越界或未知参数均 400 且
            # 仅 {"error": 非空中文}；该签名方未接收非空页（含跨租户）
            # 404 同形。200 键序恰为 signer_did、pages、next_after；
            # pages 按来源 next_after 升序取 next_after > after 的前
            # limit 页，每页键序恰为 after、next_after、digest、events
            # （events 为落盘原文，值、顺序与键序不变）；空页
            # next_after 等于 after，否则等于末页 next_after。纯只读：
            # 不推进检查点、不记审计、不触发落盘。
            params = parse_qs(query, keep_blank_values=True)
            allowed = {"signer_did", "limit", "after"}
            unknown = sorted(set(params) - allowed)
            if unknown:
                raise ValidationError(
                    f"不支持的查询参数: {', '.join(unknown)}"
                )

            def _single(name: str) -> Optional[str]:
                values = params.get(name)
                if values is None:
                    return None
                if len(values) != 1:
                    raise ValidationError(
                        f"查询参数 {name} 只能提供一次"
                    )
                return values[0]

            signer_did = _single("signer_did")
            if signer_did is None:
                raise ValidationError("查询参数 signer_did 必填")
            if not signer_did:
                raise ValidationError(
                    "查询参数 signer_did 必须为非空字符串"
                )

            limit_raw = _single("limit")
            if limit_raw is not None:
                limit = _parse_nonneg_int(limit_raw, "limit")
                if not 1 <= limit <= 200:
                    raise ValidationError(
                        "查询参数 limit 须在 1 到 200 之间"
                    )
            else:
                limit = 50

            after_raw = _single("after")
            if after_raw is not None:
                after = _parse_nonneg_int(after_raw, "after")
            else:
                after = 0

            pages, next_after = store.list_anchor_changes_sync_history(
                tenant, signer_did, after, limit
            )
            self._send_json(
                200,
                {
                    "signer_did": signer_did,
                    "pages": [
                        {
                            "after": int(page["after"]),
                            "next_after": int(page["next_after"]),
                            "digest": page["digest"],
                            "events": page["events"],
                        }
                        for page in pages
                    ],
                    "next_after": next_after,
                },
            )

        def _get_trust_anchor_changes_synced_state(
            self, tenant: str, query: str
        ) -> None:
            # GET /v1/trust/anchor-changes/synced-state：只读查询某签名
            # 方已同步锚点变更在指定时点的汇聚状态视图。
            # 查询参数仅允许 signer_did、at、limit、after 且均只能出现
            # 一次：signer_did 必填非空；at 缺省取该签名方同步检查点、
            # 须为 ASCII 非负整数；limit 缺省 50、限 1..200；after 缺
            # 省 0、须为 ASCII 非负整数。空值、重复、未知参数、非
            # ASCII 数字、符号、越界或 after>at 均 400 且仅
            # {"error": 非空中文}；该签名方未同步（含跨租户）404 同
            # 形，at 超过检查点 409 同形。200 键序恰为 signer_did、
            # at、anchors、next_after；取 cursor<=at 的已同步事件，
            # 以 (did, key_version) 末项为准，按 last_cursor>after
            # 升序取 limit 项，每项键序恰为 did、key_version、
            # public_key、status、uses（规范序）、last_action、
            # last_cursor；空页 next_after=after，否则取末项
            # last_cursor。at 分页不受后续同步影响，重启逐字节一致。
            # 纯只读：不推进检查点、不写状态或审计。
            params = parse_qs(query, keep_blank_values=True)
            allowed = {"signer_did", "at", "limit", "after"}
            unknown = sorted(set(params) - allowed)
            if unknown:
                raise ValidationError(
                    f"不支持的查询参数: {', '.join(unknown)}"
                )

            def _single(name: str) -> Optional[str]:
                values = params.get(name)
                if values is None:
                    return None
                if len(values) != 1:
                    raise ValidationError(
                        f"查询参数 {name} 只能提供一次"
                    )
                return values[0]

            signer_did = _single("signer_did")
            if signer_did is None:
                raise ValidationError("查询参数 signer_did 必填")
            if not signer_did:
                raise ValidationError(
                    "查询参数 signer_did 必须为非空字符串"
                )

            at_raw = _single("at")
            at = (
                _parse_nonneg_int(at_raw, "at")
                if at_raw is not None
                else None
            )

            limit_raw = _single("limit")
            if limit_raw is not None:
                limit = _parse_nonneg_int(limit_raw, "limit")
                if not 1 <= limit <= 200:
                    raise ValidationError(
                        "查询参数 limit 须在 1 到 200 之间"
                    )
            else:
                limit = 50

            after_raw = _single("after")
            if after_raw is not None:
                after = _parse_nonneg_int(after_raw, "after")
            else:
                after = 0

            if at is not None and after > at:
                raise ValidationError("查询参数 after 不能大于 at")

            at_value, anchors, next_after = (
                store.list_anchor_changes_synced_state(
                    tenant, signer_did, at, after, limit
                )
            )
            self._send_json(
                200,
                {
                    "signer_did": signer_did,
                    "at": at_value,
                    "anchors": anchors,
                    "next_after": next_after,
                },
            )

        def _get_trust_anchor_snapshot(self, tenant: str, query: str) -> None:
            # GET /v1/trust/anchors/snapshot?signer_did=：对本租户全部
            # 信任锚点生成签名快照。查询参数仅允许唯一非空 signer_did，
            # 缺失/空值/重复/未知参数一律 400 且仅 {"error"}；签名 DID
            # 未知（含他租户）404、已停用 409。200 键序 anchors、
            # signer_did、signer_key_version、signature；anchors 原子
            # 取本租户锚点并按 did 码点、key_version 升序，项键序 did、
            # key_version、public_key、status、updated_at、uses（类型
            # 沿用既有锚点与用途响应）；signature 由签名 DID 当前私钥
            # 对前三键递归键升序紧凑 UTF-8 JSON 做 ES256 裸 R||S 无填
            # 充 base64url 签名。纯只读：不写状态、不记审计。
            params = parse_qs(query, keep_blank_values=True)
            unknown = sorted(set(params) - {"signer_did"})
            if unknown:
                raise ValidationError(
                    f"不支持的查询参数: {', '.join(unknown)}"
                )
            signer_values = params.get("signer_did")
            if signer_values is None:
                raise ValidationError("查询参数 signer_did 必填")
            if len(signer_values) != 1:
                raise ValidationError("查询参数 signer_did 只能提供一次")
            signer_did = signer_values[0]
            if not signer_did:
                raise ValidationError(
                    "查询参数 signer_did 必须为非空字符串"
                )

            key_version, private_pem = (
                store.get_trust_anchor_snapshot_signer(tenant, signer_did)
            )
            anchors = store.list_trust_anchor_snapshot(tenant)
            signed = {
                "anchors": anchors,
                "signer_did": signer_did,
                "signer_key_version": key_version,
            }
            signature = crypto.sign(signed, private_pem)
            snapshot = dict(signed)
            snapshot["signature"] = signature
            self._send_json(200, snapshot)

        def _anchor_snapshot_is_well_formed(self, snapshot: Any) -> bool:
            # 快照结构校验（“快照非法”）：恰含四键且各键类型/取值合法。
            if not isinstance(snapshot, dict):
                return False
            if set(snapshot) != {
                "anchors",
                "signer_did",
                "signer_key_version",
                "signature",
            }:
                return False
            anchors = snapshot["anchors"]
            if not isinstance(anchors, list):
                return False
            for item in anchors:
                if not isinstance(item, dict):
                    return False
                if set(item) != {
                    "did",
                    "key_version",
                    "public_key",
                    "status",
                    "updated_at",
                    "uses",
                }:
                    return False
                if not isinstance(item["did"], str) or not item["did"]:
                    return False
                key_version = item["key_version"]
                if (
                    not isinstance(key_version, int)
                    or isinstance(key_version, bool)
                    or key_version < 1
                ):
                    return False
                if (
                    not isinstance(item["public_key"], str)
                    or not item["public_key"]
                ):
                    return False
                if item["status"] not in ("active", "revoked"):
                    return False
                updated_at = item["updated_at"]
                if updated_at is not None and not isinstance(
                    updated_at, str
                ):
                    return False
                uses = item["uses"]
                if not isinstance(uses, list) or not uses:
                    return False
                if any(
                    not isinstance(use, str) or use not in TRUST_ANCHOR_USES
                    for use in uses
                ):
                    return False
                if len(set(uses)) != len(uses) or list(uses) != sorted(
                    uses, key=TRUST_ANCHOR_USES.index
                ):
                    return False
            signer_did = snapshot["signer_did"]
            if not isinstance(signer_did, str) or not signer_did:
                return False
            signer_key_version = snapshot["signer_key_version"]
            if (
                not isinstance(signer_key_version, int)
                or isinstance(signer_key_version, bool)
                or signer_key_version < 1
            ):
                return False
            signature = snapshot["signature"]
            if not isinstance(signature, str) or not signature:
                return False
            return True

        def _verify_anchor_snapshot_item(
            self, tenant: str, snapshot: Any
        ) -> Optional[str]:
            # 快照验真：按序返回失败原因（快照非法 -> 锚点不可用 ->
            # 签名格式错误 -> 签名校验失败），成功返回 None。纯只读。
            # 阶段一：快照键集/类型
            if not self._anchor_snapshot_is_well_formed(snapshot):
                return "快照非法"

            anchors = snapshot["anchors"]
            # 阶段二：anchors 按 did 码点、key_version 严格升序（无重复）
            keys = [(item["did"], item["key_version"]) for item in anchors]
            if any(
                keys[index] >= keys[index + 1]
                for index in range(len(keys) - 1)
            ):
                return "快照非法"

            signer_did = snapshot["signer_did"]
            signer_key_version = snapshot["signer_key_version"]

            # 阶段三：本租户同 signer_did/版本且含 generic 用途的
            # active 信任锚点
            public_pem = store.get_active_trust_anchor_public_key(
                tenant,
                signer_did,
                signer_key_version,
                required_use="generic",
            )
            if public_pem is None:
                return "锚点不可用"
            try:
                crypto.validate_public_key_pem(public_pem)
            except (ValueError, TypeError):
                return "锚点不可用"

            signed = {
                "anchors": anchors,
                "signer_did": signer_did,
                "signer_key_version": signer_key_version,
            }
            signature = snapshot["signature"]

            # 阶段四：签名格式
            try:
                crypto.validate_signature_format_strict(signature)
            except crypto.MalformedSignature:
                return "签名格式错误"

            # 阶段五：密码学验签
            try:
                crypto.verify(signed, signature, public_pem)
            except crypto.MalformedSignature:
                return "签名格式错误"
            except crypto.InvalidSignature:
                return "签名校验失败"
            except Exception:  # noqa: BLE001 验签绝不向上抛错或泄露细节
                return "签名校验失败"
            return None

        def _post_trust_anchor_snapshot_verify(self, tenant: str) -> None:
            # POST /v1/trust/anchors/snapshot/verify：校验锚点快照签名。
            # 请求体须恰为 {"snapshot": 对象}，否则 400 且仅 {"error"}。
            # 外层合法后任何失败均 HTTP 200，按顺序返回
            # {"valid":false,"reason":...}：快照非法（键集/类型、anchors
            # 顺序/重复）-> 锚点不可用（本租户同 signer_did/版本且含
            # generic 用途的 active 锚点）-> 签名格式错误 -> 签名校验
            # 失败。成功仅 {"valid":true}。纯只读、租户隔离、不记审计。
            data = self._read_json()
            if set(data) != {"snapshot"}:
                if "snapshot" not in data:
                    raise ValidationError("请求缺少字段: snapshot")
                extra = sorted(set(data) - {"snapshot"})
                raise ValidationError(
                    f"请求含多余字段: {', '.join(extra)}"
                )
            snapshot = data["snapshot"]
            if not isinstance(snapshot, dict):
                raise ValidationError(
                    "请求不合法: 字段 snapshot 必须为 JSON 对象"
                )
            reason = self._verify_anchor_snapshot_item(tenant, snapshot)
            if reason is not None:
                self._send_json(200, {"valid": False, "reason": reason})
                return
            self._send_json(200, {"valid": True})

        def _get_trust_did_deactivations(self, tenant: str, query: str) -> None:
            # GET /v1/trust/dids/deactivations：只读查询本租户外部 DID
            # 停用通告审计事件。查询参数仅允许 limit、after、did、
            # key_version、from、to，且均只能出现一次：
            # - limit 缺省 50，须为 1..200 的非空 ASCII 十进制整数；
            # - after 缺省 0，须为非负 ASCII 十进制整数；
            # - did 提供时须为非空字符串；
            # - key_version 须为 ASCII 十进制正整数；
            # - from/to 须为 UTC 秒精度 Z 时间（YYYY-MM-DDTHH:MM:SSZ），
            #   且 from <= to（闭区间过滤 deactivated_at）。
            # 空值、重复参数、未知参数、格式或范围非法一律 400 且仅含
            # 非空中文 error。先按 did/key_version 精确过滤与
            # deactivated_at 闭区间过滤，再按 cursor > after 升序分页。
            # 200 键序 events、next_after；事件键序 cursor、did、
            # key_version、reason、deactivated_at；空页 next_after 等于
            # after。无任何事件也返回 200 空数组。纯只读：不写状态、
            # 不记审计。
            params = parse_qs(query, keep_blank_values=True)
            allowed = {"limit", "after", "did", "key_version", "from", "to"}
            unknown = sorted(set(params) - allowed)
            if unknown:
                raise ValidationError(
                    f"不支持的查询参数: {', '.join(unknown)}"
                )

            def _single(name: str) -> Optional[str]:
                values = params.get(name)
                if values is None:
                    return None
                if len(values) != 1:
                    raise ValidationError(
                        f"查询参数 {name} 只能提供一次"
                    )
                return values[0]

            limit_raw = _single("limit")
            if limit_raw is not None:
                limit = _parse_nonneg_int(limit_raw, "limit")
                if not 1 <= limit <= 200:
                    raise ValidationError(
                        "查询参数 limit 须在 1 到 200 之间"
                    )
            else:
                limit = 50

            after_raw = _single("after")
            if after_raw is not None:
                after = _parse_nonneg_int(after_raw, "after")
            else:
                after = 0

            did = _single("did")
            if did is not None and not did:
                raise ValidationError("查询参数 did 必须为非空字符串")

            key_version_raw = _single("key_version")
            key_version: Optional[int] = None
            if key_version_raw is not None:
                key_version = _parse_positive_int(
                    key_version_raw, "key_version"
                )

            from_raw = _single("from")
            from_time = (
                _parse_utc_z_query(from_raw, "from")
                if from_raw is not None
                else None
            )
            to_raw = _single("to")
            to_time = (
                _parse_utc_z_query(to_raw, "to")
                if to_raw is not None
                else None
            )
            if (
                from_time is not None
                and to_time is not None
                and from_time > to_time
            ):
                raise ValidationError("查询参数 from 不得晚于 to")

            events, next_after = store.list_did_deactivation_events(
                tenant,
                after,
                limit,
                did=did,
                key_version=key_version,
                from_time=from_time,
                to_time=to_time,
            )
            self._send_json(
                200,
                {
                    "events": [
                        {
                            "cursor": event.cursor,
                            "did": event.did,
                            "key_version": event.key_version,
                            "reason": event.reason,
                            "deactivated_at": event.deactivated_at,
                        }
                        for event in events
                    ],
                    "next_after": next_after,
                },
            )

        def _get_trust_did_deactivations_export(
            self, tenant: str, query: str
        ) -> None:
            # GET /v1/trust/dids/deactivations/export：确定性 NDJSON
            # 导出本租户外部 DID 停用通告审计事件，支持快照续传。
            # 查询参数仅允许 limit、after、snapshot、did、key_version、
            # from、to，且均只能出现一次：
            # - limit 缺省 1000，须为 1..10000 的非空 ASCII 十进制整数；
            # - after 缺省 0，须为非负 ASCII 十进制整数；
            # - snapshot 缺省为请求开始时原子读取的租户最大 cursor
            #   （无事件为 0），显式提供时须为非负 ASCII 十进制整数且
            #   不超过当时最大值；
            # - did/key_version/from/to 校验与 deactivations 查询一致。
            # 空值、重复参数、未知参数、格式或范围非法一律 400 且恰返
            # {"error": "非空中文原因"}。先按 did/key_version 精确过滤
            # 与 deactivated_at 闭区间过滤，再取 after < cursor <=
            # snapshot 按 cursor 升序的前 limit 条。成功 200，类型
            # application/x-ndjson; charset=utf-8；响应头
            # X-Snapshot-Cursor 为生效快照、X-Next-After 为末行
            # cursor（空结果为 after）。每行键序 cursor、did、
            # key_version、reason、deactivated_at，UTF-8 紧凑 JSON、
            # 非 ASCII 不转义、LF 结行（末行亦有 LF）、无 BOM，空结果
            # 零字节。同一 snapshot 续页天然排除快照后新事件。纯只读：
            # 不改游标、状态或审计。
            params = parse_qs(query, keep_blank_values=True)
            allowed = {
                "limit",
                "after",
                "snapshot",
                "did",
                "key_version",
                "from",
                "to",
            }
            unknown = sorted(set(params) - allowed)
            if unknown:
                raise ValidationError(
                    f"不支持的查询参数: {', '.join(unknown)}"
                )

            def _single(name: str) -> Optional[str]:
                values = params.get(name)
                if values is None:
                    return None
                if len(values) != 1:
                    raise ValidationError(
                        f"查询参数 {name} 只能提供一次"
                    )
                return values[0]

            limit_raw = _single("limit")
            if limit_raw is not None:
                limit = _parse_nonneg_int(limit_raw, "limit")
                if not 1 <= limit <= 10000:
                    raise ValidationError(
                        "查询参数 limit 须在 1 到 10000 之间"
                    )
            else:
                limit = 1000

            after_raw = _single("after")
            if after_raw is not None:
                after = _parse_nonneg_int(after_raw, "after")
            else:
                after = 0

            snapshot_raw = _single("snapshot")
            snapshot: Optional[int] = (
                _parse_nonneg_int(snapshot_raw, "snapshot")
                if snapshot_raw is not None
                else None
            )

            did = _single("did")
            if did is not None and not did:
                raise ValidationError("查询参数 did 必须为非空字符串")

            key_version_raw = _single("key_version")
            key_version: Optional[int] = None
            if key_version_raw is not None:
                key_version = _parse_positive_int(
                    key_version_raw, "key_version"
                )

            from_raw = _single("from")
            from_time = (
                _parse_utc_z_query(from_raw, "from")
                if from_raw is not None
                else None
            )
            to_raw = _single("to")
            to_time = (
                _parse_utc_z_query(to_raw, "to")
                if to_raw is not None
                else None
            )
            if (
                from_time is not None
                and to_time is not None
                and from_time > to_time
            ):
                raise ValidationError("查询参数 from 不得晚于 to")

            events, snapshot_cursor, next_after = (
                store.export_did_deactivation_events(
                    tenant,
                    after,
                    limit,
                    snapshot=snapshot,
                    did=did,
                    key_version=key_version,
                    from_time=from_time,
                    to_time=to_time,
                )
            )
            body = _deactivation_ndjson_bytes(events)
            self.send_response(200)
            self.send_header(
                "Content-Type", "application/x-ndjson; charset=utf-8"
            )
            self.send_header("X-Snapshot-Cursor", str(snapshot_cursor))
            self.send_header("X-Next-After", str(next_after))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _parse_deactivation_manifest_query(
            self, query: str
        ) -> Dict[str, Any]:
            # 清单查询参数：export 七参数（after/limit/snapshot/did/
            # key_version/from/to）加唯一 signer_did，其中 snapshot 必填。
            # 返回各参数的“显式生效值”（缺省为 None）与解析后的 limit/
            # after/snapshot。任何空值、重复、未知参数、格式或范围非法均
            # 抛 ValidationError（HTTP 400，仅含非空中文 error）。
            params = parse_qs(query, keep_blank_values=True)
            allowed = {
                "after",
                "limit",
                "snapshot",
                "did",
                "key_version",
                "from",
                "to",
                "signer_did",
            }
            unknown = sorted(set(params) - allowed)
            if unknown:
                raise ValidationError(
                    f"不支持的查询参数: {', '.join(unknown)}"
                )

            def _single(name: str) -> Optional[str]:
                values = params.get(name)
                if values is None:
                    return None
                if len(values) != 1:
                    raise ValidationError(
                        f"查询参数 {name} 只能提供一次"
                    )
                return values[0]

            limit_raw = _single("limit")
            limit_provided = limit_raw is not None
            if limit_raw is not None:
                limit = _parse_nonneg_int(limit_raw, "limit")
                if not 1 <= limit <= 10000:
                    raise ValidationError(
                        "查询参数 limit 须在 1 到 10000 之间"
                    )
            else:
                limit = 1000

            after_raw = _single("after")
            after_provided = after_raw is not None
            after = (
                _parse_nonneg_int(after_raw, "after")
                if after_raw is not None
                else 0
            )

            snapshot_raw = _single("snapshot")
            if snapshot_raw is None:
                raise ValidationError("查询参数 snapshot 必填")
            snapshot = _parse_nonneg_int(snapshot_raw, "snapshot")

            did = _single("did")
            if did is not None and not did:
                raise ValidationError("查询参数 did 必须为非空字符串")

            key_version_raw = _single("key_version")
            key_version: Optional[int] = None
            if key_version_raw is not None:
                key_version = _parse_positive_int(
                    key_version_raw, "key_version"
                )

            from_raw = _single("from")
            from_time = (
                _parse_utc_z_query(from_raw, "from")
                if from_raw is not None
                else None
            )
            to_raw = _single("to")
            to_time = (
                _parse_utc_z_query(to_raw, "to")
                if to_raw is not None
                else None
            )
            if (
                from_time is not None
                and to_time is not None
                and from_time > to_time
            ):
                raise ValidationError("查询参数 from 不得晚于 to")

            signer_did = _single("signer_did")
            if signer_did is None or not signer_did:
                raise ValidationError(
                    "查询参数 signer_did 必填且必须为非空字符串"
                )

            # filters 按固定键序记录“显式提供”的生效值，缺省项为 None。
            filters = {
                "after": after if after_provided else None,
                "limit": limit if limit_provided else None,
                "did": did,
                "key_version": key_version,
                "from": from_time,
                "to": to_time,
            }
            return {
                "after": after,
                "limit": limit,
                "snapshot": snapshot,
                "did": did,
                "key_version": key_version,
                "from_time": from_time,
                "to_time": to_time,
                "signer_did": signer_did,
                "filters": filters,
            }

        def _get_trust_did_deactivations_manifest(
            self, tenant: str, query: str
        ) -> None:
            # GET /v1/trust/dids/deactivations/manifest：对一次确定性导出
            # （与 export 同参数，snapshot 必填）生成签名摘要清单。
            # 参数/snapshot 越界 400（仅 error）；签名 DID 未知（含他租
            # 户）404、已停用 409。200 键序 snapshot、filters、count、
            # alg、digest、signer_did、key_version、signature；filters 键
            # 序 after、limit、did、key_version、from、to，缺省项为 null；
            # count 为本页非负整数行数；alg 恒为 SHA-256；digest 为本页
            # NDJSON 字节的 64 位小写 hex SHA-256；signature 由签名 DID
            # 当前私钥对前七键规范化 JSON 做 ES256 裸 R||S 无填充
            # base64url 签名。纯只读：不改游标、状态或审计。
            args = self._parse_deactivation_manifest_query(query)

            # 先做快照越界校验（400 优先于签名 DID 的 404/409）。
            events, effective_snapshot, _ = (
                store.export_did_deactivation_events(
                    tenant,
                    args["after"],
                    args["limit"],
                    snapshot=args["snapshot"],
                    did=args["did"],
                    key_version=args["key_version"],
                    from_time=args["from_time"],
                    to_time=args["to_time"],
                )
            )

            # 签名 DID 须为本租户活动本地 DID：未知 404、停用 409。
            signer_did = args["signer_did"]
            key_version, private_pem = (
                store.get_deactivation_manifest_signer(tenant, signer_did)
            )

            ndjson_bytes = _deactivation_ndjson_bytes(events)
            digest = hashlib.sha256(ndjson_bytes).hexdigest()
            signed = {
                "snapshot": effective_snapshot,
                "filters": args["filters"],
                "count": len(events),
                "alg": "SHA-256",
                "digest": digest,
                "signer_did": signer_did,
                "key_version": key_version,
            }
            signature = crypto.sign(signed, private_pem)
            manifest = dict(signed)
            manifest["signature"] = signature
            self._send_json(200, manifest)

        def _manifest_is_well_formed(self, manifest: Any) -> bool:
            # 清单结构校验（阶段一“清单非法”）：恰含八键且类型/取值合法。
            if not isinstance(manifest, dict):
                return False
            expected = {
                "snapshot",
                "filters",
                "count",
                "alg",
                "digest",
                "signer_did",
                "key_version",
                "signature",
            }
            if set(manifest) != expected:
                return False

            def _is_nonneg_int(value: Any) -> bool:
                return (
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and value >= 0
                )

            def _is_positive_int(value: Any) -> bool:
                return (
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and value >= 1
                )

            if not _is_nonneg_int(manifest["snapshot"]):
                return False
            if not _is_nonneg_int(manifest["count"]):
                return False
            if manifest["alg"] != "SHA-256":
                return False
            if not (
                isinstance(manifest["digest"], str)
                and _SHA256_HEX_RE.fullmatch(manifest["digest"])
            ):
                return False
            if (
                not isinstance(manifest["signer_did"], str)
                or not manifest["signer_did"]
            ):
                return False
            if not _is_positive_int(manifest["key_version"]):
                return False
            if (
                not isinstance(manifest["signature"], str)
                or not manifest["signature"]
            ):
                return False

            filters = manifest["filters"]
            if not isinstance(filters, dict):
                return False
            if set(filters) != {
                "after",
                "limit",
                "did",
                "key_version",
                "from",
                "to",
            }:
                return False
            if filters["after"] is not None and not _is_nonneg_int(
                filters["after"]
            ):
                return False
            limit = filters["limit"]
            if limit is not None and not (
                _is_positive_int(limit) and 1 <= limit <= 10000
            ):
                return False
            if filters["did"] is not None and not (
                isinstance(filters["did"], str) and filters["did"]
            ):
                return False
            if filters["key_version"] is not None and not _is_positive_int(
                filters["key_version"]
            ):
                return False
            from_time = filters["from"]
            to_time = filters["to"]
            if from_time is not None:
                try:
                    _parse_utc_z_query(from_time, "from")
                except ValidationError:
                    return False
            if to_time is not None:
                try:
                    _parse_utc_z_query(to_time, "to")
                except ValidationError:
                    return False
            if (
                from_time is not None
                and to_time is not None
                and from_time > to_time
            ):
                return False
            return True

        def _post_trust_did_deactivations_manifest_verify(
            self, tenant: str
        ) -> None:
            # POST /v1/trust/dids/deactivations/manifest/verify：校验一次
            # 导出清单与其 NDJSON 内容。外层请求错误（非法 JSON/非对象/
            # 缺漏或多余字段/manifest 非对象/ndjson 非字符串）一律 400 且
            # 仅 {"error": ...}。外层合法后任何失败均 HTTP 200，按顺序
            # 返回 {"valid":false,"reason":...}：清单非法 -> 锚点不可用
            # （本租户同 did/版本 active 锚点）-> 签名格式错误 -> 签名
            # 校验失败 -> 导出内容不匹配（UTF-8 SHA-256 摘要及行数）。
            # 成功仅 {"valid":true}。纯只读、租户隔离、不记审计。
            data = self._read_json()
            if set(data) != {"manifest", "ndjson"}:
                missing = [f for f in ("manifest", "ndjson") if f not in data]
                if missing:
                    raise ValidationError(
                        f"请求缺少字段: {', '.join(missing)}"
                    )
                extra = sorted(set(data) - {"manifest", "ndjson"})
                raise ValidationError(f"请求含多余字段: {', '.join(extra)}")
            manifest = data["manifest"]
            ndjson = data["ndjson"]
            if not isinstance(manifest, dict):
                raise ValidationError(
                    "请求不合法: 字段 manifest 必须为 JSON 对象"
                )
            if not isinstance(ndjson, str):
                raise ValidationError(
                    "请求不合法: 字段 ndjson 必须为字符串"
                )

            reason = self._verify_deactivation_manifest_item(
                tenant, manifest, ndjson
            )
            if reason is not None:
                self._send_json(200, {"valid": False, "reason": reason})
                return
            self._send_json(200, {"valid": True})

        def _verify_deactivation_manifest_item(
            self, tenant: str, manifest: Any, ndjson: str
        ) -> Optional[str]:
            # 单项清单验真（供单项与批量端点共用）：按序返回失败原因
            # （清单非法 -> 锚点不可用 -> 签名格式错误 -> 签名校验失败
            # -> 导出内容不匹配），成功返回 None。纯只读。
            # 阶段一：清单结构
            if not self._manifest_is_well_formed(manifest):
                return "清单非法"

            signer_did = manifest["signer_did"]
            key_version = manifest["key_version"]

            # 阶段二：本租户同 did/版本 active 信任锚点（须含
            # deactivation 用途，否则按锚点不可用处理）
            public_pem = store.get_active_trust_anchor_public_key(
                tenant, signer_did, key_version, required_use="deactivation"
            )
            if public_pem is None:
                return "锚点不可用"
            try:
                crypto.validate_public_key_pem(public_pem)
            except (ValueError, TypeError):
                return "锚点不可用"

            signed = {
                "snapshot": manifest["snapshot"],
                "filters": manifest["filters"],
                "count": manifest["count"],
                "alg": manifest["alg"],
                "digest": manifest["digest"],
                "signer_did": signer_did,
                "key_version": key_version,
            }
            signature = manifest["signature"]

            # 阶段三：签名格式
            try:
                crypto.validate_signature_format_strict(signature)
            except crypto.MalformedSignature:
                return "签名格式错误"

            # 阶段四：密码学验签
            try:
                crypto.verify(signed, signature, public_pem)
            except crypto.MalformedSignature:
                return "签名格式错误"
            except crypto.InvalidSignature:
                return "签名校验失败"
            except Exception:  # noqa: BLE001 验签绝不向上抛错或泄露细节
                return "签名校验失败"

            # 阶段五：导出内容——UTF-8 字节的 SHA-256 摘要与行数
            try:
                raw = ndjson.encode("utf-8")
            except UnicodeEncodeError:
                return "导出内容不匹配"
            actual_digest = hashlib.sha256(raw).hexdigest()
            line_count = raw.count(b"\n")
            if (
                actual_digest != manifest["digest"]
                or line_count != manifest["count"]
            ):
                return "导出内容不匹配"
            return None

        def _post_trust_did_deactivations_manifest_verify_batch(
            self, tenant: str
        ) -> None:
            # POST /v1/trust/dids/deactivations/manifest/verify-batch：
            # 批量校验停用通告清单与 NDJSON。任何失败都返回 HTTP 200。
            # 请求体须恰为 {"items": [项...]}，数组非空且不超过 100 项；
            # 请求体非法（空体、非法 JSON、非对象、字段缺失或多余、items
            # 非数组、空数组或超过上限）时返回
            # {"results": [], "reason": "请求..."}。请求级合法时返回
            # {"results": [...]}，长度与顺序与输入一致，逐项复用单项验真
            # 规则，失败不短路；每项须恰含 manifest 对象与 ndjson 字符串，
            # 项非对象、字段或类型非法按“清单非法”处理。成功项仅
            # {"valid": true}，失败项 {"valid": false, "reason": ...}。
            # 纯只读：不写状态、历史或审计，仅使用当前租户锚点。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except (ValueError, TypeError):
                self._send_json(
                    200,
                    {"results": [],
                     "reason": "请求不合法: 请求体缺失或长度声明非法"},
                )
                return
            except Exception:  # noqa: BLE001
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体读取失败"}
                )
                return
            if not raw:
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体缺失"}
                )
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._send_json(
                    200,
                    {"results": [],
                     "reason": "请求不合法: 请求体不是合法 UTF-8 文本"},
                )
                return
            except json.JSONDecodeError:
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体不是合法 JSON"}
                )
                return

            def _request_invalid(reason: str) -> None:
                self._send_json(200, {"results": [], "reason": reason})

            if not isinstance(data, dict):
                _request_invalid("请求不合法: 请求体必须为 JSON 对象")
                return
            if set(data) != {"items"}:
                if "items" not in data:
                    _request_invalid("请求缺少字段: items")
                    return
                extra = sorted(set(data) - {"items"})
                _request_invalid(f"请求含多余字段: {', '.join(extra)}")
                return
            items = data["items"]
            if not isinstance(items, list):
                _request_invalid("请求不合法: 字段 items 必须为数组")
                return
            if not items:
                _request_invalid("请求不合法: items 数组不能为空")
                return
            if len(items) > 100:
                _request_invalid(
                    "请求不合法: items 数组不能超过 100 项"
                    f"（当前 {len(items)} 项）"
                )
                return

            results: List[Dict[str, Any]] = []
            for item in items:  # 顺序校验，失败不短路
                if (
                    not isinstance(item, dict)
                    or set(item) != {"manifest", "ndjson"}
                    or not isinstance(item["manifest"], dict)
                    or not isinstance(item["ndjson"], str)
                ):
                    results.append({"valid": False, "reason": "清单非法"})
                    continue
                reason = self._verify_deactivation_manifest_item(
                    tenant, item["manifest"], item["ndjson"]
                )
                if reason is None:
                    results.append({"valid": True})
                else:
                    results.append({"valid": False, "reason": reason})
            self._send_json(200, {"results": results})

        def _put_trust_anchor_status(
            self, tenant: str, did: str, key_version: str
        ) -> None:
            # 请求体必须恰为 {"status": "revoked"}；路径 key_version
            # 须为非布尔正整数（路径参数为字符串）。
            data = self._read_json()
            if "status" not in data:
                raise ValidationError("缺少字段: status")
            extra = sorted(set(data) - {"status"})
            if extra:
                raise ValidationError(f"多余字段: {', '.join(extra)}")
            if data["status"] != "revoked":
                raise ValidationError(
                    f"字段 status 非法: {data['status']!r}（仅支持 revoked）"
                )
            if (
                not key_version
                or any(ch < "0" or ch > "9" for ch in key_version)
                or int(key_version) < 1
            ):
                raise ValidationError("路径参数 key_version 必须为正整数")
            record = store.revoke_trust_anchor(tenant, did, int(key_version))
            # 首次吊销与幂等重试均 200，updated_at 保持首次值
            self._send_json(200, self._trust_anchor_payload(record))

        def _put_trust_anchor_uses(
            self, tenant: str, did: str, key_version: str
        ) -> None:
            # PUT /v1/trust/anchors/{did}/{key_version}/uses：收紧锚点
            # 版本的用途白名单（无需轮换即可撤销用途）。请求体必须恰含
            # from_uses、uses，两者均须为非空无重复字符串数组、取值限
            # 且按规范序；路径 key_version 须为 ASCII 十进制正整数。
            # 未知或跨租户锚点 404，已吊销 409；目标等于当前值幂等
            # 200 且无副作用，否则 from_uses 须等于当前值且目标为其
            # 真子集，前置不匹配或扩权均 409。200 按键序恰返 did、
            # key_version、uses；实际变更仅记一次
            # trust.anchor.uses.updated 审计。
            data = self._read_json()
            for field in ("from_uses", "uses"):
                if field not in data:
                    raise ValidationError(f"缺少字段: {field}")
            extra = sorted(set(data) - {"from_uses", "uses"})
            if extra:
                raise ValidationError(f"多余字段: {', '.join(extra)}")
            if (
                not key_version
                or any(ch < "0" or ch > "9" for ch in key_version)
                or int(key_version) < 1
            ):
                raise ValidationError("路径参数 key_version 必须为正整数")
            uses = store.update_trust_anchor_uses(
                tenant,
                did,
                int(key_version),
                data["from_uses"],
                data["uses"],
            )
            self._send_json(
                200,
                {
                    "did": did,
                    "key_version": int(key_version),
                    "uses": uses,
                },
            )

        def _post_trust_anchor_rotate(
            self, tenant: str, did: str
        ) -> None:
            # 请求体必须恰含 from_key_version（非布尔正整数）与
            # public_key（可解析的 P-256 PEM）；缺失、多余、类型或
            # PEM 非法一律 400。DID 不存在（含他租户）由 store 判 404。
            data = self._read_json()
            if "from_key_version" not in data:
                raise ValidationError("缺少字段: from_key_version")
            if "public_key" not in data:
                raise ValidationError("缺少字段: public_key")
            extra = sorted(
                set(data) - {"from_key_version", "public_key"}
            )
            if extra:
                raise ValidationError(f"多余字段: {', '.join(extra)}")
            from_key_version = data["from_key_version"]
            if (
                not isinstance(from_key_version, int)
                or isinstance(from_key_version, bool)
                or from_key_version < 1
            ):
                raise ValidationError(
                    "字段 from_key_version 必须为正整数"
                )
            record, created = store.rotate_trust_anchor(
                tenant, did, from_key_version, data["public_key"]
            )
            # 新建版本 201；同一前置同 PEM 的幂等重试 200。
            self._send_json(
                201 if created else 200,
                self._trust_anchor_payload(record),
            )

        def _post_trust_dids_verify_document(self, tenant: str) -> None:
            # 跨系统 DID 文档验真：公开错误协议，任何失败都返回
            # 200 + {"valid": false, "reason": "<非空中文原因>"}，成功仅
            # {"valid": true}。请求体须恰含 document（JSON 对象）；非法
            # JSON/非对象/缺失/多余字段均为请求类原因。纯只读，不登记
            # 资源、不写历史或审计，跨租户不可探测。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except (ValueError, TypeError):
                self._send_invalid("请求体缺失或长度声明非法")
                return
            except Exception:  # noqa: BLE001
                self._send_invalid("请求体读取失败")
                return
            if not raw:
                self._send_invalid("请求体缺失")
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._send_invalid("请求体不是合法 UTF-8 文本")
                return
            except json.JSONDecodeError:
                self._send_invalid("请求体不是合法 JSON")
                return

            try:
                valid, reason = store.verify_trust_did_document(tenant, data)
            except Exception:  # noqa: BLE001 验真失败绝不暴露内部细节
                self._send_invalid("验真过程发生内部错误")
                return
            payload: Dict[str, Any] = {"valid": valid}
            if not valid:
                payload["reason"] = reason or "DID 文档验真失败"
            self._send_json(200, payload)

        def _post_trust_dids_verify_document_batch(self, tenant: str) -> None:
            # 批量跨系统 DID 文档验真：与单项相同的公开错误协议，任何失败
            # 都返回 HTTP 200。请求体须恰为 {"documents": [文档...]}，
            # 数组非空且不超过 100 项；请求体非法（外层缺失、非法 JSON、
            # 非对象、字段缺失或多余、documents 非数组、空数组或超过上限）
            # 时返回 {"results": [], "reason": "请求..."}。请求级合法时
            # 返回 {"results": [...]}，长度与顺序与输入一致，逐项复用单项
            # 验真规则，失败不短路。纯只读，不登记资源，不写状态、历史或
            # 审计，仅使用当前租户锚点。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except (ValueError, TypeError):
                self._send_json(
                    200,
                    {"results": [],
                     "reason": "请求不合法: 请求体缺失或长度声明非法"},
                )
                return
            except Exception:  # noqa: BLE001
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体读取失败"}
                )
                return
            if not raw:
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体缺失"}
                )
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._send_json(
                    200,
                    {"results": [], "reason": "请求不合法: 请求体不是合法 UTF-8 文本"},
                )
                return
            except json.JSONDecodeError:
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体不是合法 JSON"}
                )
                return

            try:
                ok, reason, results = store.verify_trust_did_documents_batch(
                    tenant, data
                )
            except Exception:  # noqa: BLE001 验真失败绝不暴露内部细节
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 验真过程发生内部错误"}
                )
                return
            if not ok:
                self._send_json(
                    200, {"results": [], "reason": reason or "请求不合法"}
                )
                return
            self._send_json(200, {"results": results})

        def _post_trust_dids_deactivate_sync(self, tenant: str) -> None:
            # 外部 DID 停用通告登记。请求/字段非法由 _read_json 与 store
            # 抛 ValidationError -> 400（仅含非空中文 error）；同 did 已
            # 有不同通告由 store 抛 ConflictError -> 409（仅含 error）。
            # 锚点不可用、签名格式错误、验签失败均按公开错误协议返回
            # 200 + {"valid":false,"reason":...}（原因恰为“锚点不可用”/
            # “签名格式错误”/“签名校验失败”）且不写入。首次接受 201，
            # 完全重放 200；成功响应键序 valid、did、key_version、
            # reason、deactivated_at，valid=true。
            data = self._read_json()
            result = store.sync_did_deactivation_notice(tenant, data)
            if not result.get("valid"):
                self._send_invalid(result.get("reason") or "验签失败")
                return
            record = result["record"]
            self._send_json(
                result["status_code"],
                {
                    "valid": True,
                    "did": record.did,
                    "key_version": record.key_version,
                    "reason": record.reason,
                    "deactivated_at": record.deactivated_at,
                },
            )

        def _post_trust_dids_deactivate_sync_batch(self, tenant: str) -> None:
            # 批量外部 DID 停用通告登记：任何失败都返回 HTTP 200。请求体须
            # 恰为 {"items": [项...]}，数组非空且不超过 100 项；请求体非法
            # （外层缺失、非法 JSON、非对象、字段缺失或多余、items 非数组、
            # 空数组或超过上限）时返回 {"results": [], "reason": "请求..."}。
            # 请求级合法时返回 {"results": [...]}，长度与顺序与输入一致，
            # 逐项复用单项登记规则，失败不短路：项结构/字段错误 400、同 did
            # 异通告 409、锚点/签名失败 200、落盘失败 500 均收敛为单项结果
            # （含 http_status 与非空中文 reason），不影响其余项；成功项
            # 首次 201、完全重放 200。显式空 X-Tenant-ID 在此之前由路由
            # 统一判 400。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except (ValueError, TypeError):
                self._send_json(
                    200,
                    {"results": [],
                     "reason": "请求不合法: 请求体缺失或长度声明非法"},
                )
                return
            except Exception:  # noqa: BLE001
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体读取失败"}
                )
                return
            if not raw:
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体缺失"}
                )
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._send_json(
                    200,
                    {"results": [],
                     "reason": "请求不合法: 请求体不是合法 UTF-8 文本"},
                )
                return
            except json.JSONDecodeError:
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体不是合法 JSON"}
                )
                return

            try:
                ok, reason, results = (
                    store.sync_did_deactivation_notice_batch(tenant, data)
                )
            except Exception:  # noqa: BLE001 批量登记失败绝不暴露内部细节
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 登记过程发生内部错误"}
                )
                return
            if not ok:
                self._send_json(
                    200, {"results": [], "reason": reason or "请求不合法"}
                )
                return
            self._send_json(200, {"results": results})

        def _post_trust_verify(self, tenant: str) -> None:
            # 与凭证/演示 verify 相同的公开错误协议：任何失败都返回
            # 200 + {"valid": false, "reason": "<非空中文原因>"}。
            # 签名覆盖请求对象去掉 signature 后的规范化 JSON，用匹配
            # (issuer_did, issuer_key_version) 的 active 锚点公钥验签。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except (ValueError, TypeError):
                self._send_invalid("请求体缺失或长度声明非法")
                return
            except Exception:  # noqa: BLE001
                self._send_invalid("请求体读取失败")
                return
            if not raw:
                self._send_invalid("请求体缺失")
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._send_invalid("请求体不是合法 UTF-8 文本")
                return
            except json.JSONDecodeError:
                self._send_invalid("请求体不是合法 JSON")
                return

            try:
                valid, reason = store.verify_trust(tenant, data)
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_invalid("验签过程发生内部错误")
                return
            payload: Dict[str, Any] = {"valid": valid}
            if not valid:
                payload["reason"] = reason or "验签失败"
            self._send_json(200, payload)

        def _post_trust_credentials_verify(self, tenant: str) -> None:
            # 跨系统凭证验真：与其他验签端点相同的公开错误协议，任何失败
            # 都返回 200 + {"valid": false, "reason": "<非空中文原因>"}。
            # 请求体须恰含 body（对象）与 signature（非空字符串）；非法
            # JSON/非对象/缺失/多余字段均为请求类原因。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except (ValueError, TypeError):
                self._send_invalid("请求体缺失或长度声明非法")
                return
            except Exception:  # noqa: BLE001
                self._send_invalid("请求体读取失败")
                return
            if not raw:
                self._send_invalid("请求体缺失")
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._send_invalid("请求体不是合法 UTF-8 文本")
                return
            except json.JSONDecodeError:
                self._send_invalid("请求体不是合法 JSON")
                return

            try:
                valid, reason = store.verify_trust_credential(tenant, data)
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_invalid("验签过程发生内部错误")
                return
            payload: Dict[str, Any] = {"valid": valid}
            if not valid:
                payload["reason"] = reason or "验签失败"
            self._send_json(200, payload)

        def _post_trust_credentials_verify_synced(
            self, tenant: str
        ) -> None:
            # POST /v1/trust/credentials/verify-synced：以同步锚点验真
            # 外部凭证（只读）。请求体须恰含 signer_did（非空字符串）、
            # at（非布尔非负整数）、body（JSON 对象）、signature（非空
            # 字符串）；非法 JSON、非对象、键集或类型错误均 400 且仅
            # {"error": 非空中文}。signer_did 未同步或跨租户 404、at
            # 超过同步检查点 409，同形仅 {"error"}。外层合法后任何失败
            # 均 HTTP 200 按键序恰返 {"valid":false,"reason":...}：
            # 凭证字段错误沿用 /v1/trust/credentials/verify 的“凭证”
            # 分类原因；锚点取该来源 cursor<=at 的已同步事件、以
            # (issuer_did, 版本) 最后事件为准，缺失、非 active 或
            # uses 无 vc 均为“同步锚点不可用”；签名须为 ES256、64
            # 字节裸 R||S 无填充 base64url，格式错、验签错、到期依次
            # 为“签名格式错误”“签名校验失败”“凭证已过期”；成功仅
            # {"valid":true}。issuer_key_version 省略按 1 且不注入
            # 正文。纯只读：不改同步页、检查点、锚点、凭证、状态或
            # 审计，重启一致；租户头缺省 default、显式空 400 并隔离。
            data = self._read_json()
            required = ("signer_did", "at", "body", "signature")
            if set(data) != set(required):
                missing = [f for f in required if f not in data]
                if missing:
                    raise ValidationError(
                        f"请求缺少字段: {', '.join(missing)}"
                    )
                extra = sorted(set(data) - set(required))
                raise ValidationError(
                    f"请求含多余字段: {', '.join(extra)}"
                )
            signer_did = data["signer_did"]
            if not isinstance(signer_did, str) or not signer_did:
                raise ValidationError(
                    "请求不合法: 字段 signer_did 必须为非空字符串"
                )
            at = data["at"]
            if (
                not isinstance(at, int)
                or isinstance(at, bool)
                or at < 0
            ):
                raise ValidationError(
                    "请求不合法: 字段 at 必须为非布尔非负整数"
                )
            body = data["body"]
            if not isinstance(body, dict):
                raise ValidationError(
                    "请求不合法: 字段 body 必须为 JSON 对象"
                )
            signature = data["signature"]
            if not isinstance(signature, str) or not signature:
                raise ValidationError(
                    "请求不合法: 字段 signature 必须为非空字符串"
                )
            try:
                valid, reason = store.verify_trust_credential_synced(
                    tenant, signer_did, at, body, signature
                )
            except (NotFoundError, ConflictError):
                raise
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_invalid("验签过程发生内部错误")
                return
            if not valid:
                self._send_invalid(reason or "验签失败")
                return
            self._send_json(200, {"valid": True})

        def _post_trust_credentials_verify_synced_with_status(
            self, tenant: str
        ) -> None:
            # POST /v1/trust/credentials/verify-synced-with-status：以
            # 同步锚点验真外部凭证并合并请求初始本租户状态快照（只读）。
            # 请求体须恰含 signer_did（非空字符串）、at（非布尔非负
            # 整数）、body（JSON 对象）、signature（非空字符串）；空体、
            # 非法 JSON、非对象、键集或类型错误均 400 且仅
            # {"error": 非空中文}。signer_did 未同步或跨租户 404、at
            # 超过同步检查点 409，同形仅 {"error"}。外层合法后任何失败
            # 均 HTTP 200 按键序恰返 {"valid":false,"reason":...}：
            # 凭证字段、锚点、签名覆盖、格式、验签、期限、校验顺序及
            # 原因完全沿用 verify-synced，原验真失败不查状态；验真成功
            # 后以请求初始一次原子读取的本租户状态快照查
            # (issuer_did, credential_id)：未同步、revoked、unknown
            # 依次为“外部凭证状态未同步”“外部凭证已吊销：<reason>”
            # （空或缺失 reason 用“未知原因”）“外部凭证状态未知”，
            # active 成功；成功仅 {"valid":true}。纯只读：不改同步页、
            # 检查点、锚点、凭证、状态或审计，重启一致；租户头缺省
            # default、显式空 400 并隔离。
            data = self._read_json()
            required = ("signer_did", "at", "body", "signature")
            if set(data) != set(required):
                missing = [f for f in required if f not in data]
                if missing:
                    raise ValidationError(
                        f"请求缺少字段: {', '.join(missing)}"
                    )
                extra = sorted(set(data) - set(required))
                raise ValidationError(
                    f"请求含多余字段: {', '.join(extra)}"
                )
            signer_did = data["signer_did"]
            if not isinstance(signer_did, str) or not signer_did:
                raise ValidationError(
                    "请求不合法: 字段 signer_did 必须为非空字符串"
                )
            at = data["at"]
            if (
                not isinstance(at, int)
                or isinstance(at, bool)
                or at < 0
            ):
                raise ValidationError(
                    "请求不合法: 字段 at 必须为非布尔非负整数"
                )
            body = data["body"]
            if not isinstance(body, dict):
                raise ValidationError(
                    "请求不合法: 字段 body 必须为 JSON 对象"
                )
            signature = data["signature"]
            if not isinstance(signature, str) or not signature:
                raise ValidationError(
                    "请求不合法: 字段 signature 必须为非空字符串"
                )
            try:
                valid, reason = (
                    store.verify_trust_credential_synced_with_status(
                        tenant, signer_did, at, body, signature
                    )
                )
            except (NotFoundError, ConflictError):
                raise
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_invalid("验签过程发生内部错误")
                return
            if not valid:
                self._send_invalid(reason or "验签失败")
                return
            self._send_json(200, {"valid": True})

        def _post_trust_credentials_verify_synced_batch(
            self, tenant: str
        ) -> None:
            # POST /v1/trust/credentials/verify-synced-batch：批量以同步
            # 锚点快照验真外部凭证（只读）。请求体须恰含 signer_did
            # （非空字符串）、at（非布尔非负整数）、credentials
            # （1–100 项数组）；空体、非法 JSON、非对象、键集或类型
            # 错误、空数组或超限均 400 且仅 {"error":"请求非法"}；
            # 来源未同步或跨租户 404 仅 {"error":"同步来源不存在"}，
            # at 超检查点 409 仅 {"error":"同步游标冲突"}。合法时 200
            # 仅返 {"results":[...]}，逐项不短路、等长同序：项须恰含
            # body（对象）与非空 signature，否则该项
            # {"valid":false,"reason":"请求项非法"}；合法项沿用单条
            # verify-synced 的凭证字段、版本兼容、签名覆盖、有效期及
            # 校验顺序，按该来源 cursor<=at 的 (DID,版本) 末项验真，
            # 锚点缺失/非 active/uses 无 vc 为“同步锚点不可用”，格式、
            # 验签、过期依次为“签名格式错误”“签名校验失败”“凭证已
            # 过期”，字段错误以“凭证”开头；成功项仅 {"valid":true}，
            # 失败项键序 valid、reason。纯只读：不改同步页、检查点、
            # 锚点、凭证、状态或审计，重启一致；租户头缺省 default、
            # 显式空 400 并隔离。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except Exception:  # noqa: BLE001 请求非法绝不暴露内部细节
                self._send_error(400, "请求非法")
                return
            if not raw:
                self._send_error(400, "请求非法")
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_error(400, "请求非法")
                return
            if not isinstance(data, dict) or set(data) != {
                "signer_did",
                "at",
                "credentials",
            }:
                self._send_error(400, "请求非法")
                return
            signer_did = data["signer_did"]
            at = data["at"]
            credentials = data["credentials"]
            if (
                not isinstance(signer_did, str)
                or not signer_did
                or not isinstance(at, int)
                or isinstance(at, bool)
                or at < 0
                or not isinstance(credentials, list)
                or not 1 <= len(credentials) <= 100
            ):
                self._send_error(400, "请求非法")
                return
            try:
                results = store.verify_trust_credentials_synced_batch(
                    tenant, signer_did, at, credentials
                )
            except NotFoundError:
                self._send_error(404, "同步来源不存在")
                return
            except ConflictError:
                self._send_error(409, "同步游标冲突")
                return
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_error(500, "服务器内部错误")
                return
            self._send_json(200, {"results": results})

        def _post_trust_credentials_verify_synced_batch_with_status(
            self, tenant: str
        ) -> None:
            # POST /v1/trust/credentials/verify-synced-batch-with-status：
            # 批量以同步锚点快照验真外部凭证并合并批初本租户状态快照
            # （只读）。请求级协议与 verify-synced-batch 完全一致：请求体
            # 须恰含 signer_did（非空字符串）、at（非布尔非负整数）、
            # credentials（1–100 项数组）；空体、非法 JSON、非对象、键集
            # 或类型错误、空数组或超限均 400 且仅 {"error":"请求非法"}；
            # 来源未同步或跨租户 404 仅 {"error":"同步来源不存在"}，at
            # 超检查点 409 仅 {"error":"同步游标冲突"}，均先于逐项校验。
            # 合法时 200 仅返 {"results":[...]}，逐项不短路、等长同序：
            # 项须恰含 body（对象）与非空 signature，否则该项
            # {"valid":false,"reason":"请求项非法"}；合法项沿用
            # verify-synced-batch 的凭证字段、版本兼容、cursor<=at 末
            # 锚点、签名、期限、顺序及原因；验真通过后按 (issuer_did,
            # credential_id) 查批初原子读取的本租户状态快照：未同步、
            # revoked、unknown 分别返“外部凭证状态未同步”“外部凭证已
            # 吊销：<reason>”（空原因用“未知原因”）“外部凭证状态未
            # 知”，active 成功。成功项仅 {"valid":true}，失败项键序
            # valid、reason。纯只读：不写状态或审计；租户头缺省
            # default、显式空 400 并隔离。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except Exception:  # noqa: BLE001 请求非法绝不暴露内部细节
                self._send_error(400, "请求非法")
                return
            if not raw:
                self._send_error(400, "请求非法")
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_error(400, "请求非法")
                return
            if not isinstance(data, dict) or set(data) != {
                "signer_did",
                "at",
                "credentials",
            }:
                self._send_error(400, "请求非法")
                return
            signer_did = data["signer_did"]
            at = data["at"]
            credentials = data["credentials"]
            if (
                not isinstance(signer_did, str)
                or not signer_did
                or not isinstance(at, int)
                or isinstance(at, bool)
                or at < 0
                or not isinstance(credentials, list)
                or not 1 <= len(credentials) <= 100
            ):
                self._send_error(400, "请求非法")
                return
            try:
                results = (
                    store.verify_trust_credentials_synced_batch_with_status(
                        tenant, signer_did, at, credentials
                    )
                )
            except NotFoundError:
                self._send_error(404, "同步来源不存在")
                return
            except ConflictError:
                self._send_error(409, "同步游标冲突")
                return
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_error(500, "服务器内部错误")
                return
            self._send_json(200, {"results": results})

        def _post_trust_credentials_verify_receipt(self, tenant: str) -> None:
            # POST /v1/trust/credentials/verify-receipt：跨系统凭证验真
            # 签名回执（纯只读）。
            # 1) 请求体须恰含 body、signature、verifier_did、nonce：
            #    非法 JSON/非对象、键集不符、verifier_did 非非空串、
            #    nonce 非 1..256 码点非空串均 400 且仅 {error}；
            # 2) body、signature 按既有外部凭证验真全规则处理，任一失败
            #    先 200 恰返 {valid:false,reason}（沿用原原因），不查询
            #    验证者；
            # 3) 仅成功才查本租户验证者 DID：未知或跨租户 404、停用 409，
            #    均仅 {error}；
            # 4) 成功 200 按键序恰为 valid、receipt、receipt_signature；
            #    receipt 恰含 credential_id、issuer_did、issuer_key_version、
            #    credential_digest、verifier_did、verifier_key_version、
            #    nonce，摘要为 {body,signature} 递归键升序紧凑 UTF-8 JSON
            #    的 SHA-256 小写 64 位 hex；receipt_signature 以验证者当前
            #    私钥对 receipt 规范化 JSON 按 ES256 裸 R||S 无填充
            #    base64url 规则签名。不落盘、不审计。
            data = self._read_json()
            expected_fields = (
                "body",
                "signature",
                "verifier_did",
                "nonce",
            )
            if set(data) != set(expected_fields):
                missing = [f for f in expected_fields if f not in data]
                if missing:
                    raise ValidationError(
                        f"缺少字段: {', '.join(missing)}"
                    )
                extra = sorted(set(data) - set(expected_fields))
                raise ValidationError(
                    f"多余字段: {', '.join(extra)}"
                )
            verifier_did = data["verifier_did"]
            if not isinstance(verifier_did, str) or not verifier_did:
                raise ValidationError(
                    "字段 verifier_did 必须为非空字符串"
                )
            nonce = data["nonce"]
            if not isinstance(nonce, str) or not nonce:
                raise ValidationError("字段 nonce 必须为非空字符串")
            if not 1 <= len(nonce) <= 256:
                raise ValidationError(
                    "字段 nonce 长度须为 1 到 256 个 Unicode 码点"
                )

            # 先按既有外部凭证验真全规则处理 body、signature；失败沿用
            # 原原因返回 200/valid:false，且不查询验证者 DID。
            verify_data = {"body": data["body"], "signature": data["signature"]}
            try:
                valid, reason = store.verify_trust_credential(
                    tenant, verify_data
                )
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_invalid("验签过程发生内部错误")
                return
            if not valid:
                self._send_json(
                    200,
                    {"valid": False, "reason": reason or "验签失败"},
                )
                return

            body = verify_data["body"]
            issuer_key_version = body.get("issuer_key_version", 1)

            # 仅验真成功才查本租户验证者 DID：未知（含跨租户）404、
            # 停用 409，均仅 {error}。
            verifier_key_version, verifier_private_pem = (
                store.get_verify_receipt_signer(tenant, verifier_did)
            )

            # 摘要覆盖 {body,signature} 的递归键升序紧凑 UTF-8 JSON。
            digest_input = {"body": body, "signature": data["signature"]}
            credential_digest = hashlib.sha256(
                crypto.canonicalize(digest_input)
            ).hexdigest()
            receipt = {
                "credential_id": body["credential_id"],
                "issuer_did": body["issuer_did"],
                "issuer_key_version": issuer_key_version,
                "credential_digest": credential_digest,
                "verifier_did": verifier_did,
                "verifier_key_version": verifier_key_version,
                "nonce": nonce,
            }
            receipt_signature = crypto.sign(receipt, verifier_private_pem)
            self._send_json(
                200,
                {
                    "valid": True,
                    "receipt": receipt,
                    "receipt_signature": receipt_signature,
                },
            )

        @staticmethod
        def _validate_receipt_envelope(data: Dict[str, Any]) -> None:
            """校验回执请求/批量项的外层结构（receipt/verify、
            receipt/consume 单条请求体与 consume-batch 逐项共用）。

            须恰含 receipt、receipt_signature、body、signature、
            nonce：receipt、body 为 JSON 对象，receipt_signature、
            signature、nonce 为非空字符串且 nonce 为 1..256 码点；
            键集或类型不符一律抛 ValidationError。
            """
            expected_fields = (
                "receipt",
                "receipt_signature",
                "body",
                "signature",
                "nonce",
            )
            if set(data) != set(expected_fields):
                missing = [f for f in expected_fields if f not in data]
                if missing:
                    raise ValidationError(
                        f"缺少字段: {', '.join(missing)}"
                    )
                extra = sorted(set(data) - set(expected_fields))
                raise ValidationError(
                    f"多余字段: {', '.join(extra)}"
                )
            if not isinstance(data["receipt"], dict):
                raise ValidationError("字段 receipt 必须为 JSON 对象")
            if not isinstance(data["body"], dict):
                raise ValidationError("字段 body 必须为 JSON 对象")
            for field in ("receipt_signature", "signature"):
                if not isinstance(data[field], str) or not data[field]:
                    raise ValidationError(
                        f"字段 {field} 必须为非空字符串"
                    )
            nonce = data["nonce"]
            if not isinstance(nonce, str) or not nonce:
                raise ValidationError("字段 nonce 必须为非空字符串")
            if not 1 <= len(nonce) <= 256:
                raise ValidationError(
                    "字段 nonce 长度须为 1 到 256 个 Unicode 码点"
                )

        def _read_receipt_verify_request(self) -> Dict[str, Any]:
            """receipt/verify 与 receipt/consume 共用的外层请求校验。

            请求体须恰含 receipt、receipt_signature、body、signature、
            nonce：receipt、body 为 JSON 对象，receipt_signature、
            signature、nonce 为非空字符串且 nonce 为 1..256 码点；
            非法 JSON/非对象、键集或类型不符一律抛 ValidationError
            （400 且仅 {error}）。
            """
            data = self._read_json()
            self._validate_receipt_envelope(data)
            return data

        def _post_trust_credentials_receipt_verify(self, tenant: str) -> None:
            # POST /v1/trust/credentials/receipt/verify：只读校验跨系统
            # 凭证验真签名回执。
            # 1) 请求体须恰含 receipt、receipt_signature、body、
            #    signature、nonce：receipt、body 为 JSON 对象，
            #    receipt_signature、signature、nonce 为非空字符串且
            #    nonce 为 1..256 码点；非法 JSON/非对象、键集或类型
            #    不符一律 400 且仅 {error}；
            # 2) 外层合法后任何失败均 HTTP 200，按键序恰返
            #    {valid:false, reason}，按序检查：回执非法（恰为
            #    verify-receipt 七字段且类型沿用公开协议）-> nonce错误
            #    （两处 nonce 相等）-> 绑定错误（receipt 的
            #    credential_id/issuer_did/issuer_key_version 与 body
            #    相等，缺版本按 1）-> 摘要错误（按原规则用
            #    {body,signature} 复算 credential_digest）-> 锚点不可用
            #    （本租户 verifier_did/版本 active 且含 vc 用途锚点）
            #    -> 签名格式错误 -> 签名校验失败（receipt_signature
            #    覆盖完整 receipt，ES256 裸 R||S 无填充 base64url）；
            # 3) 成功仅 {"valid":true}。不重验凭证签名、不审计；纯只读。
            data = self._read_receipt_verify_request()
            reason = self._verify_credential_receipt_item(tenant, data)
            if reason is not None:
                self._send_json(200, {"valid": False, "reason": reason})
                return
            self._send_json(200, {"valid": True})

        def _post_trust_credentials_receipt_consume(self, tenant: str) -> None:
            # POST /v1/trust/credentials/receipt/consume：验真并消费
            # 跨系统凭证验真签名回执（防重放）。
            # 1) 请求与字段约束同 receipt/verify：恰含 receipt、
            #    receipt_signature、body、signature、nonce；外层非法
            #    一律 400 且仅 {error}；
            # 2) 外层合法后先按七阶段顺序验真，失败沿用原 HTTP 200、
            #    固定 reason 及优先级，不写状态、不记审计；
            # 3) 验真成功后按租户以 (verifier_did, nonce) 为唯一键
            #    消费：首次 200 按序恰返 valid、receipt_id、
            #    consumed_at（valid:true，receipt_id 为 receipt 规范
            #    化 JSON 字节的 SHA-256 小写 64 位 hex，consumed_at
            #    为 UTC 秒精度 Z）；同键重放（receipt 可不同）200
            #    恰返 {"valid":false,"reason":"回执已消费"}；并发
            #    仅一次成功；
            # 4) 首次消费与审计（trust.credential.receipt.consumed /
            #    credential_receipt / receipt_id）同一次原子落盘；
            #    重放与验真失败不记；落盘失败回滚二者，500 仅返
            #    {"error":"存储失败"}，可重试；重启仍判重。
            data = self._read_receipt_verify_request()
            reason = self._verify_credential_receipt_item(tenant, data)
            if reason is not None:
                self._send_json(200, {"valid": False, "reason": reason})
                return
            receipt = data["receipt"]
            receipt_id = hashlib.sha256(
                crypto.canonicalize(receipt)
            ).hexdigest()
            try:
                consumed, consumed_at = store.consume_credential_receipt(
                    tenant,
                    receipt["verifier_did"],
                    receipt["nonce"],
                    receipt_id,
                )
            except StorageError:
                self._send_error(500, "存储失败")
                return
            if not consumed:
                self._send_json(
                    200, {"valid": False, "reason": "回执已消费"}
                )
                return
            self._send_json(
                200,
                {
                    "valid": True,
                    "receipt_id": receipt_id,
                    "consumed_at": consumed_at,
                },
            )

        def _post_trust_credentials_receipt_consume_batch(
            self, tenant: str
        ) -> None:
            # POST /v1/trust/credentials/receipt/consume-batch：批量验真
            # 并消费跨系统凭证验真签名回执（防重放）。
            # 1) 请求体须恰为 {"items": [项...]}，数组非空且不超过 100
            #    项；空体、非法 JSON、非对象、键集错误、items 非数组/
            #    空/超限均 HTTP 200 按键序返
            #    {"results": [], "reason": "请求..."}；
            # 2) 合法批次逐项处理、失败不短路：项须恰含 receipt、
            #    receipt_signature、body、signature、nonce，类型与
            #    nonce 规则同单条；项结构非法 ->
            #    {"valid": false, "reason": "请求项非法"}；其余复用单条
            #    七阶段顺序、reason 及优先级，失败项不写状态、不记审计；
            # 3) 验真通过后按租户 (verifier_did, nonce) 判重：批内首项
            #    成功，后项或历史重放 ->
            #    {"valid": false, "reason": "回执已消费"}；成功项键序
            #    valid、receipt_id、consumed_at，取值同单条；results
            #    与输入等长同序；
            # 4) 本批全部新消费与审计同锁原子落盘；失败全回滚，500 仅
            #    返 {"error": "存储失败"}；与单条 consume 并发每键仅
            #    一次成功，重启保持。显式空 X-Tenant-ID 由路由统一
            #    判 400。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except (ValueError, TypeError):
                self._send_json(
                    200,
                    {"results": [],
                     "reason": "请求不合法: 请求体缺失或长度声明非法"},
                )
                return
            except Exception:  # noqa: BLE001
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体读取失败"}
                )
                return
            if not raw:
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体缺失"}
                )
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._send_json(
                    200,
                    {"results": [],
                     "reason": "请求不合法: 请求体不是合法 UTF-8 文本"},
                )
                return
            except json.JSONDecodeError:
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体不是合法 JSON"}
                )
                return

            def _request_invalid(reason: str) -> None:
                self._send_json(200, {"results": [], "reason": reason})

            if not isinstance(data, dict):
                _request_invalid("请求不合法: 请求体必须为 JSON 对象")
                return
            if set(data) != {"items"}:
                if "items" not in data:
                    _request_invalid("请求缺少字段: items")
                    return
                extra = sorted(set(data) - {"items"})
                _request_invalid(f"请求含多余字段: {', '.join(extra)}")
                return
            items = data["items"]
            if not isinstance(items, list):
                _request_invalid("请求不合法: 字段 items 必须为数组")
                return
            if not items:
                _request_invalid("请求不合法: items 数组不能为空")
                return
            if len(items) > 100:
                _request_invalid(
                    "请求不合法: items 数组不能超过 100 项"
                    f"（当前 {len(items)} 项）"
                )
                return

            results: List[Optional[Dict[str, Any]]] = []
            # 验真通过、待判重消费的项：(结果下标, verifier_did, nonce,
            # receipt_id)，消费判定在全部验真完成后同锁一次完成。
            pending: List[Tuple[int, str, str, str]] = []
            for index, item in enumerate(items):  # 顺序处理，失败不短路
                if not isinstance(item, dict):
                    results.append({"valid": False, "reason": "请求项非法"})
                    continue
                try:
                    self._validate_receipt_envelope(item)
                except ValidationError:
                    results.append({"valid": False, "reason": "请求项非法"})
                    continue
                reason = self._verify_credential_receipt_item(tenant, item)
                if reason is not None:
                    results.append({"valid": False, "reason": reason})
                    continue
                receipt_id = hashlib.sha256(
                    crypto.canonicalize(item["receipt"])
                ).hexdigest()
                pending.append(
                    (
                        index,
                        item["receipt"]["verifier_did"],
                        item["receipt"]["nonce"],
                        receipt_id,
                    )
                )
                results.append(None)  # 占位，消费判定后回填

            if pending:
                try:
                    outcomes = store.consume_credential_receipts_batch(
                        tenant,
                        [
                            (verifier_did, nonce, receipt_id)
                            for _, verifier_did, nonce, receipt_id in pending
                        ],
                    )
                except StorageError:
                    self._send_error(500, "存储失败")
                    return
                for (index, _, _, receipt_id), (consumed, consumed_at) in zip(
                    pending, outcomes
                ):
                    if consumed:
                        results[index] = {
                            "valid": True,
                            "receipt_id": receipt_id,
                            "consumed_at": consumed_at,
                        }
                    else:
                        results[index] = {
                            "valid": False,
                            "reason": "回执已消费",
                        }
            self._send_json(200, {"results": results})

        def _get_trust_credential_receipt_consumptions(
            self, tenant: str, query: str
        ) -> None:
            # GET /v1/trust/credentials/receipt/consumptions：只读查询
            # 本租户验真回执消费历史。
            # 查询参数仅允许 limit、after、verifier_did，且均只能出现
            # 一次：
            # - limit 缺省 50，须为 1..200 的非空 ASCII 十进制整数；
            # - after 缺省 0，须为非空非负 ASCII 十进制整数；
            # - verifier_did 可省略，提供时须为非空字符串。
            # 空值、重复参数、未知参数一律 400 且仅含非空中文 error。
            # 先按 verifier_did 精确过滤，再取 cursor > after 的前
            # limit 项并按 cursor 升序。200 键序恰为 events、next_after；
            # 事件键序恰为 cursor、receipt_id、verifier_did、nonce、
            # consumed_at（cursor 为正整数，其余四值为字符串，
            # consumed_at 为 UTC 秒精度 Z）；空页 next_after 等于 after。
            # 无任何事件也返回 200 空数组。纯只读：不写状态或审计。
            params = parse_qs(query, keep_blank_values=True)
            allowed = {"limit", "after", "verifier_did"}
            unknown = sorted(set(params) - allowed)
            if unknown:
                raise ValidationError(
                    f"不支持的查询参数: {', '.join(unknown)}"
                )

            def _single(name: str) -> Optional[str]:
                values = params.get(name)
                if values is None:
                    return None
                if len(values) != 1:
                    raise ValidationError(
                        f"查询参数 {name} 只能提供一次"
                    )
                return values[0]

            limit_raw = _single("limit")
            if limit_raw is not None:
                limit = _parse_nonneg_int(limit_raw, "limit")
                if not 1 <= limit <= 200:
                    raise ValidationError(
                        "查询参数 limit 须在 1 到 200 之间"
                    )
            else:
                limit = 50

            after_raw = _single("after")
            if after_raw is not None:
                after = _parse_nonneg_int(after_raw, "after")
            else:
                after = 0

            verifier_did = _single("verifier_did")
            if verifier_did is not None and not verifier_did:
                raise ValidationError(
                    "查询参数 verifier_did 必须为非空字符串"
                )

            events, next_after = store.list_receipt_consumptions(
                tenant,
                after,
                limit,
                verifier_did=verifier_did,
            )
            self._send_json(
                200,
                {
                    "events": [
                        {
                            "cursor": event.cursor,
                            "receipt_id": event.receipt_id,
                            "verifier_did": event.verifier_did,
                            "nonce": event.nonce,
                            "consumed_at": event.consumed_at,
                        }
                        for event in events
                    ],
                    "next_after": next_after,
                },
            )

        def _get_trust_credential_receipt_consumptions_export(
            self, tenant: str, query: str
        ) -> None:
            # GET /v1/trust/credentials/receipt/consumptions/export：确定性
            # NDJSON 导出本租户验真回执消费历史，支持快照续传。
            # 查询参数仅允许 limit、after、snapshot，且均只能出现一次：
            # - limit 缺省 1000，须为 1..10000 的非空 ASCII 十进制整数；
            # - after 缺省 0，须为非负 ASCII 十进制整数；
            # - snapshot 缺省为请求开始时原子读取的租户最大 cursor
            #   （无事件为 0），显式提供时须为非负 ASCII 十进制整数且
            #   不超过当时最大值；
            # - after 不得大于生效 snapshot。
            # 空值、重复参数、未知参数、格式或范围非法一律 400 且恰返
            # {"error": "非空中文原因"}。取 after < cursor <= snapshot
            # 按 cursor 升序的前 limit 条。成功 200，类型
            # application/x-ndjson; charset=utf-8；响应头
            # X-Snapshot-Cursor 为生效快照、X-Next-After 为末行
            # cursor（空结果为 after）。每行键序 cursor、receipt_id、
            # verifier_did、nonce、consumed_at，UTF-8 紧凑 JSON、
            # 非 ASCII 不转义、RFC8259 最短转义、LF 结行（末行亦有
            # LF）、无 BOM，空结果零字节。同一 snapshot 续页天然排除
            # 快照后新事件。纯只读：不改游标、状态或审计。
            params = parse_qs(query, keep_blank_values=True)
            allowed = {"limit", "after", "snapshot"}
            unknown = sorted(set(params) - allowed)
            if unknown:
                raise ValidationError(
                    f"不支持的查询参数: {', '.join(unknown)}"
                )

            def _single(name: str) -> Optional[str]:
                values = params.get(name)
                if values is None:
                    return None
                if len(values) != 1:
                    raise ValidationError(
                        f"查询参数 {name} 只能提供一次"
                    )
                return values[0]

            limit_raw = _single("limit")
            if limit_raw is not None:
                limit = _parse_nonneg_int(limit_raw, "limit")
                if not 1 <= limit <= 10000:
                    raise ValidationError(
                        "查询参数 limit 须在 1 到 10000 之间"
                    )
            else:
                limit = 1000

            after_raw = _single("after")
            if after_raw is not None:
                after = _parse_nonneg_int(after_raw, "after")
            else:
                after = 0

            snapshot_raw = _single("snapshot")
            snapshot: Optional[int] = (
                _parse_nonneg_int(snapshot_raw, "snapshot")
                if snapshot_raw is not None
                else None
            )

            events, snapshot_cursor, next_after = (
                store.export_receipt_consumption_events(
                    tenant, after, limit, snapshot=snapshot
                )
            )
            body = _receipt_consumption_ndjson_bytes(events)
            self.send_response(200)
            self.send_header(
                "Content-Type", "application/x-ndjson; charset=utf-8"
            )
            self.send_header("X-Snapshot-Cursor", str(snapshot_cursor))
            self.send_header("X-Next-After", str(next_after))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _parse_receipt_consumption_manifest_query(
            self, query: str
        ) -> Dict[str, Any]:
            # 回执消费历史清单查询参数：取既有 export 的 limit、after、
            # snapshot（snapshot 必填）加唯一 signer_did。任何空值、重复、
            # 未知参数、格式或范围非法均抛 ValidationError（HTTP 400，仅含
            # 非空中文 error）。filters 仅 after、limit 两键，值为生效整数。
            params = parse_qs(query, keep_blank_values=True)
            allowed = {"limit", "after", "snapshot", "signer_did"}
            unknown = sorted(set(params) - allowed)
            if unknown:
                raise ValidationError(
                    f"不支持的查询参数: {', '.join(unknown)}"
                )

            def _single(name: str) -> Optional[str]:
                values = params.get(name)
                if values is None:
                    return None
                if len(values) != 1:
                    raise ValidationError(
                        f"查询参数 {name} 只能提供一次"
                    )
                return values[0]

            limit_raw = _single("limit")
            if limit_raw is not None:
                limit = _parse_nonneg_int(limit_raw, "limit")
                if not 1 <= limit <= 10000:
                    raise ValidationError(
                        "查询参数 limit 须在 1 到 10000 之间"
                    )
            else:
                limit = 1000

            after_raw = _single("after")
            after = (
                _parse_nonneg_int(after_raw, "after")
                if after_raw is not None
                else 0
            )

            snapshot_raw = _single("snapshot")
            if snapshot_raw is None:
                raise ValidationError("查询参数 snapshot 必填")
            snapshot = _parse_nonneg_int(snapshot_raw, "snapshot")

            signer_did = _single("signer_did")
            if signer_did is None or not signer_did:
                raise ValidationError(
                    "查询参数 signer_did 必填且必须为非空字符串"
                )

            # filters 仅 after、limit，取生效整数（含缺省值）。
            filters = {"after": after, "limit": limit}
            return {
                "after": after,
                "limit": limit,
                "snapshot": snapshot,
                "signer_did": signer_did,
                "filters": filters,
            }

        def _get_trust_credential_receipt_consumptions_manifest(
            self, tenant: str, query: str
        ) -> None:
            # GET /v1/trust/credentials/receipt/consumptions/manifest：
            # 对一次回执消费历史的确定性导出（与 export 同 limit/after/
            # snapshot，snapshot 必填）生成签名摘要清单，公开协议沿用停用
            # 通告清单。参数/snapshot 越界 400（仅 error）；签名 DID 未知
            # （含他租户）404、已停用 409（400 判定优先）。200 键序
            # snapshot、filters、count、alg、digest、signer_did、
            # key_version、signature；filters 键序 after、limit，值为生效
            # 整数；count 为本页非负整数行数；alg 恒为 SHA-256；digest 为
            # 本页 NDJSON 字节（与 export 同形状）的 64 位小写 hex
            # SHA-256；signature 由签名 DID 当前私钥对前七键规范化 JSON 做
            # ES256 裸 R||S 无填充 base64url 签名。纯只读。
            args = self._parse_receipt_consumption_manifest_query(query)

            # 先做快照越界校验（400 优先于签名 DID 的 404/409）。
            events, effective_snapshot, _ = (
                store.export_receipt_consumption_events(
                    tenant,
                    args["after"],
                    args["limit"],
                    snapshot=args["snapshot"],
                )
            )

            # 签名 DID 须为本租户活动本地 DID：未知 404、停用 409。
            signer_did = args["signer_did"]
            key_version, private_pem = (
                store.get_receipt_consumption_manifest_signer(
                    tenant, signer_did
                )
            )

            ndjson_bytes = _receipt_consumption_ndjson_bytes(events)
            digest = hashlib.sha256(ndjson_bytes).hexdigest()
            signed = {
                "snapshot": effective_snapshot,
                "filters": args["filters"],
                "count": len(events),
                "alg": "SHA-256",
                "digest": digest,
                "signer_did": signer_did,
                "key_version": key_version,
            }
            signature = crypto.sign(signed, private_pem)
            manifest = dict(signed)
            manifest["signature"] = signature
            self._send_json(200, manifest)

        def _receipt_consumption_manifest_is_well_formed(
            self, manifest: Any
        ) -> bool:
            # 回执消费历史清单结构校验（阶段一“清单非法”）：顶层恰含八键
            # 且类型/取值合法；filters 恰含 after、limit 两键且值为生效
            # 整数（after 非负、limit 为 1..10000 的正整数）。
            if not isinstance(manifest, dict):
                return False
            expected = {
                "snapshot",
                "filters",
                "count",
                "alg",
                "digest",
                "signer_did",
                "key_version",
                "signature",
            }
            if set(manifest) != expected:
                return False

            def _is_nonneg_int(value: Any) -> bool:
                return (
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and value >= 0
                )

            def _is_positive_int(value: Any) -> bool:
                return (
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and value >= 1
                )

            if not _is_nonneg_int(manifest["snapshot"]):
                return False
            if not _is_nonneg_int(manifest["count"]):
                return False
            if manifest["alg"] != "SHA-256":
                return False
            if not (
                isinstance(manifest["digest"], str)
                and _SHA256_HEX_RE.fullmatch(manifest["digest"])
            ):
                return False
            if (
                not isinstance(manifest["signer_did"], str)
                or not manifest["signer_did"]
            ):
                return False
            if not _is_positive_int(manifest["key_version"]):
                return False
            if (
                not isinstance(manifest["signature"], str)
                or not manifest["signature"]
            ):
                return False

            filters = manifest["filters"]
            if not isinstance(filters, dict):
                return False
            if set(filters) != {"after", "limit"}:
                return False
            if not _is_nonneg_int(filters["after"]):
                return False
            limit = filters["limit"]
            if not (_is_positive_int(limit) and 1 <= limit <= 10000):
                return False
            return True

        def _post_trust_credential_receipt_consumptions_manifest_verify(
            self, tenant: str
        ) -> None:
            # POST /v1/trust/credentials/receipt/consumptions/manifest/
            # verify：校验一次回执消费历史导出清单与其 NDJSON 内容，公开
            # 协议沿用停用通告清单验真。外层错误（非法 JSON/非对象/缺漏或
            # 多余字段/manifest 非对象/ndjson 非字符串）一律 400 且仅
            # {"error": ...}。外层合法后任何失败均 HTTP 200，按序返回
            # {"valid":false,"reason":...}：清单非法 -> 锚点不可用
            # （本租户同 did/版本且含 vc 用途的 active 锚点）-> 签名格式
            # 错误 -> 签名校验失败 -> 导出内容不匹配（UTF-8 SHA-256 摘要
            # 及 LF 行数）。成功仅 {"valid":true}。纯只读、租户隔离、不记
            # 审计，结论跨重启稳定。
            data = self._read_json()
            if set(data) != {"manifest", "ndjson"}:
                missing = [f for f in ("manifest", "ndjson") if f not in data]
                if missing:
                    raise ValidationError(
                        f"请求缺少字段: {', '.join(missing)}"
                    )
                extra = sorted(set(data) - {"manifest", "ndjson"})
                raise ValidationError(f"请求含多余字段: {', '.join(extra)}")
            manifest = data["manifest"]
            ndjson = data["ndjson"]
            if not isinstance(manifest, dict):
                raise ValidationError(
                    "请求不合法: 字段 manifest 必须为 JSON 对象"
                )
            if not isinstance(ndjson, str):
                raise ValidationError(
                    "请求不合法: 字段 ndjson 必须为字符串"
                )

            reason = self._verify_receipt_consumption_manifest_item(
                tenant, manifest, ndjson
            )
            if reason is not None:
                self._send_json(200, {"valid": False, "reason": reason})
                return
            self._send_json(200, {"valid": True})

        def _verify_receipt_consumption_manifest_item(
            self, tenant: str, manifest: Any, ndjson: str
        ) -> Optional[str]:
            # 单项回执消费历史清单验真：按序返回失败原因（清单非法 ->
            # 锚点不可用 -> 签名格式错误 -> 签名校验失败 -> 导出内容不
            # 匹配），成功返回 None。锚点须为本租户同 did/版本 active 且
            # 含 vc 用途。纯只读。
            # 阶段一：清单结构
            if not self._receipt_consumption_manifest_is_well_formed(manifest):
                return "清单非法"

            signer_did = manifest["signer_did"]
            key_version = manifest["key_version"]

            # 阶段二：本租户同 did/版本且含 vc 用途的 active 信任锚点
            public_pem = store.get_active_trust_anchor_public_key(
                tenant, signer_did, key_version, required_use="vc"
            )
            if public_pem is None:
                return "锚点不可用"
            try:
                crypto.validate_public_key_pem(public_pem)
            except (ValueError, TypeError):
                return "锚点不可用"

            signed = {
                "snapshot": manifest["snapshot"],
                "filters": manifest["filters"],
                "count": manifest["count"],
                "alg": manifest["alg"],
                "digest": manifest["digest"],
                "signer_did": signer_did,
                "key_version": key_version,
            }
            signature = manifest["signature"]

            # 阶段三：签名格式
            try:
                crypto.validate_signature_format_strict(signature)
            except crypto.MalformedSignature:
                return "签名格式错误"

            # 阶段四：密码学验签
            try:
                crypto.verify(signed, signature, public_pem)
            except crypto.MalformedSignature:
                return "签名格式错误"
            except crypto.InvalidSignature:
                return "签名校验失败"
            except Exception:  # noqa: BLE001 验签绝不向上抛错或泄露细节
                return "签名校验失败"

            # 阶段五：导出内容——UTF-8 字节的 SHA-256 摘要与 LF 行数
            try:
                raw = ndjson.encode("utf-8")
            except UnicodeEncodeError:
                return "导出内容不匹配"
            actual_digest = hashlib.sha256(raw).hexdigest()
            line_count = raw.count(b"\n")
            if (
                actual_digest != manifest["digest"]
                or line_count != manifest["count"]
            ):
                return "导出内容不匹配"
            return None

        @staticmethod
        def _parse_receipt_sync_ndjson(
            ndjson: str, after: int, snapshot: int
        ) -> Optional[List[Dict[str, Any]]]:
            """解析同步页 NDJSON：成功返回事件行列表，非法返回 None。

            规则沿用 export 事件：每行恰为以 LF 结行的 UTF-8 紧凑 JSON
            （末行亦有 LF、无 CR、无 BOM、无空行），行对象恰含且按键序
            为 cursor、receipt_id、verifier_did、nonce、consumed_at；
            cursor 为非布尔非负整数，receipt_id/verifier_did/nonce/
            consumed_at 为非空字符串；行内 cursor 严格递增且满足
            after < cursor <= snapshot；页内 (verifier_did, nonce) 不得
            重复。空串为零行的合法页。
            """
            if not ndjson:
                return []
            if not ndjson.endswith("\n") or "\r" in ndjson:
                return None
            events: List[Dict[str, Any]] = []
            seen_keys: set = set()
            prev_cursor = after
            for line in ndjson.split("\n")[:-1]:
                if not line:
                    return None
                try:
                    row = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    return None
                if not isinstance(row, dict):
                    return None
                if list(row.keys()) != [
                    "cursor",
                    "receipt_id",
                    "verifier_did",
                    "nonce",
                    "consumed_at",
                ]:
                    return None
                cursor = row["cursor"]
                if (
                    not isinstance(cursor, int)
                    or isinstance(cursor, bool)
                    or cursor <= after
                    or cursor > snapshot
                    or cursor <= prev_cursor
                ):
                    return None
                for field in (
                    "receipt_id",
                    "verifier_did",
                    "nonce",
                    "consumed_at",
                ):
                    if not isinstance(row[field], str) or not row[field]:
                        return None
                key = (row["verifier_did"], row["nonce"])
                if key in seen_keys:
                    return None
                seen_keys.add(key)
                prev_cursor = cursor
                events.append(row)
            return events

        def _post_trust_receipt_sync(self, tenant: str) -> None:
            # POST /v1/trust/receipt-sync：同步外系统验真回执消费历史并
            # 防重放。
            # 1) 请求体恰含 manifest（对象）、ndjson（字符串）：非法
            #    JSON/非对象、缺漏或多余字段、类型不符一律 400 且仅
            #    {"error": "非空中文原因"}；
            # 2) 外层合法后沿用回执消费历史清单验真（五段顺序，含锚点
            #    active + vc 用途），任何失败 200 恰返
            #    {valid:false,reason}；
            # 3) 解析 NDJSON：每行须符合既有 export 事件键序与类型，
            #    cursor 严格递增且 after < cursor <= snapshot，页内不得
            #    重复 (verifier_did,nonce)；非法（含与历史重复键）200
            #    返 {"valid":false,"reason":"导出内容非法"}；
            # 4) 检查点键为 (tenant, signer_did)：首 after=0；续页同
            #    snapshot、after=末 cursor；仅末 cursor=旧 snapshot 时
            #    才接受递增的新 snapshot（after=旧 snapshot）；旧快照/
            #    跳页/同位异内容 409 仅 {"error":"同步游标冲突"}；
            # 5) 首次成功 201、重放 200，成功响应按键序恰为 valid、
            #    signer_did、snapshot、next_after、count（后三为非负
            #    整数）。事件与检查点原子落盘，同步不写审计；落盘失败
            #    500 仅 {"error":"存储失败"} 并回滚，并发只增一次。
            data = self._read_json()
            if set(data) != {"manifest", "ndjson"}:
                missing = [f for f in ("manifest", "ndjson") if f not in data]
                if missing:
                    raise ValidationError(
                        f"请求缺少字段: {', '.join(missing)}"
                    )
                extra = sorted(set(data) - {"manifest", "ndjson"})
                raise ValidationError(f"请求含多余字段: {', '.join(extra)}")
            manifest = data["manifest"]
            ndjson = data["ndjson"]
            if not isinstance(manifest, dict):
                raise ValidationError(
                    "请求不合法: 字段 manifest 必须为 JSON 对象"
                )
            if not isinstance(ndjson, str):
                raise ValidationError(
                    "请求不合法: 字段 ndjson 必须为字符串"
                )

            # 阶段一：沿用清单验真（清单非法 -> 锚点不可用 -> 签名格式
            # 错误 -> 签名校验失败 -> 导出内容不匹配）。
            reason = self._verify_receipt_consumption_manifest_item(
                tenant, manifest, ndjson
            )
            if reason is not None:
                self._send_json(200, {"valid": False, "reason": reason})
                return

            signer_did = manifest["signer_did"]
            snapshot = manifest["snapshot"]
            after = manifest["filters"]["after"]

            # 阶段二：NDJSON 结构、游标窗口与页内重复键。
            events = self._parse_receipt_sync_ndjson(
                ndjson, after, snapshot
            )
            if events is None:
                self._send_json(
                    200, {"valid": False, "reason": "导出内容非法"}
                )
                return

            # 阶段三：检查点推进、历史重复键与原子落盘。
            try:
                created, effective_snapshot, next_after, count = (
                    store.sync_receipt_consumptions(
                        tenant, signer_did, snapshot, after, events
                    )
                )
            except ConflictError:
                self._send_error(409, "同步游标冲突")
                return
            except ValidationError:
                self._send_json(
                    200, {"valid": False, "reason": "导出内容非法"}
                )
                return
            except StorageError:
                self._send_error(500, "存储失败")
                return
            self._send_json(
                201 if created else 200,
                {
                    "valid": True,
                    "signer_did": signer_did,
                    "snapshot": effective_snapshot,
                    "next_after": next_after,
                    "count": count,
                },
            )

        def _post_trust_receipt_sync_batch(self, tenant: str) -> None:
            # POST /v1/trust/receipt-sync-batch：批量同步外系统验真回执
            # 消费历史，任何失败都返回 HTTP 200。请求体须恰为
            # {"items": [项...]}，数组限 1–50 项；请求级非法（空体、非法
            # JSON、非对象、键集错、items 非数组/空/超限）一律恰返
            # {"results": [], "reason": "请求非法"}，不写任何状态。
            # 请求级合法时按输入顺序逐项复用单条 receipt-sync 的完整规则
            # （清单验真、NDJSON 结构、重复键、游标与检查点、原子落盘），
            # 失败不短路：项结构/类型错误收敛为
            # {valid:false,http_status:400,reason:"请求项非法"}；验真/
            # 内容失败沿用单条 200 固定 reason；游标冲突 409“同步游标
            # 冲突”；落盘失败 500“存储失败”且仅回滚本项。失败项键序
            # valid,http_status,reason；成功项键序 valid,http_status,
            # signer_did,snapshot,next_after,count（首次检查点 201，否则
            # 200）。同签名方后项可见前项已提交状态；逐项原子提交，与单条
            # 并发不跳页、不重复推进、不半写，跨重启保持；同步不写审计。
            # 显式空 X-Tenant-ID 在此之前由路由统一判 400。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except Exception:  # noqa: BLE001 请求非法绝不暴露内部细节
                self._send_json(
                    200, {"results": [], "reason": "请求非法"}
                )
                return
            data: Any = None
            if raw:
                try:
                    data = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    data = None
            items = data.get("items") if isinstance(data, dict) else None
            if (
                not isinstance(data, dict)
                or set(data) != {"items"}
                or not isinstance(items, list)
                or not 1 <= len(items) <= 50
            ):
                self._send_json(
                    200, {"results": [], "reason": "请求非法"}
                )
                return

            results = [
                self._receipt_sync_batch_item(tenant, item) for item in items
            ]
            self._send_json(200, {"results": results})

        def _receipt_sync_batch_item(
            self, tenant: str, item: Any
        ) -> Dict[str, Any]:
            # 批量同步的单项处理：完全沿用单条 receipt-sync 的各阶段规则，
            # 将单条的 HTTP 状态与响应体收敛为单项结果对象。
            if not isinstance(item, dict) or set(item) != {
                "manifest",
                "ndjson",
            }:
                return {
                    "valid": False,
                    "http_status": 400,
                    "reason": "请求项非法",
                }
            manifest = item["manifest"]
            ndjson = item["ndjson"]
            if not isinstance(manifest, dict) or not isinstance(ndjson, str):
                return {
                    "valid": False,
                    "http_status": 400,
                    "reason": "请求项非法",
                }

            # 阶段一：清单验真（与单条相同的五段顺序与固定 reason）。
            reason = self._verify_receipt_consumption_manifest_item(
                tenant, manifest, ndjson
            )
            if reason is not None:
                return {"valid": False, "http_status": 200, "reason": reason}

            signer_did = manifest["signer_did"]
            snapshot = manifest["snapshot"]
            after = manifest["filters"]["after"]

            # 阶段二：NDJSON 结构、游标窗口与页内重复键。
            events = self._parse_receipt_sync_ndjson(ndjson, after, snapshot)
            if events is None:
                return {
                    "valid": False,
                    "http_status": 200,
                    "reason": "导出内容非法",
                }

            # 阶段三：检查点推进、历史重复键与逐项原子落盘。
            try:
                created, effective_snapshot, next_after, count = (
                    store.sync_receipt_consumptions(
                        tenant, signer_did, snapshot, after, events
                    )
                )
            except ConflictError:
                return {
                    "valid": False,
                    "http_status": 409,
                    "reason": "同步游标冲突",
                }
            except ValidationError:
                return {
                    "valid": False,
                    "http_status": 200,
                    "reason": "导出内容非法",
                }
            except StorageError:
                return {
                    "valid": False,
                    "http_status": 500,
                    "reason": "存储失败",
                }
            except Exception:  # noqa: BLE001 单项失败不影响其余项
                return {
                    "valid": False,
                    "http_status": 500,
                    "reason": "存储失败",
                }
            return {
                "valid": True,
                "http_status": 201 if created else 200,
                "signer_did": signer_did,
                "snapshot": effective_snapshot,
                "next_after": next_after,
                "count": count,
            }

        @staticmethod
        def _verify_credential_receipt_item(
            tenant: str, data: Dict[str, Any]
        ) -> Optional[str]:
            # 回执验真（只读）：按序返回失败原因（回执非法 -> nonce错误
            # -> 绑定错误 -> 摘要错误 -> 锚点不可用 -> 签名格式错误 ->
            # 签名校验失败），成功返回 None。不重验凭证签名、不记审计。
            receipt = data["receipt"]
            body = data["body"]
            signature = data["signature"]
            nonce = data["nonce"]
            receipt_signature = data["receipt_signature"]

            # 阶段一：回执结构——恰为 verify-receipt 返回的七字段对象，
            # 字段与类型沿用公开协议
            receipt_fields = (
                "credential_id",
                "issuer_did",
                "issuer_key_version",
                "credential_digest",
                "verifier_did",
                "verifier_key_version",
                "nonce",
            )
            if set(receipt) != set(receipt_fields):
                return "回执非法"
            for field in ("credential_id", "issuer_did", "verifier_did"):
                if not isinstance(receipt[field], str) or not receipt[field]:
                    return "回执非法"
            issuer_key_version = receipt["issuer_key_version"]
            if (
                not isinstance(issuer_key_version, int)
                or isinstance(issuer_key_version, bool)
                or issuer_key_version < 1
            ):
                return "回执非法"
            digest = receipt["credential_digest"]
            if not isinstance(digest, str) or not _SHA256_HEX_RE.fullmatch(
                digest
            ):
                return "回执非法"
            verifier_key_version = receipt["verifier_key_version"]
            if (
                not isinstance(verifier_key_version, int)
                or isinstance(verifier_key_version, bool)
                or verifier_key_version < 1
            ):
                return "回执非法"
            receipt_nonce = receipt["nonce"]
            if (
                not isinstance(receipt_nonce, str)
                or not 1 <= len(receipt_nonce) <= 256
            ):
                return "回执非法"

            # 阶段二：两处 nonce 相等
            if receipt_nonce != nonce:
                return "nonce错误"

            # 阶段三：绑定——receipt 的 credential_id、issuer_did、
            # issuer_key_version 与 body 相等（body 缺版本按 1）
            body_key_version = body.get("issuer_key_version", 1)
            if (
                receipt["credential_id"] != body.get("credential_id")
                or receipt["issuer_did"] != body.get("issuer_did")
                or issuer_key_version != body_key_version
            ):
                return "绑定错误"

            # 阶段四：摘要——按原规则用 {body,signature} 复算
            # credential_digest（递归键升序紧凑 UTF-8 JSON 的 SHA-256
            # 小写 64 位 hex）
            want_digest = hashlib.sha256(
                crypto.canonicalize({"body": body, "signature": signature})
            ).hexdigest()
            if digest != want_digest:
                return "摘要错误"

            # 阶段五：本租户 verifier_did/版本 active 且含 vc 用途锚点
            public_pem = store.get_active_trust_anchor_public_key(
                tenant,
                receipt["verifier_did"],
                verifier_key_version,
                required_use="vc",
            )
            if public_pem is None:
                return "锚点不可用"
            try:
                crypto.validate_public_key_pem(public_pem)
            except (ValueError, TypeError):
                return "锚点不可用"

            # 阶段六：签名格式（ES256 裸 R||S 无填充 base64url）
            try:
                crypto.validate_signature_format_strict(receipt_signature)
            except crypto.MalformedSignature:
                return "签名格式错误"

            # 阶段七：密码学验签——receipt_signature 覆盖完整 receipt
            try:
                crypto.verify(receipt, receipt_signature, public_pem)
            except crypto.MalformedSignature:
                return "签名格式错误"
            except crypto.InvalidSignature:
                return "签名校验失败"
            except Exception:  # noqa: BLE001 验签绝不向上抛错或泄露细节
                return "签名校验失败"
            return None

        def _post_trust_credentials_import(self, tenant: str) -> None:
            # 外部凭证导入：请求体恰为 {body, signature}，body 规则同
            # /v1/trust/credentials/verify（必含 credential_id/issuer_did/
            # subject_did/claims/issued_at）。请求/字段非法由 _read_json
            # 与 store 抛 ValidationError -> 400；不同内容重放由 store 抛
            # ConflictError -> 409。锚点缺失/非 active、签名格式错误、
            # 验签失败、凭证过期均按公开错误协议返回
            # 200 + {"valid":false,"reason":...}（非空中文）且不写入。
            # 首次按 tenant+issuer_did+credential_id 保存返回 201；相同
            # 内容重放 200 返回原响应。
            data = self._read_json()
            result = store.import_trust_credential(tenant, data)
            if not result.get("valid"):
                self._send_invalid(result.get("reason") or "验签失败")
                return
            record = result["record"]
            self._send_json(
                result["status_code"],
                {
                    "imported": True,
                    "issuer_did": record.issuer_did,
                    "credential_id": record.credential_id,
                    "body": record.body,
                    "signature": record.signature,
                },
            )

        def _post_trust_credentials_import_batch(self, tenant: str) -> None:
            # 批量导入外部凭证：请求体须恰为 {"items": [项...]}，数组
            # 非空且不超过 50 项。外层缺失/非法 JSON/非对象/字段错、
            # items 非数组/空/超限一律 400 {"error": "非空中文原因"}；
            # 显式空 X-Tenant-ID 在此之前由路由统一判 400。请求级合法
            # 时 200 返回 {"results": [...]}，与输入等长同序，逐项复用
            # 单项 import 规则、失败不短路：项非对象/字段错 ->
            # imported:false + http_status:400 + reason 前缀“请求”；
            # 锚点/签名/有效期失败 -> http_status:200；同双键异内容
            # -> http_status:409 + reason 前缀“冲突”。成功项首 201、
            # 同内容重放 200；批内同键同内容首 201 后 200、异 409。
            # 失败项不写入、不审计；成功项记录与审计同次原子写。
            data = self._read_json()
            if "items" not in data:
                raise ValidationError("缺少字段: items")
            extra = sorted(set(data) - {"items"})
            if extra:
                raise ValidationError(f"多余字段: {', '.join(extra)}")
            items = data["items"]
            if not isinstance(items, list):
                raise ValidationError("字段 items 必须为数组")
            if not items:
                raise ValidationError("items 数组不能为空")
            if len(items) > 50:
                raise ValidationError(
                    f"items 数组不能超过 50 项（当前 {len(items)} 项）"
                )
            results = store.import_trust_credentials_batch(tenant, items)
            self._send_json(200, {"results": results})

        def _post_trust_imported_credential_verify(
            self, tenant: str, credential_id: str, query: str
        ) -> None:
            # POST /v1/trust/credentials/imported/{credential_id}/verify
            # ?issuer_did=...：重启后重新验证已落盘凭证。
            # issuer_did 须唯一且非空，缺失/重复/空值 -> 400 {error}；
            # 请求体须恰为 {}，缺失/非法 JSON/非对象/含任意字段 ->
            # 400 {error}；按租户、issuer_did、credential_id 查导入记录，
            # 未导入/错配/跨租户 -> 404。验签结论（含锚点缺失或吊销）
            # 一律 HTTP 200：成功仅 {"valid":true}，失败为
            # {"valid":false,"reason":...}。纯只读，不写记录、状态、
            # 历史或审计。
            if not credential_id:
                raise ValidationError("路径缺少 credential_id")
            params = parse_qs(query, keep_blank_values=True)
            values = params.get("issuer_did")
            if values is None:
                raise ValidationError("查询参数 issuer_did 必填")
            if len(values) != 1:
                raise ValidationError("查询参数 issuer_did 只能提供一次")
            issuer_did = values[0]
            if not issuer_did:
                raise ValidationError(
                    "查询参数 issuer_did 必须为非空字符串"
                )

            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
            except (ValueError, TypeError) as exc:
                raise ValidationError("请求体长度声明非法") from exc
            if not raw:
                raise ValidationError("请求体缺失，必须恰为 {}")
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise ValidationError("请求体不是合法 JSON，必须恰为 {}")
            if not isinstance(data, dict) or data:
                raise ValidationError("请求体必须恰为 {}")

            # 未导入/issuer_did 错配/跨租户由 store 抛 NotFoundError
            # -> 404；其余任何验签结论均返回 200。
            try:
                valid, reason = store.verify_imported_credential(
                    tenant, issuer_did, credential_id
                )
            except NotFoundError:
                raise
            except Exception:  # noqa: BLE001 验签绝不暴露内部细节
                self._send_invalid("验签过程发生内部错误")
                return
            payload: Dict[str, Any] = {"valid": valid}
            if not valid:
                payload["reason"] = reason
            self._send_json(200, payload)

        def _post_trust_imported_credential_verify_with_status(
            self, tenant: str, credential_id: str, query: str
        ) -> None:
            # POST /v1/trust/credentials/imported/{credential_id}
            # /verify-with-status?issuer_did=...：重验已落盘凭证并只读
            # 合并本租户同步状态。请求级规则与 .../verify 完全一致：
            # issuer_did 须唯一且非空，缺失/重复/空值 -> 400 {error}；
            # 请求体须恰为 {}，空体/非法 JSON/非对象/含任意字段 ->
            # 400 {error}；按租户、issuer_did、credential_id 查导入记录，
            # 未导入/错配/跨租户 -> 404 {error}。验签结论一律 HTTP 200：
            # 锚点不可用、签名格式错、验签失败、凭证过期返回
            # {"valid":false,"reason":...}；重验成功后查同步状态——未同步
            # “外部凭证状态未同步”，active 仅 {"valid":true}，revoked 为
            # “外部凭证已吊销：<reason>”（空或缺失 reason 固定“未知原因”），
            # unknown 为“外部凭证状态未知”。失败响应键序固定 valid、reason。
            # 纯只读，不写记录、状态、历史或审计。
            if not credential_id:
                raise ValidationError("路径缺少 credential_id")
            params = parse_qs(query, keep_blank_values=True)
            values = params.get("issuer_did")
            if values is None:
                raise ValidationError("查询参数 issuer_did 必填")
            if len(values) != 1:
                raise ValidationError("查询参数 issuer_did 只能提供一次")
            issuer_did = values[0]
            if not issuer_did:
                raise ValidationError(
                    "查询参数 issuer_did 必须为非空字符串"
                )

            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
            except (ValueError, TypeError) as exc:
                raise ValidationError("请求体长度声明非法") from exc
            if not raw:
                raise ValidationError("请求体缺失，必须恰为 {}")
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise ValidationError("请求体不是合法 JSON，必须恰为 {}")
            if not isinstance(data, dict) or data:
                raise ValidationError("请求体必须恰为 {}")

            # 未导入/issuer_did 错配/跨租户由 store 抛 NotFoundError
            # -> 404；其余任何验签/状态结论均返回 200。
            try:
                valid, reason = (
                    store.verify_imported_credential_with_status(
                        tenant, issuer_did, credential_id
                    )
                )
            except NotFoundError:
                raise
            except Exception:  # noqa: BLE001 验签绝不暴露内部细节
                self._send_invalid("验签过程发生内部错误")
                return
            payload: Dict[str, Any] = {"valid": valid}
            if not valid:
                payload["reason"] = reason
            self._send_json(200, payload)

        def _post_trust_imported_credentials_verify_batch_with_status(
            self, tenant: str
        ) -> None:
            # 批量重验已导入外部凭证并合并本租户同步状态：任何请求级失败
            # 都返回 HTTP 200。请求体须恰为 {"items": [项...]}，数组非空
            # 且不超过 100 项；请求体非法（缺失、非法 JSON、非对象、字段
            # 缺失或多余、items 非数组、空数组或超限）时返回
            # {"results": [], "reason": "请求..."}。合法批次逐项重验本租户
            # 已导入凭证（不存在/跨租户 404 资源不存在；锚点、签名、过期
            # 结论 http_status 均为 200），验签成功后只读合并本租户同步
            # 状态，按输入顺序等长返回 {"results": [...]}，每项键序固定
            # valid、http_status、reason。纯只读，不写记录、状态、历史或
            # 审计，结论跨重启稳定。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except (ValueError, TypeError):
                self._send_json(
                    200,
                    {"results": [],
                     "reason": "请求不合法: 请求体缺失或长度声明非法"},
                )
                return
            except Exception:  # noqa: BLE001
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体读取失败"}
                )
                return
            if not raw:
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体缺失"}
                )
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._send_json(
                    200,
                    {"results": [], "reason": "请求不合法: 请求体不是合法 UTF-8 文本"},
                )
                return
            except json.JSONDecodeError:
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体不是合法 JSON"}
                )
                return

            try:
                ok, reason, results = (
                    store.verify_imported_credentials_batch_with_status(
                        tenant, data
                    )
                )
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 验签过程发生内部错误"}
                )
                return
            if not ok:
                self._send_json(
                    200, {"results": [], "reason": reason or "请求不合法"}
                )
                return
            self._send_json(200, {"results": results})

        def _post_trust_presentations_verify(self, tenant: str) -> None:
            # 跨系统演示验真：与其他验签端点相同的公开错误协议，任何失败
            # 都返回 200 + {"valid": false, "reason": "<非空中文原因>"}。
            # 未绑定请求体须恰含 presentation（对象）与 challenge（非空
            # 字符串）；持有者绑定请求另含非空字符串 source_tenant_id，
            # 演示对象相应多出 holder_did/holder_key_version/holder_proof。
            # 非法 JSON/非对象/缺失/多余字段均为请求类原因。只读，不写
            # 凭证、演示、状态、历史或审计。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except (ValueError, TypeError):
                self._send_invalid("请求体缺失或长度声明非法")
                return
            except Exception:  # noqa: BLE001
                self._send_invalid("请求体读取失败")
                return
            if not raw:
                self._send_invalid("请求体缺失")
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._send_invalid("请求体不是合法 UTF-8 文本")
                return
            except json.JSONDecodeError:
                self._send_invalid("请求体不是合法 JSON")
                return

            try:
                valid, reason = store.verify_trust_presentation(tenant, data)
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_invalid("验签过程发生内部错误")
                return
            payload: Dict[str, Any] = {"valid": valid}
            if not valid:
                payload["reason"] = reason or "验签失败"
            self._send_json(200, payload)

        def _post_trust_presentations_verify_synced(
            self, tenant: str
        ) -> None:
            # POST /v1/trust/presentations/verify-synced：以同步锚点验真
            # 未绑定外部演示（只读）。请求体须恰含 signer_did（非空字符
            # 串）、at（非布尔非负整数）、presentation（JSON 对象）、
            # challenge（非空字符串）；空体、非法 JSON、非对象、键集或
            # 类型错误均 400 且仅 {"error": 非空中文}。signer_did 未同步
            # 或跨租户 404、at 超过同步检查点 409，同形仅 {"error"}。
            # 外层合法后任何失败均 HTTP 200 按键序恰返
            # {"valid":false,"reason":...}：演示九字段、challenge、
            # expires_at、proof 覆盖及“请求→演示→挑战→锚点→签名格式→
            # 验签→期限”顺序沿用 /v1/trust/presentations/verify（演示
            # 出现 holder_* 字段即非法）；锚点取该来源 cursor<=at 的已
            # 同步事件、以 (issuer_did, 版本) 最后事件为准，缺失、非
            # active 或 uses 无 vp 均为“同步锚点不可用”；proof 格式错、
            # 验签失败、到期同形依次为“签名格式错误”“签名校验失败”
            # “演示已过期”，较早错误优先；成功仅 {"valid":true}。
            # 纯只读：不改同步页、检查点、锚点、演示、状态或审计，重启
            # 一致；租户头缺省 default、显式空 400 并隔离。
            data = self._read_json()
            required = ("signer_did", "at", "presentation", "challenge")
            if set(data) != set(required):
                missing = [f for f in required if f not in data]
                if missing:
                    raise ValidationError(
                        f"请求缺少字段: {', '.join(missing)}"
                    )
                extra = sorted(set(data) - set(required))
                raise ValidationError(
                    f"请求含多余字段: {', '.join(extra)}"
                )
            signer_did = data["signer_did"]
            if not isinstance(signer_did, str) or not signer_did:
                raise ValidationError(
                    "请求不合法: 字段 signer_did 必须为非空字符串"
                )
            at = data["at"]
            if (
                not isinstance(at, int)
                or isinstance(at, bool)
                or at < 0
            ):
                raise ValidationError(
                    "请求不合法: 字段 at 必须为非布尔非负整数"
                )
            presentation = data["presentation"]
            if not isinstance(presentation, dict):
                raise ValidationError(
                    "请求不合法: 字段 presentation 必须为 JSON 对象"
                )
            challenge = data["challenge"]
            if not isinstance(challenge, str) or not challenge:
                raise ValidationError(
                    "请求不合法: 字段 challenge 必须为非空字符串"
                )
            try:
                valid, reason = store.verify_trust_presentation_synced(
                    tenant, signer_did, at, presentation, challenge
                )
            except (NotFoundError, ConflictError):
                raise
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_invalid("验签过程发生内部错误")
                return
            if not valid:
                self._send_invalid(reason or "验签失败")
                return
            self._send_json(200, {"valid": True})

        def _post_trust_presentations_verify_synced_with_status(
            self, tenant: str
        ) -> None:
            # POST /v1/trust/presentations/verify-synced-with-status：以
            # 同步锚点验真外部演示并合并请求初始本租户状态快照（只读）。
            # 未绑定请求体须恰含 signer_did（非空字符串）、at（非布尔
            # 非负整数）、presentation（JSON 对象）、challenge（非空
            # 字符串）；持有者绑定请求在原四键外恰加非空字符串
            # source_tenant_id，presentation 恰为绑定十二字段。空体、
            # 非法 JSON、非对象、键集或类型错误均 400 且仅
            # {"error": 非空中文}。signer_did 未同步或跨租户 404、at
            # 超过同步检查点 409，同形仅 {"error"}。外层合法后任何失败
            # 均 HTTP 200 按键序恰返 {"valid":false,"reason":...}：
            # 未绑定演示九字段、holder_* 禁令、挑战、锚点、签名覆盖、
            # 格式、验签、期限、校验顺序及原因完全沿用 verify-synced；
            # 绑定演示签发者与持有者锚点均取该来源 cursor<=at 的
            # (DID,版本) 末事件（须 active 且 uses 含 vp），不可用依次
            # 为“同步锚点不可用”“同步持有者锚点不可用”，issuer
            # proof 覆盖去掉 proof 及 holder_* 的八字段，holder_proof
            # 覆盖去掉 proof、holder_proof 的对象并加入
            # tenant_id=source_tenant_id，持有者格式、验签失败恰为
            # “持有者签名格式错误”“持有者签名校验失败”，顺序为演示、
            # 挑战、签发锚点/格式/验签、持有者锚点/格式/验签、期限；
            # 原验真失败不查状态；验真成功后以请求初始一次原子读取的
            # 本租户状态快照查演示的 (issuer_did, credential_id)：未
            # 同步、revoked、unknown 依次为“外部凭证状态未同步”
            # “外部凭证已吊销：<reason>”（空或缺失 reason 用“未知
            # 原因”）“外部凭证状态未知”，active 成功；成功仅
            # {"valid":true}。纯只读：不改同步页、检查点、锚点、演示、
            # 状态或审计，重启一致；租户头缺省 default、显式空 400 并
            # 隔离。
            data = self._read_json()
            base_required = ("signer_did", "at", "presentation", "challenge")
            is_holder_bound = "source_tenant_id" in data
            required = base_required + (
                ("source_tenant_id",) if is_holder_bound else ()
            )
            if set(data) != set(required):
                missing = [f for f in required if f not in data]
                if missing:
                    raise ValidationError(
                        f"请求缺少字段: {', '.join(missing)}"
                    )
                extra = sorted(set(data) - set(required))
                raise ValidationError(
                    f"请求含多余字段: {', '.join(extra)}"
                )
            signer_did = data["signer_did"]
            if not isinstance(signer_did, str) or not signer_did:
                raise ValidationError(
                    "请求不合法: 字段 signer_did 必须为非空字符串"
                )
            at = data["at"]
            if (
                not isinstance(at, int)
                or isinstance(at, bool)
                or at < 0
            ):
                raise ValidationError(
                    "请求不合法: 字段 at 必须为非布尔非负整数"
                )
            presentation = data["presentation"]
            if not isinstance(presentation, dict):
                raise ValidationError(
                    "请求不合法: 字段 presentation 必须为 JSON 对象"
                )
            challenge = data["challenge"]
            if not isinstance(challenge, str) or not challenge:
                raise ValidationError(
                    "请求不合法: 字段 challenge 必须为非空字符串"
                )
            source_tenant_id: Optional[str] = None
            if is_holder_bound:
                source_tenant_id = data["source_tenant_id"]
                if not isinstance(source_tenant_id, str) or not source_tenant_id:
                    raise ValidationError(
                        "请求不合法: 字段 source_tenant_id 必须为非空字符串"
                    )
            try:
                valid, reason = (
                    store.verify_trust_presentation_synced_with_status(
                        tenant, signer_did, at, presentation, challenge,
                        source_tenant_id,
                    )
                )
            except (NotFoundError, ConflictError):
                raise
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_invalid("验签过程发生内部错误")
                return
            if not valid:
                self._send_invalid(reason or "验签失败")
                return
            self._send_json(200, {"valid": True})

        def _post_trust_presentations_verify_synced_batch(
            self, tenant: str
        ) -> None:
            # POST /v1/trust/presentations/verify-synced-batch：批量以
            # 同步锚点快照验真未绑定外部演示（只读）。请求体须恰含
            # signer_did（非空字符串）、at（非布尔非负整数）、
            # presentations（1–100 项数组）；空体、非法 JSON、非对象、
            # 键集或类型错误、空数组或超限均 400 且仅
            # {"error":"请求非法"}；来源未同步或跨租户 404 仅
            # {"error":"同步来源不存在"}，at 超检查点 409 仅
            # {"error":"同步游标冲突"}，先于项校验。合法时 200 仅返
            # {"results":[...]}，逐项不短路、等长同序：项须恰含
            # presentation（对象）与非空 challenge，否则该项
            # {"valid":false,"reason":"请求项非法"}；合法项沿用单条
            # verify-synced 的未绑定九字段、holder_* 禁令、签名覆盖及
            # 演示→挑战→锚点→格式→验签→期限顺序，按该来源 cursor<=at
            # 的 (DID,版本) 末项验真，锚点缺失/非 active/uses 无 vp 为
            # “同步锚点不可用”，格式、验签、过期依次为“签名格式错误”
            # “签名校验失败”“演示已过期”；成功项仅 {"valid":true}，
            # 失败项键序 valid、reason。纯只读：不改同步页、检查点、
            # 锚点、演示、状态或审计，重启一致；租户头缺省 default、
            # 显式空 400 并隔离。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except Exception:  # noqa: BLE001 请求非法绝不暴露内部细节
                self._send_error(400, "请求非法")
                return
            if not raw:
                self._send_error(400, "请求非法")
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_error(400, "请求非法")
                return
            if not isinstance(data, dict) or set(data) != {
                "signer_did",
                "at",
                "presentations",
            }:
                self._send_error(400, "请求非法")
                return
            signer_did = data["signer_did"]
            at = data["at"]
            presentations = data["presentations"]
            if (
                not isinstance(signer_did, str)
                or not signer_did
                or not isinstance(at, int)
                or isinstance(at, bool)
                or at < 0
                or not isinstance(presentations, list)
                or not 1 <= len(presentations) <= 100
            ):
                self._send_error(400, "请求非法")
                return
            try:
                results = store.verify_trust_presentations_synced_batch(
                    tenant, signer_did, at, presentations
                )
            except NotFoundError:
                self._send_error(404, "同步来源不存在")
                return
            except ConflictError:
                self._send_error(409, "同步游标冲突")
                return
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_error(500, "服务器内部错误")
                return
            self._send_json(200, {"results": results})

        def _post_trust_presentations_verify_synced_batch_with_status(
            self, tenant: str
        ) -> None:
            # POST /v1/trust/presentations/verify-synced-batch-with-status：
            # 批量以同步锚点快照验真未绑定外部演示并合并批初本租户状态
            # 快照（只读）。请求级协议与 verify-synced-batch 完全一致：
            # 请求体须恰含 signer_did（非空字符串）、at（非布尔非负
            # 整数）、presentations（1–100 项数组）；空体、非法 JSON、
            # 非对象、键集或类型错误、空数组或超限均 400 且仅
            # {"error":"请求非法"}；来源未同步或跨租户 404 仅
            # {"error":"同步来源不存在"}，at 超检查点 409 仅
            # {"error":"同步游标冲突"}，均先于逐项校验。合法时 200 仅
            # 返 {"results":[...]}，逐项不短路、等长同序：项须恰含
            # presentation（对象）与非空 challenge，否则该项
            # {"valid":false,"reason":"请求项非法"}；合法项沿用
            # verify-synced-batch 的 holder_* 禁令、挑战、cursor<=at 末
            # 锚点、proof 覆盖、签名格式、验签、期限、顺序及原因；验真
            # 通过后按演示的 (issuer_did, credential_id) 查批初原子
            # 读取的本租户状态快照：未同步、revoked、unknown 分别返
            # “外部凭证状态未同步”“外部凭证已吊销：<reason>”（空原因
            # 用“未知原因”）“外部凭证状态未知”，active 成功。成功项
            # 仅 {"valid":true}，失败项键序 valid、reason。纯只读：不
            # 写状态或审计；租户头缺省 default、显式空 400 并隔离。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except Exception:  # noqa: BLE001 请求非法绝不暴露内部细节
                self._send_error(400, "请求非法")
                return
            if not raw:
                self._send_error(400, "请求非法")
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_error(400, "请求非法")
                return
            if not isinstance(data, dict) or set(data) != {
                "signer_did",
                "at",
                "presentations",
            }:
                self._send_error(400, "请求非法")
                return
            signer_did = data["signer_did"]
            at = data["at"]
            presentations = data["presentations"]
            if (
                not isinstance(signer_did, str)
                or not signer_did
                or not isinstance(at, int)
                or isinstance(at, bool)
                or at < 0
                or not isinstance(presentations, list)
                or not 1 <= len(presentations) <= 100
            ):
                self._send_error(400, "请求非法")
                return
            try:
                results = store.verify_trust_presentations_synced_batch_with_status(
                    tenant, signer_did, at, presentations
                )
            except NotFoundError:
                self._send_error(404, "同步来源不存在")
                return
            except ConflictError:
                self._send_error(409, "同步游标冲突")
                return
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_error(500, "服务器内部错误")
                return
            self._send_json(200, {"results": results})

        def _post_trust_presentations_verify_batch(self, tenant: str) -> None:
            # 批量跨系统演示验真：与单项相同的公开错误协议，任何失败都
            # 返回 HTTP 200。请求体须恰为 {"presentations": [项...]}，
            # 数组非空且不超过 100 项；请求体非法（外层缺失、非法 JSON、
            # 非对象、字段缺失或多余、presentations 非数组、空数组或超过
            # 上限）时返回 {"results": [], "reason": "请求..."}。请求级
            # 合法时返回 {"results": [...]}，长度与顺序与输入一致，逐项
            # 复用单项验真规则：未绑定项恰含 presentation/challenge，
            # 持有者绑定项另须恰含非空 source_tenant_id 且演示多出
            # holder_did/holder_key_version/holder_proof（双锚点双签名，
            # source_tenant_id 作为 holder proof 覆盖的 tenant_id），
            # 失败不短路。纯只读，不消费、不登记资源，不写状态、历史或
            # 审计，仅使用当前租户锚点。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except (ValueError, TypeError):
                self._send_json(
                    200,
                    {"results": [],
                     "reason": "请求不合法: 请求体缺失或长度声明非法"},
                )
                return
            except Exception:  # noqa: BLE001
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体读取失败"}
                )
                return
            if not raw:
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体缺失"}
                )
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._send_json(
                    200,
                    {"results": [], "reason": "请求不合法: 请求体不是合法 UTF-8 文本"},
                )
                return
            except json.JSONDecodeError:
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体不是合法 JSON"}
                )
                return

            try:
                ok, reason, results = store.verify_trust_presentations_batch(
                    tenant, data
                )
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 验签过程发生内部错误"}
                )
                return
            if not ok:
                self._send_json(
                    200, {"results": [], "reason": reason or "请求不合法"}
                )
                return
            self._send_json(200, {"results": results})

        def _post_trust_presentations_verify_with_status(
            self, tenant: str
        ) -> None:
            # 外部演示验真并合并状态判定：公开错误协议，任何失败都返回
            # 200 + {"valid": false, "reason": "<非空中文原因>"}。
            # 请求体解析规则与 /v1/trust/presentations/verify 完全一致
            # （未绑定恰含 presentation/challenge；持有者绑定另含非空
            # source_tenant_id）；验真通过后由 store 只读查询本租户
            # (issuer_did, credential_id) 同步状态。纯只读，不消费、
            # 不登记资源，不写状态、历史或审计。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except (ValueError, TypeError):
                self._send_invalid("请求体缺失或长度声明非法")
                return
            except Exception:  # noqa: BLE001
                self._send_invalid("请求体读取失败")
                return
            if not raw:
                self._send_invalid("请求体缺失")
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._send_invalid("请求体不是合法 UTF-8 文本")
                return
            except json.JSONDecodeError:
                self._send_invalid("请求体不是合法 JSON")
                return

            try:
                valid, reason = (
                    store.verify_trust_presentation_with_status(tenant, data)
                )
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_invalid("验签过程发生内部错误")
                return
            payload: Dict[str, Any] = {"valid": valid}
            if not valid:
                payload["reason"] = reason or "验签失败"
            self._send_json(200, payload)

        def _post_trust_presentations_verify_batch_with_status(
            self, tenant: str
        ) -> None:
            # 批量外部演示验真并合并本租户同步状态：与 verify-batch 相同的
            # 公开错误协议，任何失败都返回 HTTP 200。请求体须恰为
            # {"presentations": [项...]}，数组非空且不超过 100 项；请求体
            # 非法（含非法 JSON、空数组、超过上限）时返回
            # {"results": [], "reason": "请求..."}。请求级合法时逐项复用
            # verify-with-status 规则（验真 + 只读合并同步状态），按输入
            # 顺序返回 {"results": [...]}，失败不短路。纯只读，不消费、
            # 不登记资源，不写状态、历史或审计。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except (ValueError, TypeError):
                self._send_json(
                    200,
                    {"results": [],
                     "reason": "请求不合法: 请求体缺失或长度声明非法"},
                )
                return
            except Exception:  # noqa: BLE001
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体读取失败"}
                )
                return
            if not raw:
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体缺失"}
                )
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._send_json(
                    200,
                    {"results": [], "reason": "请求不合法: 请求体不是合法 UTF-8 文本"},
                )
                return
            except json.JSONDecodeError:
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体不是合法 JSON"}
                )
                return

            try:
                ok, reason, results = (
                    store.verify_trust_presentations_batch_with_status(
                        tenant, data
                    )
                )
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 验签过程发生内部错误"}
                )
                return
            if not ok:
                self._send_json(
                    200, {"results": [], "reason": reason or "请求不合法"}
                )
                return
            self._send_json(200, {"results": results})

        def _post_trust_proofs_verify(self, tenant: str) -> None:
            # 跨系统谓词证明验真：与其他验签端点相同的公开错误协议，任何
            # 失败都返回 200 + {"valid": false, "reason": "<非空中文原因>"}。
            # 请求体须恰含 proof（对象）、challenge（非空字符串）与
            # source_tenant_id（非空字符串）；非法 JSON/非对象/缺失/多余
            # 字段均为请求类原因。只读，不消费、不写证明/状态/历史或审计。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except (ValueError, TypeError):
                self._send_invalid("请求体缺失或长度声明非法")
                return
            except Exception:  # noqa: BLE001
                self._send_invalid("请求体读取失败")
                return
            if not raw:
                self._send_invalid("请求体缺失")
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._send_invalid("请求体不是合法 UTF-8 文本")
                return
            except json.JSONDecodeError:
                self._send_invalid("请求体不是合法 JSON")
                return

            try:
                valid, reason = store.verify_trust_proof(tenant, data)
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_invalid("验签过程发生内部错误")
                return
            payload: Dict[str, Any] = {"valid": valid}
            if not valid:
                payload["reason"] = reason or "验签失败"
            self._send_json(200, payload)

        def _post_trust_proofs_verify_synced(self, tenant: str) -> None:
            # POST /v1/trust/proofs/verify-synced：以同步锚点验真外部
            # 谓词证明（只读）。请求体须恰含 signer_did（非空字符串）、
            # at（非布尔非负整数）、proof（JSON 对象）、challenge（非空
            # 字符串）、source_tenant_id（非空字符串）；空体、非法
            # JSON、非对象、键集或类型错误均 400 且仅 {"error": 非空
            # 中文}。signer_did 未同步或跨租户 404、at 超过同步检查点
            # 409，同形仅 {"error"}。外层合法后任何失败均 HTTP 200 按
            # 键序恰返 {"valid":false,"reason":...}：证明九字段、
            # 谓词、results、challenge、expires_at 及“请求→证明→挑战
            # →锚点→签名格式→验签→期限”顺序沿用
            # /v1/trust/proofs/verify；锚点取该来源 cursor<=at 的已
            # 同步事件、以 (issuer_did, 版本) 最后事件为准，缺失、非
            # active 或 uses 无 proof 均为“同步锚点不可用”；proof
            # 格式错、验签失败、到期同形依次为“签名格式错误”“签名
            # 校验失败”“证明已过期”，较早错误优先；成功仅
            # {"valid":true}。纯只读：不改同步页、检查点、锚点、证明、
            # 状态或审计，重启一致；租户头缺省 default、显式空 400 并
            # 隔离。
            data = self._read_json()
            required = (
                "signer_did", "at", "proof", "challenge", "source_tenant_id"
            )
            if set(data) != set(required):
                missing = [f for f in required if f not in data]
                if missing:
                    raise ValidationError(
                        f"请求缺少字段: {', '.join(missing)}"
                    )
                extra = sorted(set(data) - set(required))
                raise ValidationError(
                    f"请求含多余字段: {', '.join(extra)}"
                )
            signer_did = data["signer_did"]
            if not isinstance(signer_did, str) or not signer_did:
                raise ValidationError(
                    "请求不合法: 字段 signer_did 必须为非空字符串"
                )
            at = data["at"]
            if (
                not isinstance(at, int)
                or isinstance(at, bool)
                or at < 0
            ):
                raise ValidationError(
                    "请求不合法: 字段 at 必须为非布尔非负整数"
                )
            proof = data["proof"]
            if not isinstance(proof, dict):
                raise ValidationError(
                    "请求不合法: 字段 proof 必须为 JSON 对象"
                )
            challenge = data["challenge"]
            if not isinstance(challenge, str) or not challenge:
                raise ValidationError(
                    "请求不合法: 字段 challenge 必须为非空字符串"
                )
            source_tenant_id = data["source_tenant_id"]
            if not isinstance(source_tenant_id, str) or not source_tenant_id:
                raise ValidationError(
                    "请求不合法: 字段 source_tenant_id 必须为非空字符串"
                )
            try:
                valid, reason = store.verify_trust_proof_synced(
                    tenant, signer_did, at, proof, challenge,
                    source_tenant_id,
                )
            except (NotFoundError, ConflictError):
                raise
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_invalid("验签过程发生内部错误")
                return
            if not valid:
                self._send_invalid(reason or "验签失败")
                return
            self._send_json(200, {"valid": True})

        def _post_trust_proofs_verify_synced_with_status(
            self, tenant: str
        ) -> None:
            # POST /v1/trust/proofs/verify-synced-with-status：以同步
            # 锚点验真外部谓词证明并合并请求初始本租户状态快照（只读）。
            # 请求体须恰含 signer_did（非空字符串）、at（非布尔非负
            # 整数）、proof（JSON 对象）、challenge（非空字符串）、
            # source_tenant_id（非空字符串）；空体、非法 JSON、非对象、
            # 键集或类型错误均 400 且仅 {"error": 非空中文}。signer_did
            # 未同步或跨租户 404、at 超过同步检查点 409，同形仅
            # {"error"}。外层合法后任何失败均 HTTP 200 按键序恰返
            # {"valid":false,"reason":...}：证明九字段、谓词/results、
            # 挑战、锚点、签名覆盖、格式、验签、期限、校验顺序及原因
            # 完全沿用 verify-synced，原验真失败不查状态；验真成功后
            # 以请求初始一次原子读取的本租户状态快照查证明的
            # (issuer_did, credential_id)：未同步、revoked、unknown
            # 依次为“外部凭证状态未同步”“外部凭证已吊销：<reason>”
            # （空或缺失 reason 用“未知原因”）“外部凭证状态未知”，
            # active 成功；成功仅 {"valid":true}。纯只读：不改同步页、
            # 检查点、锚点、证明、状态或审计，重启一致；租户头缺省
            # default、显式空 400 并隔离。
            data = self._read_json()
            required = (
                "signer_did", "at", "proof", "challenge", "source_tenant_id"
            )
            if set(data) != set(required):
                missing = [f for f in required if f not in data]
                if missing:
                    raise ValidationError(
                        f"请求缺少字段: {', '.join(missing)}"
                    )
                extra = sorted(set(data) - set(required))
                raise ValidationError(
                    f"请求含多余字段: {', '.join(extra)}"
                )
            signer_did = data["signer_did"]
            if not isinstance(signer_did, str) or not signer_did:
                raise ValidationError(
                    "请求不合法: 字段 signer_did 必须为非空字符串"
                )
            at = data["at"]
            if (
                not isinstance(at, int)
                or isinstance(at, bool)
                or at < 0
            ):
                raise ValidationError(
                    "请求不合法: 字段 at 必须为非布尔非负整数"
                )
            proof = data["proof"]
            if not isinstance(proof, dict):
                raise ValidationError(
                    "请求不合法: 字段 proof 必须为 JSON 对象"
                )
            challenge = data["challenge"]
            if not isinstance(challenge, str) or not challenge:
                raise ValidationError(
                    "请求不合法: 字段 challenge 必须为非空字符串"
                )
            source_tenant_id = data["source_tenant_id"]
            if not isinstance(source_tenant_id, str) or not source_tenant_id:
                raise ValidationError(
                    "请求不合法: 字段 source_tenant_id 必须为非空字符串"
                )
            try:
                valid, reason = (
                    store.verify_trust_proof_synced_with_status(
                        tenant, signer_did, at, proof, challenge,
                        source_tenant_id,
                    )
                )
            except (NotFoundError, ConflictError):
                raise
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_invalid("验签过程发生内部错误")
                return
            if not valid:
                self._send_invalid(reason or "验签失败")
                return
            self._send_json(200, {"valid": True})

        def _post_trust_proofs_verify_synced_batch(
            self, tenant: str
        ) -> None:
            # POST /v1/trust/proofs/verify-synced-batch：批量以同步锚点
            # 快照验真外部谓词证明（只读）。请求体须恰含 signer_did
            # （非空字符串）、at（非布尔非负整数）、proofs（1–100 项
            # 数组）；空体、非法 JSON、非对象、键集或类型错误、空数组或
            # 超限均 400 且仅 {"error":"请求非法"}；来源未同步或跨租户
            # 404 仅 {"error":"同步来源不存在"}，at 超检查点 409 仅
            # {"error":"同步游标冲突"}，先于项校验。合法时 200 仅返
            # {"results":[...]}，逐项不短路、等长同序：项须恰含 proof
            # （对象）、非空 challenge、非空 source_tenant_id，否则该项
            # {"valid":false,"reason":"请求项非法"}；合法项沿用单条
            # verify-synced 的证明九字段、谓词/results、RFC6901 路径、
            # 挑战、签名覆盖、cursor<=at 末事件锚点、期限及顺序，锚点
            # 缺失/非 active/uses 无 proof 为“同步锚点不可用”，格式、
            # 验签、过期依次为“签名格式错误”“签名校验失败”“证明已
            # 过期”；成功项仅 {"valid":true}，失败项键序 valid、reason。
            # 纯只读：不改同步页、检查点、锚点、证明、状态或审计，重启
            # 一致；租户头缺省 default、显式空 400 并隔离。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except Exception:  # noqa: BLE001 请求非法绝不暴露内部细节
                self._send_error(400, "请求非法")
                return
            if not raw:
                self._send_error(400, "请求非法")
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_error(400, "请求非法")
                return
            if not isinstance(data, dict) or set(data) != {
                "signer_did",
                "at",
                "proofs",
            }:
                self._send_error(400, "请求非法")
                return
            signer_did = data["signer_did"]
            at = data["at"]
            proofs = data["proofs"]
            if (
                not isinstance(signer_did, str)
                or not signer_did
                or not isinstance(at, int)
                or isinstance(at, bool)
                or at < 0
                or not isinstance(proofs, list)
                or not 1 <= len(proofs) <= 100
            ):
                self._send_error(400, "请求非法")
                return
            try:
                results = store.verify_trust_proofs_synced_batch(
                    tenant, signer_did, at, proofs
                )
            except NotFoundError:
                self._send_error(404, "同步来源不存在")
                return
            except ConflictError:
                self._send_error(409, "同步游标冲突")
                return
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_error(500, "服务器内部错误")
                return
            self._send_json(200, {"results": results})

        def _post_trust_proofs_verify_synced_batch_with_status(
            self, tenant: str
        ) -> None:
            # POST /v1/trust/proofs/verify-synced-batch-with-status：
            # 批量以同步锚点快照验真外部谓词证明并合并批初本租户状态
            # 快照（只读）。请求级协议与 verify-synced-batch 完全一致：
            # 请求体须恰含 signer_did（非空字符串）、at（非布尔非负
            # 整数）、proofs（1–100 项数组）；空体、非法 JSON、非对象、
            # 键集或类型错误、空数组或超限均 400 且仅
            # {"error":"请求非法"}；来源未同步或跨租户 404 仅
            # {"error":"同步来源不存在"}，at 超检查点 409 仅
            # {"error":"同步游标冲突"}，均先于逐项校验。合法时 200 仅
            # 返 {"results":[...]}，逐项不短路、等长同序：项须恰含
            # proof（对象）、非空 challenge、非空 source_tenant_id，
            # 否则该项 {"valid":false,"reason":"请求项非法"}；合法项
            # 沿用 verify-synced-batch 的证明九字段、谓词/results、
            # RFC6901 路径、挑战、cursor<=at 末锚点、签名覆盖、格式、
            # 验签、期限、顺序及原因；验真通过后按证明的
            # (issuer_did, credential_id) 查批初原子读取的本租户状态
            # 快照：未同步、revoked、unknown 分别返“外部凭证状态未
            # 同步”“外部凭证已吊销：<reason>”（空或缺失 reason 用
            # “未知原因”）“外部凭证状态未知”，active 成功。成功项仅
            # {"valid":true}，失败项键序 valid、reason。纯只读：不写
            # 同步页、检查点、锚点、证明、状态或审计；租户头缺省
            # default、显式空 400 并隔离。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except Exception:  # noqa: BLE001 请求非法绝不暴露内部细节
                self._send_error(400, "请求非法")
                return
            if not raw:
                self._send_error(400, "请求非法")
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_error(400, "请求非法")
                return
            if not isinstance(data, dict) or set(data) != {
                "signer_did",
                "at",
                "proofs",
            }:
                self._send_error(400, "请求非法")
                return
            signer_did = data["signer_did"]
            at = data["at"]
            proofs = data["proofs"]
            if (
                not isinstance(signer_did, str)
                or not signer_did
                or not isinstance(at, int)
                or isinstance(at, bool)
                or at < 0
                or not isinstance(proofs, list)
                or not 1 <= len(proofs) <= 100
            ):
                self._send_error(400, "请求非法")
                return
            try:
                results = (
                    store.verify_trust_proofs_synced_batch_with_status(
                        tenant, signer_did, at, proofs
                    )
                )
            except NotFoundError:
                self._send_error(404, "同步来源不存在")
                return
            except ConflictError:
                self._send_error(409, "同步游标冲突")
                return
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_error(500, "服务器内部错误")
                return
            self._send_json(200, {"results": results})

        def _post_trust_proofs_verify_batch(self, tenant: str) -> None:
            # 批量跨系统谓词证明验真：与单项相同的公开错误协议，任何失败
            # 都返回 HTTP 200。请求体须恰为 {"proofs": [项...]}，数组非空
            # 且不超过 100 项；请求体非法（含非法 JSON、空数组、超过上限）
            # 时返回 {"results": [], "reason": "请求..."}。请求级合法时
            # 返回 {"results": [...]}，长度与顺序与输入一致，逐项复用单项
            # 验真规则，失败不短路。只读，不消费、不写任何状态、不记审计。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except (ValueError, TypeError):
                self._send_json(
                    200,
                    {"results": [],
                     "reason": "请求不合法: 请求体缺失或长度声明非法"},
                )
                return
            except Exception:  # noqa: BLE001
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体读取失败"}
                )
                return
            if not raw:
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体缺失"}
                )
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._send_json(
                    200,
                    {"results": [], "reason": "请求不合法: 请求体不是合法 UTF-8 文本"},
                )
                return
            except json.JSONDecodeError:
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体不是合法 JSON"}
                )
                return

            try:
                ok, reason, results = store.verify_trust_proofs_batch(
                    tenant, data
                )
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 验签过程发生内部错误"}
                )
                return
            if not ok:
                self._send_json(
                    200, {"results": [], "reason": reason or "请求不合法"}
                )
                return
            self._send_json(200, {"results": results})

        def _post_trust_proofs_verify_with_status(
            self, tenant: str
        ) -> None:
            # 外部谓词证明验真并合并状态判定：公开错误协议，任何失败都
            # 返回 200 + {"valid": false, "reason": "<非空中文原因>"}。
            # 请求体须恰含 proof（对象）、challenge（非空字符串）与
            # source_tenant_id（非空字符串），解析规则与
            # /v1/trust/proofs/verify 完全一致；验真通过后由 store 只读
            # 查询本租户同步状态。纯只读，不消费、不写状态、不记审计。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except (ValueError, TypeError):
                self._send_invalid("请求体缺失或长度声明非法")
                return
            except Exception:  # noqa: BLE001
                self._send_invalid("请求体读取失败")
                return
            if not raw:
                self._send_invalid("请求体缺失")
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._send_invalid("请求体不是合法 UTF-8 文本")
                return
            except json.JSONDecodeError:
                self._send_invalid("请求体不是合法 JSON")
                return

            try:
                valid, reason = store.verify_trust_proof_with_status(
                    tenant, data
                )
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_invalid("验签过程发生内部错误")
                return
            payload: Dict[str, Any] = {"valid": valid}
            if not valid:
                payload["reason"] = reason or "验签失败"
            self._send_json(200, payload)

        def _post_trust_proofs_verify_batch_with_status(
            self, tenant: str
        ) -> None:
            # 批量外部谓词证明验真并合并本租户状态：与 verify-batch 相同的
            # 公开错误协议，任何失败都返回 HTTP 200。请求体须恰为
            # {"proofs": [项...]}，数组非空且不超过 100 项；请求体非法
            # （含非法 JSON、空数组、超过上限）时返回
            # {"results": [], "reason": "请求..."}。请求级合法时逐项复用
            # verify-with-status 规则（验真 + 只读合并同步状态），按输入
            # 顺序返回 {"results": [...]}，失败不短路。只读，不消费、
            # 不写任何状态、不记审计。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except (ValueError, TypeError):
                self._send_json(
                    200,
                    {"results": [],
                     "reason": "请求不合法: 请求体缺失或长度声明非法"},
                )
                return
            except Exception:  # noqa: BLE001
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体读取失败"}
                )
                return
            if not raw:
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体缺失"}
                )
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._send_json(
                    200,
                    {"results": [], "reason": "请求不合法: 请求体不是合法 UTF-8 文本"},
                )
                return
            except json.JSONDecodeError:
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体不是合法 JSON"}
                )
                return

            try:
                ok, reason, results = (
                    store.verify_trust_proofs_batch_with_status(tenant, data)
                )
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 验签过程发生内部错误"}
                )
                return
            if not ok:
                self._send_json(
                    200, {"results": [], "reason": reason or "请求不合法"}
                )
                return
            self._send_json(200, {"results": results})

        def _post_trust_credentials_verify_batch(self, tenant: str) -> None:
            # 批量外部凭证验真：与单项相同的公开错误协议，任何失败都
            # 返回 HTTP 200。请求体须恰为 {"credentials": [项...]}，数组
            # 非空且不超过 100 项；请求体非法（含非法 JSON、空数组、超过
            # 上限）时返回 {"results": [], "reason": "请求..."}。请求级
            # 合法时返回 {"results": [...]}，长度与顺序与输入一致，逐项
            # 复用单项验真规则，失败不短路。只读，不写任何状态、不记审计。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except (ValueError, TypeError):
                self._send_json(
                    200,
                    {"results": [],
                     "reason": "请求不合法: 请求体缺失或长度声明非法"},
                )
                return
            except Exception:  # noqa: BLE001
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体读取失败"}
                )
                return
            if not raw:
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体缺失"}
                )
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._send_json(
                    200,
                    {"results": [], "reason": "请求不合法: 请求体不是合法 UTF-8 文本"},
                )
                return
            except json.JSONDecodeError:
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体不是合法 JSON"}
                )
                return

            try:
                ok, reason, results = store.verify_trust_credentials_batch(
                    tenant, data
                )
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 验签过程发生内部错误"}
                )
                return
            if not ok:
                self._send_json(
                    200, {"results": [], "reason": reason or "请求不合法"}
                )
                return
            self._send_json(200, {"results": results})

        def _post_trust_credentials_verify_batch_with_status(
            self, tenant: str
        ) -> None:
            # 批量外部凭证验真并合并本租户同步状态：与 verify-batch 相同的
            # 公开错误协议，任何失败都返回 HTTP 200。请求体须恰为
            # {"credentials": [项...]}，数组非空且不超过 100 项；请求体非法
            # （含非法 JSON、空数组、超过上限）时返回
            # {"results": [], "reason": "请求..."}。请求级合法时逐项复用
            # verify-with-status 规则（验真 + 只读合并同步状态），按输入
            # 顺序返回 {"results": [...]}，失败不短路。只读，不写凭证、
            # 状态、同步记录、历史或审计。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except (ValueError, TypeError):
                self._send_json(
                    200,
                    {"results": [],
                     "reason": "请求不合法: 请求体缺失或长度声明非法"},
                )
                return
            except Exception:  # noqa: BLE001
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体读取失败"}
                )
                return
            if not raw:
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体缺失"}
                )
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._send_json(
                    200,
                    {"results": [], "reason": "请求不合法: 请求体不是合法 UTF-8 文本"},
                )
                return
            except json.JSONDecodeError:
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体不是合法 JSON"}
                )
                return

            try:
                ok, reason, results = (
                    store.verify_trust_credentials_batch_with_status(
                        tenant, data
                    )
                )
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 验签过程发生内部错误"}
                )
                return
            if not ok:
                self._send_json(
                    200, {"results": [], "reason": reason or "请求不合法"}
                )
                return
            self._send_json(200, {"results": results})

        def _post_trust_credentials_verify_with_status(
            self, tenant: str
        ) -> None:
            # 外部凭证验真并合并状态判定：公开错误协议，任何失败都返回
            # 200 + {"valid": false, "reason": "<非空中文原因>"}。
            # 请求体须恰含 body（对象）与 signature（非空字符串），解析
            # 规则与 /v1/trust/credentials/verify 完全一致；验真通过后
            # 由 store 只读查询本租户同步状态。纯只读，不写状态、不记审计。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except (ValueError, TypeError):
                self._send_invalid("请求体缺失或长度声明非法")
                return
            except Exception:  # noqa: BLE001
                self._send_invalid("请求体读取失败")
                return
            if not raw:
                self._send_invalid("请求体缺失")
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._send_invalid("请求体不是合法 UTF-8 文本")
                return
            except json.JSONDecodeError:
                self._send_invalid("请求体不是合法 JSON")
                return

            try:
                valid, reason = (
                    store.verify_trust_credential_with_status(tenant, data)
                )
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_invalid("验签过程发生内部错误")
                return
            payload: Dict[str, Any] = {"valid": valid}
            if not valid:
                payload["reason"] = reason or "验签失败"
            self._send_json(200, payload)

        def _post_trust_credential_status_sync(self, tenant: str) -> None:
            # 外部凭证状态同步。请求/字段非法由 _read_json 与 store 抛
            # ValidationError -> 400；同 updated_at 不同内容由 store 抛
            # ConflictError -> 409。锚点缺失/吊销、签名格式错误、验签
            # 失败均按公开错误协议返回 200 + {"valid":false,"reason":...}
            # （前缀依次为“锚点”/“签名格式错误”/“签名校验失败”）且不写入。
            data = self._read_json()
            result = store.sync_credential_status(tenant, data)
            if not result.get("valid"):
                self._send_invalid(result.get("reason") or "验签失败")
                return
            record = result["record"]
            # 首次同步 201；严格更新或重放 200（重放内容不变）。
            self._send_json(
                result["status_code"],
                {
                    "issuer_did": record.issuer_did,
                    "credential_id": record.credential_id,
                    "status": record.status,
                    "reason": record.reason,
                    "updated_at": record.updated_at,
                    "issuer_key_version": record.issuer_key_version,
                },
            )

        def _post_trust_credential_status_sync_batch(
            self, tenant: str
        ) -> None:
            # 批量外部凭证状态同步：任何失败都返回 HTTP 200。请求体须恰为
            # {"items": [项...]}，数组非空且不超过 100 项；请求体非法
            # （外层缺失、非法 JSON、非对象、字段缺失或多余、items 非数组、
            # 空数组或超过上限）时返回 {"results": [], "reason": "请求..."}。
            # 请求级合法时返回 {"results": [...]}，长度与顺序与输入一致，
            # 逐项复用单项同步规则，失败不短路：字段错误 400、同秒冲突
            # 409、锚点/签名失败 200 均收敛为单项结果（含 http_status 与
            # 非空中文 reason），不影响其余项；成功项首次 201，重放/更早
            # 日 200，严格更新 200 并记审计。显式空 X-Tenant-ID 在此之前
            # 由路由统一判 400；本地（本租户）凭证状态始终不变。
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length > 0 else b""
            except (ValueError, TypeError):
                self._send_json(
                    200,
                    {"results": [],
                     "reason": "请求不合法: 请求体缺失或长度声明非法"},
                )
                return
            except Exception:  # noqa: BLE001
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体读取失败"}
                )
                return
            if not raw:
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体缺失"}
                )
                return
            try:
                data = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._send_json(
                    200,
                    {"results": [], "reason": "请求不合法: 请求体不是合法 UTF-8 文本"},
                )
                return
            except json.JSONDecodeError:
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 请求体不是合法 JSON"}
                )
                return

            try:
                ok, reason, results = store.sync_credential_status_batch(
                    tenant, data
                )
            except Exception:  # noqa: BLE001 批量同步失败绝不暴露内部细节
                self._send_json(
                    200, {"results": [], "reason": "请求不合法: 同步过程发生内部错误"}
                )
                return
            if not ok:
                self._send_json(
                    200, {"results": [], "reason": reason or "请求不合法"}
                )
                return
            self._send_json(200, {"results": results})

        def _get_trust_credential_status(
            self, tenant: str, credential_id: str, query: str
        ) -> None:
            # GET .../{credential_id}?issuer_did=...：issuer_did 须唯一
            # 且非空，否则 400；未同步（含他租户双键）404，跨租户不可
            # 探测。已同步仅返回 status、reason、updated_at。
            if not credential_id:
                raise ValidationError("路径缺少 credential_id")
            params = parse_qs(query, keep_blank_values=True)
            values = params.get("issuer_did")
            if values is None:
                raise ValidationError("查询参数 issuer_did 必填")
            if len(values) != 1:
                raise ValidationError("查询参数 issuer_did 只能提供一次")
            issuer_did = values[0]
            if not issuer_did:
                raise ValidationError(
                    "查询参数 issuer_did 必须为非空字符串"
                )
            record = store.get_synced_credential_status(
                tenant, issuer_did, credential_id
            )
            self._send_json(
                200,
                {
                    "status": record.status,
                    "reason": record.reason,
                    "updated_at": record.updated_at,
                },
            )

        def _get_trust_imported_credential(
            self, tenant: str, credential_id: str, query: str
        ) -> None:
            # GET /v1/trust/credentials/imported/{credential_id}
            # ?issuer_did=...：issuer_did 须唯一且非空，缺失/重复/空值
            # 一律 400；未导入、跨租户或 issuer_did 不匹配（含他租户
            # 双键）404，存在性不可探测。成功 200 返回键序
            # issuer_did,credential_id,body,signature。纯只读，不写状态、
            # 不记审计。
            if not credential_id:
                raise ValidationError("路径缺少 credential_id")
            params = parse_qs(query, keep_blank_values=True)
            values = params.get("issuer_did")
            if values is None:
                raise ValidationError("查询参数 issuer_did 必填")
            if len(values) != 1:
                raise ValidationError("查询参数 issuer_did 只能提供一次")
            issuer_did = values[0]
            if not issuer_did:
                raise ValidationError(
                    "查询参数 issuer_did 必须为非空字符串"
                )
            record = store.get_imported_credential(
                tenant, issuer_did, credential_id
            )
            self._send_json(
                200,
                {
                    "issuer_did": record.issuer_did,
                    "credential_id": record.credential_id,
                    "body": record.body,
                    "signature": record.signature,
                },
            )

        def _get_trust_credential_status_history(
            self, tenant: str, credential_id: str, query: str
        ) -> None:
            # GET .../{credential_id}/history?issuer_did=...&limit=&after=
            # issuer_did 须唯一且非空，否则 400；limit 缺省 50，须为
            # 1..200 的 ASCII 十进制整数；after 缺省 0，须为非负 ASCII
            # 十进制整数；重复/非法一律 400。未同步双键（含他租户）404。
            # 只读：不写任何状态、不记审计。
            if not credential_id:
                raise ValidationError("路径缺少 credential_id")
            params = parse_qs(query, keep_blank_values=True)

            issuer_values = params.get("issuer_did")
            if issuer_values is None:
                raise ValidationError("查询参数 issuer_did 必填")
            if len(issuer_values) != 1:
                raise ValidationError("查询参数 issuer_did 只能提供一次")
            issuer_did = issuer_values[0]
            if not issuer_did:
                raise ValidationError(
                    "查询参数 issuer_did 必须为非空字符串"
                )

            limit_values = params.get("limit")
            if limit_values is not None:
                if len(limit_values) != 1:
                    raise ValidationError("查询参数 limit 只能提供一次")
                limit = _parse_nonneg_int(limit_values[0], "limit")
                if not 1 <= limit <= 200:
                    raise ValidationError(
                        "查询参数 limit 须在 1 到 200 之间"
                    )
            else:
                limit = 50

            after_values = params.get("after")
            if after_values is not None:
                if len(after_values) != 1:
                    raise ValidationError("查询参数 after 只能提供一次")
                after = _parse_nonneg_int(after_values[0], "after")
            else:
                after = 0

            events, next_after = store.list_synced_credential_status_history(
                tenant, issuer_did, credential_id, after, limit
            )
            self._send_json(
                200,
                {
                    "issuer_did": issuer_did,
                    "credential_id": credential_id,
                    "events": [
                        {
                            "status": event.status,
                            "reason": event.reason,
                            "updated_at": event.updated_at,
                            "issuer_key_version": event.issuer_key_version,
                            "audit_seq": event.audit_seq,
                            "audit_timestamp": event.audit_timestamp,
                            "cursor": event.cursor,
                        }
                        for event in events
                    ],
                    "next_after": next_after,
                },
            )

        def _get_audit(self, tenant: str, query: str) -> None:            # GET /v1/audit?limit=&after=：租户内按 seq 升序。
            # limit 缺省 50，须为 1..200 的整数；after 缺省 0，须为
            # 非负整数；非法一律 400。返回 events 与 next_after，
            # 空页 next_after 保持 after。
            params = parse_qs(query, keep_blank_values=True)
            limit_values = params.get("limit")
            after_values = params.get("after")
            if limit_values is not None:
                if len(limit_values) != 1:
                    raise ValidationError("查询参数 limit 只能提供一次")
                limit = _parse_nonneg_int(limit_values[0], "limit")
                if not 1 <= limit <= 200:
                    raise ValidationError("查询参数 limit 须在 1 到 200 之间")
            else:
                limit = 50
            if after_values is not None:
                if len(after_values) != 1:
                    raise ValidationError("查询参数 after 只能提供一次")
                after = _parse_nonneg_int(after_values[0], "after")
            else:
                after = 0

            events, next_after = store.list_audit(tenant, after, limit)
            self._send_json(
                200,
                {
                    "events": [
                        {
                            "seq": event.seq,
                            "timestamp": event.timestamp,
                            "tenant_id": event.tenant_id,
                            "action": event.action,
                            "resource_type": event.resource_type,
                            "resource_id": event.resource_id,
                        }
                        for event in events
                    ],
                    "next_after": next_after,
                },
            )

    return Handler


class _ReadyServer(ThreadingHTTPServer):
    """确定性端口生命周期的 HTTP 服务。

    - allow_reuse_address：退出后同端口立即可再次绑定；
    - daemon_threads：活动请求线程不阻塞进程退出；
    - 绑定失败时关闭已创建的监听套接字，不残留监听。
    """

    allow_reuse_address = True
    daemon_threads = True

    def server_bind(self) -> None:
        try:
            super().server_bind()
        except OSError:
            try:
                self.socket.close()
            except OSError:
                pass
            raise


def _oserror_chinese(what: str, exc: OSError) -> str:
    """把 OSError 映射为单行中文原因。"""
    code = getattr(exc, "errno", None)
    if code is not None:
        if code == errno.EADDRINUSE:
            return f"{what}地址已被占用"
        if code == errno.EACCES:
            return f"{what}权限不足"
        return f"{what}失败（错误码 {code}）"
    return f"{what}失败"


def run(
    host: str = "127.0.0.1",
    port: int = 8080,
    store_path: Optional[str] = None,
    quiet: bool = False,
) -> None:
    """启动 HTTP 服务（阻塞至 Ctrl-C 后返回 None）。

    参数非法抛 ValueError；绑定或状态文件 I/O 失败抛 OSError；状态
    JSON 不可解析抛 ValueError。任何失败路径都不输出 READY 行且不
    残留监听套接字。绑定成功后向 stdout 输出一行：
    ``VCBACKEND_READY host=<host> port=<实际端口>``（port=0 时报告
    内核分配的实际端口），UTF-8 编码并 flush。
    """
    # ---- 参数校验（先于任何副作用） -------------------------------- #
    if not isinstance(host, str) or not host:
        raise ValueError("host 必须为非空字符串")
    if isinstance(port, bool) or not isinstance(port, int):
        raise ValueError("port 必须为整数")
    if not 0 <= port <= 65535:
        raise ValueError("port 必须在 0 到 65535 之间")
    if store_path is not None and not isinstance(store_path, str):
        raise ValueError("store_path 必须为 None 或字符串")

    # ---- 加载状态文件（先绑定，失败时尚无监听套接字） -------------- #
    try:
        store = VCStore(store_path)
    except (ValueError, TypeError, AttributeError) as exc:
        # json.JSONDecodeError 本身是 ValueError 子类；损坏的字段值
        # （int() 失败等）与结构畸形（顶层非对象）同样归为状态不可解析。
        message = str(exc).strip() or "状态文件内容无法解析"
        message = message.replace("\r", " ").replace("\n", " ").strip()
        raise ValueError(f"状态文件不是合法 JSON：{message}") from exc
    except OSError as exc:
        raise OSError(
            f"状态文件读取失败：{_oserror_chinese('读取状态文件', exc)}"
        ) from exc

    handler = build_handler(store)
    if quiet:
        handler.log_message = lambda *args, **kwargs: None  # noqa: E731

    # ---- 绑定监听端口 ---------------------------------------------- #
    try:
        httpd = _ReadyServer((host, port), handler)
    except OSError as exc:
        raise OSError(
            f"监听地址绑定失败：{_oserror_chinese('绑定监听地址', exc)}"
        ) from exc

    actual_port = int(httpd.server_address[1])
    try:
        sys.stdout.buffer.write(
            f"VCBACKEND_READY host={host} port={actual_port}\n".encode("utf-8")
        )
        sys.stdout.buffer.flush()
    except (AttributeError, OSError):
        # 极端环境下 stdout 无 buffer（如测试替身）：退回文本接口。
        print(f"VCBACKEND_READY host={host} port={actual_port}", flush=True)

    # ---- 服务至 Ctrl-C：守护线程承担活动请求，不阻塞退出 ----------- #
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        return None
    finally:
        try:
            httpd.server_close()
        except OSError:
            pass
    return None
