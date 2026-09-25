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
  PUT  /v1/credentials/{credential_id}/status   登记/变更状态（active 首次 201；暂停 suspended/恢复 active/幂等 200；revoked 终态 409）
  GET  /v1/credentials/{credential_id}/status   查询状态（无状态按 active）
  GET  /v1/credentials/{credential_id}/status/history  查询凭证状态历史（只读）
  POST /v1/credentials/{credential_id}/revoke   吊销凭证
  POST /v1/credentials/{credential_id}/verify  以存储记录为锚验签
  POST /v1/credentials/{credential_id}/present 生成选择性披露演示
  POST /v1/credentials/{credential_id}/present-batch 原子批量生成选择性披露演示
  POST /v1/presentations/{presentation_id}/verify  以存储记录为锚校验演示
  POST /v1/credentials/{credential_id}/prove    生成谓词证明
  POST /v1/proofs/{proof_id}/verify             以存储记录为锚校验谓词证明
  POST /v1/trust/anchors                  注册信任锚点（同 DID/版本同 PEM 幂等）
  GET  /v1/trust/anchors                  跨 DID 只读发现锚点版本（?limit=&after=&status=）
  POST /v1/trust/anchors/{did}/rotate     带前置版本校验的密钥轮换
  GET  /v1/trust/anchors/{did}            查询 DID 的全部锚点版本
  GET  /v1/trust/anchors/{did}/history    查询信任锚点生命周期历史（只读）
  PUT  /v1/trust/anchors/{did}/{key_version}/status  吊销锚点版本
  POST /v1/trust/verify                   用 active 锚点公钥验签
  POST /v1/trust/credentials/verify       跨系统凭证验真（无需登记 DID/凭证）
  POST /v1/trust/credentials/import       导入外部凭证（active 锚点验签后持久化）
  POST /v1/trust/credentials/import-batch 批量导入外部凭证（逐项不短路）
  GET  /v1/trust/credentials/imported/{credential_id}  读取已导入的外部凭证（?issuer_did=）
  POST /v1/trust/credentials/imported/{credential_id}/verify  重启后重新验证已落盘凭证（?issuer_did=，只读）
  POST /v1/trust/credentials/imported/{credential_id}/verify-with-status  重验已导入凭证并合并同步状态（?issuer_did=，只读）
  POST /v1/trust/credentials/imported/verify-batch-with-status 批量重验已导入凭证并合并同步状态（只读）
  POST /v1/trust/dids/verify-document     跨系统 DID 文档验真（仅凭提交文档，只读）
  POST /v1/trust/dids/verify-document-batch 批量跨系统 DID 文档验真（不短路，只读）
  POST /v1/trust/presentations/verify     跨系统演示验真（无需登记 DID/凭证/演示）
  POST /v1/trust/presentations/verify-batch 批量跨系统演示验真（仅未绑定形态，不消费）
  POST /v1/trust/presentations/verify-with-status 外部演示验真并合并同步状态（只读）
  POST /v1/trust/presentations/verify-batch-with-status 批量演示验真并合并同步状态（只读）
  POST /v1/trust/proofs/verify            跨系统谓词证明验真（无需登记 DID/凭证/证明，不消费）
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
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

from .store import (
    CHALLENGE_UNSET,
    ConflictError,
    DEFAULT_TENANT,
    EXPIRES_AT_UNSET,
    NotFoundError,
    PresentationRecord,
    REASON_UNSET,
    ValidationError,
    VCStore,
)


def _json_dumps(payload: Any) -> bytes:
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


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
                elif path == "/v1/trust/verify":
                    self._post_trust_verify(tenant)
                elif path == "/v1/trust/credentials/verify":
                    self._post_trust_credentials_verify(tenant)
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
            # 请求体须恰为 {"status": "active"} 或
            # {"status": "suspended", "reason": "原因"}：缺字段、未知
            # status、多余字段（active 带 reason 等）一律 400；suspended
            # 的 reason 必填，须为字符串且首尾裁剪后为 1..256 个 Unicode
            # 码点，否则 400。
            # 无状态首次登记 active 为 201；无状态/active 转 suspended、
            # suspended 恢复 active、同状态幂等均 200；暂停时原因不同
            # 409；已 revoked 409；未知或跨租户凭证 404。
            data = self._read_json()
            if "status" not in data:
                raise ValidationError("缺少字段: status")
            status = data["status"]
            if status == "active":
                extra = sorted(set(data) - {"status"})
                if extra:
                    raise ValidationError(f"多余字段: {', '.join(extra)}")
                record, created = store.set_credential_status(
                    tenant, credential_id, "active"
                )
            elif status == "suspended":
                extra = sorted(set(data) - {"status", "reason"})
                if extra:
                    raise ValidationError(f"多余字段: {', '.join(extra)}")
                if "reason" not in data:
                    raise ValidationError("缺少字段: reason")
                reason = data["reason"]
                if not isinstance(reason, str):
                    raise ValidationError("字段 reason 必须为字符串")
                reason = reason.strip()
                if not 1 <= len(reason) <= 256:
                    raise ValidationError(
                        "字段 reason 裁剪后须为 1 到 256 个字符"
                    )
                record, created = store.set_credential_status(
                    tenant, credential_id, "suspended", reason
                )
            else:
                raise ValidationError(
                    f"字段 status 非法: {status!r}（仅支持 active、suspended）"
                )
            # 首次 active 登记 201；其余转换与幂等均 200
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
            # key_version 为非布尔正整数；多余字段一律 400。
            data = self._read_json()
            self._require_fields(data, ("did", "public_key"))
            if "key_version" not in data:
                raise ValidationError("缺少字段: key_version")
            extra = sorted(
                set(data) - {"did", "public_key", "key_version"}
            )
            if extra:
                raise ValidationError(f"多余字段: {', '.join(extra)}")
            record, created = store.register_trust_anchor(
                tenant,
                data["did"],
                data["public_key"],
                data["key_version"],
            )
            # 新建 201；同 DID/版本同 PEM 幂等重试 200；PEM 不同由
            # store 抛 ConflictError -> 409。
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
