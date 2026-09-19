"""HTTP 服务：基于标准库 http.server。

路由：
  POST /v1/dids                           注册 DID
  GET  /v1/dids/{did}                     查询 DID
  POST /v1/dids/{did}/keys/rotate         轮换 DID 密钥
  POST /v1/credentials                    签发凭证
  GET  /v1/credentials/{credential_id}    查询凭证
  PUT  /v1/credentials/{credential_id}/status   登记 active（首次 201/重复 200）
  GET  /v1/credentials/{credential_id}/status   查询状态（无状态按 active）
  POST /v1/credentials/{credential_id}/revoke   吊销凭证
  POST /v1/credentials/{credential_id}/verify  以存储记录为锚验签
  POST /v1/credentials/{credential_id}/present 生成选择性披露演示
  POST /v1/presentations/{presentation_id}/verify  以存储记录为锚校验演示
  GET  /v1/audit?limit=&after=            查询本租户审计事件（seq 升序）

租户隔离：/v1 请求取 X-Tenant-ID 头，缺省为 default；显式提供但
为空（或纯空白）返回 400。DID、凭证、演示与 key_handle 仅本租户
可见，跨租户访问一律按资源不存在处理。

错误映射：ValidationError -> 400，NotFoundError -> 404，ConflictError -> 409。
例外：凭证验签端点对一切失败都返回 200 + {"valid": false, "reason": ...}。
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

from .store import (
    CHALLENGE_UNSET,
    ConflictError,
    DEFAULT_TENANT,
    NotFoundError,
    REASON_UNSET,
    ValidationError,
    VCStore,
)


def _json_dumps(payload: Any) -> bytes:
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


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
        # 租户与查询参数
        # ------------------------------------------------------------ #
        def _tenant(self) -> str:
            """取 X-Tenant-ID：缺省 default；显式提供但为空白则 400。"""
            raw = self.headers.get("X-Tenant-ID")
            if raw is None:
                return DEFAULT_TENANT
            if not raw.strip():
                raise ValidationError("X-Tenant-ID 不能为空")
            return raw.strip()

        @staticmethod
        def _parse_int_param(
            params: Dict[str, Any], name: str, default: int,
            minimum: int, maximum: Optional[int],
        ) -> int:
            """解析整数查询参数：缺失用默认值；非整数或越界抛 400。"""
            raw_values = params.get(name)
            if not raw_values:
                return default
            raw = raw_values[0]
            try:
                value = int(raw)
            except (TypeError, ValueError):
                raise ValidationError(f"查询参数 {name} 必须为整数") from None
            if isinstance(value, bool) or value < minimum or (
                maximum is not None and value > maximum
            ):
                raise ValidationError(
                    f"查询参数 {name} 须在 {minimum} 到 {maximum} 之间"
                    if maximum is not None
                    else f"查询参数 {name} 须不小于 {minimum}"
                )
            return value

        # ------------------------------------------------------------ #
        # 路由
        # ------------------------------------------------------------ #
        def do_POST(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
            try:
                path = urlparse(self.path).path.rstrip("/") or "/"
                if path == "/v1/dids":
                    self._post_dids()
                elif path == "/v1/credentials":
                    self._post_credentials()
                elif path.startswith("/v1/dids/") and path.endswith(
                    "/keys/rotate"
                ):
                    did = unquote(
                        path[len("/v1/dids/") : -len("/keys/rotate")]
                    )
                    self._post_rotate_key(did)
                elif path.startswith("/v1/credentials/") and path.endswith(
                    "/revoke"
                ):
                    credential_id = unquote(
                        path[len("/v1/credentials/") : -len("/revoke")]
                    )
                    self._post_revoke_credential(credential_id)
                elif path.startswith("/v1/credentials/") and path.endswith(
                    "/verify"
                ):
                    credential_id = unquote(
                        path[len("/v1/credentials/") : -len("/verify")]
                    )
                    self._post_verify_credential(credential_id)
                elif path.startswith("/v1/credentials/") and path.endswith(
                    "/present"
                ):
                    credential_id = unquote(
                        path[len("/v1/credentials/") : -len("/present")]
                    )
                    self._post_present(credential_id)
                elif path.startswith("/v1/presentations/") and path.endswith(
                    "/verify"
                ):
                    presentation_id = unquote(
                        path[len("/v1/presentations/") : -len("/verify")]
                    )
                    self._post_verify_presentation(presentation_id)
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
                if path.startswith("/v1/credentials/") and path.endswith(
                    "/status"
                ):
                    credential_id = unquote(
                        path[len("/v1/credentials/") : -len("/status")]
                    )
                    self._put_credential_status(credential_id)
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
                if path == "/v1/audit":
                    self._get_audit(parsed.query)
                elif path.startswith("/v1/dids/"):
                    self._get_did(unquote(path[len("/v1/dids/") :]))
                elif path.startswith("/v1/credentials/") and path.endswith(
                    "/status"
                ):
                    credential_id = unquote(
                        path[len("/v1/credentials/") : -len("/status")]
                    )
                    self._get_credential_status(credential_id)
                elif path.startswith("/v1/credentials/"):
                    self._get_credential(
                        unquote(path[len("/v1/credentials/") :])
                    )
                elif path in ("/health", "/healthz"):
                    self._send_json(200, {"status": "ok"})
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

        def _post_dids(self) -> None:
            data = self._read_json()
            self._require_fields(data, ("method", "public_key"))
            key_mode = data.get("key_mode", "server")
            record = store.create_did(
                data["method"],
                data["public_key"],
                key_mode=key_mode,
                tenant_id=self._tenant(),
            )
            self._send_json(201, self._did_payload(record))

        def _get_did(self, did: str) -> None:
            record = store.get_did(did, tenant_id=self._tenant())
            payload = self._did_payload(record)
            payload["created_at"] = record.created_at
            self._send_json(200, payload)

        def _post_rotate_key(self, did: str) -> None:
            data = self._read_json()
            self._require_fields(data, ("key_handle",))
            record = store.rotate_key(
                did, data["key_handle"], tenant_id=self._tenant()
            )
            self._send_json(200, self._did_payload(record))

        def _post_credentials(self) -> None:
            data = self._read_json()
            self._require_fields(data, ("issuer_did", "subject_did"))
            if "claims" not in data:
                raise ValidationError("缺少字段: claims")
            if not isinstance(data["claims"], dict):
                raise ValidationError("字段 claims 必须为 JSON 对象")
            record = store.create_credential(
                data["issuer_did"],
                data["subject_did"],
                data["claims"],
                tenant_id=self._tenant(),
            )
            self._send_json(
                201,
                {
                    "credential_id": record.credential_id,
                    "signature": record.signature,
                    "issuer_key_version": record.body["issuer_key_version"],
                },
            )

        def _get_credential(self, credential_id: str) -> None:
            record = store.get_credential(
                credential_id, tenant_id=self._tenant()
            )
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

        def _put_credential_status(self, credential_id: str) -> None:
            # 请求体必须恰为 {"status": "active"}：缺字段、取值非法、
            # 多余字段一律 400。
            data = self._read_json()
            if "status" not in data:
                raise ValidationError("缺少字段: status")
            extra = sorted(set(data) - {"status"})
            if extra:
                raise ValidationError(f"多余字段: {', '.join(extra)}")
            if data["status"] != "active":
                raise ValidationError(
                    f"字段 status 非法: {data['status']!r}（仅支持 active）"
                )
            record, created = store.set_credential_active(
                credential_id, tenant_id=self._tenant()
            )
            # 无状态登记 201；重复登记 200，保持首次 updated_at
            self._send_json(
                201 if created else 200, self._status_payload(record)
            )

        def _get_credential_status(self, credential_id: str) -> None:
            # 历史无状态按 active 返回，updated_at 为 null
            record = store.get_credential_status(
                credential_id, tenant_id=self._tenant()
            )
            self._send_json(200, self._status_payload(record))

        def _post_revoke_credential(self, credential_id: str) -> None:
            # reason 可省略（请求体亦可整个缺省）；已吊销时任何 reason
            # 均忽略并返回首次结果，非法 reason 仅首次请求 400。
            data = self._read_optional_json()
            # 省略 reason 时传哨兵走默认原因；提供时透传原值，非法
            # reason 的 400 判定由 store 在确认非重复吊销后做出
            # （已吊销时任何 reason 均忽略，含非法值）。
            reason = data["reason"] if "reason" in data else REASON_UNSET
            record = store.revoke_credential(
                credential_id, reason, tenant_id=self._tenant()
            )
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

        def _post_verify_credential(self, credential_id: str) -> None:
            # verify 端点的公开错误协议：任何失败都返回 200 +
            # {"valid": false, "reason": "<非空中文原因>"}，绝不返回
            # 400/404/500，也不泄露私钥或堆栈。reason 按类别措辞：
            # 请求层（请求*）、资源（凭证不存在）、锚定、签名、密钥。
            tenant = self._tenant()  # 租户头非法仍为请求级 400
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
                    credential_id, data["body"], data["signature"],
                    tenant_id=tenant,
                )
            except NotFoundError:
                self._send_invalid(f"凭证不存在: {credential_id}")
                return
            except ValidationError as exc:
                self._send_invalid(f"请求不合法: {exc}")
                return
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_invalid("验签过程发生内部错误")
                return
            payload: Dict[str, Any] = {"valid": valid}
            if not valid:
                payload["reason"] = reason or "验签失败"
            self._send_json(200, payload)

        def _post_present(self, credential_id: str) -> None:
            # 请求体必须恰为 {"disclose": [...]} 加可选 challenge、
            # expires_in：缺失 disclose、类型非法、重复路径或祖先重叠、
            # 多余字段一律 400；未知凭证 404；空列表表示零披露。
            # challenge 须为非空字符串且按 Unicode 码点不超过 256，
            # 缺省生成 32 位小写 hex；expires_in 须为非布尔整数且
            # 在 1..86400 之间，缺省 300。成功 201 返回演示记录。
            data = self._read_json()
            if "disclose" not in data:
                raise ValidationError("缺少字段: disclose")
            extra = sorted(set(data) - {"disclose", "challenge", "expires_in"})
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
            record = store.create_presentation(
                credential_id,
                data["disclose"],
                challenge=challenge,
                expires_in=expires_in,
                tenant_id=self._tenant(),
            )
            self._send_json(
                201,
                {
                    "presentation_id": record.presentation_id,
                    "credential_id": record.credential_id,
                    "issuer_did": record.issuer_did,
                    "issuer_key_version": record.issuer_key_version,
                    "disclose": record.disclose,
                    "claims": record.projection,
                    "challenge": record.challenge,
                    "expires_at": record.expires_at,
                    "proof": record.proof,
                },
            )

        def _get_audit(self, query: str) -> None:
            """GET /v1/audit?limit=&after=：本租户审计事件，seq 升序。

            limit 缺省 50，须为 1..200 的整数；after 缺省 0，须为非负
            整数（仅返回 seq 大于 after 的事件）；非法一律 400。
            返回 {"events": [...], "next_after": n}，空页保持 after。
            """
            params = parse_qs(query)
            limit = self._parse_int_param(params, "limit", 50, 1, 200)
            after = self._parse_int_param(params, "after", 0, 0, None)
            events, next_after = store.list_audit(
                self._tenant(), limit, after
            )
            self._send_json(
                200, {"events": events, "next_after": next_after}
            )

        def _post_verify_presentation(self, presentation_id: str) -> None:
            # 与凭证 verify 相同的公开错误协议：任何失败都返回 200 +
            # {"valid": false, "reason": "<非空中文原因>"}，绝不返回
            # 400/404/500。
            tenant = self._tenant()  # 租户头非法仍为请求级 400
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
                    presentation_id, data["presentation"], challenge,
                    tenant_id=tenant,
                )
            except Exception:  # noqa: BLE001 验签失败绝不暴露内部细节
                self._send_invalid("验签过程发生内部错误")
                return
            payload: Dict[str, Any] = {"valid": valid}
            if not valid:
                payload["reason"] = reason or "验签失败"
            self._send_json(200, payload)

    return Handler


def run(
    host: str = "127.0.0.1",
    port: int = 8080,
    store_path: Optional[str] = None,
    quiet: bool = False,
) -> None:
    """启动 HTTP 服务（阻塞）。"""
    store = VCStore(store_path)
    handler = build_handler(store)
    if quiet:
        handler.log_message = lambda *args, **kwargs: None  # noqa: E731
    httpd = ThreadingHTTPServer((host, port), handler)
    print(f"可验证凭证后端已启动: http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
