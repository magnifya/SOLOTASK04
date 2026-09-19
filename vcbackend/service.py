"""HTTP 服务：基于标准库 http.server。

路由：
  POST /v1/dids                       注册 DID
  GET  /v1/dids/{did}                 查询 DID
  POST /v1/credentials                签发凭证
  GET  /v1/credentials/{credential_id} 查询凭证

错误映射：ValidationError -> 400，NotFoundError -> 404。
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple
from urllib.parse import unquote, urlparse

from .store import NotFoundError, ValidationError, VCStore


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
                else:
                    self._send_error(404, f"无此路径: {path}")
            except ValidationError as exc:
                self._send_error(400, str(exc))
            except Exception as exc:  # noqa: BLE001
                self._send_error(500, f"服务器内部错误: {exc}")

        def do_GET(self) -> None:  # noqa: N802
            try:
                path = urlparse(self.path).path.rstrip("/") or "/"
                if path.startswith("/v1/dids/"):
                    self._get_did(unquote(path[len("/v1/dids/") :]))
                elif path.startswith("/v1/credentials/"):
                    self._get_credential(
                        unquote(path[len("/v1/credentials/") :])
                    )
                elif path in ("/health", "/healthz"):
                    self._send_json(200, {"status": "ok"})
                else:
                    self._send_error(404, f"无此路径: {path}")
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

        def _post_dids(self) -> None:
            data = self._read_json()
            self._require_fields(data, ("method", "public_key"))
            record = store.create_did(data["method"], data["public_key"])
            self._send_json(
                201,
                {
                    "did": record.did,
                    "public_key": record.public_key,
                },
            )

        def _get_did(self, did: str) -> None:
            record = store.get_did(did)
            self._send_json(
                200,
                {
                    "did": record.did,
                    "public_key": record.public_key,
                    "created_at": record.created_at,
                },
            )

        def _post_credentials(self) -> None:
            data = self._read_json()
            self._require_fields(data, ("issuer_did", "subject_did"))
            if "claims" not in data:
                raise ValidationError("缺少字段: claims")
            if not isinstance(data["claims"], dict):
                raise ValidationError("字段 claims 必须为 JSON 对象")
            record = store.create_credential(
                data["issuer_did"], data["subject_did"], data["claims"]
            )
            self._send_json(
                201,
                {
                    "credential_id": record.credential_id,
                    "signature": record.signature,
                },
            )

        def _get_credential(self, credential_id: str) -> None:
            record = store.get_credential(credential_id)
            self._send_json(
                200,
                {
                    "credential_id": record.credential_id,
                    "body": record.body,
                    "signature": record.signature,
                },
            )

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
