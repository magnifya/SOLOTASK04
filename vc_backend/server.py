"""HTTP 服务：POST/GET /v1/dids，POST/GET /v1/credentials。

运行：python -m vc_backend.server [--host 127.0.0.1] [--port 8000]
"""

from __future__ import annotations

import argparse
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from . import crypto, store
from .store import CredentialStore, DidStore

_DID_RE = re.compile(r"^/v1/dids/([^/]+)$")
_CRED_RE = re.compile(r"^/v1/credentials/([^/]+)$")


class VCHandler(BaseHTTPRequestHandler):
    """请求处理器。did_store / cred_store 挂在 server 实例上。"""

    server_version = "vc-backend/0.1"
    protocol_version = "HTTP/1.1"

    # ---- 基础工具 ----

    def log_message(self, fmt, *args):  # 静默访问日志
        pass

    def _send_json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _error(self, status: int, message: str) -> None:
        self._send_json(status, {"error": message})

    def _read_json(self) -> dict | None:
        """读取并解析 JSON 请求体；失败时自行回复 400 并返回 None。"""
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._error(400, "request body is not valid JSON")
            return None
        if not isinstance(body, dict):
            self._error(400, "request body must be a JSON object")
            return None
        return body

    @staticmethod
    def _require_str(body: dict, field: str) -> str | None:
        value = body.get(field)
        if not isinstance(value, str) or not value:
            return None
        return value

    # ---- 路由 ----

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/v1/dids":
            self._create_did()
        elif path == "/v1/credentials":
            self._create_credential()
        else:
            self._error(404, f"unknown endpoint: POST {path}")

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        m = _DID_RE.match(path)
        if m:
            self._get_did(m.group(1))
            return
        m = _CRED_RE.match(path)
        if m:
            self._get_credential(m.group(1))
            return
        self._error(404, f"unknown endpoint: GET {path}")

    # ---- DID ----

    def _create_did(self) -> None:
        body = self._read_json()
        if body is None:
            return
        for field in ("method", "public_key"):
            if self._require_str(body, field) is None:
                self._error(400, f"missing or invalid field: {field} (non-empty string required)")
                return
        private_key = body.get("private_key")
        if private_key is not None and not isinstance(private_key, str):
            self._error(400, "missing or invalid field: private_key (string required)")
            return
        record, created = self.server.did_store.register(
            body["method"], body["public_key"], private_key
        )
        self._send_json(201 if created else 200, {
            "did": record["did"],
            "public_key": record["public_key"],
        })

    def _get_did(self, did: str) -> None:
        record = self.server.did_store.get(did)
        if record is None:
            self._error(404, f"did not found: {did}")
            return
        self._send_json(200, {
            "did": record["did"],
            "public_key": record["public_key"],
            "created_at": record["created_at"],
        })

    # ---- 凭证 ----

    def _create_credential(self) -> None:
        body = self._read_json()
        if body is None:
            return
        for field in ("issuer_did", "subject_did"):
            if self._require_str(body, field) is None:
                self._error(400, f"missing or invalid field: {field} (non-empty string required)")
                return
        claims = body.get("claims")
        if not isinstance(claims, dict):
            self._error(400, "missing or invalid field: claims (JSON object required)")
            return

        issuer = self.server.did_store.get(body["issuer_did"])
        if issuer is None:
            self._error(400, f"unknown issuer_did: {body['issuer_did']}")
            return
        if self.server.did_store.get(body["subject_did"]) is None:
            self._error(400, f"unknown subject_did: {body['subject_did']}")
            return

        private_key = issuer.get("private_key")
        if not private_key:
            # 注册时未提供私钥（例如直接走 HTTP 注册）：服务端为其生成密钥对
            # 并更新登记记录，verify 时现取的公钥即为新公钥。
            public_key, private_key = crypto.generate_keypair()
            issuer["public_key"] = public_key
            issuer["private_key"] = private_key
            self.server.did_store.reindex(issuer)

        cred_body = {
            "credential_id": store.new_credential_id(),
            "issuer_did": body["issuer_did"],
            "subject_did": body["subject_did"],
            "claims": claims,
            "issued_at": store.now_iso(),
        }
        signature = crypto.sign_es256(private_key, crypto.canonical_json(cred_body))
        self.server.cred_store.add({
            "credential_id": cred_body["credential_id"],
            "body": cred_body,
            "signature": signature,
        })
        self._send_json(201, {
            "credential_id": cred_body["credential_id"],
            "signature": signature,
        })

    def _get_credential(self, credential_id: str) -> None:
        record = self.server.cred_store.get(credential_id)
        if record is None:
            self._error(404, f"credential not found: {credential_id}")
            return
        payload = dict(record["body"])
        payload["signature"] = record["signature"]
        self._send_json(200, payload)


class VCServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, did_store: DidStore, cred_store: CredentialStore):
        super().__init__(addr, VCHandler)
        self.did_store = did_store
        self.cred_store = cred_store


def make_server(host: str, port: int, did_store: DidStore | None = None,
                cred_store: CredentialStore | None = None) -> VCServer:
    """构造 HTTP 服务实例。"""
    return VCServer(
        (host, port),
        did_store if did_store is not None else DidStore(),
        cred_store if cred_store is not None else CredentialStore(),
    )


def main(argv: list[str] | None = None) -> None:
    """命令行入口：python -m vc_backend.server"""
    parser = argparse.ArgumentParser(description="可验证凭证后端 HTTP 服务")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    server = make_server(args.host, args.port)
    print(f"listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
