"""命令行入口：did-create / did-show / issue / verify。

用法：
    python -m vc_backend.cli [--server URL] did-create [--method example]
    python -m vc_backend.cli [--server URL] did-show <did>
    python -m vc_backend.cli [--server URL] issue <issuer_did> <subject_did> --claims '<json>'
    python -m vc_backend.cli [--server URL] verify <credential_id>
    python -m vc_backend.cli [--server URL] verify --file credential.json
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

from . import crypto

DEFAULT_SERVER = "http://127.0.0.1:8000"


class CliError(Exception):
    """携带退出码的 CLI 错误。"""


def _request(method: str, url: str, payload: dict | None = None) -> tuple[int, dict]:
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return exc.code, {"error": f"HTTP {exc.code}"}
    except urllib.error.URLError as exc:
        raise CliError(f"cannot reach server: {exc.reason}")


def _post(server: str, path: str, payload: dict) -> dict:
    status, body = _request("POST", server + path, payload)
    if status >= 400:
        raise CliError(f"POST {path} failed ({status}): {body.get('error', body)}")
    return body


def _get(server: str, path: str) -> dict:
    status, body = _request("GET", server + path)
    if status >= 400:
        raise CliError(f"GET {path} failed ({status}): {body.get('error', body)}")
    return body


def _print_json(obj: dict) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2))


# ---- 子命令 ----

def cmd_did_create(args) -> int:
    public_key, private_key = crypto.generate_keypair()
    result = _post(args.server, "/v1/dids", {
        "method": args.method,
        "public_key": public_key,
        "private_key": private_key,
    })
    _print_json({"did": result["did"], "public_key": result["public_key"]})
    return 0


def cmd_did_show(args) -> int:
    _print_json(_get(args.server, f"/v1/dids/{args.did}"))
    return 0


def _load_claims(text: str) -> dict:
    if text.startswith("@"):
        with open(text[1:], "r", encoding="utf-8") as fh:
            text = fh.read()
    try:
        claims = json.loads(text)
    except ValueError as exc:
        raise CliError(f"--claims is not valid JSON: {exc}")
    if not isinstance(claims, dict):
        raise CliError("--claims must be a JSON object")
    return claims


def cmd_issue(args) -> int:
    claims = _load_claims(args.claims)
    result = _post(args.server, "/v1/credentials", {
        "issuer_did": args.issuer_did,
        "subject_did": args.subject_did,
        "claims": claims,
    })
    _print_json({"credential_id": result["credential_id"], "signature": result["signature"]})
    return 0


def _verify_document(server: str, document: dict) -> bool:
    """校验一份凭证文档（正文字段 + signature）。失败原因通过异常抛出。"""
    if not isinstance(document, dict):
        raise CliError("credential document must be a JSON object")
    signature = document.get("signature")
    if not isinstance(signature, str):
        raise CliError("credential document has no signature")
    body = {k: v for k, v in document.items() if k != "signature"}
    issuer_did = body.get("issuer_did")
    if not isinstance(issuer_did, str):
        raise CliError("credential body has no issuer_did")
    # 现取签发者公钥
    issuer = _get(server, f"/v1/dids/{issuer_did}")
    payload = crypto.canonical_json(body)
    return crypto.verify_es256(issuer["public_key"], payload, signature)


def cmd_verify(args) -> int:
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as fh:
                document = json.load(fh)
        except (OSError, ValueError) as exc:
            raise CliError(f"cannot read credential file: {exc}")
    else:
        document = _get(args.server, f"/v1/credentials/{args.credential_id}")
    ok = _verify_document(args.server, document)
    if ok:
        print("true")
        return 0
    print("false")
    print("reason: signature does not verify against the issuer's current public key; "
          "the credential body was modified after issuance", file=sys.stderr)
    return 1


# ---- 参数解析 ----

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vc-cli", description="可验证凭证命令行工具")
    parser.add_argument("--server", default=DEFAULT_SERVER,
                        help=f"后端服务地址（默认 {DEFAULT_SERVER}）")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("did-create", help="生成密钥对并注册 DID")
    p.add_argument("--method", default="example")
    p.set_defaults(func=cmd_did_create)

    p = sub.add_parser("did-show", help="查询 DID")
    p.add_argument("did")
    p.set_defaults(func=cmd_did_show)

    p = sub.add_parser("issue", help="签发凭证")
    p.add_argument("issuer_did")
    p.add_argument("subject_did")
    p.add_argument("--claims", required=True,
                   help="claims JSON 串，或 @path/to/claims.json")
    p.set_defaults(func=cmd_issue)

    p = sub.add_parser("verify", help="校验凭证签名")
    p.add_argument("credential_id", nargs="?", help="凭证 ID（从服务器现取）")
    p.add_argument("--file", help="本地凭证 JSON 文件（含正文与 signature）")
    p.set_defaults(func=cmd_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI 主函数，返回进程退出码。"""
    args = build_parser().parse_args(argv)
    if args.command == "verify" and not args.file and not args.credential_id:
        print("verify: credential_id or --file is required", file=sys.stderr)
        return 2
    try:
        return args.func(args)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
