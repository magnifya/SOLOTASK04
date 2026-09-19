"""命令行入口。

子命令：
  did-create --method M --public-key K   注册 DID
  did-show DID                           查询 DID
  issue --issuer DID --subject DID --claims JSON   签发凭证
  verify CREDENTIAL_ID                   调用服务端验签端点，输出 true/false
  serve [--host H] [--port P]            启动 HTTP 服务

CLI 通过 HTTP 与服务通信；verify 由服务端以存储记录为锚、按
issuer_key_version 从签发者公钥历史中取公钥验签。
可用 --base-url 或环境变量 VCBACKEND_URL 指定服务地址。
"""

import argparse
import json
import sys
from typing import Any, Dict, List, Optional
from urllib import error as urlerror
from urllib import request as urlrequest

from .service import run as serve_run

DEFAULT_BASE_URL = "http://127.0.0.1:8080"


# ---------------------------------------------------------------------- #
# HTTP 客户端
# ---------------------------------------------------------------------- #
class ClientError(RuntimeError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _request(
    base_url: str,
    method: str,
    path: str,
    payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    url = f"{base_url.rstrip('/')}{path}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urlrequest.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urlrequest.urlopen(req) as resp:  # noqa: S310 (CLI 目标地址)
            body = resp.read().decode("utf-8")
            return json.loads(body) if body else {}
    except urlerror.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            message = json.loads(raw).get("error", raw)
        except json.JSONDecodeError:
            message = raw
        raise ClientError(exc.code, message) from exc
    except urlerror.URLError as exc:
        raise ClientError(
            0, f"无法连接服务 {base_url}: {exc.reason}"
        ) from exc


# ---------------------------------------------------------------------- #
# 子命令实现
# ---------------------------------------------------------------------- #
def _cmd_did_create(args: argparse.Namespace) -> int:
    result = _request(
        args.base_url,
        "POST",
        "/v1/dids",
        {"method": args.method, "public_key": args.public_key},
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def _cmd_did_show(args: argparse.Namespace) -> int:
    result = _request(args.base_url, "GET", f"/v1/dids/{args.did}")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def _cmd_issue(args: argparse.Namespace) -> int:
    try:
        claims = json.loads(args.claims)
    except json.JSONDecodeError as exc:
        print(f"claims 不是合法 JSON: {exc}", file=sys.stderr)
        return 2
    if not isinstance(claims, dict):
        print("claims 必须为 JSON 对象", file=sys.stderr)
        return 2
    result = _request(
        args.base_url,
        "POST",
        "/v1/credentials",
        {
            "issuer_did": args.issuer,
            "subject_did": args.subject,
            "claims": claims,
        },
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    # 现取凭证正文与签名，交由服务端以存储记录为锚验签；
    # 无论取凭证失败还是验签失败，都输出 false、stderr 说明原因并退出 1
    try:
        vc = _request(
            args.base_url, "GET", f"/v1/credentials/{args.credential_id}"
        )
    except ClientError as exc:
        print("false")
        print(f"原因: 获取凭证失败: {exc.message}", file=sys.stderr)
        return 1
    try:
        result = _request(
            args.base_url,
            "POST",
            f"/v1/credentials/{args.credential_id}/verify",
            {"body": vc["body"], "signature": vc["signature"]},
        )
    except ClientError as exc:
        print("false")
        print(f"原因: 验签请求失败: {exc.message}", file=sys.stderr)
        return 1
    if result.get("valid"):
        print("true")
        return 0
    reason = result.get("reason") or "验签失败"
    print("false")
    print(f"原因: {reason}", file=sys.stderr)
    return 1


def _cmd_serve(args: argparse.Namespace) -> int:
    serve_run(host=args.host, port=args.port, store_path=args.store, quiet=False)
    return 0


# ---------------------------------------------------------------------- #
# 参数解析
# ---------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vcbackend", description="可验证凭证后端命令行"
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help="HTTP 服务地址（默认取 VCBACKEND_URL 或 %(default)s）",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("did-create", help="注册 DID")
    p_create.add_argument("--method", required=True)
    p_create.add_argument("--public-key", required=True)
    p_create.set_defaults(func=_cmd_did_create)

    p_show = sub.add_parser("did-show", help="查询 DID")
    p_show.add_argument("did")
    p_show.set_defaults(func=_cmd_did_show)

    p_issue = sub.add_parser("issue", help="签发凭证")
    p_issue.add_argument("--issuer", required=True, help="签发者 DID")
    p_issue.add_argument("--subject", required=True, help="持有者 DID")
    p_issue.add_argument(
        "--claims", required=True, help="凭证 claims，JSON 对象字符串"
    )
    p_issue.set_defaults(func=_cmd_issue)

    p_verify = sub.add_parser("verify", help="校验凭证签名")
    p_verify.add_argument("credential_id")
    p_verify.set_defaults(func=_cmd_verify)

    p_serve = sub.add_parser("serve", help="启动 HTTP 服务")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8080)
    p_serve.add_argument("--store", default=None, help="状态文件路径")
    p_serve.set_defaults(func=_cmd_serve)

    parser.set_defaults(base_url=None)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    import os

    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "base_url", None):
        args.base_url = os.environ.get("VCBACKEND_URL", DEFAULT_BASE_URL)
    try:
        return args.func(args)
    except ClientError as exc:
        if exc.status == 0:
            print(exc.message, file=sys.stderr)
        else:
            print(f"HTTP {exc.status}: {exc.message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
