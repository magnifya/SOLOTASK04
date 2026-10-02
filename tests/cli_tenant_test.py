#!/usr/bin/env python3
"""CLI 租户选择（--tenant-id / VCBACKEND_TENANT_ID）回归测试。

覆盖：
  A. 选项优先级、非法值无 HTTP 请求（录制假服务器）；
  B. serve 忽略租户环境变量、显式 --tenant-id 不启动服务；
  C. 双租户真实服务回归：同句柄跨租户注册、资源隔离、
     跨租户 did-show/verify 失败协议、本租户 verify 成功、
     审计写入对应租户、默认兼容（无租户头 -> default）。

直接运行：python3 tests/cli_tenant_test.py
不依赖第三方测试框架，仅用标准库。
"""

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

CLI = [sys.executable, "-m", "vcbackend.cli"]
TENANT_ENV_VAR = "VCBACKEND_TENANT_ID"

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


def run_cli(args, base_url=None, env_tenant=None, extra_env=None):
    """以子进程运行 CLI；默认清空 VCBACKEND_TENANT_ID。"""
    env = dict(os.environ)
    env.pop(TENANT_ENV_VAR, None)
    if base_url is not None:
        env["VCBACKEND_URL"] = base_url
    if env_tenant is not None:
        env[TENANT_ENV_VAR] = env_tenant
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        CLI + args, cwd=ROOT, env=env,
        capture_output=True, text=True,
    )


def http_json(method, url, payload=None, headers=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read().decode()
            return resp.status, json.loads(raw or "{}")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        return exc.code, json.loads(raw or "{}")


def wait_up(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            http_json("GET", f"http://127.0.0.1:{port}/health")
            return True
        except OSError:
            time.sleep(0.15)
    return False


def port_listening(port):
    try:
        http_json("GET", f"http://127.0.0.1:{port}/health")
    except OSError:
        return False
    return True


def start_server(port, store):
    env = dict(os.environ, VCBACKEND_STORE=store)
    env.pop(TENANT_ENV_VAR, None)
    proc = subprocess.Popen(
        CLI + ["serve", "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if not wait_up(port):
        proc.terminate()
        raise AssertionError(f"服务启动超时 (port={port})")
    return proc


class _Recorder:
    def __init__(self):
        self.requests = []


RECORDER = _Recorder()


class _RecordingHandler(BaseHTTPRequestHandler):
    """录制请求方法/路径/租户头/正文，返回可预测的成功响应。"""

    def log_message(self, *args):
        pass

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        RECORDER.requests.append({
            "method": self.command,
            "path": self.path,
            "tenant": self.headers.get("X-Tenant-ID"),
            "body": json.loads(raw.decode()) if raw else None,
        })
        if self.path == "/v1/dids" and self.command == "POST":
            payload = {"did": "did:example:rec", "public_key": "pk-pem"}
        elif self.path.startswith("/v1/dids/"):
            payload = {"did": "did:example:rec", "public_key": "pk-pem"}
        elif (
            self.command == "GET"
            and self.path.startswith("/v1/credentials/")
            and not self.path.endswith("/verify")
        ):
            payload = {"body": {"credential_id": "vc_1"}, "signature": "sig"}
        elif self.command == "POST" and self.path.endswith("/verify"):
            payload = {"valid": True}
        else:
            payload = {}
        encoded = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    do_GET = _handle
    do_POST = _handle


def _recording_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def _expect_config_error(cp, label):
    check(f"{label} 退出码 2", cp.returncode == 2)
    check(f"{label} stdout 为空", cp.stdout == "")
    check(f"{label} stderr 为非空中文且无堆栈",
          bool(cp.stderr.strip())
          and any(ord(ch) > 127 for ch in cp.stderr)
          and "Traceback" not in cp.stderr)


def part_a_priority_and_headers():
    server, base = _recording_server()
    try:
        # A1 显式选项：四个子命令的每个请求都带同一个头，值保持
        # 原始大小写、不裁剪。
        RECORDER.requests.clear()
        cp = run_cli(
            ["--tenant-id", "TeNaNt-A", "did-create",
             "--method", "example", "--public-key", "hk"],
            base_url=base,
        )
        check("did-create 显式租户成功", cp.returncode == 0)
        req = RECORDER.requests[-1]
        check("did-create 携带 X-Tenant-ID 原文",
              req["tenant"] == "TeNaNt-A")
        check("租户标识不进入请求正文",
              "tenant" not in req["body"]
              and "tenant_id" not in req["body"]
              and "X-Tenant-ID" not in req["body"])

        cp = run_cli(
            ["--tenant-id", "TeNaNt-A", "did-show", "did:example:rec"],
            base_url=base,
        )
        check("did-show 显式租户成功", cp.returncode == 0)
        check("did-show 携带 X-Tenant-ID",
              RECORDER.requests[-1]["tenant"] == "TeNaNt-A")

        cp = run_cli(
            ["--tenant-id", "TeNaNt-A", "issue",
             "--issuer", "did:example:i", "--subject", "did:example:s",
             "--claims", '{"k":1}'],
            base_url=base,
        )
        check("issue 显式租户成功", cp.returncode == 0)
        req = RECORDER.requests[-1]
        check("issue 携带 X-Tenant-ID 且正文无租户字段",
              req["tenant"] == "TeNaNt-A"
              and "tenant_id" not in req["body"])

        RECORDER.requests.clear()
        cp = run_cli(
            ["--tenant-id", "TeNaNt-A", "verify", "vc_1"],
            base_url=base,
        )
        check("verify 显式租户成功输出 true/0",
              cp.returncode == 0 and cp.stdout.strip() == "true")
        check("verify 两次请求携带同一租户头",
              [r["tenant"] for r in RECORDER.requests]
              == ["TeNaNt-A", "TeNaNt-A"])
        verify_post = RECORDER.requests[-1]
        check("verify 请求正文不含租户字段",
              "tenant" not in verify_post["body"]
              and "tenant_id" not in verify_post["body"])

        # A2 环境变量生效时同样携带头。
        RECORDER.requests.clear()
        cp = run_cli(
            ["did-show", "did:example:rec"],
            base_url=base, env_tenant="env-tenant",
        )
        check("环境变量租户成功", cp.returncode == 0)
        check("环境变量 -> X-Tenant-ID",
              RECORDER.requests[-1]["tenant"] == "env-tenant")

        # A3 显式选项完全覆盖环境变量（环境变量非法也不影响）。
        RECORDER.requests.clear()
        cp = run_cli(
            ["--tenant-id", "win", "did-show", "did:example:rec"],
            base_url=base, env_tenant="",
        )
        check("显式选项覆盖非法环境变量", cp.returncode == 0)
        check("覆盖后头发送显式值",
              RECORDER.requests[-1]["tenant"] == "win")

        # 显式空串不退回合法环境变量。
        RECORDER.requests.clear()
        cp = run_cli(
            ["--tenant-id", "", "did-show", "did:example:rec"],
            base_url=base, env_tenant="env-tenant",
        )
        check("显式空串不退回环境变量 -> 退出码 2", cp.returncode == 2)
        check("显式空串时 stdout 为空", cp.stdout == "")
        check("显式空串时 stderr 含中文原因",
              bool(cp.stderr.strip())
              and any(ord(ch) > 127 for ch in cp.stderr))
        check("显式空串不发起任何请求", RECORDER.requests == [])

        # A4 两者均未提供：不发送租户头。
        RECORDER.requests.clear()
        cp = run_cli(["did-show", "did:example:rec"], base_url=base)
        check("无选项无环境变量 -> 成功", cp.returncode == 0)
        check("默认行为不发送 X-Tenant-ID",
              RECORDER.requests[-1]["tenant"] is None)

        # A5 显式 default：发送该值（而不是省略头）。
        RECORDER.requests.clear()
        cp = run_cli(
            ["--tenant-id", "default", "did-show", "did:example:rec"],
            base_url=base,
        )
        check("显式 default 成功", cp.returncode == 0)
        check("显式 default 仍发送头",
              RECORDER.requests[-1]["tenant"] == "default")
    finally:
        server.shutdown()
        server.server_close()


def part_a_invalid_values():
    """非法值：退出码 2、stdout 空、stderr 非空中文、无堆栈、无请求。"""
    server, base = _recording_server()
    try:
        for label, value in [
            ("空串", ""),
            ("纯空白", "   "),
            ("含制表符", "a\tb"),
            ("含换行", "ab\n"),
            ("含 DEL 控制符", "a\x7fb"),
            ("非 ASCII（中文）", "租户甲"),
        ]:
            RECORDER.requests.clear()
            cp = run_cli(
                ["--tenant-id", value, "did-show", "did:example:rec"],
                base_url=base,
            )
            _expect_config_error(cp, f"显式非法值（{label}）")
            check(f"显式非法值（{label}）无 HTTP 请求",
                  RECORDER.requests == [])

        for label, value in [
            ("环境变量空串", ""),
            ("环境变量纯空白", " "),
            ("环境变量含控制符", "a\rb"),
            ("环境变量非 ASCII", "租户"),
        ]:
            RECORDER.requests.clear()
            cp = run_cli(
                ["did-show", "did:example:rec"],
                base_url=base, env_tenant=value,
            )
            _expect_config_error(cp, label)
            check(f"{label} 无 HTTP 请求", RECORDER.requests == [])

        # 非法租户先于 issue 的 claims 校验，且不发起请求。
        RECORDER.requests.clear()
        cp = run_cli(
            ["--tenant-id", " ", "issue", "--issuer", "i",
             "--subject", "s", "--claims", "not-json"],
            base_url=base,
        )
        _expect_config_error(cp, "非法租户先于 claims 校验")
        check("非法租户时 issue 无 HTTP 请求", RECORDER.requests == [])
    finally:
        server.shutdown()
        server.server_close()


def part_b_serve_rules():
    """serve 忽略租户环境变量并服务全部租户；显式 --tenant-id 拒绝。"""
    store = tempfile.mktemp(suffix=".json")
    port = 8947
    base = f"http://127.0.0.1:{port}"
    # B1 即便环境变量非法，serve 也正常启动，且服务多租户。
    proc = start_server(port, store)
    try:
        st, _ = http_json(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "env-ignored-a"},
            headers={"X-Tenant-ID": "tenant-a"},
        )
        check("serve 启动后可服务 tenant-a", st == 201)
        st, _ = http_json(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "env-ignored-b"},
            headers={"X-Tenant-ID": "tenant-b"},
        )
        check("serve 启动后可服务 tenant-b", st == 201)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store):
            os.remove(store)

    # B2 显式 --tenant-id（合法或非法）一律配置错误退出，不监听端口。
    for label, value in [("合法值", "tenant-a"), ("空串", ""),
                         ("非 ASCII", "租户")]:
        cp = run_cli(
            ["--tenant-id", value, "serve",
             "--port", str(port), "--host", "127.0.0.1"],
        )
        _expect_config_error(cp, f"serve 显式 --tenant-id（{label}）")
        time.sleep(0.2)
        check(f"serve 显式 --tenant-id（{label}）未启动监听",
              not port_listening(port))

    # B3 无显式选项、无环境变量：serve 正常启动。
    proc = start_server(port, store)
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    check("serve 无租户配置可正常启动", True)
    if os.path.exists(store):
        os.remove(store)


def part_c_two_tenant_regression():
    """两个租户：注册/签发/查询/验签回归、隔离、审计归属、默认兼容。"""
    store = tempfile.mktemp(suffix=".json")
    port = 8948
    base = f"http://127.0.0.1:{port}"
    proc = start_server(port, store)
    try:
        # C1 同一 public_key 句柄在两个租户各注册为不同 DID。
        cp = run_cli(
            ["--tenant-id", "tenant-a", "did-create",
             "--method", "example", "--public-key", "shared-handle"],
            base_url=base,
        )
        check("tenant-a 注册成功", cp.returncode == 0)
        did_a = json.loads(cp.stdout)["did"]

        cp = run_cli(
            ["did-create", "--method", "example",
             "--public-key", "shared-handle"],
            base_url=base, env_tenant="tenant-b",
        )
        check("tenant-b（环境变量）注册成功", cp.returncode == 0)
        did_b = json.loads(cp.stdout)["did"]
        check("同句柄跨租户注册为不同 DID",
              did_a != did_b
              and did_a.startswith("did:example:")
              and did_b.startswith("did:example:"))

        # C2 资源只在所属租户可见：跨租户 did-show 为 HTTP 404、
        # CLI 退出码 1；本租户查询成功且 JSON 输出保持不变。
        cp = run_cli(
            ["--tenant-id", "tenant-a", "did-show", did_a],
            base_url=base,
        )
        check("本租户 did-show 成功",
              cp.returncode == 0
              and json.loads(cp.stdout)["did"] == did_a)
        cp = run_cli(
            ["--tenant-id", "tenant-b", "did-show", did_a],
            base_url=base,
        )
        check("跨租户 did-show 退出码 1", cp.returncode == 1)
        check("跨租户 did-show 报 HTTP 404", "HTTP 404" in cp.stderr)

        # tenant-a 内注册签发者并向 did_a 签发凭证。
        cp = run_cli(
            ["--tenant-id", "tenant-a", "did-create",
             "--method", "example", "--public-key", "issuer-a"],
            base_url=base,
        )
        issuer_a = json.loads(cp.stdout)["did"]
        cp = run_cli(
            ["--tenant-id", "tenant-a", "issue",
             "--issuer", issuer_a, "--subject", did_a,
             "--claims", '{"role":"admin","level":3}'],
            base_url=base,
        )
        check("tenant-a 签发凭证成功", cp.returncode == 0)
        issued = json.loads(cp.stdout)
        cid = issued["credential_id"]
        check("签发响应字段保持不变",
              set(issued.keys())
              == {"credential_id", "signature", "issuer_key_version"})

        # C3 verify：本租户只输出 true、退出码 0、stderr 为空；
        # 他租户输出 false、stderr 说明获取失败、退出码 1。
        cp = run_cli(
            ["--tenant-id", "tenant-a", "verify", cid],
            base_url=base,
        )
        check("本租户 verify 仅输出 true 并退出 0",
              cp.returncode == 0
              and cp.stdout.strip() == "true"
              and cp.stderr == "")

        cp = run_cli(
            ["--tenant-id", "tenant-b", "verify", cid],
            base_url=base,
        )
        check("他租户 verify 退出 1", cp.returncode == 1)
        check("他租户 verify 仅输出 false", cp.stdout.strip() == "false")
        check("他租户 verify stderr 说明获取失败且为 HTTP 404",
              "获取凭证失败" in cp.stderr and "404" in cp.stderr)

        # 环境变量选择他租户时同样隔离。
        cp = run_cli(
            ["verify", cid], base_url=base, env_tenant="tenant-b",
        )
        check("环境变量选他租户 verify 同样 false/1",
              cp.returncode == 1 and cp.stdout.strip() == "false")

        # C4 审计：成功写入按 tenant_id 归属，跨租户互不可见。
        _, audit_a = http_json(
            "GET", f"{base}/v1/audit?limit=200",
            headers={"X-Tenant-ID": "tenant-a"},
        )
        _, audit_b = http_json(
            "GET", f"{base}/v1/audit?limit=200",
            headers={"X-Tenant-ID": "tenant-b"},
        )
        events_a = audit_a["events"]
        events_b = audit_b["events"]
        check("tenant-a 审计均归属 tenant-a 且含签发事件",
              all(e["tenant_id"] == "tenant-a" for e in events_a)
              and any(e["action"] == "credential.issued"
                      and e["resource_id"] == cid for e in events_a))
        check("tenant-b 审计均归属 tenant-b 且不含 tenant-a 凭证",
              all(e["tenant_id"] == "tenant-b" for e in events_b)
              and not any(e["resource_id"] == cid for e in events_b))

        # C5 默认兼容：无租户头的 CLI 落到服务端 default 租户，
        # 与 tenant-a/tenant-b 完全隔离。
        cp = run_cli(
            ["did-create", "--method", "example",
             "--public-key", "shared-handle"],
            base_url=base,
        )
        check("default 租户同句柄可再次注册", cp.returncode == 0)
        did_default = json.loads(cp.stdout)["did"]
        check("default DID 与两个租户均不同",
              did_default != did_a and did_default != did_b)
        cp = run_cli(["did-show", did_default], base_url=base)
        check("default did-show 不带租户头成功", cp.returncode == 0)
        cp = run_cli(
            ["--tenant-id", "tenant-a", "did-show", did_default],
            base_url=base,
        )
        check("default 资源在 tenant-a 不可见（404）",
              cp.returncode == 1 and "HTTP 404" in cp.stderr)

        # C6 租户标识不进入凭证正文/签名：读取存储记录确认正文无
        # 租户字段，以存储锚再次验签仍为 true。
        st, record = http_json(
            "GET", f"{base}/v1/credentials/{cid}",
            headers={"X-Tenant-ID": "tenant-a"},
        )
        check("GET 凭证 200", st == 200)
        body = record["body"]
        check("凭证正文不含租户字段",
              "tenant" not in body and "tenant_id" not in body)
        st, verify_resp = http_json(
            "POST", f"{base}/v1/credentials/{cid}/verify",
            {"body": body, "signature": record["signature"]},
            headers={"X-Tenant-ID": "tenant-a"},
        )
        check("存储锚定再次验签 valid=true",
              st == 200 and verify_resp == {"valid": True})
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store):
            os.remove(store)


def main():
    part_a_priority_and_headers()
    part_a_invalid_values()
    part_b_serve_rules()
    part_c_two_tenant_regression()
    print()
    if failures:
        print(f"{len(failures)} 项失败:", failures)
        return 1
    print("全部 CLI 租户回归测试通过 ✔")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
