#!/usr/bin/env python3
"""CLI 租户选择（--tenant-id / VCBACKEND_TENANT_ID）回归测试。

直接运行：python3 tests/cli_tenant_test.py
不依赖第三方测试框架，仅用标准库。

覆盖：
  - 选项优先级：显式选项 > 环境变量 > 缺省；显式空串不回退环境变量；
    非法环境变量不影响有效显式选项
  - 非法值（空串、纯空白、控制字符、非 ASCII）在发起任何 HTTP 请求前
    退出，退出码 2、stdout 为空、stderr 为非空中文原因、无堆栈
  - 缺省兼容：两者均未提供时不发送 X-Tenant-ID（等同 default），
    显式 default 发送该值且资源互通
  - 两租户注册/签发/查询/验签回归：同句柄跨租户不同 DID、资源跨租户
    404、did-show 他租户 404 退出 1、verify 他租户凭证 false/退出 1、
    本租户 verify true/退出 0、审计按租户记录
  - serve 忽略租户环境变量服务全部租户；显式 --tenant-id 配置错误退出
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vcbackend.cli import (  # noqa: E402
    TENANT_ENV_VAR,
    resolve_tenant_id,
    validate_tenant_id,
)


def _http(method, url, payload=None, headers=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode() or "{}")


def wait_up(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            _http("GET", f"http://127.0.0.1:{port}/health")
            return True
        except OSError:
            time.sleep(0.1)
    return False


def port_is_listening(port, host="127.0.0.1"):
    """直接尝试绑定端口：绑定成功说明无人监听（SO_REUSEADDR 下仍可能
    漏掉 TIME_WAIT，故仅用于断言“未启动”场景）。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        sock.bind((host, port))
    except OSError:
        return True
    finally:
        sock.close()
    return False


def _clean_env(**extra):
    env = {"PATH": os.environ.get("PATH", "")}
    env = {k: v for k, v in env.items() if v}
    env.update(extra)
    return env


def run_cli(args, env=None, base_url=None):
    """以子进程运行 CLI，返回 (returncode, stdout, stderr)。"""
    full_env = _clean_env()
    if base_url is not None:
        full_env["VCBACKEND_URL"] = base_url
    if env:
        full_env.update(env)
    proc = subprocess.run(
        [sys.executable, "-m", "vcbackend.cli", *args],
        cwd=ROOT,
        env=full_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return (
        proc.returncode,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def main():
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    test_validation_unit(check)

    port = 8957
    store = tempfile.mktemp(suffix=".json")
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "vcbackend.cli", "serve",
            "--port", str(port), "--host", "127.0.0.1",
            "--store", store,
        ],
        cwd=ROOT,
        env=_clean_env(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        assert wait_up(port), "服务启动超时"
        test_invalid_values_no_request(check, base)
        test_priority(check, base)
        test_default_compatibility(check, base)
        test_two_tenant_flow(check, base)
        test_serve_tenant_handling(check, store)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    print()
    if failures:
        print(f"{len(failures)} 项失败:", failures)
        return 1
    print("CLI 租户选择回归测试全部通过 ✔")
    return 0


def test_validation_unit(check):
    # 合法值：ASCII 可打印非空白，原样保留（含大小写与符号）
    for value in ("default", "Tenant-A", "t_01.x-yz", "!#$%&()*+"):
        check(f"validate 合法值原样接受 {value!r}",
              validate_tenant_id(value) is None)
        got, err = resolve_tenant_id(value, {TENANT_ENV_VAR: "ignored"})
        check(f"显式值覆盖环境变量 {value!r}",
              got == value and err is None)
    # 非法值：空串、纯空白、含空白、控制字符、非 ASCII
    invalid = [
        "",
        "   ",
        "\t",
        "a b",
        "a\tb",
        "a\nb",
        "ab\x00",
        "租户",
        "café",
        "a\u007f",
    ]
    for value in invalid:
        reason = validate_tenant_id(value)
        check(f"validate 拒绝非法值 {value!r}",
              isinstance(reason, str) and bool(reason.strip()))
    # 显式非法即使环境变量合法也报错；显式空串不回退环境变量
    got, err = resolve_tenant_id("", {TENANT_ENV_VAR: "env-tenant"})
    check("显式空串覆盖合法环境变量并报错", got == "" and err is not None)
    got, err = resolve_tenant_id(None, {})
    check("显式与环境变量均缺省 -> None 无错", got is None and err is None)
    got, err = resolve_tenant_id(None, {TENANT_ENV_VAR: " "})
    check("环境变量纯空白报错", got == " " and err is not None)
    got, err = resolve_tenant_id("ok", {TENANT_ENV_VAR: "非法"})
    check("环境变量非法不影响有效显式选项", got == "ok" and err is None)


def _assert_config_error(check, name, args, env, base):
    """配置错误统一断言：退出 2、stdout 空、stderr 非空中文、无堆栈。"""
    code, out, err = run_cli(args, env=env, base_url=base)
    check(name,
          code == 2
          and out == ""
          and bool(err.strip())
          and any("\u4e00" <= ch <= "\u9fff" for ch in err)
          and "Traceback" not in err)


def test_invalid_values_no_request(check, base):
    # 注：NUL 字节无法进入进程 argv（内核禁止），其拒绝路径由
    # test_validation_unit 覆盖；这里使用其余控制字符验证 CLI 行为。
    bad_explicit = [
        "", "   ", "\t ", "a b", "a\tb", "a\nb", "ab\x01", "a\x1f",
        "租户", "café", "a\u007f",
    ]
    for value in bad_explicit:
        _assert_config_error(
            check,
            f"显式非法值 {value!r} -> 配置错误且无请求",
            ["--tenant-id", value, "did-show", "did:example:x"],
            None,
            base,
        )
    # issue 子命令同样在发请求前失败（claims 解析前即退出）
    _assert_config_error(
        check,
        "issue 显式非法租户 -> 配置错误且无请求",
        ["--tenant-id", " ", "issue", "--issuer", "x",
         "--subject", "y", "--claims", "{}"],
        None,
        base,
    )
    # 环境变量非法（包括空串）：未提供显式选项时拒绝
    for value in ("", "   ", "a b", "ab\x01", "租户", "a\u007f"):
        _assert_config_error(
            check,
            f"环境变量非法 {value!r} -> 配置错误且无请求",
            ["did-show", "did:example:x"],
            {TENANT_ENV_VAR: value},
            base,
        )
    # 环境变量非法但显式选项有效 -> 请求正常发出（访问不存在 DID
    # 返回 HTTP 404 / 退出 1，证明没有因环境变量而拒绝）
    code, out, err = run_cli(
        ["--tenant-id", "default", "did-show", "did:example:no-such-did"],
        env={TENANT_ENV_VAR: "非法"},
        base_url=base,
    )
    check("非法环境变量 + 有效显式选项 -> 显式生效（404 退 1）",
          code == 1 and out == "" and "404" in err)


def test_priority(check, base):
    def create(tenant_args, env, key):
        code, out, err = run_cli(
            [*tenant_args, "did-create",
             "--method", "example", "--public-key", key],
            env=env,
            base_url=base,
        )
        assert code == 0, f"注册失败: {err}"
        return json.loads(out)["did"]

    # 环境变量生效：同一 key_handle 在 env 租户与 default 下是不同 DID
    did_env = create([], {TENANT_ENV_VAR: "env-tenant"}, "pri-key")
    st, body = _http("GET", f"{base}/v1/dids/{did_env}")
    check("环境变量租户资源对 default 不可见", st == 404)
    st, _ = _http("GET", f"{base}/v1/dids/{did_env}",
                  headers={"X-Tenant-ID": "env-tenant"})
    check("环境变量租户资源在 env-tenant 可见", st == 200)

    # 显式选项覆盖环境变量
    did_opt = create(["--tenant-id", "opt-tenant"],
                     {TENANT_ENV_VAR: "env-tenant"}, "pri-key")
    check("显式选项覆盖环境变量（同句柄不同 DID）",
          did_opt != did_env)
    st, _ = _http("GET", f"{base}/v1/dids/{did_opt}",
                  headers={"X-Tenant-ID": "opt-tenant"})
    check("显式选项租户资源落在 opt-tenant", st == 200)
    st, _ = _http("GET", f"{base}/v1/dids/{did_opt}",
                  headers={"X-Tenant-ID": "env-tenant"})
    check("显式选项资源不在环境变量租户", st == 404)

    # 显式空串不回退环境变量，而是配置错误（见 test_invalid_values）；
    # 此处验证环境变量存在但显式给另一个值时完全切换。
    did_opt2 = create(["--tenant-id", "env-tenant"],
                      {TENANT_ENV_VAR: "opt-tenant"}, "pri-key")
    check("显式值与环境变量互换仍以显式为准（幂等同 DID）",
          did_opt2 == did_env)

    # 原始大小写保持，不做改写
    did_mixed = create(["--tenant-id", "MiXeD"], None, "mixed-key")
    st, _ = _http("GET", f"{base}/v1/dids/{did_mixed}",
                  headers={"X-Tenant-ID": "mixed"})
    check("租户大小写敏感（mixed 查 MiXeD 资源 -> 404）", st == 404)
    st, _ = _http("GET", f"{base}/v1/dids/{did_mixed}",
                  headers={"X-Tenant-ID": "MiXeD"})
    check("租户大小写原样保留（MiXeD 可见）", st == 200)


def test_default_compatibility(check, base):
    # 无环境变量、无显式选项：不发送租户头，等价服务端 default
    code, out, err = run_cli(
        ["did-create", "--method", "example", "--public-key", "compat-key"],
        env={},
        base_url=base,
    )
    check("缺省注册成功退出 0", code == 0)
    did_default = json.loads(out)["did"]
    st, _ = _http("GET", f"{base}/v1/dids/{did_default}")
    check("缺省注册落在 default 租户", st == 200)

    # 显式 default 与缺省互通
    code, out, err = run_cli(
        ["--tenant-id", "default", "did-show", did_default],
        env={},
        base_url=base,
    )
    check("显式 default 可见缺省租户资源，退出 0",
          code == 0 and json.loads(out)["did"] == did_default)

    # 环境变量为 default 时与缺省同样互通
    code, out, err = run_cli(
        ["did-show", did_default],
        env={TENANT_ENV_VAR: "default"},
        base_url=base,
    )
    check("环境变量 default 可见缺省租户资源，退出 0", code == 0)


def test_two_tenant_flow(check, base):
    ta = "reg-tenant-a"
    tb = "reg-tenant-b"

    def cli_json(args, env=None):
        code, out, err = run_cli(args, env=env, base_url=base)
        assert code == 0, f"CLI 失败: {err}"
        return json.loads(out)

    # 1. 同句柄在两租户注册为不同 DID
    did_a = cli_json(["--tenant-id", ta, "did-create",
                      "--method", "example", "--public-key", "shared-handle"])
    did_b = cli_json(["--tenant-id", tb, "did-create",
                      "--method", "example", "--public-key", "shared-handle"])
    check("同句柄跨租户注册为不同 DID",
          did_a["did"] != did_b["did"]
          and did_a["did"].startswith("did:example:")
          and did_b["did"].startswith("did:example:"))
    # 租户内幂等：同句柄再次注册返回既有 DID
    again = cli_json(["--tenant-id", ta, "did-create",
                      "--method", "example", "--public-key", "shared-handle"])
    check("租户内同句柄幂等返回既有 DID", again["did"] == did_a["did"])

    # 2. did-show 本租户成功；他租户 HTTP 404、退出码 1
    code, out, err = run_cli(
        ["--tenant-id", ta, "did-show", did_a["did"]], base_url=base)
    check("did-show 本租户 -> 0 且输出 JSON",
          code == 0 and json.loads(out)["did"] == did_a["did"])
    code, out, err = run_cli(
        ["--tenant-id", tb, "did-show", did_a["did"]], base_url=base)
    check("did-show 他租户 DID -> 404、退出 1、stdout 空",
          code == 1 and out == "" and "404" in err and bool(err.strip()))

    # 3. 两租户各自签发凭证（issuer/subject 均为本租户 DID）
    sub_a = cli_json(["--tenant-id", ta, "did-create",
                      "--method", "example", "--public-key", "sub-a"])
    sub_b = cli_json(["--tenant-id", tb, "did-create",
                      "--method", "example", "--public-key", "sub-b"])
    cred_a = cli_json(
        ["--tenant-id", ta, "issue",
         "--issuer", did_a["did"], "--subject", sub_a["did"],
         "--claims", json.dumps({"role": "admin", "level": 3})])
    cred_b = cli_json(
        ["--tenant-id", tb, "issue",
         "--issuer", did_b["did"], "--subject", sub_b["did"],
         "--claims", json.dumps({"role": "viewer"})])
    cid_a = cred_a["credential_id"]
    cid_b = cred_b["credential_id"]
    check("两租户各自签发成功且凭证 ID 不同", cid_a != cid_b)

    # 凭证正文不含租户字段（租户标识只进入请求头）
    st, body = _http("GET", f"{base}/v1/credentials/{cid_a}",
                     headers={"X-Tenant-ID": ta})
    check("凭证正文不携带 tenant 字段",
          st == 200
          and "tenant" not in json.dumps(body["body"])
          and "tenant_id" not in json.dumps(body["body"]))

    # 4. verify：本租户 true/退出 0、仅输出 true
    code, out, err = run_cli(
        ["--tenant-id", ta, "verify", cid_a], base_url=base)
    check("本租户 verify -> true、退出 0、stderr 空",
          code == 0 and out.strip() == "true" and err == "")
    code, out, err = run_cli(
        ["--tenant-id", tb, "verify", cid_b], base_url=base)
    check("第二租户本租户 verify -> true、退出 0",
          code == 0 and out.strip() == "true")

    # 5. verify 他租户凭证：GET 即 404，输出 false、stderr 说明获取
    #    失败、退出 1（两次请求都不得切换租户）
    code, out, err = run_cli(
        ["--tenant-id", tb, "verify", cid_a], base_url=base)
    check("他租户凭证 verify -> false、退出 1、stderr 说明获取失败",
          code == 1
          and out.strip() == "false"
          and "获取凭证失败" in err and "404" in err)
    code, out, err = run_cli(
        ["--tenant-id", ta, "verify", cid_b], base_url=base)
    check("反向他租户凭证 verify 同样 false/退出 1",
          code == 1 and out.strip() == "false" and "获取凭证失败" in err)

    # 6. 通过环境变量选定租户完成 verify，证明环境变量路径下两次
    #    请求（取凭证 + 服务端验签）携带同一租户头
    code, out, err = run_cli(
        ["verify", cid_a], env={TENANT_ENV_VAR: ta}, base_url=base)
    check("环境变量租户 verify -> true、退出 0",
          code == 0 and out.strip() == "true")
    code, out, err = run_cli(
        ["verify", cid_a], env={TENANT_ENV_VAR: tb}, base_url=base)
    check("环境变量切到他租户 verify -> false、退出 1",
          code == 1 and out.strip() == "false" and "获取凭证失败" in err)

    # 7. 审计：成功写入只记录在所属租户
    st, audit_a = _http("GET", f"{base}/v1/audit?limit=200",
                        headers={"X-Tenant-ID": ta})
    st2, audit_b = _http("GET", f"{base}/v1/audit?limit=200",
                         headers={"X-Tenant-ID": tb})
    evs_a = audit_a["events"]
    evs_b = audit_b["events"]
    check("审计事件全部记录到对应租户",
          st == 200 and st2 == 200
          and all(e["tenant_id"] == ta for e in evs_a)
          and all(e["tenant_id"] == tb for e in evs_b))
    res_a = {e["resource_id"] for e in evs_a}
    res_b = {e["resource_id"] for e in evs_b}
    check("凭证签发审计只在所属租户",
          cid_a in res_a and cid_a not in res_b
          and cid_b in res_b and cid_b not in res_a)
    check("DID 注册审计只在所属租户",
          did_a["did"] in res_a and did_a["did"] not in res_b
          and did_b["did"] in res_b and did_b["did"] not in res_a)


def test_serve_tenant_handling(check, _store):
    # serve 忽略租户环境变量：带 VCBACKEND_TENANT_ID 仍正常启动并
    # 服务全部租户
    port = 8958
    own_store = tempfile.mktemp(suffix=".json")
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1", "--store", own_store],
        cwd=ROOT,
        env=_clean_env(**{TENANT_ENV_VAR: "ignored-tenant"}),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        started = wait_up(port)
        check("serve 携带租户环境变量仍启动", started)
        if started:
            # 无租户头（default）与显式其他租户头均可用
            st, r = _http("POST", f"http://127.0.0.1:{port}/v1/dids",
                          {"method": "example", "public_key": "serve-default"})
            check("serve 仍服务 default（无头）", st == 201)
            did_d = r["did"]
            st, _ = _http(
                "GET", f"http://127.0.0.1:{port}/v1/dids/{did_d}",
                headers={"X-Tenant-ID": "default"})
            check("serve 仍服务显式 default", st == 200)
            st, r = _http("POST", f"http://127.0.0.1:{port}/v1/dids",
                          {"method": "example", "public_key": "serve-other"},
                          headers={"X-Tenant-ID": "another-tenant"})
            check("serve 仍服务其他具名租户", st == 201)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    # 显式 --tenant-id serve：配置错误退出且不启动服务
    code, out, err = run_cli(
        ["--tenant-id", "x", "serve", "--port", "8959",
         "--host", "127.0.0.1", "--store", own_store])
    check("serve 显式 --tenant-id -> 退出 2、stdout 空、stderr 中文",
          code == 2 and out == "" and bool(err.strip())
          and any("\u4e00" <= ch <= "\u9fff" for ch in err)
          and "Traceback" not in err)
    time.sleep(0.3)
    check("serve 显式 --tenant-id 未监听端口",
          not port_is_listening(8959))


if __name__ == "__main__":
    raise SystemExit(main())
