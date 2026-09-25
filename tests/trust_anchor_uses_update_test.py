#!/usr/bin/env python3
"""信任锚点用途收紧（PUT .../uses）的端到端测试。

直接运行：python3 tests/trust_anchor_uses_update_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402

ALL_USES = ["generic", "vc", "vp", "proof", "did", "status", "deactivation"]


def _http(method, url, payload=None, headers=None, raw=None):
    if raw is None:
        data = json.dumps(payload).encode() if payload is not None else None
    else:
        data = raw
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
            time.sleep(0.15)
    return False


def gen_keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv_pem, pub_pem


def audit_events(base, headers):
    st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=headers)
    assert st == 200
    return r["events"]


def main():
    port = 8961
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    try:
        assert wait_up(port), "服务启动超时"

        T1 = {"X-Tenant-ID": "narrow-a"}
        T2 = {"X-Tenant-ID": "narrow-b"}

        priv1, pub1 = gen_keypair()
        did = "did:web:example.com:narrow"

        # 1. 注册三用途锚点
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1,
                       "uses": ["generic", "vc", "vp"]}, headers=T1)
        check("注册三用途锚点 201", st == 201)

        # 2. 非法请求体一律 400 且仅含非空中文 error
        bad_bodies = [
            {"uses": ["generic"]},                       # 缺 from_uses
            {"from_uses": ["generic", "vc", "vp"]},      # 缺 uses
            {"from_uses": ["generic", "vc", "vp"],
             "uses": ["generic"], "extra": 1},           # 多余字段
            {"from_uses": None, "uses": ["generic"]},    # from_uses null
            {"from_uses": ["generic", "vc", "vp"],
             "uses": None},                              # uses null
            {"from_uses": "generic", "uses": ["generic"]},
            {"from_uses": ["generic", "vc", "vp"], "uses": []},
            {"from_uses": ["generic", "vc", "vp"], "uses": [1]},
            {"from_uses": ["generic", "vc", "vp"],
             "uses": ["generic", "generic"]},
            {"from_uses": ["generic", "vc", "vp"], "uses": ["all"]},
            {"from_uses": ["generic", "vc", "vp"],
             "uses": ["vc", "generic"]},                 # 非规范序
            {"from_uses": ["vp", "vc", "generic"],
             "uses": ["generic"]},                       # from_uses 非规范序
        ]
        for i, bad in enumerate(bad_bodies):
            st, r = _http("PUT", f"{base}/v1/trust/anchors/{did}/1/uses",
                          bad, headers=T1)
            check(f"非法请求体[{i}] -> 400", st == 400)
            check(f"非法请求体[{i}] 仅含非空中文 error",
                  set(r) == {"error"} and isinstance(r["error"], str)
                  and bool(r["error"]))

        # 3. 非法路径版本 -> 400
        for bad_ver in ["0", "-1", "1.0", "abc", "", "１２", "+1", " 1"]:
            st, r = _http(
                "PUT",
                f"{base}/v1/trust/anchors/{did}/"
                f"{urllib.parse.quote(bad_ver)}/uses",
                {"from_uses": ["generic", "vc", "vp"],
                 "uses": ["generic"]}, headers=T1)
            check(f"路径版本 {bad_ver!r} -> 400", st == 400)
            check(f"路径版本 {bad_ver!r} 仅含 error",
                  set(r) == {"error"} and bool(r.get("error")))

        # 4. 未知/跨租户 -> 404
        st, r = _http("PUT", f"{base}/v1/trust/anchors/{did}/99/uses",
                      {"from_uses": ALL_USES, "uses": ["generic"]},
                      headers=T1)
        check("未知版本 -> 404", st == 404 and set(r) == {"error"})
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/did:web:none/1/uses",
                      {"from_uses": ALL_USES, "uses": ["generic"]},
                      headers=T1)
        check("未知 DID -> 404", st == 404)
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did}/1/uses",
                      {"from_uses": ["generic", "vc", "vp"],
                       "uses": ["generic"]}, headers=T2)
        check("跨租户 -> 404", st == 404)

        # 5. 显式空租户头 -> 400；缺省租户头按 default
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did}/1/uses",
                      {"from_uses": ["generic", "vc", "vp"],
                       "uses": ["generic"]},
                      headers={"X-Tenant-ID": ""})
        check("显式空租户头 -> 400", st == 400)

        # 6. 前置不匹配 -> 409
        st, r = _http("PUT", f"{base}/v1/trust/anchors/{did}/1/uses",
                      {"from_uses": ["generic"], "uses": ["generic"]},
                      headers=T1)
        check("前置不匹配 -> 409", st == 409)
        check("409 仅含非空中文 error",
              set(r) == {"error"} and bool(r.get("error")))

        # 7. 扩权 -> 409（目标含当前没有的用途 / 目标为超集）
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did}/1/uses",
                      {"from_uses": ["generic", "vc", "vp"],
                       "uses": ["generic", "vc", "vp", "proof"]},
                      headers=T1)
        check("扩权（超集）-> 409", st == 409)
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did}/1/uses",
                      {"from_uses": ["generic", "vc", "vp"],
                       "uses": ["generic", "proof"]},
                      headers=T1)
        check("扩权（含新用途）-> 409", st == 409)

        # 8. 失败不写入：用途保持三用途
        st, r = _http("GET", f"{base}/v1/trust/anchors/{did}/1/uses",
                      headers=T1)
        check("失败不写入", r.get("uses") == ["generic", "vc", "vp"])

        # 9. 合法收紧 -> 200，响应按键序恰为 did、key_version、uses
        n_audit_before = len(audit_events(base, T1))
        st, r = _http("PUT", f"{base}/v1/trust/anchors/{did}/1/uses",
                      {"from_uses": ["generic", "vc", "vp"],
                       "uses": ["generic", "vc"]}, headers=T1)
        check("收紧 200", st == 200)
        check("200 响应恰含 did/key_version/uses",
              r == {"did": did, "key_version": 1,
                    "uses": ["generic", "vc"]})
        check("200 响应键序", list(r) == ["did", "key_version", "uses"])

        # 10. 实际变更仅追加一次 trust.anchor.uses.updated 审计
        evs = audit_events(base, T1)
        new_evs = evs[n_audit_before:]
        check("变更仅追加一条审计", len(new_evs) == 1)
        check("审计动作与资源",
              new_evs
              and new_evs[0]["action"] == "trust.anchor.uses.updated"
              and new_evs[0]["resource_type"] == "trust_anchor"
              and new_evs[0]["resource_id"] == f"{did}#1")

        # 11. GET uses 反映新值
        st, r = _http("GET", f"{base}/v1/trust/anchors/{did}/1/uses",
                      headers=T1)
        check("GET uses 反映收紧结果",
              r == {"did": did, "key_version": 1,
                    "uses": ["generic", "vc"]})

        # 12. 目标等于当前值 -> 幂等 200，无副作用（不记审计）
        st, r = _http("PUT", f"{base}/v1/trust/anchors/{did}/1/uses",
                      {"from_uses": ["generic", "vc", "vp"],
                       "uses": ["generic", "vc"]}, headers=T1)
        check("目标等于当前值 -> 幂等 200", st == 200)
        check("幂等响应不变",
              r == {"did": did, "key_version": 1,
                    "uses": ["generic", "vc"]})
        check("幂等不记审计",
              len(audit_events(base, T1)) == len(evs) + 0)

        # 13. 并发语义（顺序验证）：不同收紧最多一个成功
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did}/1/uses",
                      {"from_uses": ["generic", "vc"],
                       "uses": ["generic"]}, headers=T1)
        check("第一路收紧成功", st == 200)
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did}/1/uses",
                      {"from_uses": ["generic", "vc"],
                       "uses": ["vc"]}, headers=T1)
        check("第二路不同收紧 -> 409", st == 409)

        # 14. 用途门控立即生效：仅剩 generic 的锚点过 vc 入口被拒
        body = {"credential_id": "cred-n1", "issuer_did": did,
                "subject_did": "did:web:sub", "claims": {"a": 1},
                "issued_at": "2026-01-01T00:00:00Z",
                "issuer_key_version": 1}
        sig = crypto.sign(body, priv1)
        st, r = _http("POST", f"{base}/v1/trust/credentials/verify",
                      {"body": body, "signature": sig}, headers=T1)
        check("收紧后 vc 入口拒绝",
              st == 200 and r.get("valid") is False
              and r.get("reason") == f"锚点不存在: {did}#1")
        message = {"issuer_did": did, "issuer_key_version": 1, "nonce": "x"}
        sig = crypto.sign(message, priv1)
        st, r = _http("POST", f"{base}/v1/trust/verify",
                      {**message, "signature": sig}, headers=T1)
        check("收紧后 generic 入口仍可用", r.get("valid") is True)

        # 15. 省略 uses 注册（全用途）锚点也可收紧
        did2 = "did:web:example.com:full"
        _, pub2 = gen_keypair()
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did2, "public_key": pub2, "key_version": 1},
                      headers=T1)
        check("省略 uses 注册 201", st == 201)
        st, r = _http("PUT", f"{base}/v1/trust/anchors/{did2}/1/uses",
                      {"from_uses": ALL_USES, "uses": ["did"]}, headers=T1)
        check("全用途锚点收紧 200",
              st == 200 and r == {"did": did2, "key_version": 1,
                                  "uses": ["did"]})

        # 16. 轮换继承收紧后的用途
        _, pub3 = gen_keypair()
        st, r = _http("POST", f"{base}/v1/trust/anchors/{did2}/rotate",
                      {"from_key_version": 1, "public_key": pub3},
                      headers=T1)
        check("轮换 201", st == 201 and r["key_version"] == 2)
        st, r = _http("GET", f"{base}/v1/trust/anchors/{did2}/2/uses",
                      headers=T1)
        check("轮换继承收紧后的用途",
              r == {"did": did2, "key_version": 2, "uses": ["did"]})

        # 17. 已吊销锚点 -> 409
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did2}/2/status",
                      {"status": "revoked"}, headers=T1)
        check("吊销 200", st == 200)
        st, r = _http("PUT", f"{base}/v1/trust/anchors/{did2}/2/uses",
                      {"from_uses": ["did"], "uses": ["did"]}, headers=T1)
        check("已吊销锚点（幂等目标）-> 409", st == 409)
        st, r = _http("PUT", f"{base}/v1/trust/anchors/{did2}/2/uses",
                      {"from_uses": ALL_USES, "uses": ["did"]}, headers=T1)
        check("已吊销判定优先于前置校验", st == 409 and set(r) == {"error"})

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    # 18. 重启后收紧结果与审计稳定
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务重启超时"
        st, r = _http("GET", f"{base}/v1/trust/anchors/{did}/1/uses",
                      headers=T1)
        check("重启后收紧结果稳定",
              r == {"did": did, "key_version": 1, "uses": ["generic"]})
        st, r = _http("GET", f"{base}/v1/trust/anchors/{did2}/2/uses",
                      headers=T1)
        check("重启后轮换继承稳定",
              r == {"did": did2, "key_version": 2, "uses": ["did"]})
        evs = [e for e in audit_events(base, T1)
               if e["action"] == "trust.anchor.uses.updated"]
        check("重启后审计稳定（恰三条）", len(evs) == 3)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store):
            os.unlink(store)

    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
