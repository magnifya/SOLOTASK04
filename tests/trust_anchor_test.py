#!/usr/bin/env python3
"""信任锚点注册表的端到端测试。

直接运行：python3 tests/trust_anchor_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
覆盖：注册校验（非空 did / P-256 PEM / 非布尔正整数 key_version）、
201/200/409 幂等与冲突、GET 全数组与 404、租户隔离、吊销首次/重复与
updated_at 固定、verify 公开错误协议（缺失/吊销/验签失败均 200
valid:false）、ES256 裸 R||S base64url 验签、审计动作与“失败不记”、
跨重启持久化。
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402


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


def _pem_pair():
    priv_pem = crypto.generate_private_key_pem()
    return priv_pem, crypto.public_key_pem_from_private(priv_pem).strip()


def main():
    port = 8947
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

        priv1, pub1 = _pem_pair()
        priv2, pub2 = _pem_pair()
        did = "did:web:example.com:issuer"

        # 1. 注册字段校验
        st, rr = _http("POST", f"{base}/v1/trust/anchors", {})
        check("缺 did -> 400", st == 400 and rr.get("error"))
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": "", "public_key": pub1, "key_version": 1})
        check("空 did -> 400", st == 400)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": None, "public_key": pub1, "key_version": 1})
        check("null did -> 400", st == 400)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": 1, "public_key": pub1, "key_version": 1})
        check("非字符串 did -> 400", st == 400)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": "not-a-pem", "key_version": 1})
        check("非 PEM 公钥 -> 400", st == 400)
        p384_pem = ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": p384_pem, "key_version": 1})
        check("P-384 公钥 -> 400", st == 400)
        for bad_version in (0, -3, True, False, 1.0, "1", None):
            st, _ = _http("POST", f"{base}/v1/trust/anchors",
                          {"did": did, "public_key": pub1,
                           "key_version": bad_version})
            check(f"key_version={bad_version!r} -> 400", st == 400)
        st, _ = _http("POST", f"{base}/v1/trust/anchors", raw=b"{bad")
        check("非法 JSON -> 400", st == 400)
        st, _ = _http("POST", f"{base}/v1/trust/anchors", raw=b"[1]")
        check("非对象请求体 -> 400", st == 400)

        # 2. 注册 201 与返回字段
        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1})
        check("注册 -> 201 且字段恰为五项",
              st == 201 and r == {
                  "did": did, "public_key": pub1, "key_version": 1,
                  "status": "active", "updated_at": None,
              })

        # 3. 同 DID/版本同 PEM -> 200（不同空白写法归一化）
        folded = "\n" + pub1.replace("\n", "\r\n") + "\n"
        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": folded, "key_version": 1})
        check("同 PEM 重试 -> 200 且字段不变",
              st == 200 and r["status"] == "active"
              and r["updated_at"] is None and r["public_key"] == pub1)

        # 4. 同 DID/版本不同 PEM -> 409
        st, rr = _http("POST", f"{base}/v1/trust/anchors",
                       {"did": did, "public_key": pub2, "key_version": 1})
        check("不同 PEM 同版本 -> 409", st == 409 and rr.get("error"))

        # 5. 注册版本 2
        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub2, "key_version": 2})
        check("版本 2 -> 201", st == 201 and r["key_version"] == 2)

        # 6. GET 返回全数组（按版本升序）
        st, r = _http("GET", f"{base}/v1/trust/anchors/{did}")
        check("GET 全数组按版本升序",
              st == 200 and isinstance(r, list)
              and [a["key_version"] for a in r] == [1, 2]
              and all(set(a) == {"did", "public_key", "key_version",
                                 "status", "updated_at"} for a in r))
        st, rr = _http("GET", f"{base}/v1/trust/anchors/did:web:unknown")
        check("未知 DID -> 404", st == 404 and rr.get("error"))

        # 7. 租户隔离
        T2 = {"X-Tenant-ID": "other"}
        st, _ = _http("GET", f"{base}/v1/trust/anchors/{did}", headers=T2)
        check("他租户 GET -> 404", st == 404)
        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub2, "key_version": 1},
                      headers=T2)
        check("他租户可独立注册同一 DID/版本 -> 201", st == 201)
        st, r = _http("POST", f"{base}/v1/trust/verify",
                      {"issuer_did": did, "issuer_key_version": 1,
                       "signature": "x"}, headers=T2)
        check("他租户锚点（active）验签失败仍 200 valid:false",
              st == 200 and r.get("valid") is False and r.get("reason"))
        st, _ = _http("GET", f"{base}/v1/trust/anchors/{did}",
                      headers={"X-Tenant-ID": ""})
        check("显式空租户头 -> 400", st == 400)

        # 8. 吊销
        st, r = _http("PUT", f"{base}/v1/trust/anchors/{did}/1/status",
                      {"status": "revoked"})
        check("首次吊销 -> 200 status=revoked，updated_at 为 UTC 秒",
              st == 200 and r["status"] == "revoked"
              and isinstance(r["updated_at"], int)
              and abs(r["updated_at"] - time.time()) < 10)
        first_ts = r["updated_at"]
        time.sleep(1.1)
        st, r = _http("PUT", f"{base}/v1/trust/anchors/{did}/1/status",
                      {"status": "revoked"})
        check("重复吊销 -> 200 且 updated_at 不变",
              st == 200 and r["status"] == "revoked"
              and r["updated_at"] == first_ts)
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did}/1/status",
                      {"status": "active"})
        check("status=active -> 400", st == 400)
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did}/1/status",
                      {"status": "revoked", "extra": 1})
        check("多余字段 -> 400", st == 400)
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did}/99/status",
                      {"status": "revoked"})
        check("未知版本吊销 -> 404", st == 404)
        st, _ = _http("PUT",
                      f"{base}/v1/trust/anchors/did:web:unknown/1/status",
                      {"status": "revoked"})
        check("未知 DID 吊销 -> 404", st == 404)
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did}/x/status",
                      {"status": "revoked"})
        check("非数字版本 -> 400", st == 400)

        # 9. verify 成功：对请求体（除 signature）规范化 JSON 的 ES256 签名
        content = {"issuer_did": did, "issuer_key_version": 2,
                   "msg": "hello", "n": 7}
        signature = crypto.sign(content, priv2)
        body = dict(content)
        body["signature"] = signature
        st, r = _http("POST", f"{base}/v1/trust/verify", body)
        check("active 锚点验签成功 -> {valid:true}",
              st == 200 and r == {"valid": True})

        # 字段顺序不同不影响验签（规范化 JSON）
        reordered = {"n": 7, "signature": signature, "msg": "hello",
                     "issuer_did": did, "issuer_key_version": 2}
        st, r = _http("POST", f"{base}/v1/trust/verify", reordered)
        check("字段顺序不同仍验签成功", st == 200 and r == {"valid": True})

        tampered = dict(body)
        tampered["n"] = 8
        st, r = _http("POST", f"{base}/v1/trust/verify", tampered)
        check("内容被改 -> 200 valid:false 附原因",
              st == 200 and r.get("valid") is False and r.get("reason"))
        st, r = _http("POST", f"{base}/v1/trust/verify",
                      {"issuer_did": did, "issuer_key_version": 1,
                       "signature": signature})
        check("已吊销锚点 -> 200 valid:false",
              st == 200 and r.get("valid") is False
              and "吊销" in r.get("reason", ""))
        st, r = _http("POST", f"{base}/v1/trust/verify",
                      {"issuer_did": "did:web:nope",
                       "issuer_key_version": 1, "signature": signature})
        check("锚点缺失 -> 200 valid:false",
              st == 200 and r.get("valid") is False
              and "不存在" in r.get("reason", ""))
        st, r = _http("POST", f"{base}/v1/trust/verify",
                      {"issuer_did": did, "issuer_key_version": 2,
                       "signature": "@@not-b64@@"})
        check("签名格式错误 -> 200 valid:false",
              st == 200 and r.get("valid") is False and r.get("reason"))

        # 10. verify 请求层错误一律 200 valid:false
        for bad, label in (
            ({}, "空对象"),
            ({"issuer_did": did}, "缺版本"),
            ({"issuer_did": did, "issuer_key_version": 0,
              "signature": "a"}, "版本 0"),
            ({"issuer_did": did, "issuer_key_version": True,
              "signature": "a"}, "版本布尔"),
            ({"issuer_did": did, "issuer_key_version": 1.5,
              "signature": "a"}, "版本小数"),
            ({"issuer_did": "", "issuer_key_version": 1,
              "signature": "a"}, "空 did"),
            ({"issuer_did": did, "issuer_key_version": 2}, "缺 signature"),
            ({"issuer_did": did, "issuer_key_version": 2,
              "signature": ""}, "空 signature"),
            ({"issuer_did": did, "issuer_key_version": 2,
              "signature": 9}, "非字符串 signature"),
        ):
            stx, rr = _http("POST", f"{base}/v1/trust/verify", bad)
            check(f"verify {label} -> 200 valid:false",
                  stx == 200 and rr.get("valid") is False
                  and isinstance(rr.get("reason"), str) and rr["reason"])
        st, rr = _http("POST", f"{base}/v1/trust/verify", raw=b"not json")
        check("verify 非法 JSON -> 200 valid:false",
              st == 200 and rr.get("valid") is False)
        st, rr = _http("POST", f"{base}/v1/trust/verify", raw=b"[1]")
        check("verify 非对象 -> 200 valid:false",
              st == 200 and rr.get("valid") is False)
        st, rr = _http("POST", f"{base}/v1/trust/verify", raw=b"")
        check("verify 空体 -> 200 valid:false",
              st == 200 and rr.get("valid") is False)
        st, rr = _http("POST", f"{base}/v1/trust/verify",
                       {"issuer_did": did, "issuer_key_version": 1,
                        "signature": "x"}, headers={"X-Tenant-ID": ""})
        check("verify 显式空租户头 -> 400（先于公开错误协议）",
              st == 400 and rr.get("error"))

        # 11. 审计：注册重试记、吊销首/重记、失败与验签不记
        _, audit = _http("GET", f"{base}/v1/audit?limit=200")
        regs = [e for e in audit["events"]
                if e["action"] == "trust.anchor.registered"]
        revs = [e for e in audit["events"]
                if e["action"] == "trust.anchor.revoked"]
        check("注册审计：首次 + 重试 + 版本2 共 3 条",
              len(regs) == 3
              and all(e["resource_type"] == "trust_anchor" for e in regs)
              and {e["resource_id"] for e in regs}
              == {f"{did}#1", f"{did}#2"})
        check("吊销审计：首次 + 重复共 2 条",
              len(revs) == 2
              and all(e["resource_id"] == f"{did}#1" for e in revs))
        n_before = len(audit["events"])
        _http("POST", f"{base}/v1/trust/anchors",
              {"did": did, "public_key": pub2, "key_version": 1})  # 409
        _http("POST", f"{base}/v1/trust/verify", tampered)  # 失败
        _http("POST", f"{base}/v1/trust/verify", body)  # 成功
        _, audit2 = _http("GET", f"{base}/v1/audit?limit=200")
        check("冲突注册与验签（成败）均不记审计",
              len(audit2["events"]) == n_before)

        # 12. 跨重启持久化
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        assert wait_up(port), "服务重启超时"
        st, r = _http("GET", f"{base}/v1/trust/anchors/{did}")
        check("重启后：v1 吊销且 updated_at 固定，v2 active",
              st == 200
              and r[0]["status"] == "revoked"
              and r[0]["updated_at"] == first_ts
              and r[1]["status"] == "active"
              and r[1]["updated_at"] is None)
        st, r = _http("POST", f"{base}/v1/trust/verify", body)
        check("重启后 active 锚点仍可验签", st == 200
              and r == {"valid": True})

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store):
            os.remove(store)

    print()
    if failures:
        print(f"{len(failures)} 项失败:", failures)
        return 1
    print("信任锚点测试全部通过 ✔")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
