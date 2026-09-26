#!/usr/bin/env python3
"""跨系统演示一次性消费 POST /v1/trust/presentations/consume 的端到端测试。

直接运行：python3 tests/trust_presentation_consume_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402

UTC_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

ISSUER_DID = "did:web:issuer.external"
HOLDER_DID = "did:web:holder.external"
SOURCE_TENANT = "source-tenant-1"


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


def make_unbound(presentation_id, expires_at="2099-01-01T00:00:00Z",
                 challenge="chal-1"):
    return {
        "presentation_id": presentation_id,
        "credential_id": "vc_external_0001",
        "issuer_did": ISSUER_DID,
        "issuer_key_version": 1,
        "disclose": ["/role"],
        "claims": {"role": "admin"},
        "challenge": challenge,
        "expires_at": expires_at,
    }


def sign_unbound(p, issuer_priv):
    """issuer proof 覆盖去掉 proof 及 holder_* 后的八个字段。"""
    p = dict(p)
    unsigned = {
        k: v for k, v in p.items()
        if k != "proof" and not k.startswith("holder_")
    }
    p["proof"] = crypto.sign(unsigned, issuer_priv)
    return p


def make_bound(presentation_id, expires_at="2099-01-01T00:00:00Z",
               challenge="chal-1"):
    p = make_unbound(presentation_id, expires_at, challenge)
    p["holder_did"] = HOLDER_DID
    p["holder_key_version"] = 1
    return p


def sign_bound(p, issuer_priv, holder_priv, tenant_id=SOURCE_TENANT):
    """issuer 覆盖八字段；holder 覆盖绑定对象并加入 tenant_id。"""
    p = dict(p)
    unsigned = {
        k: v for k, v in p.items()
        if k != "proof" and not k.startswith("holder_")
    }
    p["proof"] = crypto.sign(unsigned, issuer_priv)
    holder_msg = dict(unsigned)
    holder_msg["holder_did"] = p["holder_did"]
    holder_msg["holder_key_version"] = p["holder_key_version"]
    holder_msg["tenant_id"] = tenant_id
    p["holder_proof"] = crypto.sign(holder_msg, holder_priv)
    return p


def start_server(port, store):
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up(port), "服务启动超时"
    return proc


def main():
    port = 8988
    store = tempfile.mktemp(suffix=".json")
    proc = start_server(port, store)
    base = f"http://127.0.0.1:{port}"
    path = "/v1/trust/presentations/consume"
    verify_path = "/v1/trust/presentations/verify"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def consume(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{path}", payload,
                     headers=headers, raw=raw)

    def audit_events(headers):
        st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=headers)
        assert st == 200
        return r["events"]

    def consumed_audits(headers):
        return [e for e in audit_events(headers)
                if e["action"] == "trust.presentation.consumed"]

    def want_id(payload):
        return hashlib.sha256(crypto.canonicalize(payload)).hexdigest()

    try:
        T1 = {"X-Tenant-ID": "tpc-a"}
        T2 = {"X-Tenant-ID": "tpc-b"}

        iss_priv, iss_pub = gen_keypair()
        hold_priv, hold_pub = gen_keypair()

        for headers in (T1, T2):
            st, _ = _http("POST", f"{base}/v1/trust/anchors",
                          {"did": ISSUER_DID, "public_key": iss_pub,
                           "key_version": 1}, headers=headers)
            check(f"注册签发者锚点（{headers['X-Tenant-ID']}）-> 201",
                  st == 201)
            st, _ = _http("POST", f"{base}/v1/trust/anchors",
                          {"did": HOLDER_DID, "public_key": hold_pub,
                           "key_version": 1}, headers=headers)
            check(f"注册持有者锚点（{headers['X-Tenant-ID']}）-> 201",
                  st == 201)

        # ---- 未绑定演示 ----
        p1 = sign_unbound(make_unbound("vp_" + "1" * 32), iss_priv)
        good_unbound = {"presentation": p1, "challenge": "chal-1"}

        # 1. 验真失败（含请求结构）均 200 按序恰返 valid:false、reason，
        #    不消费、不记审计
        def expect_invalid(name, payload=None, raw=None, headers=T1,
                           prefix=None):
            st, r = consume(payload=payload, raw=raw, headers=headers)
            ok = (st == 200 and list(r.keys()) == ["valid", "reason"]
                  and r["valid"] is False
                  and isinstance(r["reason"], str) and r["reason"])
            if ok and prefix is not None:
                ok = r["reason"].startswith(prefix)
            check(name, ok)

        expect_invalid("空请求体 -> 200 valid:false", raw=b"",
                       prefix="请求")
        expect_invalid("非法 JSON -> 200 valid:false", raw=b"not-json",
                       prefix="请求")
        expect_invalid("缺 challenge -> 200 valid:false",
                       {"presentation": p1}, prefix="请求缺少字段")
        expect_invalid("多余字段 -> 200 valid:false",
                       dict(good_unbound, x=1), prefix="请求含多余字段")
        expect_invalid("挑战不匹配 -> 200 valid:false",
                       {"presentation": p1, "challenge": "other"},
                       prefix="挑战不匹配")
        bad_sig = dict(good_unbound)
        bad_sig["presentation"] = dict(p1, proof=crypto.sign(
            {"x": 1}, iss_priv))
        expect_invalid("签名校验失败 -> 200 valid:false", bad_sig,
                       prefix="签名校验失败")
        expired = sign_unbound(
            make_unbound("vp_" + "e" * 32,
                         expires_at="2020-01-01T00:00:00Z"), iss_priv)
        expect_invalid("演示已过期 -> 200 valid:false",
                       {"presentation": expired, "challenge": "chal-1"},
                       prefix="演示已过期")
        check("验真失败不记消费审计", consumed_audits(T1) == [])

        # 显式空租户头 -> 400 仅 {error}
        st, r = consume(good_unbound, headers={"X-Tenant-ID": ""})
        check("显式空租户头 -> 400 仅 {error}",
              st == 400 and set(r.keys()) == {"error"}
              and isinstance(r["error"], str) and r["error"])

        # 2. 首次消费（未绑定）：200 按序恰返 valid、consumption_id、
        #    consumed_at
        st, r = consume(good_unbound, headers=T1)
        check("首次消费（未绑定）-> 200 恰返 valid,consumption_id,consumed_at",
              st == 200
              and list(r.keys()) == ["valid", "consumption_id", "consumed_at"]
              and r["valid"] is True)
        check("consumption_id 为请求规范化 JSON 的 SHA-256 小写 64 位 hex",
              r.get("consumption_id") == want_id(good_unbound))
        check("consumed_at 为 UTC 秒精度 Z 字符串",
              isinstance(r.get("consumed_at"), str)
              and UTC_Z_RE.fullmatch(r["consumed_at"]) is not None)

        audits = consumed_audits(T1)
        check("首次消费恰记一条 trust.presentation.consumed 审计",
              len(audits) == 1
              and audits[0]["resource_type"] == "trust_presentation"
              and audits[0]["resource_id"] == want_id(good_unbound))

        # 3. 同键重放（同演示）-> 200 恰返 外部演示已消费，不再记审计
        st, r = consume(good_unbound, headers=T1)
        check("同键重放 -> 200 恰返 外部演示已消费",
              st == 200 and list(r.keys()) == ["valid", "reason"]
              and r["valid"] is False and r["reason"] == "外部演示已消费")
        check("重放不记审计", len(consumed_audits(T1)) == 1)

        # 4. 同键重放（演示内容不同但 issuer_did/presentation_id 相同）
        p1b = sign_unbound(
            dict(make_unbound("vp_" + "1" * 32), claims={"role": "user"}),
            iss_priv)
        st, r = consume({"presentation": p1b, "challenge": "chal-1"},
                        headers=T1)
        check("同键重放（演示不同）-> 外部演示已消费",
              st == 200 and r == {"valid": False, "reason": "外部演示已消费"})
        check("不同演示重放不记审计", len(consumed_audits(T1)) == 1)

        # 5. 消费不影响只读 /verify（仍验真通过，不消费）
        st, r = _http("POST", f"{base}{verify_path}", good_unbound,
                      headers=T1)
        check("消费后 /verify 仍只读验真通过",
              st == 200 and r == {"valid": True})

        # 6. 不同 presentation_id -> 新键，可成功消费
        p2 = sign_unbound(make_unbound("vp_" + "2" * 32), iss_priv)
        good2 = {"presentation": p2, "challenge": "chal-1"}
        st, r = consume(good2, headers=T1)
        check("不同 presentation_id -> 首次消费成功",
              st == 200 and r.get("valid") is True
              and r.get("consumption_id") == want_id(good2))
        check("第二次首次消费再记一条审计", len(consumed_audits(T1)) == 2)

        # 7. 租户隔离：同演示在他租户各自首次成功
        st, r = consume(good_unbound, headers=T2)
        check("租户 B 同演示互不影响首次消费成功",
              st == 200 and r.get("valid") is True)
        st, r = consume(good_unbound, headers=T2)
        check("租户 B 重放 -> 外部演示已消费",
              st == 200 and r == {"valid": False, "reason": "外部演示已消费"})
        check("消费审计按租户隔离",
              len(consumed_audits(T1)) == 2
              and len(consumed_audits(T2)) == 1)

        # ---- 持有者绑定演示 ----
        pb = sign_bound(make_bound("vp_" + "b" * 32), iss_priv, hold_priv)
        good_bound = {"presentation": pb, "challenge": "chal-1",
                      "source_tenant_id": SOURCE_TENANT}

        st, r = consume({"presentation": pb, "challenge": "chal-1"},
                        headers=T1)
        check("绑定演示缺 source_tenant_id -> 200 valid:false",
              st == 200 and r.get("valid") is False
              and isinstance(r.get("reason"), str) and r["reason"])
        st, r = consume(good_bound, headers=T1)
        check("首次消费（绑定）-> 200 恰返三键且 valid:true",
              st == 200
              and list(r.keys()) == ["valid", "consumption_id", "consumed_at"]
              and r["valid"] is True
              and r.get("consumption_id") == want_id(good_bound))
        st, r = consume(good_bound, headers=T1)
        check("绑定演示同键重放 -> 外部演示已消费",
              st == 200 and r == {"valid": False, "reason": "外部演示已消费"})
        audits = consumed_audits(T1)
        check("绑定演示消费恰记一条审计且 resource_id 为 consumption_id",
              len(audits) == 3
              and audits[-1]["resource_type"] == "trust_presentation"
              and audits[-1]["resource_id"] == want_id(good_bound))

        # 8. 并发：同键仅一次成功
        pc = sign_unbound(make_unbound("vp_" + "c" * 32), iss_priv)
        conc_payload = {"presentation": pc, "challenge": "chal-1"}
        results = []

        def worker():
            results.append(consume(conc_payload, headers=T1))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        n_ok = sum(1 for st, r in results
                   if st == 200 and r.get("valid") is True)
        n_replay = sum(1 for st, r in results
                       if st == 200
                       and r == {"valid": False, "reason": "外部演示已消费"})
        check("并发同键仅一次成功，其余均为已消费",
              n_ok == 1 and n_replay == 7)

        # 9. 落盘失败：500 仅 {"error":"存储失败"}，回滚可重试
        pf = sign_unbound(make_unbound("vp_" + "f" * 32), iss_priv)
        fail_payload = {"presentation": pf, "challenge": "chal-1"}
        audits_before = len(consumed_audits(T1))
        os.unlink(store)
        os.mkdir(store)
        try:
            st, r = consume(fail_payload, headers=T1)
            check("落盘失败 -> 500 仅 {error:存储失败}",
                  st == 500 and r == {"error": "存储失败"})
        finally:
            os.rmdir(store)
        check("落盘失败不记审计", len(consumed_audits(T1)) == audits_before)
        st, r = consume(fail_payload, headers=T1)
        check("落盘失败回滚后同键可重试成功",
              st == 200 and r.get("valid") is True)

        # 10. 重启仍判重
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server(port, store)
        st, r = consume(good_unbound, headers=T1)
        check("重启后同键重放 -> 外部演示已消费",
              st == 200 and r == {"valid": False, "reason": "外部演示已消费"})
        st, r = consume(good_bound, headers=T1)
        check("重启后绑定演示同键重放 -> 外部演示已消费",
              st == 200 and r == {"valid": False, "reason": "外部演示已消费"})
        check("重启后重放不新增审计",
              len(consumed_audits(T1)) == audits_before + 1)

    finally:
        proc.terminate()
        proc.wait(timeout=10)
        if os.path.isdir(store):
            shutil.rmtree(store)
        elif os.path.exists(store):
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
    raise SystemExit(main())
