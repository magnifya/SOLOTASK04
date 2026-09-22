#!/usr/bin/env python3
"""外部演示验真并合并状态判定：

  POST /v1/trust/presentations/verify-with-status
  POST /v1/trust/presentations/verify-batch-with-status

直接运行：python3 tests/trust_presentation_verify_with_status_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
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


def utc_z(delta):
    return (datetime.now(timezone.utc) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")


ISSUER_DID = "did:web:issuer.pws"
HOLDER_DID = "did:web:holder.pws"
SOURCE_TENANT = "source-tenant-pws"


def make_presentation(cred_id, expires_at="2099-01-01T00:00:00Z",
                      challenge="chal-1"):
    return {
        "presentation_id": "vp_" + "c" * 32,
        "credential_id": cred_id,
        "issuer_did": ISSUER_DID,
        "issuer_key_version": 1,
        "disclose": ["/role"],
        "claims": {"role": "admin"},
        "challenge": challenge,
        "expires_at": expires_at,
    }


def sign_unbound(p, issuer_priv):
    p = dict(p)
    message = {k: v for k, v in p.items() if k != "proof"}
    p["proof"] = crypto.sign(message, issuer_priv)
    return p


def sign_bound(p, issuer_priv, holder_priv, tenant_id=SOURCE_TENANT):
    p = dict(p)
    p["holder_did"] = HOLDER_DID
    p["holder_key_version"] = 1
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


def main():
    port = 8956
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    single = "/v1/trust/presentations/verify-with-status"
    batch = "/v1/trust/presentations/verify-batch-with-status"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    issuer_priv, issuer_pub = gen_keypair()
    holder_priv, holder_pub = gen_keypair()
    T1 = {"X-Tenant-ID": "tpws-a"}
    T2 = {"X-Tenant-ID": "tpws-b"}

    def unbound_item(cred_id, **kw):
        return sign_unbound(make_presentation(cred_id, **kw), issuer_priv)

    def bound_item(cred_id, **kw):
        return sign_bound(make_presentation(cred_id, **kw),
                          issuer_priv, holder_priv)

    def call_single(pres, headers=T1, bound=False, challenge="chal-1"):
        payload = {"presentation": pres, "challenge": challenge}
        if bound:
            payload["source_tenant_id"] = SOURCE_TENANT
        return _http("POST", f"{base}{single}", payload, headers=headers)

    def call_batch(items, headers=T1):
        return _http("POST", f"{base}{batch}",
                     {"presentations": items}, headers=headers)

    _DELETE = object()

    def sync(cred_id, status, reason=_DELETE, updated_at=None):
        sb = {
            "issuer_did": ISSUER_DID,
            "credential_id": cred_id,
            "status": status,
            "updated_at": updated_at or utc_z(timedelta(days=-1)),
            "issuer_key_version": 1,
        }
        if reason is not _DELETE:
            sb["reason"] = reason
        return _http("POST", f"{base}/v1/trust/credential-status/sync",
                     {"body": sb, "signature": crypto.sign(sb, issuer_priv)},
                     headers=T1)

    try:
        assert wait_up(port), "服务启动超时"

        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": ISSUER_DID, "public_key": issuer_pub,
                       "key_version": 1}, headers=T1)
        check("注册签发者锚点 -> 201", st == 201)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": HOLDER_DID, "public_key": holder_pub,
                       "key_version": 1}, headers=T1)
        check("注册持有者锚点 -> 201", st == 201)

        # ---------- 单项：租户头协议 ----------
        st, _ = _http("POST", f"{base}{single}",
                      {"presentation": {}, "challenge": "x"},
                      headers={"X-Tenant-ID": ""})
        check("单项：显式空 X-Tenant-ID -> 400", st == 400)
        st, _ = _http("POST", f"{base}{batch}",
                      {"presentations": []},
                      headers={"X-Tenant-ID": ""})
        check("批量：显式空 X-Tenant-ID -> 400", st == 400)

        # ---------- 单项：状态合并 ----------
        st, r = call_single(unbound_item("vc_nosync"))
        check("未同步", st == 200
              and r == {"valid": False, "reason": "外部凭证状态未同步"})

        check("同步 active -> 201", sync("vc_active", "active")[0] == 201)
        st, r = call_single(unbound_item("vc_active"))
        check("active 仅返回 valid:true", st == 200 and r == {"valid": True})

        check("同步 revoked 带原因 -> 201",
              sync("vc_rev", "revoked", reason="持证人违规")[0] == 201)
        st, r = call_single(unbound_item("vc_rev"))
        check("revoked 带保存原因",
              st == 200 and r == {"valid": False,
                                  "reason": "外部凭证已吊销：持证人违规"})

        check("同步 revoked 无原因 -> 201",
              sync("vc_rev_nr", "revoked")[0] == 201)
        st, r = call_single(unbound_item("vc_rev_nr"))
        check("revoked 无原因用未知原因",
              st == 200 and r == {"valid": False,
                                  "reason": "外部凭证已吊销：未知原因"})

        check("同步 unknown -> 201", sync("vc_unk", "unknown")[0] == 201)
        st, r = call_single(unbound_item("vc_unk"))
        check("unknown", st == 200
              and r == {"valid": False, "reason": "外部凭证状态未知"})

        # ---------- 单项：验真优先于状态 ----------
        pres = unbound_item("vc_active")
        pres["proof"] = pres["proof"][:-2] + (
            "AA" if pres["proof"][-2:] != "AA" else "BB")
        st, r = call_single(pres)
        check("签名失败优先于 active 状态",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名校验失败"))

        st, r = _http("POST", f"{base}{single}",
                      {"presentation": unbound_item("vc_active"),
                       "challenge": "chal-1", "extra": 1}, headers=T1)
        check("多余字段 -> 请求前缀",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("请求"))

        st, r = call_single(
            unbound_item("vc_active", expires_at=utc_z(timedelta(hours=-1))))
        check("已过期优先于 active",
              st == 200 and r == {"valid": False, "reason": "演示已过期"})

        st, r = call_single(unbound_item("vc_active"), headers=T2)
        check("他租户无锚点 -> 锚点不存在",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("锚点不存在"))

        # ---------- 单项：持有者绑定形态 ----------
        st, r = call_single(bound_item("vc_active"), bound=True)
        check("绑定形态 active 成功", st == 200 and r == {"valid": True})
        st, r = call_single(bound_item("vc_nosync"), bound=True)
        check("绑定形态未同步",
              st == 200
              and r == {"valid": False, "reason": "外部凭证状态未同步"})
        st, r = call_single(bound_item("vc_rev"), bound=True)
        check("绑定形态 revoked",
              st == 200 and r == {"valid": False,
                                  "reason": "外部凭证已吊销：持证人违规"})
        bad_bound = bound_item("vc_active")
        bad_bound["holder_proof"] = bad_bound["holder_proof"][:-2] + (
            "AA" if bad_bound["holder_proof"][-2:] != "AA" else "BB")
        st, r = call_single(bad_bound, bound=True)
        check("绑定形态 holder_proof 失败优先于状态",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名校验失败"))

        # ---------- 批量：请求级错误 ----------
        for name, payload in (
            ("空数组", {"presentations": []}),
            ("缺 presentations", {}),
            ("多余字段", {"presentations": [1], "x": 1}),
            ("非数组", {"presentations": {}}),
            ("超过 100 项", {"presentations": [1] * 101}),
        ):
            st, r = _http("POST", f"{base}{batch}", payload, headers=T1)
            check(f"批量请求级错误：{name}",
                  st == 200 and r.get("results") == []
                  and isinstance(r.get("reason"), str)
                  and r["reason"].startswith("请求"))
        st, r = _http("POST", f"{base}{batch}", raw=b"not-json", headers=T1)
        check("批量非法 JSON -> 请求前缀",
              st == 200 and r.get("results") == []
              and r.get("reason", "").startswith("请求"))

        # ---------- 批量：逐项合并，失败不短路 ----------
        items = [
            {"presentation": unbound_item("vc_active"),
             "challenge": "chal-1"},
            {"presentation": unbound_item("vc_nosync"),
             "challenge": "chal-1"},
            {"presentation": unbound_item("vc_rev"),
             "challenge": "chal-1"},
            {"presentation": unbound_item("vc_unk"),
             "challenge": "chal-1"},
            {"presentation": pres, "challenge": "chal-1"},  # 坏签名
            {"presentation": bound_item("vc_active"),
             "challenge": "chal-1", "source_tenant_id": SOURCE_TENANT},
            {"presentation": unbound_item("vc_active"),
             "challenge": "chal-1", "extra": 1},  # 请求级项错误
        ]
        st, r = call_batch(items)
        check("批量等长结果", st == 200 and len(r.get("results", [])) == 7)
        results = r.get("results", [])
        check("批量第1项 active", results[0] == {"valid": True})
        check("批量第2项未同步",
              results[1] == {"valid": False, "reason": "外部凭证状态未同步"})
        check("批量第3项 revoked",
              results[2] == {"valid": False,
                             "reason": "外部凭证已吊销：持证人违规"})
        check("批量第4项 unknown",
              results[3] == {"valid": False, "reason": "外部凭证状态未知"})
        check("批量第5项签名失败",
              results[4].get("valid") is False
              and results[4].get("reason", "").startswith("签名校验失败"))
        check("批量第6项绑定 active", results[5] == {"valid": True})
        check("批量第7项请求错误且非空中文原因",
              results[6].get("valid") is False
              and isinstance(results[6].get("reason"), str)
              and results[6]["reason"].startswith("请求"))
        check("批量失败不短路：末项之后仍返回完整结果",
              len(results) == 7)

        # ---------- 只读：不新增审计、不改同步记录 ----------
        _, before = _http("GET", f"{base}/v1/audit?limit=200&after=0",
                          headers=T1)
        call_single(unbound_item("vc_active"))
        call_single(unbound_item("vc_rev"))
        call_batch([{"presentation": unbound_item("vc_active"),
                     "challenge": "chal-1"}])
        _, after = _http("GET", f"{base}/v1/audit?limit=200&after=0",
                         headers=T1)
        check("只读：不新增审计",
              len(before.get("events", [])) == len(after.get("events", [])))
        st, r = _http(
            "GET",
            f"{base}/v1/trust/credential-status/vc_rev"
            f"?issuer_did={ISSUER_DID}",
            headers=T1)
        check("同步记录保持不变",
              st == 200 and r.get("status") == "revoked"
              and r.get("reason") == "持证人违规")

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 重启持久化：同一状态文件新起服务，结论保持一致。
    port2 = port + 100
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port2), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base2 = f"http://127.0.0.1:{port2}"
    try:
        assert wait_up(port2), "重启服务启动超时"
        st, r = _http("POST", f"{base2}{single}",
                      {"presentation": sign_unbound(
                          make_presentation("vc_rev"), issuer_priv),
                       "challenge": "chal-1"}, headers=T1)
        check("重启后 revoked 结论持久化",
              st == 200 and r == {"valid": False,
                                  "reason": "外部凭证已吊销：持证人违规"})
        st, r = _http("POST", f"{base2}{single}",
                      {"presentation": sign_unbound(
                          make_presentation("vc_active"), issuer_priv),
                       "challenge": "chal-1"}, headers=T1)
        check("重启后 active 结论持久化",
              st == 200 and r == {"valid": True})
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    print()
    if failures:
        print(f"{len(failures)} 项失败")
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    main()
