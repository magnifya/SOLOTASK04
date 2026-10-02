#!/usr/bin/env python3
"""跨系统谓词证明一次性消费 POST /v1/trust/proofs/consume 的端到端测试。

直接运行：python3 tests/trust_proof_consume_test.py
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
ISSUER_DID = "did:web:issuer.proof.consume.example"
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


DEFAULT_PREDS = [
    {"path": "/age", "op": "gte", "value": 18},
    {"path": "/role", "op": "eq", "value": "admin"},
    {"path": "/name", "op": "exists"},
]


def make_proof(proof_id=None, challenge="chal-1",
               expires_at="2099-01-01T00:00:00Z",
               issuer_did=ISSUER_DID, version=1, results=None):
    return {
        "proof_id": proof_id or ("zp_" + "a" * 32),
        "credential_id": "vc_proof_consume_0001",
        "issuer_did": issuer_did,
        "issuer_key_version": version,
        "predicates": DEFAULT_PREDS,
        "results": [True, False, True] if results is None else results,
        "challenge": challenge,
        "expires_at": expires_at,
    }


def sign_proof(p, priv, source=SOURCE_TENANT):
    """proof 覆盖去掉 proof 后的八字段并加入 tenant_id=source。"""
    p = dict(p)
    message = {k: v for k, v in p.items() if k != "proof"}
    message["tenant_id"] = source
    p["proof"] = crypto.sign(message, priv)
    return p


def main():
    port = 9241
    store = tempfile.mktemp(suffix=".json")
    proc = start_server(port, store)
    base = f"http://127.0.0.1:{port}"
    path = "/v1/trust/proofs/consume"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def consume(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{path}", payload,
                     headers=headers, raw=raw)

    def consumed_audits(headers):
        st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=headers)
        assert st == 200
        return [e for e in r["events"]
                if e["action"] == "trust.proof.consumed"]

    try:
        T1 = {"X-Tenant-ID": "tzp-a"}
        T2 = {"X-Tenant-ID": "tzp-b"}

        iss_priv, iss_pub = gen_keypair()

        good_proof = sign_proof(make_proof(), iss_priv)
        good_req = {"proof": good_proof, "challenge": "chal-1",
                    "source_tenant_id": SOURCE_TENANT}

        # 显式空租户头 -> 400（进入请求体验真前判定）
        st, r = consume(good_req, headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400 仅 {error}",
              st == 400 and r == {"error": "X-Tenant-ID 不能为空"})

        # 注册签发者锚点（默认 uses 含 proof）
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": ISSUER_DID, "public_key": iss_pub,
                       "key_version": 1}, headers=T1)
        check("注册签发者锚点 -> 201", st == 201)

        # 1. 外层/验真失败 -> 200 仅 valid,reason，且不写入不记审计
        def expect_invalid(name, payload=None, raw=None, headers=T1,
                           reason=None, prefix=None):
            st, r = consume(payload=payload, raw=raw, headers=headers)
            ok = (
                st == 200
                and list(r.keys()) == ["valid", "reason"]
                and r["valid"] is False
                and isinstance(r["reason"], str) and r["reason"]
            )
            if reason is not None:
                ok = ok and r["reason"] == reason
            if prefix is not None:
                ok = ok and r["reason"].startswith(prefix)
            check(name, ok)

        expect_invalid("空请求体 -> 200 请求类原因", raw=b"", prefix="请求")
        expect_invalid("非法 UTF-8 -> 200 请求类原因", raw=b"\xff\xfe",
                       prefix="请求")
        expect_invalid("非法 JSON -> 200 请求类原因", raw=b"not-json",
                       prefix="请求")
        expect_invalid("非对象 -> 200 请求类原因", raw=b"[1,2]",
                       prefix="请求")
        expect_invalid("缺 challenge -> 请求类原因",
                       {"proof": good_proof,
                        "source_tenant_id": SOURCE_TENANT}, prefix="请求")
        expect_invalid("多余字段 -> 请求类原因",
                       dict(good_req, extra=1), prefix="请求")
        expect_invalid("challenge 不一致 -> 挑战类原因",
                       {"proof": good_proof, "challenge": "chal-2",
                        "source_tenant_id": SOURCE_TENANT}, prefix="挑战")
        unknown = sign_proof(
            make_proof(issuer_did="did:web:nobody.example"), iss_priv)
        expect_invalid("未知签发者锚点 -> 锚点类原因",
                       {"proof": unknown, "challenge": "chal-1",
                        "source_tenant_id": SOURCE_TENANT}, prefix="锚点")
        bad_sig = dict(good_proof, proof="!!!bad!!!")
        expect_invalid("坏签名 -> 签名格式错误",
                       {"proof": bad_sig, "challenge": "chal-1",
                        "source_tenant_id": SOURCE_TENANT},
                       prefix="签名格式错误")
        expired = sign_proof(
            make_proof(expires_at="2020-01-01T00:00:00Z"), iss_priv)
        expect_invalid("已过期 -> 证明已过期",
                       {"proof": expired, "challenge": "chal-1",
                        "source_tenant_id": SOURCE_TENANT},
                       reason="证明已过期")
        check("验真失败不记消费审计", consumed_audits(T1) == [])

        # 2. 首次消费（results 含 false 不影响验真）：200 按序恰返
        #    valid、consumption_id、consumed_at
        st, r = consume(good_req, headers=T1)
        want_cid = hashlib.sha256(
            crypto.canonicalize(good_req)).hexdigest()
        check("首次消费 -> 200 恰返 valid,consumption_id,consumed_at",
              st == 200 and list(r.keys())
              == ["valid", "consumption_id", "consumed_at"]
              and r["valid"] is True)
        check("consumption_id 为完整请求规范化 JSON 的 SHA-256 小写 hex",
              r.get("consumption_id") == want_cid
              and re.fullmatch(r"[0-9a-f]{64}", r["consumption_id"]))
        check("consumed_at 为 UTC 秒精度 Z",
              isinstance(r.get("consumed_at"), str)
              and UTC_Z_RE.fullmatch(r["consumed_at"]) is not None)
        first_consumed_at = r["consumed_at"]

        # 3. 审计：恰记一条，字段正确
        audits = consumed_audits(T1)
        check("首次消费记一条 trust.proof.consumed 审计",
              len(audits) == 1
              and audits[0]["resource_type"] == "trust_proof"
              and audits[0]["resource_id"] == want_cid
              and audits[0]["tenant_id"] == "tzp-a")

        # 4. 同键重放（完全同体）-> 200 仅 外部证明已消费，不记审计
        st, r = consume(good_req, headers=T1)
        check("同体重放 -> 200 仅 外部证明已消费",
              st == 200 and r == {"valid": False, "reason": "外部证明已消费"})
        check("重放不记审计", len(consumed_audits(T1)) == 1)

        # 5. 同键重放（proof_id/issuer_did/source 相同但内容不同、签名
        #    合法、challenge 不同）-> 仍按组合键判重
        same_id = good_proof["proof_id"]
        other_proof = sign_proof(
            make_proof(proof_id=same_id, challenge="chal-9"), iss_priv)
        st, r = consume({"proof": other_proof, "challenge": "chal-9",
                         "source_tenant_id": SOURCE_TENANT}, headers=T1)
        check("同 (source,issuer,proof_id) 异内容重放 -> 外部证明已消费",
              st == 200 and r == {"valid": False, "reason": "外部证明已消费"})
        check("异内容重放不记审计", len(consumed_audits(T1)) == 1)

        # 6. 不同 proof_id -> 新键首次成功
        proof2 = sign_proof(make_proof(proof_id="zp_" + "b" * 32), iss_priv)
        req2 = {"proof": proof2, "challenge": "chal-1",
                "source_tenant_id": SOURCE_TENANT}
        st, r = consume(req2, headers=T1)
        want_cid2 = hashlib.sha256(crypto.canonicalize(req2)).hexdigest()
        check("不同 proof_id -> 首次消费成功",
              st == 200 and list(r.keys())
              == ["valid", "consumption_id", "consumed_at"]
              and r["consumption_id"] == want_cid2
              and r["consumed_at"] >= first_consumed_at)
        check("第二次首次消费再记一条审计", len(consumed_audits(T1)) == 2)

        # 7. 不同 source_tenant_id -> 新键（同 proof_id 同 issuer）
        other_source_proof = sign_proof(make_proof(proof_id=same_id),
                                        iss_priv, source="source-tenant-2")
        req3 = {"proof": other_source_proof, "challenge": "chal-1",
                "source_tenant_id": "source-tenant-2"}
        st, r = consume(req3, headers=T1)
        check("不同 source_tenant_id 同 proof_id -> 首次消费成功",
              st == 200 and r.get("valid") is True)
        check("第三首次消费再记一条审计", len(consumed_audits(T1)) == 3)

        # 8. 已消费证明在只读验真接口仍按原规则验真通过
        st, r = _http("POST", f"{base}/v1/trust/proofs/verify", good_req,
                      headers=T1)
        check("已消费证明 verify 仍只读验真通过",
              st == 200 and r == {"valid": True})
        check("只读验真不记消费审计", len(consumed_audits(T1)) == 3)

        # 9. 租户隔离：T2 注册同 DID 锚点后同键各自首次成功
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": ISSUER_DID, "public_key": iss_pub,
                       "key_version": 1}, headers=T2)
        check("T2 注册签发者锚点 -> 201", st == 201)
        st, r = consume(good_req, headers=T2)
        check("租户 B 同键首次消费成功",
              st == 200 and r.get("valid") is True
              and r.get("consumption_id") == want_cid)
        st, r = consume(good_req, headers=T2)
        check("租户 B 重放 -> 外部证明已消费",
              st == 200 and r == {"valid": False, "reason": "外部证明已消费"})
        check("消费审计按租户隔离",
              len(consumed_audits(T1)) == 3 and len(consumed_audits(T2)) == 1)

        # 10. 并发：同键仅一次成功
        conc_proof = sign_proof(
            make_proof(proof_id="zp_" + "c" * 32), iss_priv)
        conc_req = {"proof": conc_proof, "challenge": "chal-1",
                    "source_tenant_id": SOURCE_TENANT}
        results = []

        def worker():
            results.append(consume(conc_req, headers=T1))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        n_ok = sum(1 for st, r in results
                   if st == 200 and r.get("valid") is True)
        n_replay = sum(1 for st, r in results
                       if st == 200
                       and r == {"valid": False, "reason": "外部证明已消费"})
        check("并发同键仅一次成功，其余均为已消费",
              n_ok == 1 and n_replay == 7)
        check("并发首次消费仅一条审计",
              len([e for e in consumed_audits(T1)
                   if e["resource_id"]
                   == hashlib.sha256(
                       crypto.canonicalize(conc_req)).hexdigest()]) == 1)

        # 11. 落盘失败：500 仅 {"error":"存储失败"}，回滚可重试
        fail_proof = sign_proof(
            make_proof(proof_id="zp_" + "d" * 32), iss_priv)
        fail_req = {"proof": fail_proof, "challenge": "chal-1",
                    "source_tenant_id": SOURCE_TENANT}
        audits_before = len(consumed_audits(T1))
        os.unlink(store)
        os.mkdir(store)
        try:
            st, r = consume(fail_req, headers=T1)
            check("落盘失败 -> 500 仅 {error:存储失败}",
                  st == 500 and r == {"error": "存储失败"})
        finally:
            os.rmdir(store)
        check("落盘失败不记审计", len(consumed_audits(T1)) == audits_before)
        st, r = consume(fail_req, headers=T1)
        check("落盘失败回滚后同键可重试成功",
              st == 200 and r.get("valid") is True)
        st, r = consume(fail_req, headers=T1)
        check("重试成功后重放 -> 外部证明已消费",
              st == 200 and r == {"valid": False, "reason": "外部证明已消费"})

        # 12. 重启仍判重（含两租户）
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server(port, store)
        st, r = consume(good_req, headers=T1)
        check("重启后租户 A 同键重放 -> 外部证明已消费",
              st == 200 and r == {"valid": False, "reason": "外部证明已消费"})
        st, r = consume(good_req, headers=T2)
        check("重启后租户 B 同键重放 -> 外部证明已消费",
              st == 200 and r == {"valid": False, "reason": "外部证明已消费"})
        st, r = consume(fail_req, headers=T1)
        check("重启后落盘失败重试键仍判重",
              st == 200 and r == {"valid": False, "reason": "外部证明已消费"})
        # 重启不产生新审计
        check("重启后重放不新增审计",
              len(consumed_audits(T1)) == audits_before + 1
              and len(consumed_audits(T2)) == 1)

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
