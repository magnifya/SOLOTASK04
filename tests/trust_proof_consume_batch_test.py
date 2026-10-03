#!/usr/bin/env python3
"""批量一次性消费 POST /v1/trust/proofs/consume-batch 的端到端测试。

直接运行：python3 tests/trust_proof_consume_batch_test.py
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
ISSUER_DID = "did:web:issuer.proof.consumebatch.example"
SOURCE_TENANT = "source-tenant-1"
REQUEST_INVALID = {"results": [], "reason": "请求非法"}


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
        "credential_id": "vc_proof_cb_0001",
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
    port = 9242
    store = tempfile.mktemp(suffix=".json")
    proc = start_server(port, store)
    base = f"http://127.0.0.1:{port}"
    path = "/v1/trust/proofs/consume-batch"
    single_path = "/v1/trust/proofs/consume"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def consume_batch(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{path}", payload,
                     headers=headers, raw=raw)

    def consume_single(payload, headers=None):
        return _http("POST", f"{base}{single_path}", payload,
                     headers=headers)

    def consumed_audits(headers):
        st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=headers)
        assert st == 200
        return [e for e in r["events"]
                if e["action"] == "trust.proof.consumed"]

    try:
        T1 = {"X-Tenant-ID": "tzcb-a"}
        T2 = {"X-Tenant-ID": "tzcb-b"}

        iss_priv, iss_pub = gen_keypair()

        good_proof = sign_proof(make_proof(), iss_priv)
        good_req = {"proof": good_proof, "challenge": "chal-1",
                    "source_tenant_id": SOURCE_TENANT}

        # 0. 显式空租户头 -> 400（进入处理前判定）
        st, r = consume_batch({"items": [good_req]},
                              headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400 仅 {error}",
              st == 400 and r == {"error": "X-Tenant-ID 不能为空"})

        # 1. 请求级非法 -> 200 恰返 {"results":[],"reason":"请求非法"}
        def expect_request_invalid(name, payload=None, raw=None):
            st, r = consume_batch(payload=payload, raw=raw, headers=T1)
            check(name, st == 200 and r == REQUEST_INVALID
                  and list(r.keys()) == ["results", "reason"])

        expect_request_invalid("空请求体 -> 请求非法", raw=b"")
        expect_request_invalid("非法 JSON -> 请求非法", raw=b"not-json")
        expect_request_invalid("非 UTF-8 -> 请求非法", raw=b"\xff\xfe")
        expect_request_invalid("非对象 -> 请求非法", raw=b"[1,2]")
        expect_request_invalid("缺 items -> 请求非法", payload={"x": []})
        expect_request_invalid("多余字段 -> 请求非法",
                               payload={"items": [good_req], "extra": 1})
        expect_request_invalid("items 非数组 -> 请求非法",
                               payload={"items": {"a": 1}})
        expect_request_invalid("items 空数组 -> 请求非法",
                               payload={"items": []})
        expect_request_invalid("items 超 100 项 -> 请求非法",
                               payload={"items": [good_req] * 101})
        check("请求级非法不记审计", consumed_audits(T1) == [])

        # 注册签发者锚点（默认 uses 含 proof）
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": ISSUER_DID, "public_key": iss_pub,
                       "key_version": 1}, headers=T1)
        check("注册签发者锚点 -> 201", st == 201)

        # 2. 项结构非法 -> {"valid":false,"reason":"请求项非法"}，不短路
        bad_items = [
            "not-a-dict",
            {"challenge": "chal-1",
             "source_tenant_id": SOURCE_TENANT},        # 缺 proof
            {"proof": good_proof,
             "source_tenant_id": SOURCE_TENANT},         # 缺 challenge
            {"proof": good_proof, "challenge": "chal-1"},  # 缺 source
            dict(good_req, extra=1),                     # 多余字段
            {"proof": "x", "challenge": "chal-1",
             "source_tenant_id": SOURCE_TENANT},         # proof 非对象
            {"proof": good_proof, "challenge": 1,
             "source_tenant_id": SOURCE_TENANT},         # challenge 非字符串
            {"proof": good_proof, "challenge": "",
             "source_tenant_id": SOURCE_TENANT},         # 空 challenge
            {"proof": good_proof, "challenge": "chal-1",
             "source_tenant_id": ""},                    # 空 source_tenant_id
        ]
        st, r = consume_batch({"items": bad_items}, headers=T1)
        check("项结构非法 -> 全部 请求项非法 且等长同序",
              st == 200 and list(r.keys()) == ["results"]
              and len(r["results"]) == len(bad_items)
              and all(item == {"valid": False, "reason": "请求项非法"}
                      for item in r["results"]))
        check("项结构非法不记审计", consumed_audits(T1) == [])

        # 3. 验真失败项复用单条 reason，失败不短路、无副作用
        unknown = sign_proof(
            make_proof(proof_id="zp_" + "u" * 32,
                       issuer_did="did:web:nobody.example"), iss_priv)
        bad_sig_proof = dict(
            make_proof(proof_id="zp_" + "s" * 32), proof="!!!bad!!!")
        expired = sign_proof(
            make_proof(proof_id="zp_" + "e" * 32,
                       expires_at="2020-01-01T00:00:00Z"), iss_priv)
        verify_fail_items = [
            {"proof": good_proof, "challenge": "chal-2",
             "source_tenant_id": SOURCE_TENANT},
            {"proof": unknown, "challenge": "chal-1",
             "source_tenant_id": SOURCE_TENANT},
            {"proof": bad_sig_proof, "challenge": "chal-1",
             "source_tenant_id": SOURCE_TENANT},
            {"proof": expired, "challenge": "chal-1",
             "source_tenant_id": SOURCE_TENANT},
        ]
        st, r = consume_batch({"items": verify_fail_items}, headers=T1)
        results = r.get("results", [])
        check("验真失败项复用单条 reason 且等长同序",
              st == 200 and len(results) == 4
              and all(list(item.keys()) == ["valid", "reason"]
                      and item["valid"] is False for item in results)
              and results[0]["reason"].startswith("挑战")
              and results[1]["reason"].startswith("锚点")
              and results[2]["reason"].startswith("签名格式错误")
              and results[3]["reason"] == "证明已过期")
        check("验真失败不记审计", consumed_audits(T1) == [])

        # 4. 混合批次：成功项键序恰为 valid、consumption_id、consumed_at；
        #    默认 results 含 false 仍可消费（验真不重算 results）
        proof2 = sign_proof(make_proof(proof_id="zp_" + "b" * 32), iss_priv)
        req2 = {"proof": proof2, "challenge": "chal-1",
                "source_tenant_id": SOURCE_TENANT}
        mixed = [good_req, "bad-item", req2]
        st, r = consume_batch({"items": mixed}, headers=T1)
        results = r.get("results", [])
        want_cid = hashlib.sha256(
            crypto.canonicalize(good_req)).hexdigest()
        want_cid2 = hashlib.sha256(
            crypto.canonicalize(req2)).hexdigest()
        ok_success = all(
            list(item.keys()) == ["valid", "consumption_id", "consumed_at"]
            and item["valid"] is True
            and re.fullmatch(r"[0-9a-f]{64}", item["consumption_id"])
            and UTC_Z_RE.fullmatch(item["consumed_at"])
            for item in (results[0], results[2])
        ) if len(results) == 3 else False
        check("混合批次成功项键序与取值正确（摘要针对单项请求）",
              st == 200 and list(r.keys()) == ["results"]
              and len(results) == 3 and ok_success
              and results[0]["consumption_id"] == want_cid
              and results[2]["consumption_id"] == want_cid2)
        check("混合批次结构错项 -> 请求项非法",
              len(results) == 3
              and results[1] == {"valid": False, "reason": "请求项非法"})

        # 5. 审计：两个首次消费各记一条，失败项不记
        audits = consumed_audits(T1)
        check("首次消费各记一条审计（共 2 条）",
              len(audits) == 2
              and [a["resource_id"] for a in audits]
              == [want_cid, want_cid2]
              and all(a["resource_type"] == "trust_proof"
                      and a["tenant_id"] == "tzcb-a" for a in audits))

        # 6. 批内判重：同键首项成功、后项（含异内容）外部证明已消费
        proof3 = sign_proof(make_proof(proof_id="zp_" + "c" * 32), iss_priv)
        req3 = {"proof": proof3, "challenge": "chal-1",
                "source_tenant_id": SOURCE_TENANT}
        proof3_other = sign_proof(
            make_proof(proof_id="zp_" + "c" * 32, challenge="chal-9"),
            iss_priv)
        req3_other = {"proof": proof3_other, "challenge": "chal-9",
                      "source_tenant_id": SOURCE_TENANT}
        st, r = consume_batch(
            {"items": [req3, req3_other, req3]}, headers=T1)
        results = r.get("results", [])
        check("批内同键首项成功、后项均 外部证明已消费",
              st == 200 and len(results) == 3
              and results[0].get("valid") is True
              and results[1] == {"valid": False, "reason": "外部证明已消费"}
              and results[2] == {"valid": False, "reason": "外部证明已消费"})
        check("批内同键仅记一条审计",
              len([a for a in consumed_audits(T1)
                   if a["resource_id"] == hashlib.sha256(
                       crypto.canonicalize(req3)).hexdigest()]) == 1)

        # 6b. 无效项不占键：同 proof_id 的坏签名项在前，合法项仍首次成功
        proof4_badsig = dict(
            make_proof(proof_id="zp_" + "k" * 32), proof="!!!bad!!!")
        req4_bad = {"proof": proof4_badsig, "challenge": "chal-1",
                    "source_tenant_id": SOURCE_TENANT}
        proof4 = sign_proof(make_proof(proof_id="zp_" + "k" * 32), iss_priv)
        req4 = {"proof": proof4, "challenge": "chal-1",
                "source_tenant_id": SOURCE_TENANT}
        st, r = consume_batch({"items": [req4_bad, req4]}, headers=T1)
        results = r.get("results", [])
        check("无效项不占键：前项签名失败、后项同键首次成功",
              st == 200 and len(results) == 2
              and results[0]["reason"].startswith("签名格式错误")
              and results[1].get("valid") is True
              and results[1]["consumption_id"]
              == hashlib.sha256(crypto.canonicalize(req4)).hexdigest())
        check("无效项不占键仅记一条审计",
              len([a for a in consumed_audits(T1)
                   if a["resource_id"] == hashlib.sha256(
                       crypto.canonicalize(req4)).hexdigest()]) == 1)

        # 7. 历史判重：批次重放已消费键（含与单条 consume 互判）
        st, r = consume_batch({"items": [good_req, req2]}, headers=T1)
        check("批次重放历史键 -> 全部 外部证明已消费",
              st == 200 and r["results"]
              == [{"valid": False, "reason": "外部证明已消费"}] * 2)
        st, r = consume_single(req2, headers=T1)
        check("单条重放批次已消费键 -> 外部证明已消费",
              st == 200 and r == {"valid": False,
                                  "reason": "外部证明已消费"})
        proof5 = sign_proof(make_proof(proof_id="zp_" + "f" * 32), iss_priv)
        req5 = {"proof": proof5, "challenge": "chal-1",
                "source_tenant_id": SOURCE_TENANT}
        st, r = consume_single(req5, headers=T1)
        check("单条首次消费新键成功", st == 200 and r.get("valid") is True)
        st, r = consume_batch({"items": [req5]}, headers=T1)
        check("批次重放单条已消费键 -> 外部证明已消费",
              st == 200 and r["results"]
              == [{"valid": False, "reason": "外部证明已消费"}])
        # 不同 source_tenant_id 为不同键：同 proof_id 仍可首次成功
        proof_other_src = sign_proof(
            make_proof(proof_id="zp_" + "a" * 32), iss_priv,
            source="source-tenant-2")
        req_other_src = {"proof": proof_other_src, "challenge": "chal-1",
                         "source_tenant_id": "source-tenant-2"}
        st, r = consume_batch({"items": [req_other_src]}, headers=T1)
        check("不同 source_tenant_id 同 proof_id -> 首次消费成功",
              st == 200 and r["results"][0].get("valid") is True)
        check("重放均不新增审计（仅其他来源新增 1 条）",
              len(consumed_audits(T1)) == 6)

        # 8. 租户隔离：T2 同键各自首次成功
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": ISSUER_DID, "public_key": iss_pub,
                       "key_version": 1}, headers=T2)
        check("T2 注册签发者锚点 -> 201", st == 201)
        st, r = consume_batch({"items": [good_req]}, headers=T2)
        check("租户 B 同键首次消费成功",
              st == 200 and len(r["results"]) == 1
              and r["results"][0].get("valid") is True
              and r["results"][0].get("consumption_id") == want_cid)
        st, r = consume_batch({"items": [good_req]}, headers=T2)
        check("租户 B 重放 -> 外部证明已消费",
              st == 200 and r["results"]
              == [{"valid": False, "reason": "外部证明已消费"}])
        check("消费审计按租户隔离",
              len(consumed_audits(T1)) == 6
              and len(consumed_audits(T2)) == 1)

        # 9. 并发：批次与单条同键仅一次成功
        conc_proof = sign_proof(
            make_proof(proof_id="zp_" + "g" * 32), iss_priv)
        conc_req = {"proof": conc_proof, "challenge": "chal-1",
                    "source_tenant_id": SOURCE_TENANT}
        conc_cid = hashlib.sha256(
            crypto.canonicalize(conc_req)).hexdigest()
        outcomes = []

        def batch_worker():
            outcomes.append(consume_batch({"items": [conc_req]},
                                          headers=T1))

        def single_worker():
            outcomes.append(consume_single(conc_req, headers=T1))

        threads = ([threading.Thread(target=batch_worker)
                    for _ in range(4)]
                   + [threading.Thread(target=single_worker)
                      for _ in range(4)])
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        flat = []
        for st, r in outcomes:
            if st == 200 and "results" in r:
                flat.extend(r["results"])
            else:
                flat.append(r)
        n_ok = sum(1 for item in flat if item.get("valid") is True)
        n_replay = sum(1 for item in flat
                       if item == {"valid": False,
                                   "reason": "外部证明已消费"})
        check("并发批次/单条同键仅一次成功，其余均为已消费",
              n_ok == 1 and n_replay == 7)
        check("并发首次消费仅一条审计",
              len([a for a in consumed_audits(T1)
                   if a["resource_id"] == conc_cid]) == 1)

        # 10. 落盘失败：500 仅 {"error":"存储失败"}，全回滚可重试
        fail_proof = sign_proof(
            make_proof(proof_id="zp_" + "h" * 32), iss_priv)
        fail_req = {"proof": fail_proof, "challenge": "chal-1",
                    "source_tenant_id": SOURCE_TENANT}
        fail_proof2 = sign_proof(
            make_proof(proof_id="zp_" + "i" * 32), iss_priv)
        fail_req2 = {"proof": fail_proof2, "challenge": "chal-1",
                     "source_tenant_id": SOURCE_TENANT}
        audits_before = len(consumed_audits(T1))
        os.unlink(store)
        os.mkdir(store)
        try:
            st, r = consume_batch({"items": [fail_req, fail_req2]},
                                  headers=T1)
            check("落盘失败 -> 500 仅 {error:存储失败}",
                  st == 500 and r == {"error": "存储失败"})
        finally:
            os.rmdir(store)
        check("落盘失败不记审计", len(consumed_audits(T1)) == audits_before)
        st, r = consume_batch({"items": [fail_req, fail_req2]}, headers=T1)
        check("落盘失败回滚后同批两键可重试成功",
              st == 200 and len(r["results"]) == 2
              and all(item.get("valid") is True for item in r["results"]))
        st, r = consume_batch({"items": [fail_req, fail_req2]}, headers=T1)
        check("重试成功后重放 -> 外部证明已消费",
              st == 200 and r["results"]
              == [{"valid": False, "reason": "外部证明已消费"}] * 2)

        # 11. 重启仍判重（含两租户）
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server(port, store)
        st, r = consume_batch(
            {"items": [good_req, fail_req, fail_req2]}, headers=T1)
        check("重启后租户 A 同键重放 -> 全部 外部证明已消费",
              st == 200 and r["results"]
              == [{"valid": False, "reason": "外部证明已消费"}] * 3)
        st, r = consume_batch({"items": [good_req]}, headers=T2)
        check("重启后租户 B 同键重放 -> 外部证明已消费",
              st == 200 and r["results"]
              == [{"valid": False, "reason": "外部证明已消费"}])
        check("重启后重放不新增审计",
              len(consumed_audits(T1)) == audits_before + 2
              and len(consumed_audits(T2)) == 1)

        # 12. 只读验真接口不受消费影响，且不记消费审计
        st, r = _http("POST", f"{base}/v1/trust/proofs/verify", good_req,
                      headers=T1)
        check("已消费证明 verify 仍只读验真通过",
              st == 200 and r == {"valid": True})
        check("只读验真不记消费审计",
              len(consumed_audits(T1)) == audits_before + 2)

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
