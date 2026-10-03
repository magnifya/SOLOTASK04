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
        "credential_id": "vc_proof_consumebatch_0001",
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


def make_item(proof_id, priv, challenge="chal-1", source=SOURCE_TENANT,
              **kw):
    proof = sign_proof(
        make_proof(proof_id=proof_id, challenge=challenge, **kw),
        priv, source=source)
    return {"proof": proof, "challenge": challenge,
            "source_tenant_id": source}


def cid_of(item):
    return hashlib.sha256(crypto.canonicalize(item)).hexdigest()


def main():
    port = 9242
    store = tempfile.mktemp(suffix=".json")
    proc = start_server(port, store)
    base = f"http://127.0.0.1:{port}"
    path = "/v1/trust/proofs/consume-batch"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def consume_batch(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{path}", payload,
                     headers=headers, raw=raw)

    def consumed_audits(headers):
        st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=headers)
        assert st == 200
        return [e for e in r["events"]
                if e["action"] == "trust.proof.consumed"]

    try:
        T1 = {"X-Tenant-ID": "tzpb-a"}
        T2 = {"X-Tenant-ID": "tzpb-b"}

        iss_priv, iss_pub = gen_keypair()

        good_item = make_item("zp_" + "a" * 32, iss_priv)

        # 显式空租户头 -> 400（进入请求体验真前判定）
        st, r = consume_batch({"items": [good_item]},
                              headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400 仅 {error}",
              st == 400 and r == {"error": "X-Tenant-ID 不能为空"})

        # 注册签发者锚点（默认 uses 含 proof）
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": ISSUER_DID, "public_key": iss_pub,
                       "key_version": 1}, headers=T1)
        check("注册签发者锚点 -> 201", st == 201)

        # 1. 请求级非法 -> 200 恰返 {"results": [], "reason": "请求非法"}
        def expect_request_invalid(name, payload=None, raw=None, headers=T1):
            st, r = consume_batch(payload=payload, raw=raw, headers=headers)
            check(name, st == 200 and r == REQUEST_INVALID)

        expect_request_invalid("空请求体 -> 请求非法", raw=b"")
        expect_request_invalid("非法 UTF-8 -> 请求非法", raw=b"\xff\xfe")
        expect_request_invalid("非法 JSON -> 请求非法", raw=b"not-json")
        expect_request_invalid("非对象 -> 请求非法", raw=b"[1,2]")
        expect_request_invalid("缺 items -> 请求非法", payload={})
        expect_request_invalid("多余字段 -> 请求非法",
                               payload={"items": [good_item], "extra": 1})
        expect_request_invalid("items 非数组 -> 请求非法",
                               payload={"items": "nope"})
        expect_request_invalid("items 空数组 -> 请求非法",
                               payload={"items": []})
        expect_request_invalid(
            "items 超过 100 项 -> 请求非法",
            payload={"items": [good_item] * 101})
        check("请求级非法不记审计", consumed_audits(T1) == [])

        # 2. 项级非法 -> 该项仅 {"valid": false, "reason": "请求项非法"}，
        #    失败不短路、不占键
        bad_items = [
            42,                                                   # 非对象
            {"proof": good_item["proof"],                         # 缺字段
             "challenge": "chal-1"},
            dict(good_item, extra=1),                             # 多余字段
            {"proof": "nope", "challenge": "chal-1",              # proof 非对象
             "source_tenant_id": SOURCE_TENANT},
            {"proof": good_item["proof"], "challenge": "",        # 空 challenge
             "source_tenant_id": SOURCE_TENANT},
            {"proof": good_item["proof"], "challenge": 7,         # 非字符串
             "source_tenant_id": SOURCE_TENANT},
            {"proof": good_item["proof"], "challenge": "chal-1",  # 空 source
             "source_tenant_id": ""},
        ]
        st, r = consume_batch({"items": bad_items + [good_item]}, headers=T1)
        ok = st == 200 and list(r.keys()) == ["results"] and len(
            r["results"]) == len(bad_items) + 1
        ok = ok and all(
            item == {"valid": False, "reason": "请求项非法"}
            for item in r["results"][:-1])
        tail = r["results"][-1]
        ok = ok and list(tail.keys()) == [
            "valid", "consumption_id", "consumed_at"] and tail["valid"] is True
        check("项级非法逐项 请求项非法，失败不短路且末项成功", ok)
        check("成功项 consumption_id 针对单项请求",
              tail["consumption_id"] == cid_of(good_item)
              and re.fullmatch(r"[0-9a-f]{64}",
                               tail["consumption_id"]) is not None)
        check("成功项 consumed_at 为 UTC 秒精度 Z",
              isinstance(tail["consumed_at"], str)
              and UTC_Z_RE.fullmatch(tail["consumed_at"]) is not None)
        audits = consumed_audits(T1)
        check("仅成功项记一条 trust.proof.consumed 审计",
              len(audits) == 1
              and audits[0]["resource_type"] == "trust_proof"
              and audits[0]["resource_id"] == cid_of(good_item)
              and audits[0]["tenant_id"] == "tzpb-a")

        # 3. 验真失败项 -> 与单条相同 reason，不占键、不记审计
        bad_chal = {"proof": good_item["proof"], "challenge": "chal-2",
                    "source_tenant_id": SOURCE_TENANT}
        unknown = make_item("zp_" + "e" * 32, iss_priv,
                            issuer_did="did:web:nobody.example")
        bad_sig_item = make_item("zp_" + "f" * 32, iss_priv)
        bad_sig_item["proof"]["proof"] = "!!!bad!!!"
        expired = make_item("zp_" + "0" * 32, iss_priv,
                            expires_at="2020-01-01T00:00:00Z")
        st, r = consume_batch(
            {"items": [bad_chal, unknown, bad_sig_item, expired]},
            headers=T1)
        res = r["results"]
        check("验真失败项逐项返回单条相同 reason",
              st == 200 and len(res) == 4
              and res[0]["valid"] is False
              and res[0]["reason"].startswith("挑战")
              and res[1]["valid"] is False
              and res[1]["reason"].startswith("锚点")
              and res[2]["valid"] is False
              and res[2]["reason"].startswith("签名格式错误")
              and res[3] == {"valid": False, "reason": "证明已过期"})
        check("验真失败不记审计", len(consumed_audits(T1)) == 1)
        # 失败项不占键：修复 challenge 后同证明可首次消费
        # （good_item 已在步骤 2 消费，改用新 proof_id 验证失败不占键）
        retry = make_item("zp_" + "1" * 32, iss_priv, challenge="chal-x")
        st, r = consume_batch(
            {"items": [{"proof": retry["proof"], "challenge": "chal-y",
                        "source_tenant_id": SOURCE_TENANT}, retry]},
            headers=T1)
        check("验真失败项不占键，修正后同批后续项首次成功",
              st == 200
              and r["results"][0]["valid"] is False
              and r["results"][1].get("valid") is True)

        # 4. 批内判重：同键后项 -> 外部证明已消费；异内容同键亦判重
        dup_proof = sign_proof(
            make_proof(proof_id="zp_" + "2" * 32, challenge="chal-9"),
            iss_priv)
        dup_other = {"proof": dup_proof, "challenge": "chal-9",
                     "source_tenant_id": SOURCE_TENANT}
        dup_same = make_item("zp_" + "2" * 32, iss_priv)
        st, r = consume_batch({"items": [dup_same, dup_same, dup_other]},
                              headers=T1)
        check("批内同键首个成功、后续重复（含异内容）均 外部证明已消费",
              st == 200 and len(r["results"]) == 3
              and r["results"][0].get("valid") is True
              and r["results"][1]
              == {"valid": False, "reason": "外部证明已消费"}
              and r["results"][2]
              == {"valid": False, "reason": "外部证明已消费"})
        check("批内判重仅记一条审计",
              len([e for e in consumed_audits(T1)
                   if e["resource_id"] == cid_of(dup_same)]) == 1)

        # 5. 与单条 consume 共享防重放：历史重放 -> 外部证明已消费
        st, r = consume_batch({"items": [good_item]}, headers=T1)
        check("批量重放单条已消费键 -> 外部证明已消费",
              st == 200 and r["results"]
              == [{"valid": False, "reason": "外部证明已消费"}])
        single_item = make_item("zp_" + "3" * 32, iss_priv)
        st, r = consume_batch({"items": [single_item]}, headers=T1)
        check("批量首次消费成功", st == 200
              and r["results"][0].get("valid") is True)
        st, r = _http("POST", f"{base}/v1/trust/proofs/consume",
                      single_item, headers=T1)
        check("单条重放批量已消费键 -> 外部证明已消费",
              st == 200 and r == {"valid": False,
                                  "reason": "外部证明已消费"})

        # 6. 不同 source_tenant_id / 不同接收租户互不影响
        other_source = make_item("zp_" + "2" * 32, iss_priv,
                                 source="source-tenant-2")
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": ISSUER_DID, "public_key": iss_pub,
                       "key_version": 1}, headers=T2)
        check("T2 注册签发者锚点 -> 201", st == 201)
        st, r = consume_batch({"items": [other_source, good_item]},
                              headers=T1)
        check("不同 source_tenant_id 同 proof_id -> 新键首次成功",
              st == 200 and r["results"][0].get("valid") is True)
        check("T1 同键重放 -> 外部证明已消费",
              r["results"][1]
              == {"valid": False, "reason": "外部证明已消费"})
        st, r = consume_batch({"items": [good_item]}, headers=T2)
        check("租户 B 同键首次消费成功",
              st == 200 and r["results"][0].get("valid") is True
              and r["results"][0]["consumption_id"] == cid_of(good_item))
        check("消费审计按租户隔离",
              len(consumed_audits(T2)) == 1)

        # 7. 并发：同键仅一次成功
        conc_item = make_item("zp_" + "4" * 32, iss_priv)
        conc_results = []

        def worker():
            conc_results.append(
                consume_batch({"items": [conc_item]}, headers=T1))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        n_ok = sum(1 for st, r in conc_results
                   if st == 200 and r["results"][0].get("valid") is True)
        n_replay = sum(1 for st, r in conc_results
                       if st == 200 and r["results"][0]
                       == {"valid": False, "reason": "外部证明已消费"})
        check("并发同键仅一次成功，其余均为已消费",
              n_ok == 1 and n_replay == 7)

        # 8. 落盘失败：500 仅 {"error":"存储失败"}，整批不生效且可重试
        fail_item = make_item("zp_" + "5" * 32, iss_priv)
        audits_before = len(consumed_audits(T1))
        os.unlink(store)
        os.mkdir(store)
        try:
            st, r = consume_batch({"items": [fail_item]}, headers=T1)
            check("落盘失败 -> 500 仅 {error:存储失败}",
                  st == 500 and r == {"error": "存储失败"})
        finally:
            os.rmdir(store)
        check("落盘失败不记审计", len(consumed_audits(T1)) == audits_before)
        st, r = consume_batch({"items": [fail_item]}, headers=T1)
        check("落盘失败回滚后同键可重试成功",
              st == 200 and r["results"][0].get("valid") is True)
        st, r = consume_batch({"items": [fail_item]}, headers=T1)
        check("重试成功后重放 -> 外部证明已消费",
              st == 200 and r["results"][0]
              == {"valid": False, "reason": "外部证明已消费"})

        # 9. 已消费证明在只读验真接口仍按原规则验真通过，且不记审计
        st, r = _http("POST", f"{base}/v1/trust/proofs/verify-batch",
                      {"proofs": [good_item]}, headers=T1)
        check("已消费证明 verify-batch 仍只读验真通过",
              st == 200 and r == {"results": [{"valid": True}]})
        check("只读验真不记消费审计",
              len(consumed_audits(T1)) == audits_before + 1)

        # 10. 重启仍判重（含两租户）
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server(port, store)
        st, r = consume_batch({"items": [good_item]}, headers=T1)
        check("重启后租户 A 同键重放 -> 外部证明已消费",
              st == 200 and r["results"][0]
              == {"valid": False, "reason": "外部证明已消费"})
        st, r = consume_batch({"items": [good_item]}, headers=T2)
        check("重启后租户 B 同键重放 -> 外部证明已消费",
              st == 200 and r["results"][0]
              == {"valid": False, "reason": "外部证明已消费"})
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
