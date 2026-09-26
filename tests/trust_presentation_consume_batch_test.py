#!/usr/bin/env python3
"""批量一次性消费 POST /v1/trust/presentations/consume-batch 的端到端测试。

直接运行：python3 tests/trust_presentation_consume_batch_test.py
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
ISSUER_DID = "did:web:issuer.consumebatch.example"
HOLDER_DID = "did:web:holder.consumebatch.example"
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


def make_presentation(presentation_id=None, challenge="chal-1",
                      expires_at="2099-01-01T00:00:00Z",
                      credential_id="vc_cb_0001",
                      issuer_did=ISSUER_DID, version=1):
    return {
        "presentation_id": presentation_id or ("vp_" + "a" * 32),
        "credential_id": credential_id,
        "issuer_did": issuer_did,
        "issuer_key_version": version,
        "disclose": ["/role", "/addr/city"],
        "claims": {"role": "admin", "addr": {"city": "北京"}},
        "challenge": challenge,
        "expires_at": expires_at,
    }


def sign_presentation(p, priv):
    """未绑定：proof 覆盖去掉 proof 后的全部字段。"""
    message = {k: v for k, v in p.items() if k != "proof"}
    p = dict(p)
    p["proof"] = crypto.sign(message, priv)
    return p


def make_bound(presentation_id=None, challenge="chal-1",
               expires_at="2099-01-01T00:00:00Z"):
    p = make_presentation(presentation_id=presentation_id
                          or ("vp_" + "b" * 32),
                          challenge=challenge, expires_at=expires_at,
                          credential_id="vc_cb_0002")
    p["holder_did"] = HOLDER_DID
    p["holder_key_version"] = 1
    return p


def sign_bound(p, issuer_priv, holder_priv, tenant_id=SOURCE_TENANT):
    """issuer proof 覆盖去掉 proof/holder_* 的八字段；holder proof 覆盖
    去掉 proof/holder_proof 的对象并加入 tenant_id。"""
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


def main():
    port = 8992
    store = tempfile.mktemp(suffix=".json")
    proc = start_server(port, store)
    base = f"http://127.0.0.1:{port}"
    path = "/v1/trust/presentations/consume-batch"
    single_path = "/v1/trust/presentations/consume"
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
                if e["action"] == "trust.presentation.consumed"]

    try:
        T1 = {"X-Tenant-ID": "tpcb-a"}
        T2 = {"X-Tenant-ID": "tpcb-b"}

        iss_priv, iss_pub = gen_keypair()
        hold_priv, hold_pub = gen_keypair()

        good_pres = sign_presentation(make_presentation(), iss_priv)
        good_req = {"presentation": good_pres, "challenge": "chal-1"}
        good_bound = sign_bound(make_bound(), iss_priv, hold_priv)
        bound_req = {"presentation": good_bound, "challenge": "chal-1",
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

        # 注册签发者/持有者锚点
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": ISSUER_DID, "public_key": iss_pub,
                       "key_version": 1}, headers=T1)
        check("注册签发者锚点 -> 201", st == 201)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": HOLDER_DID, "public_key": hold_pub,
                       "key_version": 1}, headers=T1)
        check("注册持有者锚点 -> 201", st == 201)

        # 2. 项结构非法 -> {"valid":false,"reason":"请求项非法"}，不短路
        bad_items = [
            "not-a-dict",
            {"challenge": "chal-1"},                       # 缺 presentation
            {"presentation": good_pres},                   # 缺 challenge
            dict(good_req, extra=1),                       # 多余字段
            {"presentation": "x", "challenge": "chal-1"},  # 非对象
            {"presentation": good_pres, "challenge": ""},  # 空 challenge
            {"presentation": good_pres, "challenge": "chal-1",
             "source_tenant_id": ""},                      # 空 source_tenant_id
        ]
        st, r = consume_batch({"items": bad_items}, headers=T1)
        check("项结构非法 -> 全部 请求项非法 且等长同序",
              st == 200 and list(r.keys()) == ["results"]
              and len(r["results"]) == len(bad_items)
              and all(item == {"valid": False, "reason": "请求项非法"}
                      for item in r["results"]))
        check("项结构非法不记审计", consumed_audits(T1) == [])

        # 3. 验真失败项复用单条 reason，失败不短路、无副作用
        unknown = dict(good_pres)
        unknown["issuer_did"] = "did:web:nobody.example"
        unknown = sign_presentation(unknown, iss_priv)
        bad_sig = dict(good_pres, proof="!!!bad!!!")
        expired = sign_presentation(
            make_presentation(presentation_id="vp_" + "e" * 32,
                              expires_at="2020-01-01T00:00:00Z"), iss_priv)
        wrong_hold = sign_bound(make_bound(), iss_priv, gen_keypair()[0])
        verify_fail_items = [
            {"presentation": good_pres, "challenge": "chal-2"},
            {"presentation": unknown, "challenge": "chal-1"},
            {"presentation": bad_sig, "challenge": "chal-1"},
            {"presentation": expired, "challenge": "chal-1"},
            {"presentation": wrong_hold, "challenge": "chal-1",
             "source_tenant_id": SOURCE_TENANT},
        ]
        st, r = consume_batch({"items": verify_fail_items}, headers=T1)
        results = r.get("results", [])
        check("验真失败项复用单条 reason 且等长同序",
              st == 200 and len(results) == 5
              and all(list(item.keys()) == ["valid", "reason"]
                      and item["valid"] is False for item in results)
              and results[0]["reason"].startswith("挑战")
              and results[1]["reason"].startswith("锚点")
              and results[2]["reason"].startswith("签名格式错误")
              and results[3]["reason"] == "演示已过期"
              and results[4]["reason"].startswith(
                  "签名校验失败: holder_proof"))
        check("验真失败不记审计", consumed_audits(T1) == [])

        # 4. 混合批次：成功项键序恰为 valid、consumption_id、consumed_at
        pres2 = sign_presentation(
            make_presentation(presentation_id="vp_" + "c" * 32), iss_priv)
        req2 = {"presentation": pres2, "challenge": "chal-1"}
        mixed = [good_req, "bad-item", bound_req, req2]
        st, r = consume_batch({"items": mixed}, headers=T1)
        results = r.get("results", [])
        want_cid = hashlib.sha256(
            crypto.canonicalize(good_req)).hexdigest()
        want_bound_cid = hashlib.sha256(
            crypto.canonicalize(bound_req)).hexdigest()
        want_cid2 = hashlib.sha256(
            crypto.canonicalize(req2)).hexdigest()
        ok_success = all(
            list(item.keys()) == ["valid", "consumption_id", "consumed_at"]
            and item["valid"] is True
            and re.fullmatch(r"[0-9a-f]{64}", item["consumption_id"])
            and UTC_Z_RE.fullmatch(item["consumed_at"])
            for item in (results[0], results[2], results[3])
        ) if len(results) == 4 else False
        check("混合批次成功项键序与取值正确",
              st == 200 and list(r.keys()) == ["results"]
              and len(results) == 4 and ok_success
              and results[0]["consumption_id"] == want_cid
              and results[2]["consumption_id"] == want_bound_cid
              and results[3]["consumption_id"] == want_cid2)
        check("混合批次结构错项 -> 请求项非法",
              len(results) == 4
              and results[1] == {"valid": False, "reason": "请求项非法"})

        # 5. 审计：三个首次消费各记一条，失败项不记
        audits = consumed_audits(T1)
        check("首次消费各记一条审计（共 3 条）",
              len(audits) == 3
              and [a["resource_id"] for a in audits]
              == [want_cid, want_bound_cid, want_cid2]
              and all(a["resource_type"] == "trust_presentation"
                      and a["tenant_id"] == "tpcb-a" for a in audits))

        # 6. 批内判重：同键首项成功、后项 外部演示已消费
        pres3 = sign_presentation(
            make_presentation(presentation_id="vp_" + "d" * 32), iss_priv)
        req3 = {"presentation": pres3, "challenge": "chal-1"}
        req3_other = {
            "presentation": sign_presentation(
                make_presentation(presentation_id="vp_" + "d" * 32,
                                  challenge="chal-9"), iss_priv),
            "challenge": "chal-9",
        }
        st, r = consume_batch({"items": [req3, req3_other, req3]},
                              headers=T1)
        results = r.get("results", [])
        check("批内同键首项成功、后项均 外部演示已消费",
              st == 200 and len(results) == 3
              and results[0].get("valid") is True
              and results[1] == {"valid": False, "reason": "外部演示已消费"}
              and results[2] == {"valid": False, "reason": "外部演示已消费"})
        check("批内同键仅记一条审计",
              len([a for a in consumed_audits(T1)
                   if a["resource_id"] == hashlib.sha256(
                       crypto.canonicalize(req3)).hexdigest()]) == 1)

        # 7. 历史判重：批次重放已消费键（含与单条 consume 互判）
        st, r = consume_batch({"items": [good_req, bound_req]}, headers=T1)
        check("批次重放历史键 -> 全部 外部演示已消费",
              st == 200 and r["results"]
              == [{"valid": False, "reason": "外部演示已消费"}] * 2)
        st, r = consume_single(req2, headers=T1)
        check("单条重放批次已消费键 -> 外部演示已消费",
              st == 200 and r == {"valid": False, "reason": "外部演示已消费"})
        pres4 = sign_presentation(
            make_presentation(presentation_id="vp_" + "f" * 32), iss_priv)
        req4 = {"presentation": pres4, "challenge": "chal-1"}
        st, r = consume_single(req4, headers=T1)
        check("单条首次消费新键成功", st == 200 and r.get("valid") is True)
        st, r = consume_batch({"items": [req4]}, headers=T1)
        check("批次重放单条已消费键 -> 外部演示已消费",
              st == 200 and r["results"]
              == [{"valid": False, "reason": "外部演示已消费"}])
        check("重放均不新增审计", len(consumed_audits(T1)) == 5)

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
        check("租户 B 重放 -> 外部演示已消费",
              st == 200 and r["results"]
              == [{"valid": False, "reason": "外部演示已消费"}])
        check("消费审计按租户隔离",
              len(consumed_audits(T1)) == 5
              and len(consumed_audits(T2)) == 1)

        # 9. 并发：批次与单条同键仅一次成功
        conc_pres = sign_presentation(
            make_presentation(presentation_id="vp_" + "g" * 32), iss_priv)
        conc_req = {"presentation": conc_pres, "challenge": "chal-1"}
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
                                   "reason": "外部演示已消费"})
        check("并发批次/单条同键仅一次成功，其余均为已消费",
              n_ok == 1 and n_replay == 7)
        check("并发首次消费仅一条审计",
              len([a for a in consumed_audits(T1)
                   if a["resource_id"] == conc_cid]) == 1)

        # 10. 落盘失败：500 仅 {"error":"存储失败"}，全回滚可重试
        fail_pres = sign_presentation(
            make_presentation(presentation_id="vp_" + "h" * 32), iss_priv)
        fail_req = {"presentation": fail_pres, "challenge": "chal-1"}
        fail_pres2 = sign_presentation(
            make_presentation(presentation_id="vp_" + "i" * 32), iss_priv)
        fail_req2 = {"presentation": fail_pres2, "challenge": "chal-1"}
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
        check("重试成功后重放 -> 外部演示已消费",
              st == 200 and r["results"]
              == [{"valid": False, "reason": "外部演示已消费"}] * 2)

        # 11. 重启仍判重（含两租户与绑定形态）
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server(port, store)
        st, r = consume_batch({"items": [good_req, bound_req, fail_req]},
                              headers=T1)
        check("重启后租户 A 同键重放 -> 全部 外部演示已消费",
              st == 200 and r["results"]
              == [{"valid": False, "reason": "外部演示已消费"}] * 3)
        st, r = consume_batch({"items": [good_req]}, headers=T2)
        check("重启后租户 B 同键重放 -> 外部演示已消费",
              st == 200 and r["results"]
              == [{"valid": False, "reason": "外部演示已消费"}])
        check("重启后重放不新增审计",
              len(consumed_audits(T1)) == audits_before + 2
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
