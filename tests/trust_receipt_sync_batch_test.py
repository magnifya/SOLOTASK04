#!/usr/bin/env python3
"""POST /v1/trust/receipt-sync-batch 批量回执同步端到端测试。

直接运行：python3 tests/trust_receipt_sync_batch_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

数据来源与 trust_receipt_sync_test.py 相同：来源租户先经
verify-receipt + consume 产生真实回执消费历史，再由 export（NDJSON）
与 manifest（签名清单）导出；目标租户登记同 did/公钥的信任锚点后通过
receipt-sync-batch 批量同步。

覆盖：
- 请求级非法（空体/非法 JSON/非对象/键集错、items 非数组/空/超过 50
  项）均 HTTP 200 且恰返 {"results":[],"reason":"请求非法"}；
- 显式空 X-Tenant-ID 400；
- 项结构/类型错误（非对象、缺漏/多余键、manifest 非对象、ndjson 非
  字符串）收敛为 {valid:false,http_status:400,reason:"请求项非法"}，
  失败不短路；
- 清单验真/导出内容失败沿用单条 200 固定 reason；游标冲突 409
  “同步游标冲突”；
- 失败项键序 valid、http_status、reason；成功项键序 valid、
  http_status、signer_did、snapshot、next_after、count；首次检查点
  201，否则 200；
- 顶层 HTTP 200 且仅含等长同序 results；同签名方后项可见前项；
  失败项不影响其余项落盘；
- 与单条 receipt-sync 并发同页仅一次 201；同步不写审计；租户隔离；
  跨重启检查点保持。
"""

import concurrent.futures
import copy
import hashlib
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

SYNC_PATH = "/v1/trust/receipt-sync"
BATCH_PATH = "/v1/trust/receipt-sync-batch"
EXPORT_PATH = "/v1/trust/credentials/receipt/consumptions/export"
MANIFEST_PATH = "/v1/trust/credentials/receipt/consumptions/manifest"
VERIFY_RECEIPT_PATH = "/v1/trust/credentials/verify-receipt"
CONSUME_PATH = "/v1/trust/credentials/receipt/consume"
ANCHORS_PATH = "/v1/trust/anchors"
OK_KEYS = ["valid", "http_status", "signer_did", "snapshot",
           "next_after", "count"]
ERR_KEYS = ["valid", "http_status", "reason"]

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


def _http(method, url, payload=None, headers=None, raw_body=None):
    if raw_body is not None:
        data = raw_body
    else:
        data = (
            json.dumps(payload).encode("utf-8")
            if payload is not None
            else None
        )
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def wait_up(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            _http("GET", f"http://127.0.0.1:{port}/health")
            return True
        except OSError:
            time.sleep(0.15)
    return False


def _keypair():
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


def main():
    port = 9052
    store_path = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store_path)

    def start():
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(port), "服务启动超时"
        return proc

    proc = start()
    base = f"http://127.0.0.1:{port}"

    def post(path, payload=None, headers=None, raw_body=None):
        return _http("POST", base + path, payload=payload,
                     headers=headers, raw_body=raw_body)

    def get(path, headers=None):
        return _http("GET", base + path, headers=headers)

    try:
        SRC = {"X-Tenant-ID": "src-tenant"}
        DST = {"X-Tenant-ID": "dst-tenant"}
        OTHER = {"X-Tenant-ID": "other-tenant"}

        issuer_priv, issuer_pub = _keypair()
        issuer_did = "did:web:receipt-batch-issuer.example"

        st, _, _ = post(ANCHORS_PATH,
                        {"did": issuer_did, "public_key": issuer_pub,
                         "key_version": 1}, SRC)
        assert st == 201, st
        st, _, raw = post("/v1/dids",
                          {"method": "web",
                           "public_key": "receipt-sync-batch-signer"}, SRC)
        assert st == 201, (st, raw)
        did_rec = json.loads(raw)
        signer_did = did_rec["did"]
        signer_pub = did_rec["public_key"]

        with open(store_path, "r", encoding="utf-8") as fh:
            state = json.load(fh)
        signer_priv = state["tenants"]["src-tenant"]["dids"][signer_did][
            "key_history"][0]["private_key_pem"]

        for tenant in (SRC, DST):
            st, _, _ = post(ANCHORS_PATH,
                            {"did": signer_did, "public_key": signer_pub,
                             "key_version": 1}, tenant)
            assert st in (200, 201), st

        for i in range(1, 6):  # 来源侧 5 条消费历史
            body = {
                "credential_id": f"vc_sync_batch_{i:03d}",
                "issuer_did": issuer_did,
                "subject_did": "did:web:subject.example",
                "claims": {"seq": i},
                "issued_at": "2026-09-20T00:00:00Z",
                "issuer_key_version": 1,
            }
            sig = crypto.sign(body, issuer_priv)
            nonce ="sync-batch-nonce-%d" % i
            st, _, raw = post(VERIFY_RECEIPT_PATH,
                              {"body": body, "signature": sig,
                               "verifier_did": signer_did, "nonce": nonce},
                              SRC)
            assert st == 200
            pack = json.loads(raw)
            st, _, raw = post(CONSUME_PATH,
                              {"receipt": pack["receipt"],
                               "receipt_signature": pack["receipt_signature"],
                               "body": body, "signature": sig,
                               "nonce": nonce}, SRC)
            assert st == 200 and json.loads(raw)["valid"] is True, raw

        def export_page(after, limit, snapshot):
            st, _, raw = get(
                f"{EXPORT_PATH}?after={after}&limit={limit}"
                f"&snapshot={snapshot}", headers=SRC)
            assert st == 200, (st, raw)
            return raw.decode("utf-8")

        def manifest_page(after, limit, snapshot):
            st, _, raw = get(
                f"{MANIFEST_PATH}?after={after}&limit={limit}"
                f"&snapshot={snapshot}&signer_did={signer_did}",
                headers=SRC)
            assert st == 200, (st, raw)
            return json.loads(raw)

        def item(manifest_obj, ndjson_text):
            return {"manifest": manifest_obj, "ndjson": ndjson_text}

        def batch(items, headers=DST, **kwargs):
            if kwargs:
                return post(BATCH_PATH, headers=headers, **kwargs)
            return post(BATCH_PATH, {"items": items}, headers=headers)

        nd1 = export_page(0, 2, 2)
        m1 = manifest_page(0, 2, 2)
        nd2 = export_page(2, 3, 5)
        m2 = manifest_page(2, 3, 5)

        # ---------------------------------------------------------- #
        # 1. 请求级非法：200 且恰 {"results":[],"reason":"请求非法"}
        # ---------------------------------------------------------- #
        def expect_bad_request(name, **kwargs):
            st, _, raw = batch(None, **kwargs)
            check(name, st == 200 and json.loads(raw)
                  == {"results": [], "reason": "请求非法"})

        expect_bad_request("空体", raw_body=b"")
        expect_bad_request("非法 JSON", raw_body=b"not-json")
        expect_bad_request("非对象", raw_body=b"[1,2]")
        expect_bad_request("缺 items", payload={})
        expect_bad_request("多余字段",
                           payload={"items": [{"x": 1}], "y": 2})
        expect_bad_request("items 非数组", payload={"items": {}})
        expect_bad_request("items 空数组", payload={"items": []})
        expect_bad_request(
            "items 超过 50 项",
            payload={"items": [{"manifest": {}, "ndjson": ""}] * 51})
        # 恰 50 项为请求级合法（逐项失败不属请求级非法）
        st, _, raw = batch([{"manifest": {}, "ndjson": ""}] * 50)
        r = json.loads(raw)
        check("恰 50 项请求级合法",
              st == 200 and list(r.keys()) == ["results"]
              and len(r["results"]) == 50)

        # 显式空租户头 400
        st, _, _ = post(BATCH_PATH, {"items": []},
                        headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", st == 400)

        # ---------------------------------------------------------- #
        # 2. 混合批：项结构错误 400 不短路，同签名方后项可见前项
        # ---------------------------------------------------------- #
        items = [
            item(m1, nd1),                       # 首次 201
            {"manifest": {}},                    # 缺 ndjson
            {"manifest": {}, "ndjson": 5},       # ndjson 非字符串
            "not-an-object",                     # 项非对象
            {"manifest": "x", "ndjson": ""},     # manifest 非对象
            {"manifest": {}, "ndjson": "", "z": 1},  # 多余键
            item(m2, nd2),                       # 续页 200（可见前项）
        ]
        st, _, raw = batch(items)
        r = json.loads(raw)
        check("顶层 200 且仅含 results",
              st == 200 and list(r.keys()) == ["results"])
        results = r["results"]
        check("results 等长同序", len(results) == 7)
        check("成功项键序", list(results[0].keys()) == OK_KEYS)
        check("首项首次 201",
              results[0] == {"valid": True, "http_status": 201,
                             "signer_did": signer_did, "snapshot": 2,
                             "next_after": 2, "count": 2})
        for idx in (1, 2, 3, 4, 5):
            check(f"项{idx} 结构错误 400 键序",
                  list(results[idx].keys()) == ERR_KEYS)
            check(f"项{idx} 请求项非法",
                  results[idx] == {"valid": False, "http_status": 400,
                                   "reason": "请求项非法"})
        check("后项可见前项（续页 200 追平到 5）",
              results[6] == {"valid": True, "http_status": 200,
                             "signer_did": signer_did, "snapshot": 5,
                             "next_after": 5, "count": 3})

        # ---------------------------------------------------------- #
        # 3. 验真/内容/游标失败项：沿用单条 reason 与状态
        # ---------------------------------------------------------- #
        def resign(manifest_obj, ndjson_text):
            m = copy.deepcopy(manifest_obj)
            m["count"] = ndjson_text.count("\n")
            m["digest"] = hashlib.sha256(
                ndjson_text.encode("utf-8")).hexdigest()
            m["signature"] = crypto.sign(
                {k: m[k] for k in (
                    "snapshot", "filters", "count", "alg", "digest",
                    "signer_did", "key_version")}, signer_priv)
            return m

        bad_manifest = copy.deepcopy(m1)
        bad_manifest.pop("alg")
        bad_sig = copy.deepcopy(m1)
        bad_sig["signature"] = "A" * 86
        illegal_nd = "not-json\n"
        m_illegal = resign(m1, illegal_nd)
        nd_old = export_page(0, 1, 1)
        m_old = manifest_page(0, 1, 1)  # 旧快照倒退 -> 409

        items = [
            item(bad_manifest, nd1),     # 清单非法
            item(bad_sig, nd1),          # 签名校验失败
            item(m1, nd1 + '{"cursor":9}\n'),  # 导出内容不匹配
            item(m_illegal, illegal_nd),  # 导出内容非法
            item(m_old, nd_old),         # 同步游标冲突 409
            item(m2, nd2),               # 同页重放 200（失败项不短路）
        ]
        st, _, raw = batch(items)
        results = json.loads(raw)["results"]
        check("批内清单非法",
              results[0] == {"valid": False, "http_status": 200,
                             "reason": "清单非法"})
        check("批内签名校验失败",
              results[1] == {"valid": False, "http_status": 200,
                             "reason": "签名校验失败"})
        check("批内导出内容不匹配",
              results[2] == {"valid": False, "http_status": 200,
                             "reason": "导出内容不匹配"})
        check("批内导出内容非法",
              results[3] == {"valid": False, "http_status": 200,
                             "reason": "导出内容非法"})
        check("批内游标冲突 409",
              results[4] == {"valid": False, "http_status": 409,
                             "reason": "同步游标冲突"})
        check("失败项后重放仍 200",
              results[5] == {"valid": True, "http_status": 200,
                             "signer_did": signer_did, "snapshot": 5,
                             "next_after": 5, "count": 3})

        # 他租户无 signer 锚点 -> 锚点不可用
        st, _, raw = batch([item(m1, nd1)], headers=OTHER)
        check("批内锚点不可用（他租户）",
              json.loads(raw)["results"][0]
              == {"valid": False, "http_status": 200,
                  "reason": "锚点不可用"})

        # ---------------------------------------------------------- #
        # 4. 同步不写审计
        # ---------------------------------------------------------- #
        st, _, raw = get("/v1/audit?limit=200", headers=DST)
        actions = [e["action"] for e in json.loads(raw)["events"]]
        check("批量同步不写审计", all("receipt" not in a for a in actions))

        # ---------------------------------------------------------- #
        # 5. 租户隔离：他租户首批仍 201
        # ---------------------------------------------------------- #
        st, _, _ = post(ANCHORS_PATH,
                        {"did": signer_did, "public_key": signer_pub,
                         "key_version": 1}, OTHER)
        assert st == 201, st
        st, _, raw = batch([item(m1, nd1)], headers=OTHER)
        check("他租户首批独立 201",
              json.loads(raw)["results"][0]["http_status"] == 201)

        # ---------------------------------------------------------- #
        # 6. 与单条并发同页：合计仅一次 201
        # ---------------------------------------------------------- #
        conc_priv, conc_pub = _keypair()
        conc_signer = "did:web:conc-batch-signer.example"
        st, _, _ = post(ANCHORS_PATH,
                        {"did": conc_signer, "public_key": conc_pub,
                         "key_version": 1}, DST)
        assert st == 201, st
        conc_nd = (
            json.dumps(
                {"cursor": 1, "receipt_id": "d" * 64,
                 "verifier_did": "did:web:conc-batch-verifier.example",
                 "nonce": "c1", "consumed_at": "2026-09-20T00:00:00Z"},
                separators=(",", ":"), ensure_ascii=False) + "\n"
        )
        conc_manifest = {
            "snapshot": 1,
            "filters": {"after": 0, "limit": 1000},
            "count": 1,
            "alg": "SHA-256",
            "digest": hashlib.sha256(conc_nd.encode("utf-8")).hexdigest(),
            "signer_did": conc_signer,
            "key_version": 1,
        }
        conc_manifest["signature"] = crypto.sign(
            {k: conc_manifest[k] for k in (
                "snapshot", "filters", "count", "alg", "digest",
                "signer_did", "key_version")}, conc_priv)

        def call_single(_):
            st, _, _ = post(SYNC_PATH,
                            {"manifest": conc_manifest, "ndjson": conc_nd},
                            headers=DST)
            return st

        def call_batch(_):
            st, _, raw = batch([item(conc_manifest, conc_nd)])
            assert st == 200
            return json.loads(raw)["results"][0]["http_status"]

        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            codes = list(pool.map(
                lambda i: call_single(i) if i % 2 == 0 else call_batch(i),
                range(16)))
        check("与单条并发同页仅一次 201",
              codes.count(201) == 1 and codes.count(200) == 15)

        # ---------------------------------------------------------- #
        # 7. 跨重启：检查点保持，重放 200、旧快照仍 409
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, _, raw = batch([item(m2, nd2), item(m_old, nd_old)])
        results = json.loads(raw)["results"]
        check("重启后重放 200",
              results[0]["valid"] is True
              and results[0]["http_status"] == 200
              and results[0]["next_after"] == 5)
        check("重启后旧快照仍 409",
              results[1] == {"valid": False, "http_status": 409,
                             "reason": "同步游标冲突"})

    finally:
        proc.terminate()
        proc.wait(timeout=10)
        if os.path.exists(store_path):
            os.remove(store_path)

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
