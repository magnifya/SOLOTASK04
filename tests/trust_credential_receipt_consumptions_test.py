#!/usr/bin/env python3
"""只读验真回执消费历史 GET /v1/trust/credentials/receipt/consumptions 的端到端测试。

直接运行：python3 tests/trust_credential_receipt_consumptions_test.py
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


def main():
    port = 8997
    store = tempfile.mktemp(suffix=".json")
    proc = start_server(port, store)
    base = f"http://127.0.0.1:{port}"
    path = "/v1/trust/credentials/receipt/consumptions"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def query(qs="", headers=None):
        url = f"{base}{path}" + (f"?{qs}" if qs else "")
        return _http("GET", url, headers=headers)

    T1 = {"X-Tenant-ID": "rh-a"}
    T2 = {"X-Tenant-ID": "rh-b"}

    try:
        # ---- 1. 查询参数合法性：一律 400 且仅 {error: 非空中文} ----
        def expect_400(name, qs, headers=T1):
            st, r = query(qs, headers=headers)
            check(name,
                  st == 400 and set(r.keys()) == {"error"}
                  and isinstance(r["error"], str) and r["error"])

        expect_400("未知参数 -> 400", "foo=1")
        expect_400("limit 重复 -> 400", "limit=1&limit=2")
        expect_400("after 重复 -> 400", "after=1&after=2")
        expect_400("verifier_did 重复 -> 400",
                   "verifier_did=a&verifier_did=b")
        expect_400("limit 空值 -> 400", "limit=")
        expect_400("limit 裸键 -> 400", "limit")
        expect_400("limit 为 0 -> 400", "limit=0")
        expect_400("limit 为 201 -> 400", "limit=201")
        expect_400("limit 负数 -> 400", "limit=-1")
        expect_400("limit 小数 -> 400", "limit=1.5")
        expect_400("limit 空白 -> 400", "limit=%20")
        expect_400("limit Unicode 数字 -> 400", "limit=%D9%A5")
        expect_400("after 空值 -> 400", "after=")
        expect_400("after 负数 -> 400", "after=-1")
        expect_400("after 非数字 -> 400", "after=abc")
        expect_400("verifier_did 空值 -> 400", "verifier_did=")
        expect_400("显式空租户头 -> 400", "", headers={"X-Tenant-ID": ""})

        # ---- 2. 空历史：200 恰返 events、next_after ----
        st, r = query()
        check("空历史缺省查询 -> 200 恰返 events,next_after",
              st == 200 and list(r.keys()) == ["events", "next_after"]
              and r["events"] == [] and r["next_after"] == 0)
        st, r = query("after=7&limit=3")
        check("空页 next_after 保持 after",
              st == 200 and r["events"] == [] and r["next_after"] == 7)

        # ---- 3. 准备两个验证者并消费三张回执（单条 + 批量） ----
        issuer_priv, issuer_pub = gen_keypair()
        issuer_did = "did:web:issuer.example"
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": issuer_did, "public_key": issuer_pub,
             "key_version": 1},
            headers=T1,
        )
        check("注册外部签发者锚点 -> 201", st == 201)

        ver_priv, ver_pub = gen_keypair()
        verifier_a = "did:web:verifier-a.example"
        verifier_b = "did:web:verifier-b.example"
        for did in (verifier_a, verifier_b):
            st, _ = _http(
                "POST", f"{base}/v1/trust/anchors",
                {"did": did, "public_key": ver_pub, "key_version": 1},
                headers=T1,
            )
            check(f"注册验证者锚点 {did} -> 201", st == 201)

        body = {
            "credential_id": "vc_rh_0001",
            "issuer_did": issuer_did,
            "subject_did": "did:web:subject.example",
            "claims": {"role": "admin"},
            "issued_at": "2026-09-21T00:00:00Z",
            "issuer_key_version": 1,
        }
        sig = crypto.sign(body, issuer_priv)

        def make_item(verifier_did, nonce):
            rcpt = {
                "credential_id": body["credential_id"],
                "issuer_did": issuer_did,
                "issuer_key_version": 1,
                "credential_digest": hashlib.sha256(
                    crypto.canonicalize({"body": body, "signature": sig})
                ).hexdigest(),
                "verifier_did": verifier_did,
                "verifier_key_version": 1,
                "nonce": nonce,
            }
            return {
                "receipt": rcpt,
                "receipt_signature": crypto.sign(rcpt, ver_priv),
                "body": body,
                "signature": sig,
                "nonce": nonce,
            }

        item_a1 = make_item(verifier_a, "nonce-史-001")
        st, r = _http(
            "POST", f"{base}/v1/trust/credentials/receipt/consume",
            item_a1, headers=T1,
        )
        check("单条首次消费 -> 200 valid", st == 200 and r.get("valid"))
        rid_a1 = r["receipt_id"]

        item_b1 = make_item(verifier_b, "nonce-史-002")
        item_a2 = make_item(verifier_a, "nonce-史-003")
        st, r = _http(
            "POST", f"{base}/v1/trust/credentials/receipt/consume-batch",
            {"items": [item_b1, item_a2]}, headers=T1,
        )
        check("批量两项首次消费 -> 全部 valid",
              st == 200 and all(x.get("valid") for x in r["results"]))
        rid_b1 = r["results"][0]["receipt_id"]
        rid_a2 = r["results"][1]["receipt_id"]

        # 重放与验真失败不追加历史
        st, r = _http(
            "POST", f"{base}/v1/trust/credentials/receipt/consume",
            item_a1, headers=T1,
        )
        check("重放 -> 回执已消费",
              st == 200 and r == {"valid": False, "reason": "回执已消费"})
        bad = dict(item_a2, nonce="其他nonce")
        st, r = _http(
            "POST", f"{base}/v1/trust/credentials/receipt/consume",
            bad, headers=T1,
        )
        check("验真失败 -> nonce错误",
              st == 200 and r.get("reason") == "nonce错误")

        # ---- 4. 全量列表：cursor 1..3 升序、键序与类型 ----
        st, r = query(headers=T1)
        check("三次消费后恰三条事件",
              st == 200 and len(r["events"]) == 3)
        evs = r["events"]
        check("事件键序恰为 cursor,receipt_id,verifier_did,nonce,consumed_at",
              all(list(e.keys()) == ["cursor", "receipt_id", "verifier_did",
                                     "nonce", "consumed_at"] for e in evs))
        check("cursor 为正整数且按 1,2,3 升序",
              [e["cursor"] for e in evs] == [1, 2, 3]
              and all(isinstance(e["cursor"], int) for e in evs))
        check("事件内容按消费顺序对应",
              [e["receipt_id"] for e in evs] == [rid_a1, rid_b1, rid_a2]
              and [e["verifier_did"] for e in evs]
              == [verifier_a, verifier_b, verifier_a]
              and [e["nonce"] for e in evs]
              == ["nonce-史-001", "nonce-史-002", "nonce-史-003"])
        check("consumed_at 为 UTC 秒精度 Z 字符串",
              all(isinstance(e["consumed_at"], str)
                  and UTC_Z_RE.fullmatch(e["consumed_at"]) for e in evs))
        check("重放与验真失败不追加历史", len(evs) == 3)
        check("末页 next_after 为末项 cursor", r["next_after"] == 3)

        # ---- 5. verifier_did 精确过滤 ----
        st, r = query(f"verifier_did={verifier_a}", headers=T1)
        check("按 verifier_did 过滤 -> 仅该验证者两条",
              st == 200 and len(r["events"]) == 2
              and all(e["verifier_did"] == verifier_a for e in r["events"])
              and r["next_after"] == 3)
        st, r = query("verifier_did=did:web:nobody", headers=T1)
        check("未知 verifier_did -> 空页", st == 200 and r["events"] == [])

        # ---- 6. 分页：limit/after/next_after ----
        st, r = query("limit=2", headers=T1)
        check("limit=2 -> 前两项，next_after=2",
              st == 200 and [e["cursor"] for e in r["events"]] == [1, 2]
              and r["next_after"] == 2)
        st, r = query("after=2", headers=T1)
        check("after=2 -> 仅第三项，next_after=3",
              st == 200 and [e["cursor"] for e in r["events"]] == [3]
              and r["next_after"] == 3)
        st, r = query("after=3", headers=T1)
        check("after=3 -> 空页 next_after=3",
              st == 200 and r["events"] == [] and r["next_after"] == 3)
        st, r = query("limit=1&after=1", headers=T1)
        check("limit=1&after=1 -> 仅第二项",
              st == 200 and [e["cursor"] for e in r["events"]] == [2]
              and r["next_after"] == 2)
        st, r = query(f"after=1&verifier_did={verifier_a}", headers=T1)
        check("过滤后再分页 -> 仅 cursor=3",
              st == 200 and [e["cursor"] for e in r["events"]] == [3])

        # ---- 7. 租户隔离与缺省租户 ----
        st, r = query(headers=T2)
        check("他租户看不到消费历史",
              st == 200 and r["events"] == [] and r["next_after"] == 0)
        st, r = query()
        check("缺省租户头按 default 隔离为空",
              st == 200 and r["events"] == [])

        # ---- 8. 查询不写状态或审计 ----
        st, ra = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        audits_before = len(ra["events"])
        for _ in range(3):
            query("limit=2", headers=T1)
            query(f"verifier_did={verifier_a}", headers=T1)
        st, ra = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("查询不新增审计", len(ra["events"]) == audits_before)

        # ---- 9. 重启：游标与历史保持，新消费续增 ----
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server(port, store)
        st, r = query(headers=T1)
        check("重启后历史与游标不变",
              st == 200
              and [e["cursor"] for e in r["events"]] == [1, 2, 3]
              and r["next_after"] == 3)
        item_b2 = make_item(verifier_b, "nonce-史-004")
        st, r = _http(
            "POST", f"{base}/v1/trust/credentials/receipt/consume",
            item_b2, headers=T1,
        )
        check("重启后新消费成功", st == 200 and r.get("valid") is True)
        st, r = query(headers=T1)
        check("新消费分配递增 cursor=4",
              st == 200 and [e["cursor"] for e in r["events"]]
              == [1, 2, 3, 4])

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 10. 旧记录稳定补录：旧状态文件无消费历史 ----
    legacy_store = tempfile.mktemp(suffix=".json")
    legacy = {
        "tenants": {
            "rh-old": {
                "consumed_receipts": {
                    "did:web:ver-b": {
                        "n2": {"receipt_id": "r" * 64,
                               "consumed_at": "2026-09-20T00:00:02Z"},
                        "n1": {"receipt_id": "q" * 64,
                               "consumed_at": "2026-09-20T00:00:01Z"},
                    },
                    "did:web:ver-a": {
                        "n9": {"receipt_id": "p" * 64,
                               "consumed_at": "2026-09-20T00:00:01Z"},
                    },
                }
            }
        },
        "audit": [],
        "audit_seq": 0,
    }
    with open(legacy_store, "w", encoding="utf-8") as fh:
        json.dump(legacy, fh)
    proc = start_server(port, legacy_store)
    try:
        st, r = query(headers={"X-Tenant-ID": "rh-old"})
        evs = r["events"]
        # 按（consumed_at、verifier_did、nonce）升序补录：
        # (…01, ver-a, n9) -> (…01, ver-b, n1) -> (…02, ver-b, n2)
        check("旧记录按 consumed_at,verifier_did,nonce 稳定补录",
              st == 200
              and [(e["cursor"], e["verifier_did"], e["nonce"])
                   for e in evs]
              == [(1, "did:web:ver-a", "n9"),
                  (2, "did:web:ver-b", "n1"),
                  (3, "did:web:ver-b", "n2")]
              and [e["receipt_id"] for e in evs]
              == ["p" * 64, "q" * 64, "r" * 64])
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server(port, legacy_store)
        st, r = query(headers={"X-Tenant-ID": "rh-old"})
        check("重启后补录游标不变",
              st == 200
              and [e["cursor"] for e in r["events"]] == [1, 2, 3])
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        for p in (store, legacy_store):
            if os.path.isdir(p):
                shutil.rmtree(p)
            elif os.path.exists(p):
                os.unlink(p)

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
