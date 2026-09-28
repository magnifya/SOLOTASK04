#!/usr/bin/env python3
"""只读消费历史
GET /v1/trust/credential-status/receipt-sync/receipt/consumptions
的端到端测试。

直接运行：
python3 tests/trust_credential_status_receipt_sync_receipt_consumptions_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import hashlib
import json
import os
import re
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

UTC_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

SYNC_PATH = "/v1/trust/credential-status/receipt-sync"
RECEIPT_PATH = "/v1/trust/credential-status/receipt-sync/receipt"
CONSUME_PATH = "/v1/trust/credential-status/receipt-sync/receipt/consume"
BATCH_PATH = (
    "/v1/trust/credential-status/receipt-sync/receipt/consume-batch"
)
LIST_PATH = (
    "/v1/trust/credential-status/receipt-sync/receipt/consumptions"
)
ANCHORS_PATH = "/v1/trust/anchors"
DIDS_PATH = "/v1/dids"


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


ROW_VERIFIER_DID = "did:web:cssrchist-row-verifier.example"


def make_row(cursor, index):
    return {
        "cursor": cursor,
        "receipt_id": f"rcpt-cssrchist-{index:055d}",
        "verifier_did": ROW_VERIFIER_DID,
        "nonce": f"cssrchist-row-nonce-{index:03d}",
        "consumed_at": "2099-01-01T00:00:00Z",
    }


def to_ndjson(rows):
    return "".join(
        json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n"
        for row in rows
    )


def main():
    port = 9079
    store = tempfile.mktemp(suffix=".json")
    proc = start_server(port, store)
    base = f"http://127.0.0.1:{port}"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def post(path, payload=None, headers=None, raw=None):
        return _http("POST", base + path, payload=payload,
                     headers=headers, raw=raw)

    def get(path, headers=None):
        return _http("GET", base + path, headers=headers)

    def listing(qs="", headers=None):
        return get(f"{LIST_PATH}{qs}", headers=headers)

    def consumed_audits(headers):
        st, r = get("/v1/audit?limit=200", headers=headers)
        assert st == 200
        return [e for e in r["events"]
                if e["action"]
                == "trust.credential.status.sync.receipt.consumed"]

    def expect_400_exact(name, qs="", headers=None):
        st, r = listing(qs, headers=headers)
        check(name, st == 400 and r == {"error": "请求非法"})

    try:
        T1 = {"X-Tenant-ID": "cssrchist-a"}
        T2 = {"X-Tenant-ID": "cssrchist-b"}

        # 空历史：200 恰返 events、next_after
        st, r = listing(headers=T1)
        check("空历史 -> 200", st == 200)
        check("空历史键序恰为 events,next_after 且空页 next_after=0",
              list(r.keys()) == ["events", "next_after"]
              and r["events"] == [] and r["next_after"] == 0)

        # 查询参数非法 -> 400 恰返 {"error":"请求非法"}
        expect_400_exact("未知参数 -> 400", "?foo=1")
        expect_400_exact("重复 limit -> 400", "?limit=1&limit=2")
        expect_400_exact("重复 after -> 400", "?after=0&after=1")
        expect_400_exact("重复 verifier_did -> 400",
                         "?verifier_did=a&verifier_did=b")
        expect_400_exact("空 limit -> 400", "?limit=")
        expect_400_exact("空 after -> 400", "?after=")
        expect_400_exact("空 verifier_did -> 400", "?verifier_did=")
        expect_400_exact("limit=0 -> 400", "?limit=0")
        expect_400_exact("limit=201 -> 400", "?limit=201")
        expect_400_exact("limit=-1 -> 400", "?limit=-1")
        expect_400_exact("limit=1.0 -> 400", "?limit=1.0")
        expect_400_exact("limit=true -> 400", "?limit=true")
        expect_400_exact("limit 含空白 -> 400", "?limit=%201")
        expect_400_exact("limit Unicode 数字 -> 400",
                         "?limit=%E0%A5%91")
        expect_400_exact("limit 超长 -> 400", "?limit=" + "9" * 5000)
        expect_400_exact("after=-1 -> 400", "?after=-1")
        expect_400_exact("after=+1 -> 400", "?after=%2B1")
        expect_400_exact("after 含空白 -> 400", "?after=%20")
        expect_400_exact("after 小数 -> 400", "?after=1.5")
        expect_400_exact("after Unicode 数字 -> 400",
                         "?after=%E0%A5%91")
        expect_400_exact("after 超长 -> 400", "?after=" + "9" * 5000)

        # 显式空租户头 400（由统一路由处理）
        st, r = listing(headers={"X-Tenant-ID": ""})
        check("显式空租户头 -> 400 仅 {error} 单键",
              st == 400 and set(r.keys()) == {"error"}
              and isinstance(r["error"], str) and r["error"])

        # ---- 准备同步来源签名锚点（status 用途）----
        signer_priv, signer_pub = gen_keypair()
        signer_did = "did:web:cssrchist-signer.example"
        st, _ = post(ANCHORS_PATH,
                     {"did": signer_did, "public_key": signer_pub,
                      "key_version": 1,
                      "uses": ["generic", "status"]}, T1)
        assert st in (200, 201), st

        def signed_manifest(snapshot, after, ndjson):
            manifest = {
                "snapshot": snapshot,
                "filters": {"after": after, "limit": 1000},
                "count": ndjson.count("\n"),
                "alg": "SHA-256",
                "digest": hashlib.sha256(
                    ndjson.encode("utf-8")).hexdigest(),
                "signer_did": signer_did,
                "key_version": 1,
            }
            manifest["signature"] = crypto.sign(
                {k: manifest[k] for k in (
                    "snapshot", "filters", "count", "alg", "digest",
                    "signer_did", "key_version")}, signer_priv)
            return manifest

        def sync_page(cursors, after, snapshot):
            rows = [make_row(c, c) for c in cursors]
            ndjson = to_ndjson(rows)
            st, r = post(SYNC_PATH,
                         {"manifest": signed_manifest(snapshot, after,
                                                      ndjson),
                          "ndjson": ndjson}, T1)
            assert st in (200, 201), (st, r)
            return ndjson

        ndjson1 = sync_page([1, 2, 3], 0, 3)

        # ---- 两个本地验证者 DID（托管私钥）并注册 status 锚点 ----
        verifiers = []
        for handle in ("cssrchist-verifier-a", "cssrchist-verifier-b"):
            st, rec = post(DIDS_PATH,
                           {"method": "web", "public_key": handle}, T1)
            assert st == 201, (st, rec)
            v_did = rec["did"]
            st, _ = post(ANCHORS_PATH,
                         {"did": v_did, "public_key": rec["public_key"],
                          "key_version": rec["key_version"],
                          "uses": ["generic", "status"]}, T1)
            assert st in (200, 201), st
            verifiers.append((v_did, handle))

        def make_item(verifier_did, nonce):
            qs = urllib.parse.urlencode(
                {"signer_did": signer_did, "verifier_did": verifier_did,
                 "nonce": nonce})
            st, issued = get(f"{RECEIPT_PATH}?{qs}", headers=T1)
            assert st == 200, (st, issued)
            return {"receipt": issued["receipt"],
                    "signature": issued["signature"],
                    "ndjson": ndjson1, "nonce": nonce}

        def receipt_id_of(item):
            return hashlib.sha256(
                crypto.canonicalize(item["receipt"])
            ).hexdigest()

        va, vb = verifiers[0][0], verifiers[1][0]
        item1 = make_item(va, "n-1")
        item2 = make_item(vb, "n-2")
        item3 = make_item(va, "n-3")
        item4 = make_item(vb, "n-4")

        st, r = post(CONSUME_PATH, item1, headers=T1)
        check("单条消费 item1 成功", st == 200 and r.get("valid") is True)
        st, r = post(CONSUME_PATH, item2, headers=T1)
        check("单条消费 item2 成功", st == 200 and r.get("valid") is True)
        st, r = post(BATCH_PATH, {"items": [item3, item4]}, headers=T1)
        check("批量消费 item3/item4 成功",
              st == 200
              and [x.get("valid") for x in r.get("results", [])]
              == [True, True])

        want_ids = [receipt_id_of(x) for x in (item1, item2, item3, item4)]

        # 全量查询
        st, r = listing("?limit=200", headers=T1)
        check("全量查询 -> 200", st == 200)
        check("响应键序 events,next_after",
              list(r.keys()) == ["events", "next_after"])
        events = r["events"]
        check("四条消费事件", len(events) == 4)
        check("事件键序恰为 cursor,receipt_id,verifier_did,nonce,consumed_at",
              all(list(e.keys()) == ["cursor", "receipt_id",
                                    "verifier_did", "nonce", "consumed_at"]
                  for e in events))
        check("cursor 为正整数且按升序连续 1..4",
              [e["cursor"] for e in events] == [1, 2, 3, 4])
        check("receipt_id 依次匹配",
              [e["receipt_id"] for e in events] == want_ids)
        check("验证者依次为 A,B,A,B（跨验证者共享游标）",
              [e["verifier_did"] for e in events]
              == [va, vb, va, vb])
        check("nonce 依次为 n-1..n-4",
              [e["nonce"] for e in events] == ["n-1", "n-2", "n-3", "n-4"])
        check("consumed_at 均为 UTC 秒精度 Z 非空字符串",
              all(isinstance(e["consumed_at"], str)
                  and UTC_Z_RE.fullmatch(e["consumed_at"])
                  for e in events))
        check("receipt_id 均为 64 位小写 hex",
              all(SHA256_HEX_RE.fullmatch(e["receipt_id"]) for e in events))
        check("next_after 为末项 cursor=4", r["next_after"] == 4)

        # verifier_did 精确过滤
        st, r = listing(f"?limit=200&verifier_did={va}", headers=T1)
        ev_a = r["events"]
        check("verifier_a 过滤得两条且 cursor 为 1,3",
              st == 200 and [e["cursor"] for e in ev_a] == [1, 3]
              and all(e["verifier_did"] == va for e in ev_a))
        check("过滤后 next_after=3", r["next_after"] == 3)
        st, r = listing("?verifier_did=did:web:nobody.example",
                        headers=T1)
        check("无匹配验证者 -> 空页 next_after=0",
              st == 200 and r["events"] == [] and r["next_after"] == 0)

        # 分页：limit=2
        st, p1 = listing("?limit=2", headers=T1)
        check("第一页两条 next_after=2",
              st == 200 and [e["cursor"] for e in p1["events"]] == [1, 2]
              and p1["next_after"] == 2)
        st, p2 = listing(f"?limit=2&after={p1['next_after']}", headers=T1)
        check("第二页两条 next_after=4",
              st == 200 and [e["cursor"] for e in p2["events"]] == [3, 4]
              and p2["next_after"] == 4)
        st, p3 = listing(f"?limit=2&after={p2['next_after']}", headers=T1)
        check("空页 next_after 保持 after=4",
              st == 200 and p3["events"] == [] and p3["next_after"] == 4)

        # 过滤 + 分页 + 排序
        st, r = listing(f"?after=1&verifier_did={va}", headers=T1)
        check("after=1 + verifier_a 仅得 cursor=3",
              [e["cursor"] for e in r["events"]] == [3]
              and r["next_after"] == 3)

        # 缺省 limit=50 / after=0
        st, r = listing(headers=T1)
        check("缺省参数等价 limit=50/after=0，仍为四条",
              st == 200 and [e["cursor"] for e in r["events"]]
              == [1, 2, 3, 4] and r["next_after"] == 4)

        # 纯只读：查询不追加审计、不改状态
        audits_before = consumed_audits(T1)
        st1, r1 = listing("?limit=1", headers=T1)
        st2, r2 = listing("?limit=1", headers=T1)
        check("重复只读查询结果一致", r1 == r2 and st1 == st2 == 200)
        check("查询不记消费审计",
              consumed_audits(T1) == audits_before)

        # 重放不追加历史
        st, r = post(CONSUME_PATH, item1, headers=T1)
        check("重放返回状态同步回执已消费",
              st == 200 and r == {
                  "valid": False, "reason": "状态同步回执已消费"})
        st, r = listing("?limit=200", headers=T1)
        check("重放不追加历史事件",
              st == 200 and len(r["events"]) == 4
              and [e["cursor"] for e in r["events"]] == [1, 2, 3, 4])

        # 验真失败不追加：错误签名消费新 nonce
        bad = make_item(va, "n-bad")
        bad["signature"] = "!!!"
        st, r = post(CONSUME_PATH, bad, headers=T1)
        check("签名格式错误 -> 200 valid:false",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "签名格式错误")
        st, r = listing("?limit=200", headers=T1)
        check("验真失败不追加历史",
              len(r["events"]) == 4
              and all(e["nonce"] != "n-bad" for e in r["events"]))

        # 游标空间独立于普通凭证状态同步回执消费历史
        st, r = get(
            "/v1/trust/credential-status/receipt/consumptions?limit=200",
            headers=T1)
        check("普通凭证状态回执消费历史为空（游标空间隔离）",
              st == 200 and r["events"] == [])

        # 租户隔离：T2 独立游标、空历史
        st, r = listing(headers=T2)
        check("租户 B 初始空历史",
              st == 200 and r["events"] == [] and r["next_after"] == 0)
        # T2 注册同名验证者锚点并消费同键，互不影响。
        st, rec = post(DIDS_PATH,
                       {"method": "web",
                        "public_key": "cssrchist-verifier-a"}, T2)
        assert st == 201
        st, _ = post(ANCHORS_PATH,
                     {"did": rec["did"], "public_key": rec["public_key"],
                      "key_version": rec["key_version"],
                      "uses": ["generic", "status"]}, T2)
        assert st in (200, 201)
        # T2 无同步来源，GET receipt 404；改用直接验真失败路径验证隔离：
        # T1 同键在 T2 锚点下验真必失败（锚点不可用），不消费。
        st, r = post(CONSUME_PATH, item1, headers=T2)
        check("租户 B 同键验真失败（锚点不可用）",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "锚点不可用")
        st, r = listing(headers=T2)
        check("租户 B 仍为空历史",
              st == 200 and r["events"] == [])
        st, r = listing("?limit=200", headers=T1)
        check("租户 A 历史不受租户 B 影响",
              [e["cursor"] for e in r["events"]] == [1, 2, 3, 4])

        # ---- 旧记录补录：删除新结构后重启，按
        # (consumed_at, verifier_did, nonce) 稳定补录，游标重启不变 ----
        proc.terminate()
        proc.wait(timeout=10)
        with open(store, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        for bucket in raw.get("tenants", {}).values():
            bucket.pop(
                "credential_status_sync_receipt_consumption_events", None
            )
        raw.pop(
            "credential_status_sync_receipt_consumption_cursors", None
        )
        with open(store, "w", encoding="utf-8") as fh:
            json.dump(raw, fh, ensure_ascii=False, indent=2,
                      sort_keys=True)

        proc = start_server(port, store)

        def backfill_snapshot(headers):
            st, r = listing("?limit=200", headers=headers)
            assert st == 200
            return [
                (e["cursor"], e["receipt_id"], e["verifier_did"],
                 e["nonce"], e["consumed_at"])
                for e in r["events"]
            ], r["next_after"]

        snap1, na1 = backfill_snapshot(T1)
        check("补录后租户 A 仍为四条", len(snap1) == 4)
        check("补录 cursor 连续 1..4",
              [row[0] for row in snap1] == [1, 2, 3, 4])
        check("补录 next_after=4", na1 == 4)
        check("补录 receipt_id 集合一致",
              sorted(row[1] for row in snap1) == sorted(want_ids))
        check("补录 (verifier_did,nonce) 集合一致",
              sorted((row[2], row[3]) for row in snap1)
              == sorted([(va, "n-1"), (vb, "n-2"),
                         (va, "n-3"), (vb, "n-4")]))
        check("补录 consumed_at 均为 UTC 秒精度 Z",
              all(UTC_Z_RE.fullmatch(row[4]) for row in snap1))

        # 再次重启：补录结果稳定（cursor 不变）
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server(port, store)
        snap2, na2 = backfill_snapshot(T1)
        check("重启后补录 cursor 与顺序不变", snap2 == snap1 and na2 == na1)

        # 补录后新消费继续在既有 cursor 之上递增
        item5 = make_item(va, "n-5")
        st, r = post(CONSUME_PATH, item5, headers=T1)
        check("补录后新消费成功", st == 200 and r.get("valid") is True)
        st, r = listing("?limit=200", headers=T1)
        check("补录后新事件 cursor=5",
              [e["cursor"] for e in r["events"]] == [1, 2, 3, 4, 5]
              and r["events"][-1]["nonce"] == "n-5")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
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
    raise SystemExit(main())
