#!/usr/bin/env python3
"""只读消费历史
GET /v1/trust/credential-status/receipt-sync/receipt/consumptions
的端到端测试。

直接运行：
python3 tests/trust_credential_status_receipt_sync_receipt_consumptions_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 400：空值、重复、未知参数、符号/小数/空白/布尔词、Unicode 数字、
  超长、越界（limit=0/201），均仅 {"error":"请求非法"}；显式空租户头
  400 且仅固定文案；
- 200 键序恰为 events、next_after；事件键序恰为 cursor、receipt_id、
  verifier_did、nonce、consumed_at；cursor 为正整数，余项非空字符串，
  consumed_at UTC 秒精度 Z；
- 单条与批量首次消费在租户内跨验证者共享持久递增 cursor；重放、批内
  判重与验真失败不追加；查询不记审计；
- verifier_did 精确过滤、cursor>after 升序前 limit 项；空页
  next_after=after，否则取末项 cursor；缺省 limit=50/after=0；
- 租户隔离、重启 cursor 不变；旧记录按
  (consumed_at, verifier_did, nonce) 升序补录且重启稳定；
- 与凭证状态同步签名回执消费历史游标空间相互独立。
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
from vcbackend.store import VCStore  # noqa: E402

UTC_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

SYNC_PATH = "/v1/trust/credential-status/receipt-sync"
RECEIPT_PATH = "/v1/trust/credential-status/receipt-sync/receipt"
CONSUME_PATH = "/v1/trust/credential-status/receipt-sync/receipt/consume"
CONSUME_BATCH_PATH = (
    "/v1/trust/credential-status/receipt-sync/receipt/consume-batch"
)
LIST_PATH = (
    "/v1/trust/credential-status/receipt-sync/receipt/consumptions"
)
SIBLING_LIST_PATH = "/v1/trust/credential-status/receipt/consumptions"
ANCHORS_PATH = "/v1/trust/anchors"
DIDS_PATH = "/v1/dids"

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


def _http(method, url, payload=None, headers=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw.decode() or "{}"), raw
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, json.loads(raw.decode() or "{}"), raw


def wait_up(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/health"
            )
            urllib.request.urlopen(req)
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


ROW_VERIFIER_DID = "did:web:cs-sync-rcpt-list-verifier.example"


def make_row(cursor, index):
    return {
        "cursor": cursor,
        "receipt_id": f"rcpt-sync-list-{index:055d}",
        "verifier_did": ROW_VERIFIER_DID,
        "nonce": f"cs-sync-rcpt-list-nonce-{index:03d}",
        "consumed_at": "2099-01-01T00:00:00Z",
    }


def to_ndjson(rows):
    return "".join(
        json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n"
        for row in rows
    )


def main():
    port = 9142
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

    def post(path, payload=None, headers=None):
        return _http("POST", base + path, payload=payload, headers=headers)

    def get(path, headers=None):
        return _http("GET", base + path, headers=headers)

    try:
        TENANT = {"X-Tenant-ID": "cs-sync-rcpt-list-tenant"}
        OTHER = {"X-Tenant-ID": "cs-sync-rcpt-list-other"}

        # ---------------------------------------------------------- #
        # 空租户与空页
        # ---------------------------------------------------------- #
        st, body, _ = get(LIST_PATH, headers=TENANT)
        check("无事件 200 空页", st == 200 and body == {
            "events": [], "next_after": 0})

        st, body, _ = get(f"{LIST_PATH}?after=7", headers=TENANT)
        check("空页 next_after 保持 after",
              st == 200 and body == {"events": [], "next_after": 7})

        # ---------------------------------------------------------- #
        # 400：仅 {"error":"请求非法"}
        # ---------------------------------------------------------- #
        def expect_400(name, qs="", headers=None):
            st, body, _ = get(f"{LIST_PATH}{qs}", headers=headers)
            check(name, st == 400 and body == {"error": "请求非法"})

        expect_400("未知参数 -> 400", "?unknown=1")
        expect_400("重复 limit -> 400", "?limit=1&limit=2")
        expect_400("重复 after -> 400", "?after=0&after=1")
        expect_400("重复 verifier_did -> 400",
                   "?verifier_did=a&verifier_did=b")
        expect_400("空 limit -> 400", "?limit=")
        expect_400("空 after -> 400", "?after=")
        expect_400("空 verifier_did -> 400", "?verifier_did=")
        expect_400("limit=0 -> 400", "?limit=0")
        expect_400("limit=201 -> 400", "?limit=201")
        expect_400("limit=-1 -> 400", "?limit=-1")
        expect_400("limit=1.0 -> 400", "?limit=1.0")
        expect_400("limit=true -> 400", "?limit=true")
        expect_400("limit 含空白 -> 400", "?limit=%201")
        expect_400("limit 含正号 -> 400", "?limit=%2B1")
        expect_400("limit Unicode 数字 -> 400", "?limit=%E0%A5%91")
        expect_400("limit 超长 -> 400", "?limit=" + "9" * 5000)
        expect_400("after=-1 -> 400", "?after=-1")
        expect_400("after=1.0 -> 400", "?after=1.0")
        expect_400("after Unicode 数字 -> 400", "?after=%E0%A5%91")
        expect_400("after 超长 -> 400", "?after=" + "9" * 5000)
        # 显式空租户头 400（由统一路由处理）。
        st, body, _ = get(LIST_PATH, headers={"X-Tenant-ID": ""})
        check("显式空租户头 -> 400 仅 error 单键",
              st == 400 and set(body.keys()) == {"error"}
              and isinstance(body["error"], str) and body["error"])

        # ---------------------------------------------------------- #
        # 准备：锚点、同步页、receipt、两次首次消费
        # ---------------------------------------------------------- #
        signer_priv, signer_pub = _keypair()
        signer_did = "did:web:cs-sync-rcpt-list-signer.example"
        st, _, _ = post(ANCHORS_PATH,
                        {"did": signer_did, "public_key": signer_pub,
                         "key_version": 1,
                         "uses": ["generic", "status"]}, TENANT)
        assert st in (200, 201), st

        st, raw, _ = post(DIDS_PATH,
                          {"method": "web",
                           "public_key": "credential-status-sync-rcpt-list"},
                          TENANT)
        assert st == 201, (st, raw)
        verifier_rec = raw
        verifier_did = verifier_rec["did"]
        verifier_pub = verifier_rec["public_key"]

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
            st, r, _ = post(SYNC_PATH,
                            {"manifest": signed_manifest(
                                snapshot, after, ndjson),
                             "ndjson": ndjson}, TENANT)
            assert st in (200, 201), (st, r)
            return ndjson

        def get_receipt(nonce):
            qs = urllib.parse.urlencode(
                {"signer_did": signer_did,
                 "verifier_did": verifier_did, "nonce": nonce})
            st, r, _ = get(f"{RECEIPT_PATH}?{qs}", headers=TENANT)
            assert st == 200, (st, r)
            return r["receipt"], r["signature"]

        ndjson1 = sync_page([1, 2, 3], 0, 3)
        nonce = "nonce-sync-list-一"
        receipt, signature = get_receipt(nonce)
        key_version = receipt["verifier_key_version"]
        st, _, _ = post(ANCHORS_PATH,
                        {"did": verifier_did, "public_key": verifier_pub,
                         "key_version": key_version,
                         "uses": ["generic", "status"]}, TENANT)
        assert st in (200, 201), st

        good = {"receipt": receipt, "signature": signature,
                "ndjson": ndjson1, "nonce": nonce}
        st, r1, _ = post(CONSUME_PATH, good, TENANT)
        assert st == 200 and r1["valid"] is True, (st, r1)

        # 重放不追加。
        st, rr, _ = post(CONSUME_PATH, good, TENANT)
        check("重放 valid:false 已消费",
              st == 200 and rr == {
                  "valid": False, "reason": "状态同步回执已消费"})

        # 验真失败不追加（错 nonce）。
        bad = dict(good)
        bad["nonce"] = nonce + "x"
        st, rb, _ = post(CONSUME_PATH, bad, TENANT)
        check("验真失败 valid:false",
              st == 200 and rb["valid"] is False)

        # 第二个 nonce（同验证者），单条首次消费。
        receipt2, signature2 = get_receipt("nonce-sync-list-二")
        good2 = {"receipt": receipt2, "signature": signature2,
                 "ndjson": ndjson1, "nonce": "nonce-sync-list-二"}
        st, r2, _ = post(CONSUME_PATH, good2, TENANT)
        assert st == 200 and r2["valid"] is True, (st, r2)

        # 第二个本地验证者 DID（跨验证者共享 cursor 空间）。
        st, raw2, _ = post(DIDS_PATH,
                           {"method": "web",
                            "public_key": "credential-status-sync-rcpt-list-2"},
                           TENANT)
        assert st == 201, (st, raw2)
        verifier2_did = raw2["did"]
        verifier2_pub = raw2["public_key"]
        st, _, _ = post(ANCHORS_PATH,
                        {"did": verifier2_did, "public_key": verifier2_pub,
                         "key_version": raw2["key_version"],
                         "uses": ["generic", "status"]}, TENANT)
        assert st in (200, 201), st

        def get_receipt_as(nonce, vdid):
            qs = urllib.parse.urlencode(
                {"signer_did": signer_did,
                 "verifier_did": vdid, "nonce": nonce})
            st, r, _ = get(f"{RECEIPT_PATH}?{qs}", headers=TENANT)
            assert st == 200, (st, r)
            return r["receipt"], r["signature"]

        receipt3v, signature3v = get_receipt_as(
            "nonce-sync-list-三", verifier2_did)
        good3v = {"receipt": receipt3v, "signature": signature3v,
                  "ndjson": ndjson1, "nonce": "nonce-sync-list-三"}
        st, r3v, _ = post(CONSUME_PATH, good3v, TENANT)
        assert st == 200 and r3v["valid"] is True, (st, r3v)

        # 批量：一条新消费 + 一条历史重放 + 批内判重。
        receipt4, signature4 = get_receipt("nonce-sync-list-四")
        receipt5, signature5 = get_receipt("nonce-sync-list-五")
        batch_items = [
            {"receipt": receipt4, "signature": signature4,
             "ndjson": ndjson1, "nonce": "nonce-sync-list-四"},
            {"receipt": receipt2, "signature": signature2,
             "ndjson": ndjson1, "nonce": "nonce-sync-list-二"},
            {"receipt": receipt5, "signature": signature5,
             "ndjson": ndjson1, "nonce": "nonce-sync-list-五"},
            {"receipt": receipt5, "signature": signature5,
             "ndjson": ndjson1, "nonce": "nonce-sync-list-五"},
        ]
        st, br, _ = post(CONSUME_BATCH_PATH, {"items": batch_items}, TENANT)
        assert st == 200 and len(br["results"]) == 4, (st, br)
        check("批量新消费成功", br["results"][0]["valid"] is True
              and br["results"][2]["valid"] is True)
        check("批量历史/批内判重",
              br["results"][1] == {
                  "valid": False, "reason": "状态同步回执已消费"}
              and br["results"][3] == {
                  "valid": False, "reason": "状态同步回执已消费"})

        # ---------------------------------------------------------- #
        # 列表查询
        # ---------------------------------------------------------- #
        st, body, raw = get(f"{LIST_PATH}?limit=200", headers=TENANT)
        check("五笔首次消费", st == 200 and len(body["events"]) == 5)
        check("顶层键序 events,next_after",
              list(json.loads(raw.decode()).keys())
              == ["events", "next_after"])
        events = body["events"]
        check("事件键序",
              all(list(e.keys()) == [
                  "cursor", "receipt_id", "verifier_did", "nonce",
                  "consumed_at"] for e in events))
        cursors = [e["cursor"] for e in events]
        check("cursor 正整数且严格升序",
              all(isinstance(c, int) and c > 0 for c in cursors)
              and cursors == sorted(set(cursors)))
        check("租户内跨验证者连续递增", cursors == [1, 2, 3, 4, 5])
        check("跨验证者第三笔归属第二验证者",
              events[2]["verifier_did"] == verifier2_did
              and events[2]["receipt_id"] == r3v["receipt_id"])
        check("字段非空与时间格式",
              all(SHA256_HEX_RE.match(e["receipt_id"])
                  and isinstance(e["verifier_did"], str)
                  and e["verifier_did"]
                  and isinstance(e["nonce"], str) and e["nonce"]
                  and UTC_Z_RE.match(e["consumed_at"])
                  for e in events))
        check("next_after 取末项 cursor",
              body["next_after"] == events[-1]["cursor"])
        check("receipt_id 与消费响应一致",
              events[0]["receipt_id"] == r1["receipt_id"]
              and events[1]["receipt_id"] == r2["receipt_id"]
              and events[3]["receipt_id"]
              == br["results"][0]["receipt_id"]
              and events[4]["receipt_id"]
              == br["results"][2]["receipt_id"])

        # verifier_did 过滤：命中与未命中。
        st, body, _ = get(
            f"{LIST_PATH}?verifier_did={urllib.parse.quote(verifier_did)}",
            headers=TENANT)
        check("verifier_did 精确过滤",
              st == 200 and [e["cursor"] for e in body["events"]] == [1, 2, 4, 5]
              and body["next_after"] == 5)
        st, body, _ = get(
            f"{LIST_PATH}?verifier_did={urllib.parse.quote(verifier2_did)}",
            headers=TENANT)
        check("verifier_did 第二验证者",
              st == 200 and [e["cursor"] for e in body["events"]] == [3])
        st, body, _ = get(
            f"{LIST_PATH}?verifier_did=did:web:nobody.example",
            headers=TENANT)
        check("verifier_did 不命中空页且 next_after=0",
              st == 200 and body == {"events": [], "next_after": 0})

        # 分页 after/limit。
        st, p1, _ = get(f"{LIST_PATH}?limit=2", headers=TENANT)
        check("首页 limit=2",
              [e["cursor"] for e in p1["events"]] == [1, 2]
              and p1["next_after"] == 2)
        st, p2, _ = get(
            f"{LIST_PATH}?limit=2&after={p1['next_after']}",
            headers=TENANT)
        check("次页接续",
              [e["cursor"] for e in p2["events"]] == [3, 4]
              and p2["next_after"] == 4)
        st, p3, _ = get(
            f"{LIST_PATH}?limit=2&after={p2['next_after']}",
            headers=TENANT)
        check("末页仅一项且 next_after 为末项 cursor",
              [e["cursor"] for e in p3["events"]] == [5]
              and p3["next_after"] == 5)
        st, p4, _ = get(
            f"{LIST_PATH}?limit=2&after={p3['next_after']}",
            headers=TENANT)
        check("再翻为空保持 after",
              p4 == {"events": [], "next_after": 5})

        # 缺省 limit=50/after=0。
        st, body, _ = get(LIST_PATH, headers=TENANT)
        check("缺省参数等价 limit=50/after=0",
              [e["cursor"] for e in body["events"]] == [1, 2, 3, 4, 5])

        # 只读不审计。
        st, audit, _ = get("/v1/audit?limit=200", headers=TENANT)
        assert st == 200
        consumed_audits = [
            e for e in audit["events"]
            if e["action"]
            == "trust.credential.status.sync.receipt.consumed"
        ]
        check("仅五笔首次消费审计", len(consumed_audits) == 5)

        # 与普通凭证状态回执消费历史游标空间独立。
        st, sib, _ = get(f"{SIBLING_LIST_PATH}?limit=200", headers=TENANT)
        check("兄弟消费历史互不串扰",
              st == 200 and sib["events"] == [])

        # 租户隔离。
        st, body, _ = get(f"{LIST_PATH}?limit=200", headers=OTHER)
        check("租户隔离", body == {"events": [], "next_after": 0})

        # ---------------------------------------------------------- #
        # 重启 cursor 稳定
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait()
        proc = start()
        st, body, _ = get(f"{LIST_PATH}?limit=200", headers=TENANT)
        check("重启后事件与 cursor 逐字节稳定",
              st == 200
              and [e["cursor"] for e in body["events"]]
              == [1, 2, 3, 4, 5]
              and body["next_after"] == 5
              and body["events"] == events)

        # 重启后再消费一笔，cursor 接续为 6。
        receipt6, signature6 = get_receipt("nonce-sync-list-六")
        good6 = {"receipt": receipt6, "signature": signature6,
                 "ndjson": ndjson1, "nonce": "nonce-sync-list-六"}
        st, r6, _ = post(CONSUME_PATH, good6, TENANT)
        assert st == 200 and r6["valid"] is True, r6
        st, body, _ = get(
            f"{LIST_PATH}?after=5&limit=10", headers=TENANT)
        check("重启后新消费 cursor 接续",
              [e["cursor"] for e in body["events"]] == [6]
              and body["next_after"] == 6)

    finally:
        proc.terminate()
        proc.wait()

    # ---------------------------------------------------------- #
    # 旧记录补录（不经服务端，直接构造旧状态文件）
    # ---------------------------------------------------------- #
    legacy_path = tempfile.mktemp(suffix=".json")
    old_rows = {
        "did:web:v3.example": {
            "n1": {"receipt_id": "r3", "consumed_at": "2020-01-01T00:00:00Z"},
            "n0": {"receipt_id": "r4", "consumed_at": "2019-01-01T00:00:00Z"},
        },
        "did:web:v1.example": {
            "n9": {"receipt_id": "r1", "consumed_at": "2019-01-01T00:00:00Z"},
        },
        "did:web:v2.example": {
            "n5": {"receipt_id": "r2", "consumed_at": "2019-06-01T00:00:00Z"},
        },
    }
    with open(legacy_path, "w", encoding="utf-8") as fh:
        json.dump({
            "tenants": {
                "default": {
                    "consumed_credential_status_sync_receipts": old_rows,
                },
            },
            "audit": [],
            "audit_seq": 0,
        }, fh)

    def backfilled():
        store = VCStore(legacy_path)
        events, next_after = (
            store.list_credential_status_sync_receipt_consumptions(
                "default", 0, 50
            )
        )
        return [(e.cursor, e.verifier_did, e.nonce, e.receipt_id)
                for e in events], next_after

    first, next_after = backfilled()
    # 期望按 (consumed_at, verifier_did, nonce) 升序：
    # 2019 v1/n9, 2019 v3/n0, 2019-06 v2/n5, 2020 v3/n1
    expected_order = [
        (1, "did:web:v1.example", "n9", "r1"),
        (2, "did:web:v3.example", "n0", "r4"),
        (3, "did:web:v2.example", "n5", "r2"),
        (4, "did:web:v3.example", "n1", "r3"),
    ]
    check("旧记录按 consumed_at,verifier_did,nonce 补录",
          first == expected_order and next_after == 4)
    second, second_next = backfilled()
    check("补录重启 cursor 不变",
          second == expected_order and second_next == 4)

    if failures:
        print(f"\n{len(failures)} 项失败")
        sys.exit(1)
    print("\n全部通过")


if __name__ == "__main__":
    main()
