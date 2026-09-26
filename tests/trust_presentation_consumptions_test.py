#!/usr/bin/env python3
"""只读消费历史 GET /v1/trust/presentations/consumptions 的端到端测试。

直接运行：python3 tests/trust_presentation_consumptions_test.py
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
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402

UTC_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
ISSUER_A = "did:web:issuer-pch-a.example"
ISSUER_B = "did:web:issuer-pch-b.example"


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


def make_presentation(pid, issuer_did, credential_id="vc_pch_0001",
                      challenge="chal-1"):
    return {
        "presentation_id": pid,
        "credential_id": credential_id,
        "issuer_did": issuer_did,
        "issuer_key_version": 1,
        "disclose": ["/role"],
        "claims": {"role": "admin", "city": "北京"},
        "challenge": challenge,
        "expires_at": "2099-01-01T00:00:00Z",
    }


def sign_item(pid, issuer_did, priv, challenge="chal-1",
              credential_id="vc_pch_0001"):
    p = make_presentation(pid, issuer_did, credential_id=credential_id,
                          challenge=challenge)
    p["proof"] = crypto.sign(
        {k: v for k, v in p.items() if k != "proof"}, priv
    )
    return {"presentation": p, "challenge": challenge}


def main():
    port = 8993
    store = tempfile.mktemp(suffix=".json")
    proc = start_server(port, store)
    base = f"http://127.0.0.1:{port}"
    list_path = "/v1/trust/presentations/consumptions"
    consume_path = "/v1/trust/presentations/consume"
    batch_path = "/v1/trust/presentations/consume-batch"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def listing(qs="", headers=None):
        return _http("GET", f"{base}{list_path}{qs}", headers=headers)

    def consumed_audits(headers):
        st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=headers)
        assert st == 200
        return [e for e in r["events"]
                if e["action"] == "trust.presentation.consumed"]

    def expect_400(name, qs="", headers=None):
        st, r = listing(qs, headers=headers)
        check(name, st == 400 and r == {"error": "请求非法"})

    try:
        T1 = {"X-Tenant-ID": "pch-a"}
        T2 = {"X-Tenant-ID": "pch-b"}

        # 空历史：200 恰返 events、next_after
        st, r = listing(headers=T1)
        check("空历史 -> 200", st == 200)
        check("空历史键序恰为 events,next_after 且空页 next_after=0",
              list(r.keys()) == ["events", "next_after"]
              and r["events"] == [] and r["next_after"] == 0)

        # 查询参数非法 -> 400 恰返 {"error":"请求非法"}
        expect_400("未知参数 -> 400", "?foo=1")
        expect_400("重复 limit -> 400", "?limit=1&limit=2")
        expect_400("重复 after -> 400", "?after=0&after=1")
        expect_400("重复 issuer_did -> 400",
                   "?issuer_did=a&issuer_did=b")
        expect_400("空 limit -> 400", "?limit=")
        expect_400("空 after -> 400", "?after=")
        expect_400("空 issuer_did -> 400", "?issuer_did=")
        expect_400("limit=0 -> 400", "?limit=0")
        expect_400("limit=201 -> 400", "?limit=201")
        expect_400("limit=-1 -> 400", "?limit=-1")
        expect_400("limit=1.0 -> 400", "?limit=1.0")
        expect_400("limit=true -> 400", "?limit=true")
        expect_400("limit 含空白 -> 400", "?limit=%201")
        expect_400("limit Unicode 数字 -> 400", "?limit=%E0%A5%91")
        expect_400("after=-1 -> 400", "?after=-1")
        expect_400("after=+1 -> 400", "?after=%2B1")
        expect_400("after 含空白 -> 400", "?after=%20")
        expect_400("after 小数 -> 400", "?after=1.5")
        st, r = listing(headers={"X-Tenant-ID": ""})
        check("显式空租户头 -> 400 仅非空中文 error",
              st == 400 and set(r.keys()) == {"error"}
              and isinstance(r["error"], str) and r["error"])

        # 注册两个签发者锚点
        a_priv, a_pub = gen_keypair()
        b_priv, b_pub = gen_keypair()
        for did, pub in ((ISSUER_A, a_pub), (ISSUER_B, b_pub)):
            st, _ = _http(
                "POST", f"{base}/v1/trust/anchors",
                {"did": did, "public_key": pub, "key_version": 1},
                headers=T1,
            )
            assert st == 201

        # 验真失败（未知签发者）不可见
        bad_req = sign_item("vp_bad0000000000000000000000000001",
                            "did:web:nobody.example", gen_keypair()[0])
        st, r = _http("POST", f"{base}{consume_path}", bad_req, headers=T1)
        check("未知签发者验真失败 -> 200 valid:false",
              st == 200 and r.get("valid") is False)
        st, r = listing(headers=T1)
        check("验真失败不出现在消费历史",
              st == 200 and r["events"] == [] and r["next_after"] == 0)
        check("验真失败不记消费审计", consumed_audits(T1) == [])

        # 单条消费 A、单条消费 B、批量消费 A、B
        item1 = sign_item("vp_" + "1" * 32, ISSUER_A, a_priv,
                          credential_id="vc_pch_0001")
        item2 = sign_item("vp_" + "2" * 32, ISSUER_B, b_priv,
                          credential_id="vc_pch_0002")
        item3 = sign_item("vp_" + "3" * 32, ISSUER_A, a_priv,
                          credential_id="vc_pch_0003")
        item4 = sign_item("vp_" + "4" * 32, ISSUER_B, b_priv,
                          credential_id="vc_pch_0004")

        st, r1 = _http("POST", f"{base}{consume_path}", item1, headers=T1)
        assert st == 200 and r1.get("valid") is True
        st, r2 = _http("POST", f"{base}{consume_path}", item2, headers=T1)
        assert st == 200 and r2.get("valid") is True
        st, rb = _http("POST", f"{base}{batch_path}",
                       {"items": [item3, item4]}, headers=T1)
        assert st == 200 and [x.get("valid") for x in rb["results"]] == [
            True, True
        ]
        r3, r4 = rb["results"]

        want = [
            (r1["consumption_id"], ISSUER_A, "vp_" + "1" * 32,
             r1["consumed_at"]),
            (r2["consumption_id"], ISSUER_B, "vp_" + "2" * 32,
             r2["consumed_at"]),
            (r3["consumption_id"], ISSUER_A, "vp_" + "3" * 32,
             r3["consumed_at"]),
            (r4["consumption_id"], ISSUER_B, "vp_" + "4" * 32,
             r4["consumed_at"]),
        ]

        # cursor 恰为对应审计 seq
        seq_by_cid = {e["resource_id"]: e["seq"]
                      for e in consumed_audits(T1)}
        check("四次首次消费对应四条审计",
              sorted(seq_by_cid) == sorted(row[0] for row in want))

        st, r = listing("?limit=200", headers=T1)
        check("全量查询 -> 200", st == 200)
        check("响应键序 events,next_after",
              list(r.keys()) == ["events", "next_after"])
        events = r["events"]
        check("四条消费事件", len(events) == 4)
        check("事件键序恰为 cursor,consumption_id,issuer_did,"
              "presentation_id,consumed_at",
              all(list(e.keys()) == [
                  "cursor", "consumption_id", "issuer_did",
                  "presentation_id", "consumed_at"]
                  for e in events))
        check("cursor 为正整数且严格升序、等于审计 seq",
              [e["cursor"] for e in events]
              == [seq_by_cid[row[0]] for row in want]
              and all(isinstance(e["cursor"], int) and e["cursor"] > 0
                      for e in events))
        check("consumption_id/issuer_did/presentation_id 依次匹配",
              [(e["consumption_id"], e["issuer_did"], e["presentation_id"])
               for e in events] == [row[:3] for row in want])
        check("consumption_id 均为 64 位小写 hex",
              all(SHA256_HEX_RE.fullmatch(e["consumption_id"])
                  for e in events))
        check("consumed_at 均为 UTC 秒精度 Z 字符串且与消费响应一致",
              all(isinstance(e["consumed_at"], str)
                  and UTC_Z_RE.fullmatch(e["consumed_at"])
                  for e in events)
              and [e["consumed_at"] for e in events]
              == [row[3] for row in want])
        last_cursor = events[-1]["cursor"]
        check("next_after 为末项 cursor", r["next_after"] == last_cursor)

        # issuer_did 精确过滤
        st, r = listing(f"?limit=200&issuer_did={ISSUER_A}", headers=T1)
        ev_a = r["events"]
        check("issuer_a 过滤得两条且均属 A",
              st == 200 and len(ev_a) == 2
              and all(e["issuer_did"] == ISSUER_A for e in ev_a)
              and [e["consumption_id"] for e in ev_a]
              == [want[0][0], want[2][0]])
        check("过滤后 next_after 为末项 cursor",
              r["next_after"] == ev_a[-1]["cursor"])
        st, r = listing("?issuer_did=did:web:nobody.example", headers=T1)
        check("无匹配签发者 -> 空页 next_after=0",
              st == 200 and r["events"] == [] and r["next_after"] == 0)
        # 精确匹配：前缀/子串不得命中
        st, r = listing(f"?issuer_did={ISSUER_A}.evil.example",
                        headers=T1)
        check("issuer_did 按字面值精确匹配", r["events"] == [])

        # 分页：limit=2
        st, p1 = listing("?limit=2", headers=T1)
        check("第一页两条",
              st == 200 and [e["cursor"] for e in p1["events"]]
              == [seq_by_cid[want[0][0]], seq_by_cid[want[1][0]]]
              and p1["next_after"] == seq_by_cid[want[1][0]])
        st, p2 = listing(f"?limit=2&after={p1['next_after']}", headers=T1)
        check("第二页两条",
              st == 200 and [e["cursor"] for e in p2["events"]]
              == [seq_by_cid[want[2][0]], seq_by_cid[want[3][0]]]
              and p2["next_after"] == seq_by_cid[want[3][0]])
        st, p3 = listing(f"?limit=2&after={p2['next_after']}", headers=T1)
        check("空页 next_after 保持 after",
              st == 200 and p3["events"] == []
              and p3["next_after"] == p2["next_after"])

        # 过滤 + 分页：after 第一条后仅取 A 的第二条
        st, r = listing(
            f"?after={seq_by_cid[want[0][0]]}&issuer_did={ISSUER_A}",
            headers=T1)
        check("after + issuer_a 仅得 A 的第二条",
              [e["consumption_id"] for e in r["events"]] == [want[2][0]]
              and r["next_after"] == seq_by_cid[want[2][0]])

        # after 超过最大 cursor：空页 next_after=after（即使过滤集非空）
        st, r = listing(f"?after={last_cursor + 1000}&issuer_did={ISSUER_A}",
                        headers=T1)
        check("after 越过最大 cursor -> 空页 next_after=after",
              st == 200 and r["events"] == []
              and r["next_after"] == last_cursor + 1000)

        # 纯只读：重复查询结果一致、不追加审计
        audits_before = consumed_audits(T1)
        q1 = listing("?limit=1", headers=T1)
        q2 = listing("?limit=1", headers=T1)
        check("重复只读查询结果一致", q1 == q2 and q1[0] == 200)
        check("查询不记消费审计", consumed_audits(T1) == audits_before)

        # 重放不追加历史
        st, r = _http("POST", f"{base}{consume_path}", item1, headers=T1)
        check("重放 -> 已消费",
              st == 200 and r == {"valid": False, "reason": "外部演示已消费"})
        st, r = listing("?limit=200", headers=T1)
        check("重放不追加历史事件",
              st == 200 and len(r["events"]) == 4
              and [e["cursor"] for e in r["events"]]
              == [seq_by_cid[row[0]] for row in want])

        # 租户隔离：T2 空历史；同键消费独立且 T1 不受影响
        st, r = listing(headers=T2)
        check("租户 B 初始空历史",
              st == 200 and r["events"] == [] and r["next_after"] == 0)
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": ISSUER_A, "public_key": a_pub, "key_version": 1},
            headers=T2,
        )
        assert st == 201
        other = sign_item("vp_" + "1" * 32, ISSUER_A, a_priv,
                          credential_id="vc_pch_0001")
        st, r = _http("POST", f"{base}{consume_path}", other, headers=T2)
        check("租户 B 同键独立消费成功",
              st == 200 and r.get("valid") is True)
        st, r = listing("?limit=200", headers=T2)
        check("租户 B 仅见本租户一条",
              st == 200 and len(r["events"]) == 1
              and r["events"][0]["presentation_id"] == "vp_" + "1" * 32)
        b_cursor = r["events"][0]["cursor"]
        st, r = listing("?limit=200", headers=T1)
        check("租户 A 历史不受租户 B 影响", len(r["events"]) == 4)
        check("租户游标空间按审计 seq 隔离取值", b_cursor != last_cursor
              or r["events"][-1]["cursor"] == last_cursor)

        # 缺省租户头 -> default，与显式租户隔离
        st, r = listing()
        check("缺省租户头 -> default 空历史 200",
              st == 200 and r["events"] == [] and r["next_after"] == 0)

        # 重启稳定：事件与 cursor（审计 seq）完全不变
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server(port, store)
        st, r1b = listing("?limit=200", headers=T1)
        st2, r2b = listing("?limit=200", headers=T2)
        check("重启后租户 A 历史与 cursor 不变",
              st == 200 and [
                  (e["cursor"], e["consumption_id"], e["issuer_did"],
                   e["presentation_id"], e["consumed_at"])
                  for e in r1b["events"]]
              == [
                  (seq_by_cid[row[0]], row[0], row[1], row[2], row[3])
                  for row in want]
              and r1b["next_after"] == last_cursor)
        check("重启后租户 B 历史不变",
              st2 == 200 and len(r2b["events"]) == 1
              and r2b["events"][0]["cursor"] == b_cursor)

        # 重启后新消费继续出现，且只读性保持
        item5 = sign_item("vp_" + "5" * 32, ISSUER_A, a_priv,
                          credential_id="vc_pch_0005")
        st, r5 = _http("POST", f"{base}{consume_path}", item5, headers=T1)
        check("重启后新消费成功",
              st == 200 and r5.get("valid") is True)
        st, r = listing("?limit=200", headers=T1)
        check("重启后新事件出现在末位，cursor 为其审计 seq",
              st == 200 and len(r["events"]) == 5
              and r["events"][-1]["consumption_id"]
              == r5["consumption_id"]
              and r["events"][-1]["cursor"]
              == consumed_audits(T1)[-1]["seq"]
              and r["next_after"] == r["events"][-1]["cursor"])

    finally:
        proc.terminate()
        proc.wait(timeout=10)
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
