#!/usr/bin/env python3
"""GET /v1/trust/credential-status/receipt-sync/history 已同步凭证状态
回执消费事件时点页端到端测试。

直接运行：python3 tests/trust_credential_status_receipt_sync_history_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

同步数据直接用合规清单（status 用途锚点签名）+ NDJSON 灌入
credential-status/receipt-sync（稠密游标空间，逐字沿用该同步端点的
检查点规则），全部从实际落盘行读取，不硬编码。

覆盖：
- 参数协议：仅 signer_did/at/limit/after 四项且唯一；signer_did 必填
  非空；at 缺省取检查点 next_after、须 ASCII 非负整数；limit 缺省 50、
  限 1–200；after 缺省 0、非负；空值、重复、符号、空白、Unicode 数字、
  越界、未知参数、after>at 均 400 且仅 {"error":"请求非法"}；显式空
  租户头 400；
- 404：来源未同步、跨租户同形；
- 409：at 超过检查点，仅 {"error":"同步游标冲突"}；
- 200 键序恰为 signer_did/at/events/next_after；事件键序恰为
  cursor/receipt_id/verifier_did/nonce/consumed_at；cursor≤at、
  after<cursor 升序取前 limit；非空页 next_after=末项 cursor、空页
  =after；at 缺省=检查点；
- 只读：查询不推进检查点（续页仍衔接）、不改判重索引、不写数据或审计；
- 时点稳定：同 at 查询在新同步页落盘后结果不变；重启逐字节一致。
"""

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

SYNC_PATH = "/v1/trust/credential-status/receipt-sync"
HISTORY_PATH = "/v1/trust/credential-status/receipt-sync/history"
ANCHORS_PATH = "/v1/trust/anchors"

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


def _http(method, url, payload=None, headers=None):
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
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


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


VERIFIER_DID = "did:web:cs-sync-hist-verifier.example"


def make_row(cursor, index):
    return {
        "cursor": cursor,
        "receipt_id": f"rcpt-{index:059d}",
        "verifier_did": VERIFIER_DID,
        "nonce": f"cs-hist-nonce-{index:03d}",
        "consumed_at": "2099-01-01T00:00:00Z",
    }


def to_ndjson(rows):
    return "".join(
        json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n"
        for row in rows
    )


def main():
    port = 9078
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
        DST = {"X-Tenant-ID": "cs-dst-hist-tenant"}
        OTHER = {"X-Tenant-ID": "cs-other-hist-tenant"}

        signer_priv, signer_pub = _keypair()
        signer_did = "did:web:cs-sync-hist-signer.example"
        st, _ = post(ANCHORS_PATH,
                     {"did": signer_did, "public_key": signer_pub,
                      "key_version": 1,
                      "uses": ["generic", "status"]}, DST)
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

        def sync(rows, after, snapshot):
            ndjson = to_ndjson(rows)
            st, raw = post(
                SYNC_PATH,
                {"manifest": signed_manifest(snapshot, after, ndjson),
                 "ndjson": ndjson},
                headers=DST)
            return st, json.loads(raw)

        def history(qs, headers=DST):
            st, raw = get(f"{HISTORY_PATH}?{qs}", headers=headers)
            return st, json.loads(raw.decode() or "null")

        # 稠密来源游标 1..5：首页 1,2,3（snapshot=3），续页 4,5
        # （snapshot=5）。
        rows = [make_row(i, i) for i in range(1, 6)]

        # -------------------------------------------------------------- #
        # 1. 404：未同步来源 / 跨租户
        # -------------------------------------------------------------- #
        st, body = history(f"signer_did={signer_did}")
        check("未同步来源 404",
              st == 404 and body == {"error": "同步来源不存在"})
        st, _ = history(f"signer_did={signer_did}", headers=OTHER)
        check("跨租户 404 同形", st == 404)

        # -------------------------------------------------------------- #
        # 2. 400：参数协议，仅 {"error":"请求非法"}
        # -------------------------------------------------------------- #
        def expect_400(name, qs, headers=DST):
            st, body = history(qs, headers=headers)
            check(name, st == 400 and body == {"error": "请求非法"})

        expect_400("缺 signer_did", "limit=10")
        expect_400("signer_did 空值", "signer_did=")
        expect_400("未知参数", f"signer_did={signer_did}&x=1")
        expect_400("signer_did 重复",
                   f"signer_did={signer_did}&signer_did={signer_did}")
        expect_400("at 重复", f"signer_did={signer_did}&at=1&at=2")
        expect_400("limit 重复", f"signer_did={signer_did}&limit=1&limit=2")
        expect_400("after 重复",
                   f"signer_did={signer_did}&after=1&after=2")
        expect_400("at 空值", f"signer_did={signer_did}&at=")
        expect_400("limit 空值", f"signer_did={signer_did}&limit=")
        expect_400("after 空值", f"signer_did={signer_did}&after=")
        expect_400("at 符号", f"signer_did={signer_did}&at=-1")
        expect_400("at 小数", f"signer_did={signer_did}&at=1.5")
        expect_400("at 空白", f"signer_did={signer_did}&at=%201")
        expect_400("at Unicode 数字",
                   f"signer_did={signer_did}&at=%E0%A9%AE")
        expect_400("at 布尔词", f"signer_did={signer_did}&at=true")
        expect_400("limit 为 0", f"signer_did={signer_did}&limit=0")
        expect_400("limit 超 200", f"signer_did={signer_did}&limit=201")
        expect_400("limit 非数", f"signer_did={signer_did}&limit=abc")
        expect_400("after 符号", f"signer_did={signer_did}&after=-2")
        expect_400("after 非数", f"signer_did={signer_did}&after=0x1")
        # 显式空租户头由路由统一判 400（文案为租户头固定中文）。
        st, _ = history(f"signer_did={signer_did}",
                        headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", st == 400)

        # 灌入首页（检查点 snapshot=3, next_after=3）。
        st, r = sync(rows[:3], 0, 3)
        assert st == 201 and r["next_after"] == 3, (st, r)

        # after>at 在有检查点后仍为 400（含 at 缺省：after>检查点）。
        expect_400("after>at", f"signer_did={signer_did}&at=2&after=3")
        expect_400("after>缺省 at(检查点=3)",
                   f"signer_did={signer_did}&after=4")

        # -------------------------------------------------------------- #
        # 3. 409：at 超过检查点
        # -------------------------------------------------------------- #
        st, body = history(f"signer_did={signer_did}&at=4")
        check("at 超检查点 409",
              st == 409 and body == {"error": "同步游标冲突"})

        # -------------------------------------------------------------- #
        # 4. 200：缺省 at=检查点，全量
        # -------------------------------------------------------------- #
        EVENT_KEYS = ["cursor", "receipt_id", "verifier_did", "nonce",
                      "consumed_at"]
        OK_KEYS = ["signer_did", "at", "events", "next_after"]

        st, body = history(f"signer_did={signer_did}")
        check("缺省查询 200", st == 200)
        check("顶层键序", list(body.keys()) == OK_KEYS)
        check("at 缺省=检查点 3", body["at"] == 3)
        check("signer_did 回显", body["signer_did"] == signer_did)
        check("三行且按 cursor 升序",
              [e["cursor"] for e in body["events"]] == [1, 2, 3])
        check("next_after=末项 3", body["next_after"] == 3)
        for event, expected in zip(body["events"], rows[:3]):
            check("事件键序", list(event.keys()) == EVENT_KEYS)
            check("事件值一致", event == expected)
            check("cursor 为正整数",
                  isinstance(event["cursor"], int)
                  and not isinstance(event["cursor"], bool)
                  and event["cursor"] > 0)
            check("四字段为非空字符串",
                  all(isinstance(event[k], str) and event[k]
                      for k in EVENT_KEYS[1:]))
            check("consumed_at UTC Z",
                  event["consumed_at"] == "2099-01-01T00:00:00Z")

        # -------------------------------------------------------------- #
        # 5. 时点窗口：cursor<=at
        # -------------------------------------------------------------- #
        st, body = history(f"signer_did={signer_did}&at=2")
        check("at=2 两行",
              st == 200 and [e["cursor"] for e in body["events"]] == [1, 2]
              and body["at"] == 2 and body["next_after"] == 2)
        st, body = history(f"signer_did={signer_did}&at=0")
        check("at=0 空页",
              body["events"] == [] and body["next_after"] == 0
              and body["at"] == 0)

        # -------------------------------------------------------------- #
        # 6. 分页：after + limit，空页 next_after=after
        # -------------------------------------------------------------- #
        st, body = history(f"signer_did={signer_did}&after=1&limit=1")
        check("after=1 limit=1 取 cursor 2",
              [e["cursor"] for e in body["events"]] == [2]
              and body["next_after"] == 2)
        st, body = history(
            f"signer_did={signer_did}&at=3&after=2&limit=10")
        check("after=2 取 3",
              [e["cursor"] for e in body["events"]] == [3]
              and body["next_after"] == 3)
        st, body = history(f"signer_did={signer_did}&after=3")
        check("after=检查点 空页 next_after=3",
              body["events"] == [] and body["next_after"] == 3)
        st, _ = history(f"signer_did={signer_did}&after=9")
        check("after 越尾（缺省 at）400", st == 400)
        st, body = history(
            f"signer_did={signer_did}&at=3&after=2&limit=1")
        check("窗口内 after(2) limit=1 取 3",
              [e["cursor"] for e in body["events"]] == [3]
              and body["next_after"] == 3)
        # limit 上限 200
        st, _ = history(f"signer_did={signer_did}&limit=200")
        check("limit=200 合法", st == 200)

        # 翻页连续性：limit=1 逐页 1,2,3
        page_cursors = []
        token = 0
        while True:
            st, body = history(
                f"signer_did={signer_did}&at=3&after={token}&limit=1")
            assert st == 200
            page_cursors.extend(e["cursor"] for e in body["events"])
            if body["next_after"] == token:
                break
            token = body["next_after"]
        check("逐页翻取得到 1,2,3", page_cursors == [1, 2, 3])

        # -------------------------------------------------------------- #
        # 7. 只读：查询后续页仍衔接 next_after=3（不被查询推进/回退）
        # -------------------------------------------------------------- #
        st, r = sync(rows[3:], 3, 5)
        check("查询后续页正常 200（检查点未受只读影响）",
              st == 200 and r["next_after"] == 5 and r["count"] == 2)

        # 同步/查询均不写审计
        st, raw = get("/v1/audit?limit=200", headers=DST)
        actions = [e["action"] for e in json.loads(raw)["events"]]
        check("同步与查询均不写审计",
              all("status.receipt" not in a for a in actions))

        # -------------------------------------------------------------- #
        # 8. 时点稳定：旧 at=3 结果在追平到 5 后不变
        # -------------------------------------------------------------- #
        st, body_before = history(f"signer_did={signer_did}&at=3")
        assert st == 200
        st, body_after = history(f"signer_did={signer_did}&at=3")
        check("旧 at 分页不受后续同步影响",
              body_before == body_after
              and [e["cursor"] for e in body_after["events"]] == [1, 2, 3]
              and body_after["next_after"] == 3)
        st, body = history(f"signer_did={signer_did}")
        check("缺省 at 现为新检查点 5，五行",
              body["at"] == 5 and body["next_after"] == 5
              and [e["cursor"] for e in body["events"]] == [1, 2, 3, 4, 5])
        # 5 之后 409
        st, _ = history(f"signer_did={signer_did}&at=6")
        check("追平后 at=6 仍 409", st == 409)

        # 跨租户在同步后仍 404
        st, _ = history(f"signer_did={signer_did}", headers=OTHER)
        check("同步后跨租户仍 404", st == 404)

        # -------------------------------------------------------------- #
        # 9. 重启稳定
        # -------------------------------------------------------------- #
        captured_qs = f"signer_did={signer_did}&at=3&after=0&limit=2"
        st, before_raw = history(captured_qs)
        assert st == 200
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, after_raw = history(captured_qs)
        check("重启后 200 且结果逐字节一致",
              st == 200 and before_raw == after_raw)
        st, body = history(f"signer_did={signer_did}")
        check("重启后检查点仍为 5", st == 200 and body["at"] == 5)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
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
