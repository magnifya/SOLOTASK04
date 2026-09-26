#!/usr/bin/env python3
"""GET /v1/trust/presentations/consumptions/export 确定性 NDJSON
快照导出端到端测试。

直接运行：python3 tests/trust_presentation_consumptions_export_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 仅允许 limit/after/snapshot 三参数且不得重复，空值、未知参数、
  ASCII 整数/范围非法、snapshot 超过当前最大游标、after>snapshot 均
  400 且仅返 {"error":"请求非法"}；
- limit 缺省 1000、限 1–10000；after 缺省 0；snapshot 缺省为请求时
  租户最大 cursor（无事件为 0）；
- 成功 200：Content-Type application/x-ndjson; charset=utf-8，
  X-Snapshot-Cursor 为生效快照、X-Next-After 为末行 cursor
  （空页为 after）；
- 每行键序 cursor、consumption_id、issuer_did、presentation_id、
  consumed_at，UTF-8 紧凑 JSON、非 ASCII 不转义、RFC8259 最短转义、
  LF 结行（末行亦有 LF）、无 BOM，空结果零字节；
- 同 snapshot 续页排除快照后新事件；
- 租户隔离、纯只读（不改游标/状态/审计）、跨重启字节一致。
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


def _http(method, url, payload=None, headers=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode() or "{}")


def _http_raw(url, headers=None):
    """GET 并返回 (status, 响应头, 原始字节)，不解析 JSON。"""
    req = urllib.request.Request(url, method="GET")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, dict(resp.headers.items()), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read()


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


EXPORT_PATH = "/v1/trust/presentations/consumptions/export"
LIST_PATH = "/v1/trust/presentations/consumptions"
CONSUME_PATH = "/v1/trust/presentations/consume"
BATCH_PATH = "/v1/trust/presentations/consume-batch"
EVENT_KEYS = [
    "cursor", "consumption_id", "issuer_did", "presentation_id",
    "consumed_at",
]

ISSUER_A = "did:web:issuer-pexp-a.example"
ISSUER_B = "did:web:issuer-pexp-b.example"


def make_presentation(presentation_id, issuer_did, challenge="chal-1"):
    return {
        "presentation_id": presentation_id,
        "credential_id": "vc_pexp_0001",
        "issuer_did": issuer_did,
        "issuer_key_version": 1,
        "disclose": ["/role"],
        "claims": {"role": "admin"},
        "challenge": challenge,
        "expires_at": "2099-01-01T00:00:00Z",
    }


def sign_presentation(p, priv):
    message = {k: v for k, v in p.items() if k != "proof"}
    p = dict(p)
    p["proof"] = crypto.sign(message, priv)
    return p


def main():
    port = 9024
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)

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
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def export(query="", headers=None):
        url = f"{base}{EXPORT_PATH}?{query}" if query else base + EXPORT_PATH
        return _http_raw(url, headers=headers)

    try:
        TA = {"X-Tenant-ID": "pexp-a"}
        TB = {"X-Tenant-ID": "pexp-b"}

        # ---------------------------------------------------------- #
        # 1. 无事件：200 零字节，快照 0，X-Next-After=after
        # ---------------------------------------------------------- #
        st, hd, body = export(headers=TA)
        check("无事件 200 零字节",
              st == 200 and body == b"")
        check("无事件 Content-Type",
              hd.get("Content-Type") == "application/x-ndjson; charset=utf-8")
        check("无事件快照头为 0、next_after=after(0)",
              hd.get("X-Snapshot-Cursor") == "0"
              and hd.get("X-Next-After") == "0")
        st, hd, body = export("after=0", headers=TA)
        check("无事件 after=0 空结果 X-Next-After 保持 0",
              st == 200 and body == b"" and hd.get("X-Next-After") == "0"
              and hd.get("X-Snapshot-Cursor") == "0")

        # ---------------------------------------------------------- #
        # 2. 参数非法 -> 400 且仅返 {"error":"请求非法"}
        # ---------------------------------------------------------- #
        def expect_400(name, query, headers=None):
            st, _, raw = export(query, headers=headers)
            try:
                r = json.loads(raw.decode() or "{}")
            except ValueError:
                r = {}
            check(f"400 仅返请求非法: {name}",
                  st == 400 and r == {"error": "请求非法"})

        expect_400("未知参数", "unknown=1")
        expect_400("issuer_did 不被允许", "issuer_did=did:web:x")
        expect_400("limit 空值", "limit=")
        expect_400("limit 重复", "limit=1&limit=2")
        expect_400("limit=0", "limit=0")
        expect_400("limit=10001", "limit=10001")
        expect_400("limit 字母", "limit=abc")
        expect_400("limit 小数", "limit=1.5")
        expect_400("limit 符号", "limit=%2B1")
        expect_400("limit 布尔", "limit=true")
        expect_400("limit 空白", "limit=%20")
        expect_400("limit Unicode 数字", "limit=%E0%A9%91")
        expect_400("after 空值", "after=")
        expect_400("after 负数", "after=-1")
        expect_400("after 小数", "after=1.0")
        expect_400("after 布尔", "after=true")
        expect_400("after 重复", "after=0&after=1")
        expect_400("snapshot 空值", "snapshot=")
        expect_400("snapshot 负数", "snapshot=-1")
        expect_400("snapshot 小数", "snapshot=1.0")
        expect_400("snapshot 布尔", "snapshot=true")
        expect_400("snapshot 空白", "snapshot=%20")
        expect_400("snapshot Unicode 数字", "snapshot=%E0%A9%91")
        expect_400("snapshot 重复", "snapshot=0&snapshot=1")
        expect_400("snapshot 超过当前最大值(无事件)", "snapshot=1")
        expect_400("无事件 after>snapshot(缺省0)", "after=1")
        # 显式空 X-Tenant-ID -> 400（租户头校验在路由层统一处理）
        st, _, raw = export("", headers={"X-Tenant-ID": ""})
        try:
            r = json.loads(raw.decode() or "{}")
        except ValueError:
            r = {}
        check("显式空 X-Tenant-ID -> 400",
              st == 400 and isinstance(r.get("error"), str)
              and bool(r["error"]))

        # ---------------------------------------------------------- #
        # 3. 准备锚点与演示消费（presentation_id 含中文与特殊转义字符）
        # ---------------------------------------------------------- #
        iss_a_priv, iss_a_pub = _keypair()
        iss_b_priv, iss_b_pub = _keypair()
        for did, pub in ((ISSUER_A, iss_a_pub), (ISSUER_B, iss_b_pub)):
            st, _ = _http("POST", f"{base}/v1/trust/anchors",
                          {"did": did, "public_key": pub, "key_version": 1},
                          headers=TA)
            assert st == 201

        def make_req(pid, issuer_did, priv, challenge="chal-1"):
            pres = sign_presentation(
                make_presentation(pid, issuer_did, challenge), priv)
            return {"presentation": pres, "challenge": challenge}

        def cid_of(req):
            return hashlib.sha256(crypto.canonicalize(req)).hexdigest()

        # 接受顺序 req1, req2, req3+req4（批量内两项）；
        # presentation_id 覆盖中文、引号、反斜杠、换行、制表符
        req1 = make_req("vp_中文-1", ISSUER_A, iss_a_priv)
        req2 = make_req('vp_"引号"\\反斜杠\n换行\t制表', ISSUER_B, iss_b_priv)
        req3 = make_req("vp_" + "3" * 32, ISSUER_A, iss_a_priv)
        req4 = make_req("vp_" + "4" * 32, ISSUER_B, iss_b_priv)
        st, r = _http("POST", f"{base}{CONSUME_PATH}", req1, headers=TA)
        assert st == 200 and r.get("valid") is True, r
        st, r = _http("POST", f"{base}{CONSUME_PATH}", req2, headers=TA)
        assert st == 200 and r.get("valid") is True, r
        st, r = _http("POST", f"{base}{BATCH_PATH}",
                      {"items": [req3, req4]}, headers=TA)
        assert st == 200 and [x.get("valid") for x in r["results"]] == [
            True, True
        ], r

        want_cids = [cid_of(x) for x in (req1, req2, req3, req4)]
        want_issuers = [ISSUER_A, ISSUER_B, ISSUER_A, ISSUER_B]
        want_pids = [x["presentation"]["presentation_id"]
                     for x in (req1, req2, req3, req4)]

        # cursor 为各次首次消费的审计 seq，由查询端点读取期望值
        st, r = _http("GET", f"{base}{LIST_PATH}?limit=200", headers=TA)
        assert st == 200 and len(r["events"]) == 4, r
        want_events = r["events"]
        want_cursors = [e["cursor"] for e in want_events]
        max_cursor = want_cursors[-1]

        # ---------------------------------------------------------- #
        # 4. 全量导出：字节级形状
        # ---------------------------------------------------------- #
        st, hd, raw = export(headers=TA)
        check("导出 200 且 Content-Type 正确",
              st == 200
              and hd.get("Content-Type")
              == "application/x-ndjson; charset=utf-8")
        check("快照头为最大 cursor、next_after 为末行 cursor",
              hd.get("X-Snapshot-Cursor") == str(max_cursor)
              and hd.get("X-Next-After") == str(max_cursor))
        check("无 BOM", not raw.startswith(b"\xef\xbb\xbf"))
        check("LF 结行且末行亦有 LF",
              raw.endswith(b"\n") and b"\r" not in raw
              and raw.count(b"\n") == 4)
        lines = raw.decode("utf-8").split("\n")[:-1]
        check("四行均为紧凑 JSON（无空格）",
              all(", " not in line and ": " not in line for line in lines))
        events = [json.loads(line) for line in lines]
        check("行键序固定",
              all(list(e.keys()) == EVENT_KEYS for e in events))
        check("行类型正确",
              all(type(e["cursor"]) is int and e["cursor"] > 0
                  and isinstance(e["consumption_id"], str)
                  and isinstance(e["issuer_did"], str)
                  and isinstance(e["presentation_id"], str)
                  and isinstance(e["consumed_at"], str)
                  for e in events))
        check("cursor 按消费顺序升序",
              [e["cursor"] for e in events] == want_cursors)
        check("consumption_id 依次匹配",
              [e["consumption_id"] for e in events] == want_cids)
        check("issuer_did 依次匹配",
              [e["issuer_did"] for e in events] == want_issuers)
        check("presentation_id 依次匹配",
              [e["presentation_id"] for e in events] == want_pids)
        check("与查询端点事件一致", events == want_events)
        check("非 ASCII 不转义",
              "vp_中文-1".encode("utf-8") in raw and b"\\u" not in raw)
        check("字符串按 RFC8259 最短转义",
              'vp_\\"引号\\"\\\\反斜杠\\n换行\\t制表'.encode("utf-8") in raw)
        full_export_bytes = raw

        # ---------------------------------------------------------- #
        # 5. 分页与快照续传
        # ---------------------------------------------------------- #
        st, hd, raw = export("limit=2", headers=TA)
        page1 = [json.loads(x) for x in raw.decode().split("\n")[:-1]]
        check("limit=2 首页",
              st == 200 and [e["cursor"] for e in page1] == want_cursors[:2]
              and hd.get("X-Next-After") == str(want_cursors[1])
              and hd.get("X-Snapshot-Cursor") == str(max_cursor))
        st, hd, raw = export(f"limit=2&after={want_cursors[1]}", headers=TA)
        page2 = [json.loads(x) for x in raw.decode().split("\n")[:-1]]
        check("第二页",
              [e["cursor"] for e in page2] == want_cursors[2:]
              and hd.get("X-Next-After") == str(want_cursors[3]))
        st, hd, raw = export(f"after={max_cursor}", headers=TA)
        check("after=末游标空结果零字节且 X-Next-After=after",
              st == 200 and raw == b""
              and hd.get("X-Next-After") == str(max_cursor)
              and hd.get("X-Snapshot-Cursor") == str(max_cursor))

        # 显式 snapshot 合法：等于/小于最大值
        st, hd, raw = export(f"snapshot={want_cursors[1]}", headers=TA)
        ev = [json.loads(x) for x in raw.decode().split("\n")[:-1]]
        check("显式 snapshot=次项 cursor 仅含前两条",
              st == 200 and [e["cursor"] for e in ev] == want_cursors[:2]
              and hd.get("X-Snapshot-Cursor") == str(want_cursors[1])
              and hd.get("X-Next-After") == str(want_cursors[1]))
        st, hd, raw = export("snapshot=0", headers=TA)
        check("显式 snapshot=0 空结果",
              st == 200 and raw == b""
              and hd.get("X-Snapshot-Cursor") == "0"
              and hd.get("X-Next-After") == "0")
        expect_400("snapshot 超过当前最大值", f"snapshot={max_cursor + 1}")
        expect_400("snapshot 远超当前最大值", "snapshot=999999")
        expect_400("after 大于显式 snapshot",
                   f"after={want_cursors[2]}&snapshot={want_cursors[1]}")
        expect_400("after 等于 snapshot+1", f"after={max_cursor + 1}")

        # 同 snapshot 续页排除快照后新事件
        st, hd, raw = export("limit=3", headers=TA)
        snap = hd["X-Snapshot-Cursor"]
        check("续传首页快照=最大 cursor", snap == str(max_cursor))
        # 快照后新增一条消费
        req5 = make_req("vp_" + "5" * 32, ISSUER_A, iss_a_priv)
        st, r = _http("POST", f"{base}{CONSUME_PATH}", req5, headers=TA)
        assert st == 200 and r.get("valid") is True, r
        st, hd, raw = export(
            f"snapshot={snap}&after={want_cursors[1]}", headers=TA)
        ev = [json.loads(x) for x in raw.decode().split("\n")[:-1]]
        check("同 snapshot 续页排除后续消费",
              st == 200 and [e["cursor"] for e in ev] == want_cursors[2:]
              and hd.get("X-Snapshot-Cursor") == str(max_cursor)
              and hd.get("X-Next-After") == str(want_cursors[3]))
        st, hd, raw = export(headers=TA)
        new_max = hd.get("X-Snapshot-Cursor")
        check("新请求缺省快照读到新最大值",
              new_max is not None and int(new_max) > max_cursor
              and hd.get("X-Next-After") == new_max
              and raw.count(b"\n") == 5)
        expect_400("snapshot 超过新最大值",
                   f"snapshot={int(new_max) + 1}")
        full_export_bytes_5 = raw

        # ---------------------------------------------------------- #
        # 6. 租户隔离与缺省租户
        # ---------------------------------------------------------- #
        st, hd, raw = export(headers=TB)
        check("他租户不可见（零字节、快照 0）",
              st == 200 and raw == b""
              and hd.get("X-Snapshot-Cursor") == "0"
              and hd.get("X-Next-After") == "0")
        st, hd, raw = export()
        check("缺省 default 租户零字节",
              st == 200 and raw == b"" and hd.get("X-Snapshot-Cursor") == "0")
        # 租户 B 独立锚点并消费同键演示
        for did, pub in ((ISSUER_A, iss_a_pub), (ISSUER_B, iss_b_pub)):
            st, _ = _http("POST", f"{base}/v1/trust/anchors",
                          {"did": did, "public_key": pub, "key_version": 1},
                          headers=TB)
            assert st == 201
        st, r = _http("POST", f"{base}{CONSUME_PATH}", req1, headers=TB)
        assert st == 200 and r.get("valid") is True, r
        st, hd, raw = export(headers=TB)
        ev = [json.loads(x) for x in raw.decode().split("\n")[:-1]]
        check("他租户独立消费仅一条且为本租户游标",
              len(ev) == 1
              and ev[0]["consumption_id"] == want_cids[0]
              and ev[0]["issuer_did"] == ISSUER_A
              and hd.get("X-Snapshot-Cursor") == str(ev[0]["cursor"]))
        st, hd, raw = export(headers=TA)
        check("租户 A 不受影响（仍 5 条）",
              raw.count(b"\n") == 5
              and hd.get("X-Snapshot-Cursor") == new_max)

        # ---------------------------------------------------------- #
        # 7. 纯只读：导出不改游标、状态与审计
        # ---------------------------------------------------------- #
        st, audit_before = _http("GET", f"{base}/v1/audit", headers=TA)
        st, hd, raw = export(headers=TA)
        st, hd2, raw2 = export(headers=TA)
        check("重复导出字节一致",
              raw == raw2
              and hd.get("X-Snapshot-Cursor") == hd2.get("X-Snapshot-Cursor")
              and hd.get("X-Next-After") == hd2.get("X-Next-After"))
        st, audit_after = _http("GET", f"{base}/v1/audit", headers=TA)
        check("导出不记审计", audit_before == audit_after)
        st, r = _http("GET", f"{base}{LIST_PATH}?limit=200", headers=TA)
        check("导出不改游标与事件",
              [e["cursor"] for e in r["events"]]
              == want_cursors + [int(new_max)]
              and r["next_after"] == int(new_max))

        # ---------------------------------------------------------- #
        # 8. 跨重启字节一致
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, hd, raw = export(headers=TA)
        check("重启后全量导出字节一致",
              st == 200 and raw == full_export_bytes_5
              and hd.get("X-Snapshot-Cursor") == new_max
              and hd.get("X-Next-After") == new_max)
        st2, r = _http("GET", f"{base}{LIST_PATH}?limit=200", headers=TA)
        exported = [json.loads(x) for x in raw.decode().split("\n")[:-1]]
        check("重启后导出与查询事件一致",
              st2 == 200 and exported == r["events"])
        # 前 4 条字节与重启前完全一致
        head4 = b"".join(raw.splitlines(keepends=True)[:4])
        check("重启后前 4 条字节一致", head4 == full_export_bytes)
        st, hd, raw = export(f"snapshot={max_cursor}", headers=TA)
        check("重启后旧快照仍可用且排除快照后消费",
              st == 200 and raw == full_export_bytes
              and hd.get("X-Snapshot-Cursor") == str(max_cursor)
              and hd.get("X-Next-After") == str(max_cursor))
        st, hd, raw = export(headers=TB)
        check("重启后租户 B 导出稳定",
              raw.count(b"\n") == 1
              and hd.get("X-Snapshot-Cursor") == str(ev[0]["cursor"]))

    finally:
        proc.terminate()
        proc.wait(timeout=10)
        if os.path.exists(store):
            os.remove(store)

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
