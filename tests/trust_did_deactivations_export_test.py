#!/usr/bin/env python3
"""GET /v1/trust/dids/deactivations/export 确定性 NDJSON 导出端到端测试。

直接运行：python3 tests/trust_did_deactivations_export_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 仅允许 limit/after/snapshot/did/key_version/from/to 七参数且不得重复，
  空值、未知参数、ASCII 整数/范围非法、UTC 秒精度 Z 时间非法、from>to、
  snapshot 超过当前最大游标均 400 且恰返 {"error": "非空中文原因"}；
- limit 缺省 1000、限 1–10000；snapshot 缺省为请求时租户最大 cursor；
- 成功 200：Content-Type application/x-ndjson; charset=utf-8，
  X-Snapshot-Cursor 为生效快照、X-Next-After 为末行 cursor（空为 after）；
- 每行键序 cursor、did、key_version、reason、deactivated_at，UTF-8 紧凑
  JSON、非 ASCII 不转义、RFC8259 最短转义、LF 结行（末行亦有 LF）、
  无 BOM，空结果零字节；
- 同 snapshot 续页排除快照后新事件；过滤规则与查询端点一致；
- 租户隔离、纯只读（不改游标/状态/审计）、跨重启字节一致。
"""

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


EXPORT_PATH = "/v1/trust/dids/deactivations/export"
LIST_PATH = "/v1/trust/dids/deactivations"
SYNC_PATH = "/v1/trust/dids/deactivate-sync"
EVENT_KEYS = ["cursor", "did", "key_version", "reason", "deactivated_at"]


def main():
    port = 9011
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
        TA = {"X-Tenant-ID": "tenant-a"}
        TB = {"X-Tenant-ID": "tenant-b"}

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
        st, hd, body = export("after=7", headers=TA)
        check("无事件空结果 X-Next-After 保持 after",
              st == 200 and body == b"" and hd.get("X-Next-After") == "7")

        # ---------------------------------------------------------- #
        # 2. 参数非法 -> 400 且恰返非空中文 error
        # ---------------------------------------------------------- #
        def expect_400(name, query, headers=None):
            st, _, raw = export(query, headers=headers)
            try:
                r = json.loads(raw.decode() or "{}")
            except ValueError:
                r = {}
            check(f"400 仅 error 非空中文: {name}",
                  st == 400 and list(r.keys()) == ["error"]
                  and isinstance(r["error"], str) and bool(r["error"]))

        expect_400("未知参数", "unknown=1")
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
        expect_400("did 空值", "did=")
        expect_400("did 重复", "did=a&did=b")
        expect_400("key_version 空值", "key_version=")
        expect_400("key_version=0", "key_version=0")
        expect_400("key_version 负数", "key_version=-1")
        expect_400("key_version 重复", "key_version=1&key_version=2")
        expect_400("from 空值", "from=")
        expect_400("from 缺 Z", "from=2026-01-01T00:00:00")
        expect_400("from 毫秒", "from=2026-01-01T00:00:00.0Z")
        expect_400("from 非法日期", "from=2026-13-01T00:00:00Z")
        expect_400("to 非法时刻", "to=2026-01-01T24:00:00Z")
        expect_400("from 晚于 to",
                   "from=2026-03-01T00:00:00Z&to=2026-02-01T00:00:00Z")
        expect_400("from 重复",
                   "from=2026-01-01T00:00:00Z&from=2026-02-01T00:00:00Z")
        expect_400("显式空 X-Tenant-ID", "", headers={"X-Tenant-ID": ""})

        # ---------------------------------------------------------- #
        # 3. 准备锚点与通告（含非 ASCII 与需最短转义的字符）
        # ---------------------------------------------------------- #
        did_a = "did:web:exp-a.example"
        did_b = "did:web:exp-b.example"
        did_c = "did:web:exp-c.example"
        priv_a, pub_a = _keypair()
        priv_b, pub_b = _keypair()
        priv_c, pub_c = _keypair()
        for did, pub, ver in ((did_a, pub_a, 1), (did_b, pub_b, 2),
                              (did_c, pub_c, 1)):
            st, _ = _http("POST", f"{base}/v1/trust/anchors",
                          {"did": did, "public_key": pub,
                           "key_version": ver}, headers=TA)
            assert st == 201, did

        def make_body(did, key_version=1, reason="机构业务终止",
                      deactivated_at="2026-09-20T10:00:00Z"):
            return {"did": did, "key_version": key_version,
                    "reason": reason, "deactivated_at": deactivated_at}

        def sync_notice(body, priv, headers=TA):
            return _http("POST", f"{base}{SYNC_PATH}",
                         {"body": body, "signature": crypto.sign(body, priv)},
                         headers=headers)

        # 接受顺序 c, b, a；reason 覆盖中文、引号、反斜杠、换行、制表符
        body_c = make_body(did_c, reason='含"引号"与\\反斜杠\n换行\t制表',
                           deactivated_at="2026-03-01T00:00:00Z")
        body_b = make_body(did_b, key_version=2,
                           deactivated_at="2026-02-01T00:00:00Z")
        body_a = make_body(did_a, deactivated_at="2026-01-01T00:00:00Z")
        for body, priv in ((body_c, priv_c), (body_b, priv_b),
                           (body_a, priv_a)):
            st, r = sync_notice(body, priv)
            assert st == 201, r

        # ---------------------------------------------------------- #
        # 4. 全量导出：字节级形状
        # ---------------------------------------------------------- #
        st, hd, raw = export(headers=TA)
        check("导出 200 且 Content-Type 正确",
              st == 200
              and hd.get("Content-Type")
              == "application/x-ndjson; charset=utf-8")
        check("快照头为最大 cursor、next_after 为末行 cursor",
              hd.get("X-Snapshot-Cursor") == "3"
              and hd.get("X-Next-After") == "3")
        check("无 BOM", not raw.startswith(b"\xef\xbb\xbf"))
        check("LF 结行且末行亦有 LF",
              raw.endswith(b"\n") and b"\r" not in raw
              and raw.count(b"\n") == 3)
        lines = raw.decode("utf-8").split("\n")[:-1]
        check("三行均为紧凑 JSON（无空格）",
              all(", " not in line and ": " not in line for line in lines))
        events = [json.loads(line) for line in lines]
        check("行键序固定",
              all(list(e.keys()) == EVENT_KEYS for e in events))
        check("行类型与查询端点一致",
              all(type(e["cursor"]) is int
                  and type(e["key_version"]) is int
                  and isinstance(e["did"], str)
                  and isinstance(e["reason"], str)
                  and isinstance(e["deactivated_at"], str)
                  for e in events))
        check("cursor 按接受顺序升序",
              [e["cursor"] for e in events] == [1, 2, 3]
              and [e["did"] for e in events] == [did_c, did_b, did_a])
        check("非 ASCII 不转义",
              "机构业务终止".encode("utf-8") in raw
              and b"\\u" not in raw)
        check("字符串按 RFC8259 最短转义",
              '\\"引号\\"与\\\\反斜杠\\n换行\\t制表'.encode("utf-8") in raw)
        full_export_bytes = raw

        # 与查询端点同事件内容一致
        st, r = _http("GET", f"{base}{LIST_PATH}", headers=TA)
        check("与查询端点事件一致",
              st == 200 and r["events"] == events)

        # ---------------------------------------------------------- #
        # 5. 分页与快照续传
        # ---------------------------------------------------------- #
        st, hd, raw = export("limit=2", headers=TA)
        page1 = [json.loads(x) for x in raw.decode().split("\n")[:-1]]
        check("limit=2 首页",
              st == 200 and [e["cursor"] for e in page1] == [1, 2]
              and hd.get("X-Next-After") == "2"
              and hd.get("X-Snapshot-Cursor") == "3")
        st, hd, raw = export("limit=2&after=2", headers=TA)
        page2 = [json.loads(x) for x in raw.decode().split("\n")[:-1]]
        check("after=2 第二页",
              [e["cursor"] for e in page2] == [3]
              and hd.get("X-Next-After") == "3")
        st, hd, raw = export("after=3", headers=TA)
        check("after=末游标空结果零字节且 X-Next-After=after",
              st == 200 and raw == b"" and hd.get("X-Next-After") == "3"
              and hd.get("X-Snapshot-Cursor") == "3")

        # 显式 snapshot 合法：等于/小于最大值
        st, hd, raw = export("snapshot=2", headers=TA)
        ev = [json.loads(x) for x in raw.decode().split("\n")[:-1]]
        check("显式 snapshot=2 仅含 cursor<=2",
              st == 200 and [e["cursor"] for e in ev] == [1, 2]
              and hd.get("X-Snapshot-Cursor") == "2"
              and hd.get("X-Next-After") == "2")
        st, hd, raw = export("snapshot=0", headers=TA)
        check("显式 snapshot=0 空结果",
              st == 200 and raw == b""
              and hd.get("X-Snapshot-Cursor") == "0"
              and hd.get("X-Next-After") == "0")
        expect_400("snapshot 超过当前最大值", "snapshot=4")
        expect_400("snapshot 远超当前最大值", "snapshot=999999")

        # 同 snapshot 续页排除快照后新事件
        st, hd, raw = export("limit=2", headers=TA)
        snap = hd["X-Snapshot-Cursor"]
        check("续传首页快照=3", snap == "3")
        # 快照后新增一条事件（cursor=4）
        did_d = "did:web:exp-d.example"
        priv_d, pub_d = _keypair()
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did_d, "public_key": pub_d, "key_version": 1},
                      headers=TA)
        assert st == 201
        body_d = make_body(did_d, deactivated_at="2026-04-01T00:00:00Z")
        st, r = sync_notice(body_d, priv_d)
        assert st == 201, r
        st, hd, raw = export(f"snapshot={snap}&after=2", headers=TA)
        ev = [json.loads(x) for x in raw.decode().split("\n")[:-1]]
        check("同 snapshot 续页排除后续事件",
              st == 200 and [e["cursor"] for e in ev] == [3]
              and hd.get("X-Snapshot-Cursor") == "3"
              and hd.get("X-Next-After") == "3")
        st, hd, raw = export(headers=TA)
        check("新请求缺省快照读到新最大值 4",
              hd.get("X-Snapshot-Cursor") == "4"
              and hd.get("X-Next-After") == "4"
              and raw.count(b"\n") == 4)
        expect_400("snapshot 超过新最大值", "snapshot=5")

        # ---------------------------------------------------------- #
        # 6. 过滤：did / key_version / from / to（闭区间）
        # ---------------------------------------------------------- #
        st, hd, raw = export(f"did={did_b}", headers=TA)
        ev = [json.loads(x) for x in raw.decode().split("\n")[:-1]]
        check("did 精确过滤",
              len(ev) == 1 and ev[0]["did"] == did_b
              and hd.get("X-Next-After") == "2")
        st, hd, raw = export("did=did:web:not-exist.example", headers=TA)
        check("未知 did 空结果且 X-Next-After=after(0)",
              st == 200 and raw == b"" and hd.get("X-Next-After") == "0"
              and hd.get("X-Snapshot-Cursor") == "4")
        st, _, raw = export("key_version=1", headers=TA)
        ev = [json.loads(x) for x in raw.decode().split("\n")[:-1]]
        check("key_version=1 命中 c,a,d",
              [e["did"] for e in ev] == [did_c, did_a, did_d])
        st, _, raw = export("from=2026-02-01T00:00:00Z&"
                            "to=2026-03-01T00:00:00Z", headers=TA)
        ev = [json.loads(x) for x in raw.decode().split("\n")[:-1]]
        check("from/to 闭区间命中 c,b",
              [e["did"] for e in ev] == [did_c, did_b])
        st, _, raw = export("from=2026-02-01T00:00:00Z&limit=1", headers=TA)
        ev = [json.loads(x) for x in raw.decode().split("\n")[:-1]]
        check("先过滤后分页",
              [e["cursor"] for e in ev] == [1])

        # ---------------------------------------------------------- #
        # 7. 租户隔离与缺省租户
        # ---------------------------------------------------------- #
        st, hd, raw = export(headers=TB)
        check("他租户不可见（零字节、快照 0）",
              st == 200 and raw == b""
              and hd.get("X-Snapshot-Cursor") == "0"
              and hd.get("X-Next-After") == "0")
        st, hd, raw = export()
        check("缺省 default 租户零字节",
              st == 200 and raw == b"" and hd.get("X-Snapshot-Cursor") == "0")
        priv_b2, pub_b2 = _keypair()
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did_b, "public_key": pub_b2, "key_version": 1},
                      headers=TB)
        assert st == 201
        body_b2 = make_body(did_b, key_version=1, reason="租户B停用",
                            deactivated_at="2026-05-01T00:00:00Z")
        st, r = sync_notice(body_b2, priv_b2, headers=TB)
        assert st == 201, r
        st, hd, raw = export(headers=TB)
        ev = [json.loads(x) for x in raw.decode().split("\n")[:-1]]
        check("他租户游标自 1 计起",
              [(e["cursor"], e["did"], e["reason"]) for e in ev]
              == [(1, did_b, "租户B停用")]
              and hd.get("X-Snapshot-Cursor") == "1")
        st, hd, raw = export(headers=TA)
        check("租户 A 不受影响（仍 4 条）",
              raw.count(b"\n") == 4 and hd.get("X-Snapshot-Cursor") == "4")

        # ---------------------------------------------------------- #
        # 8. 纯只读：导出不改游标、状态与审计
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
        st, r = _http("GET", f"{base}{LIST_PATH}", headers=TA)
        check("导出不改游标与事件",
              [e["cursor"] for e in r["events"]] == [1, 2, 3, 4]
              and r["next_after"] == 4)

        # ---------------------------------------------------------- #
        # 9. 跨重启字节一致
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, hd, raw = export(headers=TA)
        check("重启后导出字节一致",
              st == 200 and raw == full_export_bytes + b"".join([
                  (json.dumps({
                      "cursor": 4,
                      "did": did_d,
                      "key_version": 1,
                      "reason": "机构业务终止",
                      "deactivated_at": "2026-04-01T00:00:00Z",
                  }, ensure_ascii=False, separators=(",", ":")) + "\n"
                  ).encode("utf-8")])
              and hd.get("X-Snapshot-Cursor") == "4")
        st, hd, raw = export("snapshot=3", headers=TA)
        check("重启后旧快照仍可用且排除 cursor=4",
              st == 200 and raw == full_export_bytes
              and hd.get("X-Snapshot-Cursor") == "3"
              and hd.get("X-Next-After") == "3")
        st, hd, raw = export(headers=TB)
        check("重启后租户 B 导出稳定",
              raw.count(b"\n") == 1 and hd.get("X-Snapshot-Cursor") == "1")

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
