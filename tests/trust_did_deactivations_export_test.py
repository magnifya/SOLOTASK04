#!/usr/bin/env python3
"""GET /v1/trust/dids/deactivations/export 快照确定性 NDJSON 导出端到端测试。

直接运行：python3 tests/trust_did_deactivations_export_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 仅允许 limit/after/snapshot/did/key_version/from/to 七参数且不得重复，
  空值、未知参数、ASCII 整数/范围非法、UTC 秒精度 Z 时间非法、from>to、
  snapshot 超过当前最大游标均 400 且恰返 {"error": "非空中文原因"}；
- limit 缺省 1000、限 1–10000；snapshot 缺省为请求开始时原子读取的
  租户最大游标（无事件为 0）；
- 200 类型 application/x-ndjson; charset=utf-8；X-Snapshot-Cursor 为
  快照、X-Next-After 为末行 cursor（空结果为 after）；
- 每行紧凑 JSON，键序 cursor、did、key_version、reason、deactivated_at，
  UTF-8 非 ASCII 不转义，LF 结行（末行亦有）、无 BOM，空结果零字节；
- 先过滤后取 after<cursor<=snapshot 的前 limit 条；同 snapshot 续页
  排除后续新事件；租户隔离；只读不改游标；跨重启字节一致。
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


def _http_raw(method, url, headers=None):
    req = urllib.request.Request(url, method=method)
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


EXPORT_PATH = "/v1/trust/dids/deactivations/export"
LIST_PATH = "/v1/trust/dids/deactivations"
SYNC_PATH = "/v1/trust/dids/deactivate-sync"
EVENT_KEYS = ["cursor", "did", "key_version", "reason", "deactivated_at"]
NDJSON_TYPE = "application/x-ndjson; charset=utf-8"


def main():
    port = 8998
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def make_body(did, key_version=1, reason="机构业务终止",
                  deactivated_at="2026-09-20T10:00:00Z"):
        return {
            "did": did,
            "key_version": key_version,
            "reason": reason,
            "deactivated_at": deactivated_at,
        }

    def export(query="", headers=None):
        return _http_raw(
            "GET", f"{base}{EXPORT_PATH}?{query}" if query else
            f"{base}{EXPORT_PATH}", headers=headers
        )

    try:
        assert wait_up(port), "服务启动超时"

        TA = {"X-Tenant-ID": "tenant-a"}
        TB = {"X-Tenant-ID": "tenant-b"}

        # ---------------------------------------------------------- #
        # 1. 无事件：200 零字节，快照 0，next_after=after
        # ---------------------------------------------------------- #
        st, hd, body = export(headers=TA)
        check("无事件 200 零字节且类型为 NDJSON",
              st == 200 and body == b""
              and hd.get("Content-Type") == NDJSON_TYPE)
        check("无事件 X-Snapshot-Cursor=0 且 X-Next-After=0",
              hd.get("X-Snapshot-Cursor") == "0"
              and hd.get("X-Next-After") == "0")
        st, hd, body = export("after=5", headers=TA)
        check("无事件空结果 X-Next-After=after",
              st == 200 and body == b"" and hd.get("X-Next-After") == "5")

        # ---------------------------------------------------------- #
        # 2. 参数非法 -> 400 且恰返非空中文 error
        # ---------------------------------------------------------- #
        def expect_400(name, query, headers=None):
            st, hd, raw = export(query, headers=headers)
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
        expect_400("snapshot 空值", "snapshot=")
        expect_400("snapshot 负数", "snapshot=-1")
        expect_400("snapshot 字母", "snapshot=abc")
        expect_400("snapshot 小数", "snapshot=1.0")
        expect_400("snapshot 符号", "snapshot=%2B1")
        expect_400("snapshot 空白", "snapshot=%20")
        expect_400("snapshot 重复", "snapshot=0&snapshot=1")
        expect_400("snapshot 超当前最大游标", "snapshot=1")
        after_bad = ["", "-1", "1.0", "true", "01x", "%20", "%2B1"]
        for val in after_bad:
            expect_400(f"after={val!r}", f"after={val}")
        expect_400("after 重复", "after=0&after=1")
        expect_400("did 空值", "did=")
        expect_400("did 重复", "did=a&did=b")
        expect_400("key_version 空值", "key_version=")
        expect_400("key_version=0", "key_version=0")
        expect_400("key_version 负数", "key_version=-1")
        expect_400("key_version 小数", "key_version=1.0")
        expect_400("key_version 重复", "key_version=1&key_version=2")
        expect_400("from 空值", "from=")
        expect_400("from 缺 Z", "from=2026-01-01T00:00:00")
        expect_400("from 毫秒", "from=2026-01-01T00:00:00.0Z")
        expect_400("from 偏移", "from=2026-01-01T00:00:00%2B00:00")
        expect_400("from 非法日期", "from=2026-13-01T00:00:00Z")
        expect_400("to 非法时刻", "to=2026-01-01T24:00:00Z")
        expect_400("from 晚于 to",
                   "from=2026-03-01T00:00:00Z&to=2026-02-01T00:00:00Z")
        expect_400("from 重复",
                   "from=2026-01-01T00:00:00Z&from=2026-02-01T00:00:00Z")
        expect_400("显式空 X-Tenant-ID", "", headers={"X-Tenant-ID": ""})

        # ---------------------------------------------------------- #
        # 3. 准备锚点与通告：接受顺序 c, b, a
        # ---------------------------------------------------------- #
        did_a = "did:web:export-a.example"
        did_b = "did:web:export-b.example"
        did_c = "did:web:export-c.example"
        priv_a, pub_a = _keypair()
        priv_b, pub_b = _keypair()
        priv_c, pub_c = _keypair()
        for did, pub, ver in ((did_a, pub_a, 1), (did_b, pub_b, 2),
                              (did_c, pub_c, 1)):
            st, _ = _http("POST", f"{base}/v1/trust/anchors",
                          {"did": did, "public_key": pub,
                           "key_version": ver}, headers=TA)
            assert st == 201, did

        body_c = make_body(did_c, deactivated_at="2026-03-01T00:00:00Z")
        body_b = make_body(did_b, key_version=2,
                           deactivated_at="2026-02-01T00:00:00Z")
        body_a = make_body(did_a, deactivated_at="2026-01-01T00:00:00Z")
        for body, priv in ((body_c, priv_c), (body_b, priv_b),
                           (body_a, priv_a)):
            st, r = _http("POST", f"{base}{SYNC_PATH}",
                          {"body": body, "signature": crypto.sign(body, priv)},
                          headers=TA)
            assert st == 201, r

        # ---------------------------------------------------------- #
        # 4. 全量导出：行格式、键序、头与字节形状
        # ---------------------------------------------------------- #
        st, hd, body = export(headers=TA)
        check("全量 200 且类型 NDJSON",
              st == 200 and hd.get("Content-Type") == NDJSON_TYPE)
        check("缺省 snapshot 为当前最大游标 3",
              hd.get("X-Snapshot-Cursor") == "3")
        check("X-Next-After 为末行 cursor 3",
              hd.get("X-Next-After") == "3")
        check("无 BOM", not body.startswith(b"\xef\xbb\xbf"))
        check("每行 LF 结行且末行亦有 LF",
              body.endswith(b"\n") and body.count(b"\n") == 3
              and b"\r" not in body)
        lines = body.decode("utf-8").splitlines()
        events = [json.loads(line) for line in lines]
        check("三行事件", len(events) == 3)
        check("行内键序 cursor,did,key_version,reason,deactivated_at",
              all(list(e.keys()) == EVENT_KEYS for e in events))
        check("行内字段类型",
              all(type(e["cursor"]) is int and type(e["key_version"]) is int
                  and isinstance(e["did"], str)
                  and isinstance(e["reason"], str)
                  and isinstance(e["deactivated_at"], str)
                  for e in events))
        check("cursor 按接受顺序 1,2,3",
              [e["cursor"] for e in events] == [1, 2, 3])
        check("按接受顺序（与 deactivated_at 顺序无关）",
              [(e["did"], e["key_version"], e["deactivated_at"])
               for e in events] == [
                  (did_c, 1, "2026-03-01T00:00:00Z"),
                  (did_b, 2, "2026-02-01T00:00:00Z"),
                  (did_a, 1, "2026-01-01T00:00:00Z"),
              ])
        check("紧凑 JSON（无空白分隔）",
              lines[0].startswith('{"cursor":1,"did":"')
              and '": "' not in lines[0] and '": ' not in lines[0])
        check("非 ASCII 不转义（UTF-8 原文）",
              "机构业务终止".encode("utf-8") in body
              and b"\\u" not in body)
        full_body = body

        # ---------------------------------------------------------- #
        # 5. 显式 snapshot 与分页
        # ---------------------------------------------------------- #
        st, hd, body = export("snapshot=2", headers=TA)
        ev = [json.loads(x) for x in body.decode().splitlines()]
        check("显式 snapshot=2 仅含 cursor 1,2",
              st == 200 and [e["cursor"] for e in ev] == [1, 2]
              and hd.get("X-Snapshot-Cursor") == "2"
              and hd.get("X-Next-After") == "2")
        st, hd, body = export("snapshot=0", headers=TA)
        check("snapshot=0 空结果零字节",
              st == 200 and body == b""
              and hd.get("X-Snapshot-Cursor") == "0"
              and hd.get("X-Next-After") == "0")
        expect_400("snapshot 超过最大值 3", "snapshot=4")

        st, hd, page1 = export("limit=2", headers=TA)
        ev1 = [json.loads(x) for x in page1.decode().splitlines()]
        check("limit=2 首页",
              st == 200 and [e["cursor"] for e in ev1] == [1, 2]
              and hd.get("X-Snapshot-Cursor") == "3"
              and hd.get("X-Next-After") == "2")
        st, hd, page2 = export("limit=2&after=2&snapshot=3", headers=TA)
        ev2 = [json.loads(x) for x in page2.decode().splitlines()]
        check("after=2&snapshot=3 第二页",
              [e["cursor"] for e in ev2] == [3]
              and hd.get("X-Next-After") == "3")
        st, hd, page3 = export("after=3&snapshot=3", headers=TA)
        check("after=末游标空页零字节且 X-Next-After=after",
              st == 200 and page3 == b"" and hd.get("X-Next-After") == "3")
        st, hd, body = export("limit=10000", headers=TA)
        check("limit=10000 合法且容纳全部",
              st == 200 and body.count(b"\n") == 3)
        st, hd, body = export("limit=1000", headers=TA)
        check("limit 缺省值同 1000",
              st == 200 and body == full_body)

        # ---------------------------------------------------------- #
        # 6. 过滤：did / key_version / from / to（闭区间）
        # ---------------------------------------------------------- #
        st, hd, body = export(f"did={did_b}", headers=TA)
        ev = [json.loads(x) for x in body.decode().splitlines()]
        check("did 精确过滤",
              len(ev) == 1 and ev[0]["did"] == did_b
              and hd.get("X-Next-After") == "2")
        st, hd, body = export("did=did:web:not-exist.example", headers=TA)
        check("未知 did 空结果零字节且 X-Next-After=after(0)",
              st == 200 and body == b"" and hd.get("X-Next-After") == "0")
        st, hd, body = export("key_version=2", headers=TA)
        ev = [json.loads(x) for x in body.decode().splitlines()]
        check("key_version 精确过滤",
              len(ev) == 1 and ev[0]["did"] == did_b)
        st, hd, body = export("from=2026-02-01T00:00:00Z", headers=TA)
        ev = [json.loads(x) for x in body.decode().splitlines()]
        check("from 闭区间（含边界 b）",
              [e["did"] for e in ev] == [did_c, did_b])
        st, hd, body = export("to=2026-02-01T00:00:00Z", headers=TA)
        ev = [json.loads(x) for x in body.decode().splitlines()]
        check("to 闭区间（含边界 b）",
              [e["did"] for e in ev] == [did_b, did_a])
        st, hd, body = export(
            "from=2026-02-01T00:00:00Z&to=2026-02-01T00:00:00Z",
            headers=TA)
        ev = [json.loads(x) for x in body.decode().splitlines()]
        check("from==to 仅边界 b", [e["did"] for e in ev] == [did_b])
        st, hd, body = export(
            f"did={did_b}&key_version=2&from=2026-01-01T00:00:00Z"
            "&to=2026-12-31T00:00:00Z", headers=TA)
        ev = [json.loads(x) for x in body.decode().splitlines()]
        check("组合过滤命中", len(ev) == 1 and ev[0]["did"] == did_b)
        st, hd, body = export(f"did={did_b}&key_version=1", headers=TA)
        check("组合过滤无命中空结果",
              st == 200 and body == b"" and hd.get("X-Next-After") == "0")
        # 先过滤后分页：from 命中 c,b（游标 1,2），limit=1
        st, hd, body = export("from=2026-02-01T00:00:00Z&limit=1",
                              headers=TA)
        ev = [json.loads(x) for x in body.decode().splitlines()]
        check("先过滤后分页",
              [e["cursor"] for e in ev] == [1]
              and hd.get("X-Next-After") == "1")
        st, hd, body = export(
            "from=2026-02-01T00:00:00Z&limit=1&after=1", headers=TA)
        ev = [json.loads(x) for x in body.decode().splitlines()]
        check("先过滤后分页第二页",
              [e["cursor"] for e in ev] == [2]
              and hd.get("X-Next-After") == "2")

        # ---------------------------------------------------------- #
        # 7. 同 snapshot 续页排除后续事件
        # ---------------------------------------------------------- #
        st, hd, snap_page = export("limit=3", headers=TA)
        snap = hd["X-Snapshot-Cursor"]
        check("取快照 3", snap == "3")
        # 快照后新接受一条通告（cursor 4）
        did_d = "did:web:export-d.example"
        priv_d, pub_d = _keypair()
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did_d, "public_key": pub_d, "key_version": 1},
                      headers=TA)
        assert st == 201
        body_d = make_body(did_d, deactivated_at="2026-04-01T00:00:00Z")
        st, r = _http("POST", f"{base}{SYNC_PATH}",
                      {"body": body_d,
                       "signature": crypto.sign(body_d, priv_d)}, headers=TA)
        assert st == 201, r
        st, hd, body = export(f"after=3&snapshot={snap}", headers=TA)
        check("同 snapshot 续页排除后续事件（零字节）",
              st == 200 and body == b""
              and hd.get("X-Snapshot-Cursor") == "3"
              and hd.get("X-Next-After") == "3")
        st, hd, body = export(headers=TA)
        check("新快照缺省为 4 且含新事件",
              hd.get("X-Snapshot-Cursor") == "4"
              and hd.get("X-Next-After") == "4"
              and body.count(b"\n") == 4)
        expect_400("snapshot 超过新最大值 4", "snapshot=5")
        full_body4 = body

        # ---------------------------------------------------------- #
        # 8. 租户隔离与只读
        # ---------------------------------------------------------- #
        st, hd, body = export(headers=TB)
        check("他租户不可见（零字节，快照 0）",
              st == 200 and body == b""
              and hd.get("X-Snapshot-Cursor") == "0")
        st, hd, body = export()
        check("缺省租户 default 空结果", st == 200 and body == b"")
        # 导出为只读：列表游标与事件不变
        st, r = _http("GET", f"{base}{LIST_PATH}", headers=TA)
        check("导出后列表游标不变（只读）",
              st == 200 and [e["cursor"] for e in r["events"]] == [1, 2, 3, 4]
              and r["next_after"] == 4)

        # ---------------------------------------------------------- #
        # 9. 跨重启字节一致
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(port), "服务重启超时"
        st, hd, body = export(headers=TA)
        check("重启后导出字节一致",
              st == 200 and body == full_body4
              and hd.get("X-Snapshot-Cursor") == "4"
              and hd.get("X-Next-After") == "4")
        st, hd, body = export("snapshot=2", headers=TA)
        check("重启后显式 snapshot 字节一致",
              st == 200
              and body == b"".join(
                  line + b"\n"
                  for line in full_body4.split(b"\n")[:2]
              ))

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
