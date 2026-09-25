#!/usr/bin/env python3
"""GET /v1/trust/dids/deactivations 外部 DID 停用通告审计查询端到端测试。

直接运行：python3 tests/trust_did_deactivations_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 仅允许 limit/after/did/key_version/from/to 六参数且不得重复，空值、
  未知参数、ASCII 整数/范围非法、UTC 秒精度 Z 时间非法、from>to 均 400
  且恰返 {"error": "非空中文原因"}；
- X-Tenant-ID 缺省 default、显式空 400、仅返本租户事件，无结果仍 200；
- 首次接受通告即原子追加审计事件；完全重放、锚点/签名失败、同 did
  异通告 409 均不追加；
- 先按 did、key_version 精确过滤及 deactivated_at 闭区间过滤，再按
  cursor>after 升序分页；limit 缺省 50、限 1–200，after 缺省 0；
- 200 键序 events、next_after；事件键序 cursor、did、key_version、
  reason、deactivated_at（整数/字符串/整数/字符串/字符串）；空页
  next_after=after，否则取页末 cursor；
- 旧通告加载时按 (deactivated_at, did) 升序补录，迁移原子、重启后
  cursor 不变；
- 批量逐项提交：仅首次接受的项追加事件，其余成功（重放）/失败不追加。
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


def _http(method, url, payload=None, headers=None, raw=None):
    if raw is not None:
        data = raw
    else:
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


LIST_PATH = "/v1/trust/dids/deactivations"
SYNC_PATH = "/v1/trust/dids/deactivate-sync"
BATCH_PATH = "/v1/trust/dids/deactivate-sync-batch"
EVENT_KEYS = ["cursor", "did", "key_version", "reason", "deactivated_at"]


def main():
    port = 8999
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

    def listing(query="", headers=None):
        return _http(
            "GET", f"{base}{LIST_PATH}?{query}" if query else
            f"{base}{LIST_PATH}", headers=headers
        )

    try:
        assert wait_up(port), "服务启动超时"

        TA = {"X-Tenant-ID": "tenant-a"}
        TB = {"X-Tenant-ID": "tenant-b"}

        # ---------------------------------------------------------- #
        # 1. 无通告：仍 200 空页，键序固定
        # ---------------------------------------------------------- #
        st, r = listing(headers=TA)
        check("无结果 200 空页且键序 events,next_after",
              st == 200 and list(r.keys()) == ["events", "next_after"]
              and r["events"] == [] and r["next_after"] == 0)

        # ---------------------------------------------------------- #
        # 2. 参数非法 -> 400 且恰返非空中文 error
        # ---------------------------------------------------------- #
        def expect_400(name, query, headers=None):
            st, r = listing(query, headers=headers)
            check(f"400 仅 error 非空中文: {name}",
                  st == 400 and list(r.keys()) == ["error"]
                  and isinstance(r["error"], str) and bool(r["error"]))

        expect_400("未知参数", "unknown=1")
        expect_400("limit 空值", "limit=")
        expect_400("limit 重复", "limit=1&limit=2")
        expect_400("limit=0", "limit=0")
        expect_400("limit=201", "limit=201")
        expect_400("limit 字母", "limit=abc")
        expect_400("limit 小数", "limit=1.5")
        expect_400("limit 符号", "limit=%2B1")
        expect_400("limit 布尔", "limit=true")
        expect_400("limit 空白", "limit=%20")
        expect_400("limit Unicode 数字", "limit=%E0%A9%91")
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
        expect_400("key_version 布尔", "key_version=true")
        expect_400("key_version 重复", "key_version=1&key_version=2")
        expect_400("from 空值", "from=")
        expect_400("from 缺 Z", "from=2026-01-01T00:00:00")
        expect_400("from 毫秒", "from=2026-01-01T00:00:00.0Z")
        expect_400("from 偏移", "from=2026-01-01T00:00:00%2B00:00")
        expect_400("from 非法日期", "from=2026-13-01T00:00:00Z")
        expect_400("from 未补零", "from=2026-1-1T00:00:00Z")
        expect_400("to 非法时刻", "to=2026-01-01T24:00:00Z")
        expect_400("from 晚于 to",
                   "from=2026-03-01T00:00:00Z&to=2026-02-01T00:00:00Z")
        expect_400("from 重复",
                   "from=2026-01-01T00:00:00Z&from=2026-02-01T00:00:00Z")

        # 显式空租户头 -> 400
        expect_400("显式空 X-Tenant-ID", "", headers={"X-Tenant-ID": ""})

        # ---------------------------------------------------------- #
        # 3. 准备锚点与通告：接受顺序 c, b, a（与时间顺序不同）
        # ---------------------------------------------------------- #
        did_a, did_b, did_c = (
            "did:web:audit-a.example",
            "did:web:audit-b.example",
            "did:web:audit-c.example",
        )
        priv_a, pub_a = _keypair()
        priv_b, pub_b = _keypair()
        priv_c, pub_c = _keypair()
        # a/c 用 v1；b 注册为 v2 锚点，通告 key_version=2
        for did, pub, ver in ((did_a, pub_a, 1), (did_b, pub_b, 2),
                              (did_c, pub_c, 1)):
            st, _ = _http("POST", f"{base}/v1/trust/anchors",
                          {"did": did, "public_key": pub,
                           "key_version": ver}, headers=TA)
            assert st == 201, did

        def sync_notice(did, priv, **kw):
            body = make_body(did, **kw)
            return _http("POST", f"{base}{SYNC_PATH}",
                         {"body": body, "signature": crypto.sign(body, priv)},
                         headers=TA)

        body_c = make_body(did_c, deactivated_at="2026-03-01T00:00:00Z")
        body_b = make_body(did_b, key_version=2,
                           deactivated_at="2026-02-01T00:00:00Z")
        body_a = make_body(did_a, deactivated_at="2026-01-01T00:00:00Z")
        st, r = _http("POST", f"{base}{SYNC_PATH}",
                      {"body": body_c,
                       "signature": crypto.sign(body_c, priv_c)}, headers=TA)
        assert st == 201, r
        st, r = _http("POST", f"{base}{SYNC_PATH}",
                      {"body": body_b,
                       "signature": crypto.sign(body_b, priv_b)}, headers=TA)
        assert st == 201, r
        st, r = _http("POST", f"{base}{SYNC_PATH}",
                      {"body": body_a,
                       "signature": crypto.sign(body_a, priv_a)}, headers=TA)
        assert st == 201, r

        # ---------------------------------------------------------- #
        # 4. 列表：cursor 按接受顺序升序、键序与类型固定
        # ---------------------------------------------------------- #
        st, r = listing(headers=TA)
        check("三条事件 200", st == 200 and len(r["events"]) == 3)
        check("顶层键序 events,next_after", list(r.keys()) == ["events", "next_after"])
        expect_order = [
            (did_c, 1, "2026-03-01T00:00:00Z"),
            (did_b, 2, "2026-02-01T00:00:00Z"),
            (did_a, 1, "2026-01-01T00:00:00Z"),
        ]
        ok_shape = (
            all(list(e.keys()) == EVENT_KEYS for e in r["events"])
            and all(type(e["cursor"]) is int for e in r["events"])
            and all(type(e["key_version"]) is int for e in r["events"])
            and all(isinstance(e["did"], str)
                    and isinstance(e["reason"], str)
                    and isinstance(e["deactivated_at"], str)
                    for e in r["events"])
        )
        check("事件键序与类型", ok_shape)
        check("cursor 正整数且升序连续",
              [e["cursor"] for e in r["events"]] == [1, 2, 3])
        check("按接受顺序（与 deactivated_at 顺序无关）",
              [(e["did"], e["key_version"], e["deactivated_at"])
               for e in r["events"]] == expect_order)
        check("页满 next_after 取页末 cursor", r["next_after"] == 3)

        # ---------------------------------------------------------- #
        # 5. 重放/失败/冲突均不追加
        # ---------------------------------------------------------- #
        # 完全重放 200
        st, r2 = _http("POST", f"{base}{SYNC_PATH}",
                       {"body": body_a,
                        "signature": crypto.sign(body_a, priv_a)}, headers=TA)
        check("完全重放 200", st == 200 and r2["valid"] is True)
        # 签名失败 200 valid:false
        st, r2 = sync_notice(did_c, priv_a,
                             deactivated_at="2026-03-01T00:00:00Z")
        check("锚点同 did 但签名不匹配 -> 200 验签失败",
              st == 200 and r2["valid"] is False)
        # 同 did 异通告冲突 409
        body_conflict = make_body(
            did_a, reason="其他原因",
            deactivated_at="2026-01-01T00:00:00Z")
        st, r2 = _http("POST", f"{base}{SYNC_PATH}",
                       {"body": body_conflict,
                        "signature": crypto.sign(body_conflict, priv_a)},
                       headers=TA)
        check("同 did 异通告 409", st == 409 and "error" in r2)
        st, r = listing(headers=TA)
        check("重放/失败/冲突均不追加事件",
              len(r["events"]) == 3
              and [e["cursor"] for e in r["events"]] == [1, 2, 3])

        # ---------------------------------------------------------- #
        # 6. 过滤：did / key_version / from / to（闭区间）
        # ---------------------------------------------------------- #
        st, r = listing(f"did={did_b}", headers=TA)
        check("did 精确过滤",
              st == 200 and len(r["events"]) == 1
              and r["events"][0]["did"] == did_b
              and r["next_after"] == 2)
        st, r = listing("did=did:web:not-exist.example", headers=TA)
        check("未知 did 空页 200 且 next_after=after(0)",
              st == 200 and r["events"] == [] and r["next_after"] == 0)
        st, r = listing("key_version=2", headers=TA)
        check("key_version 精确过滤",
              len(r["events"]) == 1 and r["events"][0]["did"] == did_b)
        st, r = listing("key_version=1", headers=TA)
        check("key_version=1 命中 a,c",
              [e["did"] for e in r["events"]] == [did_c, did_a])
        st, r = listing("from=2026-02-01T00:00:00Z", headers=TA)
        check("from 闭区间（含边界 b）",
              [e["did"] for e in r["events"]] == [did_c, did_b])
        st, r = listing("to=2026-02-01T00:00:00Z", headers=TA)
        check("to 闭区间（含边界 b）",
              [e["did"] for e in r["events"]] == [did_b, did_a])
        st, r = listing(
            "from=2026-02-01T00:00:00Z&to=2026-02-01T00:00:00Z",
            headers=TA)
        check("from==to 仅边界 b",
              [e["did"] for e in r["events"]] == [did_b])
        st, r = listing(
            f"did={did_b}&key_version=2&from=2026-01-01T00:00:00Z"
            "&to=2026-12-31T00:00:00Z", headers=TA)
        check("组合过滤命中", len(r["events"]) == 1
              and r["events"][0]["did"] == did_b)
        st, r = listing(
            f"did={did_b}&key_version=1", headers=TA)
        check("组合过滤无命中空页", r["events"] == []
              and r["next_after"] == 0)

        # ---------------------------------------------------------- #
        # 7. 分页：limit/after 按 cursor 升序
        # ---------------------------------------------------------- #
        st, page1 = listing("limit=2", headers=TA)
        check("limit=2 首页",
              st == 200 and [e["cursor"] for e in page1["events"]] == [1, 2]
              and page1["next_after"] == 2)
        st, page2 = listing("limit=2&after=2", headers=TA)
        check("after=2 第二页",
              [e["cursor"] for e in page2["events"]] == [3]
              and page2["next_after"] == 3)
        st, page3 = listing("after=3", headers=TA)
        check("after=末游标空页 next_after=after",
              page3["events"] == [] and page3["next_after"] == 3)
        st, page_all = listing("limit=200", headers=TA)
        check("limit=200 合法且容纳全部",
              len(page_all["events"]) == 3)
        st, page_f = listing("limit=50", headers=TA)
        check("limit 缺省值同 50",
              [e["cursor"] for e in page_f["events"]] == [1, 2, 3])

        # 先过滤后分页：from 命中 c,b（游标 1,2），limit=1
        st, r = listing("from=2026-02-01T00:00:00Z&limit=1", headers=TA)
        check("先过滤后分页",
              [e["cursor"] for e in r["events"]] == [1]
              and r["next_after"] == 1)
        st, r = listing("from=2026-02-01T00:00:00Z&limit=1&after=1",
                        headers=TA)
        check("先过滤后分页第二页",
              [e["cursor"] for e in r["events"]] == [2]
              and r["next_after"] == 2)

        # ---------------------------------------------------------- #
        # 8. 租户隔离
        # ---------------------------------------------------------- #
        st, r = listing(headers=TB)
        check("他租户不可见", st == 200 and r["events"] == [])
        # 他租户同名 DID 各自独立
        priv_b2, pub_b2 = _keypair()
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did_b, "public_key": pub_b2, "key_version": 1},
                      headers=TB)
        assert st == 201
        body_b2 = make_body(did_b, key_version=1,
                            reason="租户B停用",
                            deactivated_at="2026-05-01T00:00:00Z")
        st, r = _http("POST", f"{base}{SYNC_PATH}",
                      {"body": body_b2,
                       "signature": crypto.sign(body_b2, priv_b2)},
                      headers=TB)
        check("他租户首次接受 201", st == 201)
        st, r = listing(headers=TB)
        check("他租户游标自 1 计起且仅本租户事件",
              [(e["cursor"], e["did"], e["reason"]) for e in r["events"]]
              == [(1, did_b, "租户B停用")])
        st, r = listing(headers=TA)
        check("租户 A 不受影响（仍 3 条）",
              len(r["events"]) == 3
              and all(e["reason"] == "机构业务终止" for e in r["events"]))

        # 缺省 default 租户
        st, r = listing()
        check("缺省租户 default 空页", st == 200 and r["events"] == [])

        # ---------------------------------------------------------- #
        # 9. 批量逐项提交：仅首次接受追加，重放/失败不追加
        # ---------------------------------------------------------- #
        did_d = "did:web:audit-d.example"
        did_e = "did:web:audit-e.example"
        did_ghost = "did:web:audit-ghost.example"
        priv_d, pub_d = _keypair()
        priv_e, pub_e = _keypair()
        for d, p in ((did_d, pub_d), (did_e, pub_e)):
            st, _ = _http("POST", f"{base}/v1/trust/anchors",
                          {"did": d, "public_key": p, "key_version": 1},
                          headers=TA)
            assert st == 201
        item_first = {"body": make_body(did_d,
                                        deactivated_at="2026-04-01T00:00:00Z"),
                      "signature": crypto.sign(
                          make_body(did_d,
                                    deactivated_at="2026-04-01T00:00:00Z"),
                          priv_d)}
        item_replay = {"body": body_a,
                       "signature": crypto.sign(body_a, priv_a)}
        item_no_anchor = {"body": make_body(did_ghost),
                          "signature": crypto.sign(make_body(did_ghost),
                                                   priv_d)}
        item_bad_field = {"body": make_body(did_e, key_version=0),
                          "signature": "x"}
        items = [item_first, item_replay, item_no_anchor, item_bad_field]
        st, r = _http("POST", f"{base}{BATCH_PATH}",
                      {"items": items}, headers=TA)
        check("批量 200 等长不短路",
              st == 200 and len(r["results"]) == 4
              and [x["http_status"] for x in r["results"]] == [201, 200, 200, 400])
        st, r = listing(headers=TA)
        check("批量仅首次接受项追加一条事件",
              [e["did"] for e in r["events"]]
              == [did_c, did_b, did_a, did_d]
              and [e["cursor"] for e in r["events"]] == [1, 2, 3, 4])

        # ---------------------------------------------------------- #
        # 10. 重启稳定
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
        st, r = listing(headers=TA)
        check("重启后事件与 cursor 稳定",
              st == 200
              and [(e["cursor"], e["did"]) for e in r["events"]]
              == [(1, did_c), (2, did_b), (3, did_a), (4, did_d)])
        st, rb = listing(headers=TB)
        check("重启后租户 B 事件稳定",
              [(e["cursor"], e["did"]) for e in rb["events"]]
              == [(1, did_b)])

        # ---------------------------------------------------------- #
        # 11. 旧通告补录迁移：删除事件与游标字段后重启
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        with open(store, "r", encoding="utf-8") as fh:
            legacy = json.load(fh)
        for bucket in legacy["tenants"].values():
            bucket.pop("did_deactivation_events", None)
        legacy.pop("did_deactivation_event_cursors", None)
        with open(store, "w", encoding="utf-8") as fh:
            json.dump(legacy, fh, ensure_ascii=False, sort_keys=True)

        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(port), "迁移后服务启动超时"
        st, r = listing(headers=TA)
        # 按 (deactivated_at, did) 升序：a(01-01), d(04-01), b(02-01?)
        order_a = sorted(
            [(did_a, "2026-01-01T00:00:00Z"),
             (did_b, "2026-02-01T00:00:00Z"),
             (did_c, "2026-03-01T00:00:00Z"),
             (did_d, "2026-04-01T00:00:00Z")],
            key=lambda x: (x[1], x[0]),
        )
        check("旧通告按 deactivated_at,did 补录",
              st == 200 and len(r["events"]) == 4
              and [(e["did"], e["deactivated_at"]) for e in r["events"]]
              == order_a
              and [e["cursor"] for e in r["events"]] == [1, 2, 3, 4])
        st, rb = listing(headers=TB)
        check("补录租户隔离且各自从 1 计",
              [(e["cursor"], e["did"]) for e in rb["events"]]
              == [(1, did_b)])

        # 补录期间只读不落盘：再重启仍按相同顺序重建为相同 cursor
        proc.terminate()
        proc.wait(timeout=10)
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(port), "二次重启超时"
        st, r2 = listing(headers=TA)
        check("无写操作二次重启 cursor 不变",
              [(e["cursor"], e["did"]) for e in r2["events"]]
              == [(e["cursor"], e["did"]) for e in r["events"]])

        # 补录后新接受通告 cursor 接续
        did_f = "did:web:audit-f.example"
        priv_f, pub_f = _keypair()
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did_f, "public_key": pub_f, "key_version": 1},
                      headers=TA)
        assert st == 201
        body_f = make_body(did_f, deactivated_at="2026-05-15T00:00:00Z")
        st, rf = _http("POST", f"{base}{SYNC_PATH}",
                       {"body": body_f,
                        "signature": crypto.sign(body_f, priv_f)}, headers=TA)
        check("补录后首次接受 201 且 cursor 接续为 5",
              st == 201)
        st, r = listing(f"did={did_f}", headers=TA)
        check("新事件 cursor=5",
              len(r["events"]) == 1 and r["events"][0]["cursor"] == 5
              and r["next_after"] == 5)

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
