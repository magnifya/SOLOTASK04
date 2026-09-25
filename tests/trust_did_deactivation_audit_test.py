#!/usr/bin/env python3
"""GET /v1/trust/dids/deactivations 外部 DID 停用通告审计查询端到端测试。

直接运行：python3 tests/trust_did_deactivation_audit_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 仅首次接受追加审计事件（与通告同一次原子写）：重放、冲突、锚点/
  签名失败均不追加；批量逐项提交，失败项不追加、成功项按提交顺序
  获得游标；
- cursor 为租户内跨 DID 递增正整数，跨租户独立；
- 旧状态文件（有通告无审计事件）加载时按 deactivated_at、did 升序
  补录，内存补录只读可见，重启后 cursor 稳定，落盘后仍稳定；
- 六参数白名单、不得重复、空值/格式/范围非法均 400 且仅含非空
  中文 error；
- 先 did/key_version 精确过滤与 deactivated_at 闭区间过滤，再
  cursor>after 升序分页；空页 next_after=after，默认 limit 50；
- 200 顶层键序 events、next_after；事件键序
  cursor,did,key_version,reason,deactivated_at，类型正确；
- X-Tenant-ID 缺省 default、显式空值 400、跨租户隔离，无结果 200。
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
        data = json.dumps(payload).encode() if payload is not None else b""
    req = urllib.request.Request(url, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def _http_json(method, url, payload=None, **kwargs):
    status, text = _http(method, url, payload=payload, **kwargs)
    return status, json.loads(text or "{}"), text


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


SYNC_PATH = "/v1/trust/dids/deactivate-sync"
BATCH_PATH = "/v1/trust/dids/deactivate-sync-batch"
LIST_PATH = "/v1/trust/dids/deactivations"

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


def main():
    port = 8999
    store_path = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store_path)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    TA = {"X-Tenant-ID": "tenant-a"}
    TB = {"X-Tenant-ID": "tenant-b"}
    try:
        assert wait_up(port), "服务启动超时"

        def list_get(query="", headers=TA):
            return _http_json("GET", f"{base}{LIST_PATH}?{query}",
                              headers=headers)

        # ---- 无数据：200 空页 ----
        st, r, text = list_get()
        check("无数据 200 空页 next_after=0",
              st == 200 and r == {"events": [], "next_after": 0})
        check("无数据顶层键序 events,next_after",
              json.loads(
                  text, object_pairs_hook=lambda p: [k for k, _ in p]
              ) == ["events", "next_after"])

        # ---- 准备锚点与通告 ----
        priv_a1, pub_a1 = _keypair()
        priv_a2, pub_a2 = _keypair()
        priv_b, pub_b = _keypair()
        did1 = "did:web:d1.example"
        did2 = "did:web:d2.example"
        did3 = "did:web:d3.example"
        for did, pub in ((did1, pub_a1), (did2, pub_a1), (did3, pub_a2)):
            st, _, _ = _http_json(
                "POST", f"{base}/v1/trust/anchors",
                {"did": did, "public_key": pub, "key_version": 1},
                headers=TA)
            assert st == 201, (did,)
        st, _, _ = _http_json(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did1, "public_key": pub_b, "key_version": 1},
            headers=TB)
        assert st == 201

        def body(did, kv=1, reason="机构业务终止", ts="2026-09-20T10:00:00Z"):
            return {"did": did, "key_version": kv, "reason": reason,
                    "deactivated_at": ts}

        def sync_ok(b, priv=priv_a1, headers=TA):
            return _http_json(
                "POST", f"{base}{SYNC_PATH}",
                {"body": b, "signature": crypto.sign(b, priv)},
                headers=headers)

        # did1 首次接受 -> 201
        b1 = body(did1, ts="2026-09-20T10:00:00Z")
        st, r, _ = sync_ok(b1)
        check("did1 首次接受 201", st == 201)
        # 完全重放 -> 200 不追加
        st, r2, _ = sync_ok(b1)
        check("did1 完全重放 200", st == 200)
        # 不同通告 -> 409 不追加
        st, err, _ = sync_ok(body(did1, reason="其他原因"))
        check("did1 异通告 409", st == 409 and set(err) == {"error"})
        # 锚点缺失（未注册的 did）-> 200 valid:false 不追加
        st, miss, _ = sync_ok(body("did:web:nope.example"),
                              priv=priv_a1)
        check("锚点缺失 valid:false 不追加",
              st == 200 and miss.get("valid") is False)
        # 签名错误 -> 不追加
        st, badsig, _ = _http_json(
            "POST", f"{base}{SYNC_PATH}",
            {"body": body(did2),
             "signature": crypto.sign(body(did2, reason="不同内容"), priv_a1)},
            headers=TA)
        check("签名校验失败 valid:false 不追加",
              st == 200 and badsig.get("valid") is False)

        # did2 首次接受 -> 201，cursor 递增
        b2 = body(did2, reason="迁移关停", ts="2026-09-19T08:30:00Z")
        st, _, _ = sync_ok(b2)
        check("did2 首次接受 201", st == 201)

        # did3 使用 priv_a2
        b3 = body(did3, reason="到期终止", ts="2026-09-20T10:00:00Z")
        st, _, _ = sync_ok(b3, priv=priv_a2)
        check("did3 首次接受 201", st == 201)

        # 租户 B 的同 did1 通告：独立游标
        bb = body(did1, reason="租户B终止", ts="2026-09-18T00:00:00Z")
        st, _, _ = sync_ok(bb, priv=priv_b, headers=TB)
        check("租户B did1 首次接受 201", st == 201)

        # ---- 批量：逐项提交，失败不短路不追加 ----
        did4, did5, did6 = ("did:web:d4.example", "did:web:d5.example",
                            "did:web:d6.example")
        for did in (did4, did5, did6):
            st, _, _ = _http_json(
                "POST", f"{base}/v1/trust/anchors",
                {"did": did, "public_key": pub_a1, "key_version": 1},
                headers=TA)
            assert st == 201
        items = [
            {"body": body(did4, ts="2026-09-21T00:00:00Z"),
             "signature": crypto.sign(body(did4, ts="2026-09-21T00:00:00Z"),
                                      priv_a1)},
            {"body": body(did5, ts="2026-09-22T00:00:00Z"),
             "signature": "@@@not-base64url@@@"},                # 失败项
            {"body": body(did6, ts="2026-09-23T00:00:00Z"),
             "signature": crypto.sign(body(did6, ts="2026-09-23T00:00:00Z"),
                                      priv_a1)},
        ]
        st, br, _ = _http_json("POST", f"{base}{BATCH_PATH}",
                               {"items": items}, headers=TA)
        check("批量 200 三项结果",
              st == 200 and len(br["results"]) == 3
              and br["results"][0]["valid"] is True
              and br["results"][1]["valid"] is False
              and br["results"][2]["valid"] is True)

        # ---- 全量查询：仅成功项，按 cursor 升序 ----
        st, r, text = list_get("limit=200")
        events = r["events"]
        check("TA 恰有 5 个事件且按 cursor 升序",
              st == 200 and len(events) == 5
              and [e["did"] for e in events] == [did1, did2, did3, did4, did6]
              and [e["cursor"] for e in events]
              == sorted(e["cursor"] for e in events)
              and events[0]["cursor"] >= 1)
        check("cursor 严格递增正整数",
              all(events[i]["cursor"] + 1 == events[i + 1]["cursor"]
                  for i in range(len(events) - 1)))
        # 键序与类型
        expected_keys = ["cursor", "did", "key_version", "reason",
                         "deactivated_at"]
        ordered_ok = True
        type_ok = True
        for e in events:
            pairs = []
            json.loads(json.dumps(e),
                       object_pairs_hook=lambda p: pairs.extend(p))
            if [k for k, _ in pairs] != expected_keys:
                ordered_ok = False
            if not (isinstance(e["cursor"], int)
                    and isinstance(e["did"], str)
                    and isinstance(e["key_version"], int)
                    and isinstance(e["reason"], str)
                    and isinstance(e["deactivated_at"], str)):
                type_ok = False
        check("事件键序 cursor,did,key_version,reason,deactivated_at",
              ordered_ok)
        check("事件字段类型 整数/字符串/整数/字符串/字符串", type_ok)
        check("next_after 为页末 cursor",
              r["next_after"] == events[-1]["cursor"])

        # 租户隔离
        st, rb, _ = list_get("limit=200", headers=TB)
        check("租户 B 只见本租户事件",
              st == 200 and len(rb["events"]) == 1
              and rb["events"][0]["did"] == did1
              and rb["events"][0]["reason"] == "租户B终止")
        st, rd, _ = list_get("limit=200",
                             headers={"X-Tenant-ID": "default"})
        check("default 租户空页", st == 200 and rd["events"] == [])
        st, empty_h, _ = list_get("limit=200", headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID 400",
              st == 400 and set(empty_h) == {"error"} and empty_h["error"])

        # ---- 分页：limit/after ----
        st, p1, _ = list_get("limit=2")
        st2, p2, _ = list_get(f"limit=2&after={p1['next_after']}")
        st3, p3, _ = list_get(f"limit=2&after={p2['next_after']}")
        check("分页三页拼接等于全量且升序",
              st == st2 == st3 == 200
              and [e["cursor"] for e in p1["events"]]
              + [e["cursor"] for e in p2["events"]]
              + [e["cursor"] for e in p3["events"]]
              == [e["cursor"] for e in events]
              and len(p1["events"]) == 2 and len(p2["events"]) == 2
              and len(p3["events"]) == 1)
        check("各页 next_after 为页末 cursor",
              p1["next_after"] == p1["events"][-1]["cursor"]
              and p2["next_after"] == p2["events"][-1]["cursor"])
        st, pe, _ = list_get(f"after={p3['next_after']}")
        check("末页之后空页 next_after=after",
              st == 200 and pe["events"] == []
              and pe["next_after"] == p3["next_after"])

        # 默认 limit=50（显式给 50 与缺省一致即可；这里数据少）
        st, pd, _ = list_get("after=0")
        check("缺省 limit/after 等价 limit=50&after=0",
              st == 200 and len(pd["events"]) == 5)

        # ---- 过滤 ----
        st, f1, _ = list_get(f"did={urllib.request.quote(did2)}")
        check("did 精确过滤",
              st == 200 and [e["did"] for e in f1["events"]] == [did2])
        st, f2, _ = list_get("did=did:web:missing.example")
        check("did 无匹配 200 空页 next_after=0",
              st == 200 and f2["events"] == [] and f2["next_after"] == 0)
        st, f3, _ = list_get("key_version=1")
        check("key_version 精确过滤",
              st == 200 and len(f3["events"]) == 5
              and all(e["key_version"] == 1 for e in f3["events"]))
        st, f4, _ = list_get("key_version=9")
        check("key_version 无匹配空页",
              st == 200 and f4["events"] == [])
        st, f5, _ = list_get(
            "from=2026-09-20T10:00:00Z&to=2026-09-20T10:00:00Z")
        check("deactivated_at 闭区间含边界",
              st == 200
              and {e["did"] for e in f5["events"]} == {did1, did3})
        st, f6, _ = list_get("from=2026-09-22T00:00:00Z")
        check("仅 from 闭区间：did5 失败不写入，结果恰为 did6",
              st == 200 and [e["did"] for e in f6["events"]] == [did6]
              and all(e["deactivated_at"] >= "2026-09-22T00:00:00Z"
                      for e in f6["events"]))
        st, f7, _ = list_get("to=2026-09-19T08:30:00Z")
        check("仅 to 闭区间含边界(did2)",
              st == 200 and [e["did"] for e in f7["events"]] == [did2])
        st, f8, _ = list_get(
            f"did={urllib.request.quote(did1)}&key_version=1"
            "&from=2026-09-01T00:00:00Z&to=2026-09-30T00:00:00Z"
            f"&after=0&limit=10")
        check("六参数组合命中",
              st == 200 and len(f8["events"]) == 1
              and f8["events"][0]["did"] == did1)

        # ---- 参数非法一律 400 且仅含非空中文 error ----
        bad_queries = [
            "unknown=1",
            "limit=1&limit=2",
            "after=1&after=2",
            "did=a&did=b",
            "key_version=1&key_version=2",
            "from=2026-09-20T00:00:00Z&from=2026-09-21T00:00:00Z",
            "to=2026-09-20T00:00:00Z&to=2026-09-21T00:00:00Z",
            "limit=",
            "after=",
            "did=",
            "key_version=",
            "from=",
            "to=",
            "limit=0",
            "limit=201",
            "limit=-1",
            "limit=1.5",
            "limit=abc",
            "limit=%201",
            "limit=true",
            f"limit={urllib.request.quote('１')}",  # Unicode 全角数字
            "after=-1",
            "after=1.0",
            "after=%200",
            "key_version=0",
            "key_version=-2",
            "key_version=1.0",
            f"key_version={urllib.request.quote('＋1')}",
            "from=2026-09-20",                 # 缺时间与 Z
            "from=2026-09-20T10:00:00",        # 缺 Z
            "from=2026-09-20T10:00:00+00:00",  # 偏移
            "from=2026-09-20T10:00:00.000Z",   # 小数秒
            "from=2026-13-40T25:61:61Z",       # 非法时刻
            "to=not-a-time",
            "from=2026-09-21T00:00:00Z&to=2026-09-20T00:00:00Z",  # from>to
        ]
        for q in bad_queries:
            st, err, _ = list_get(q)
            check(f"400: ?{q}",
                  st == 400 and set(err) == {"error"}
                  and isinstance(err["error"], str) and err["error"].strip())

        # 失败/重放不改变游标序列：再次全量仍为 5 个
        st, again, _ = list_get("limit=200")
        check("重放/失败后事件集合不变",
              [e["cursor"] for e in again["events"]]
              == [e["cursor"] for e in events])

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 旧状态文件迁移：有通告无事件 ----
    legacy_path = tempfile.mktemp(suffix=".json")
    legacy_notices = {
        # 故意乱序放置，验证按 (deactivated_at, did) 补录
        "did:web:zeta.example": {
            "did": "did:web:zeta.example", "key_version": 1,
            "reason": "Z原因", "deactivated_at": "2026-09-20T10:00:00Z",
            "signature": "sig-z"},
        "did:web:alpha.example": {
            "did": "did:web:alpha.example", "key_version": 2,
            "reason": "A原因", "deactivated_at": "2026-09-18T00:00:00Z",
            "signature": "sig-a"},
        "did:web:mid.example": {
            "did": "did:web:mid.example", "key_version": 1,
            "reason": "M原因", "deactivated_at": "2026-09-20T10:00:00Z",
            "signature": "sig-m"},
    }
    legacy = {
        "tenants": {
            "default": {"did_deactivation_notices": legacy_notices},
        },
    }
    with open(legacy_path, "w", encoding="utf-8") as fh:
        json.dump(legacy, fh, ensure_ascii=False)

    from vcbackend.store import VCStore
    s1 = VCStore(legacy_path)
    ev1, nxt1 = s1.list_did_deactivation_events("default", 0, 50)
    check("旧文件补录顺序 (deactivated_at, did)",
          [(e.did, e.key_version, e.reason) for e in ev1] == [
              ("did:web:alpha.example", 2, "A原因"),
              ("did:web:mid.example", 1, "M原因"),
              ("did:web:zeta.example", 1, "Z原因"),
          ] and [e.cursor for e in ev1] == [1, 2, 3])
    check("补录查询空页 next_after=after",
          s1.list_did_deactivation_events("default", 3, 50) == ([], 3))
    check("补录对他租户不可见",
          s1.list_did_deactivation_events("other", 0, 50) == ([], 0))

    # 不触落盘重启：内存补录可重复，cursor 稳定
    del s1
    s2 = VCStore(legacy_path)
    ev2, _ = s2.list_did_deactivation_events("default", 0, 50)
    check("未写盘重启 cursor 稳定",
          [(e.did, e.cursor) for e in ev2]
          == [(e.did, e.cursor) for e in ev1])

    # 触发一次写（再加载验证：已补录不重复，游标持久）
    # 直接重启服务让其在首次同步时原子落盘迁移项
    port2 = 8998
    env2 = dict(os.environ, VCBACKEND_STORE=legacy_path)
    proc2 = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port2), "--host", "127.0.0.1"],
        cwd=ROOT, env=env2,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base2 = f"http://127.0.0.1:{port2}"
    try:
        assert wait_up(port2), "服务2启动超时"
        st, migrated, _ = _http_json(
            "GET", f"{base2}{LIST_PATH}?limit=10")
        check("迁移服务读补录事件",
              st == 200 and [e["did"] for e in migrated["events"]]
              == ["did:web:alpha.example", "did:web:mid.example",
                  "did:web:zeta.example"]
              and [e["cursor"] for e in migrated["events"]] == [1, 2, 3])
        # 只读查询不触发落盘：文件仍无事件字段（内存补录）
        with open(legacy_path, encoding="utf-8") as fh:
            before_write = json.load(fh)
        check("只读查询不触发落盘",
              "did_deactivation_events"
              not in before_write["tenants"]["default"]
              and "did_deactivation_event_cursors" not in before_write)
        # 注册锚点并首次接受新通告：迁移项与新事件同一次原子写落盘
        priv_n, pub_n = _keypair()
        new_did = "did:web:new.example"
        st, _, _ = _http_json(
            "POST", f"{base2}/v1/trust/anchors",
            {"did": new_did, "public_key": pub_n, "key_version": 1})
        assert st == 201
        nb = body(new_did, reason="新通告", ts="2026-09-24T00:00:00Z")
        st, nr, _ = _http_json(
            "POST", f"{base2}/v1/trust/dids/deactivate-sync",
            {"body": nb, "signature": crypto.sign(nb, priv_n)})
        check("迁移后新通告首次接受 201 且 cursor 延续为 4",
              st == 201)
        st, after_write, _ = _http_json(
            "GET", f"{base2}{LIST_PATH}?limit=10")
        check("新事件 cursor 延续补录序列",
              st == 200
              and [e["cursor"] for e in after_write["events"]]
              == [1, 2, 3, 4]
              and after_write["events"][-1]["did"] == new_did)
    finally:
        proc2.terminate()
        proc2.wait(timeout=10)

    # 落盘后再加载：事件不重复、游标持久
    with open(legacy_path, encoding="utf-8") as fh:
        persisted = json.load(fh)
    check("补录项已随原子写落盘",
          len(persisted["tenants"]["default"]
              .get("did_deactivation_events", [])) == 4
          and persisted.get("did_deactivation_event_cursors", {})
          .get("default") == 4)
    s3 = VCStore(legacy_path)
    ev3, _ = s3.list_did_deactivation_events("default", 0, 50)
    check("落盘重启不重复补录且 cursor 稳定",
          [(e.did, e.cursor) for e in ev3]
          == [(e.did, e.cursor) for e in ev1]
          + [(new_did, 4)])

    if failures:
        print(f"\n{len(failures)} 项失败")
        sys.exit(1)
    print("\n全部通过")


if __name__ == "__main__":
    main()
