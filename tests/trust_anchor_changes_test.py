#!/usr/bin/env python3
"""GET /v1/trust/anchor-changes 可签名锚点变更流端到端测试。

直接运行：python3 tests/trust_anchor_changes_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 查询参数仅许唯一 after 与唯一非空 signer_did（缺失/空值/重复/空白/
  符号/小数/布尔词/Unicode 数字/未知参数 400，仅 {"error"}；显式空
  租户头 400）；签名 DID 未知/他租户 404、已停用 409；
- 注册/轮换/首次吊销/实际用途收紧依次产生 registered/rotated/revoked/
  uses.updated 事件；幂等重试、冲突与失败不产生事件；事件字段值为变更
  后状态，键序固定；
- cursor 租户内跨 DID 持久递增、租户间独立；分页 cursor>after 取至多
  200 项，空页 next_after=after；
- 200 键序 events,next_after,signer_did,signer_key_version,signature；
  签名可由签名 DID 当前公钥对前四键规范化 JSON 验签（86 字符无填充
  base64url）；
- 旧锚点（无变更事件）加载时按 did/版本序补 snapshot，重启 cursor 稳定；
- GET 纯只读（不记审计）。
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

from vcbackend import crypto  # noqa: E402

CHANGES_PATH = "/v1/trust/anchor-changes"
RESP_KEYS = [
    "events", "next_after", "signer_did",
    "signer_key_version", "signature",
]
EVENT_KEYS = [
    "cursor", "action", "did", "key_version",
    "public_key", "status", "uses",
]
ALL_USES = ["generic", "vc", "vp", "proof", "did", "status", "deactivation"]


def _http(method, url, payload=None, headers=None, raw_body=None):
    if raw_body is not None:
        data = raw_body
    else:
        data = json.dumps(payload).encode() if payload is not None else None
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


def gen_pub_pem():
    priv = crypto.generate_private_key_pem()
    return crypto.public_key_pem_from_private(priv)


def main():
    port = 9031
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
    old_store = None

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def changes_get(query="", headers=None):
        url = f"{base}{CHANGES_PATH}?{query}" if query else base + CHANGES_PATH
        return _http("GET", url, headers=headers)

    try:
        TA = {"X-Tenant-ID": "tenant-a"}
        TB = {"X-Tenant-ID": "tenant-b"}

        def make_did(label, headers):
            st, raw = _http("POST", f"{base}/v1/dids",
                            {"method": "web", "public_key": label}, headers)
            assert st in (200, 201), raw
            body = json.loads(raw)
            return body["did"], body["public_key"]

        def add_anchor(did, pub, version, headers, uses=None, status=None):
            payload = {"did": did, "public_key": pub, "key_version": version}
            if uses is not None:
                payload["uses"] = uses
            st, raw = _http("POST", f"{base}/v1/trust/anchors",
                            payload, headers)
            assert st in (200, 201), raw
            return json.loads(raw)

        signer_did, signer_pub = make_did("changes-signer", TA)

        def fetch(after=None, signer=signer_did, headers=TA):
            qs = f"signer_did={signer}"
            if after is not None:
                qs += f"&after={after}"
            st, raw = changes_get(qs, headers=headers)
            assert st == 200, raw
            body = json.loads(raw)
            return body

        def verify_signature(body):
            signed = {k: body[k] for k in RESP_KEYS[:4]}
            crypto.verify(signed, body["signature"], signer_pub)

        # ---------------------------------------------------------- #
        # 1. 400 族：仅 {error} 非空中文
        # ---------------------------------------------------------- #
        def expect_400(name, query, headers=None):
            st, raw = changes_get(query, headers=headers)
            try:
                r = json.loads(raw.decode() or "{}")
            except ValueError:
                r = {}
            check(f"400 仅 error: {name}",
                  st == 400 and list(r.keys()) == ["error"]
                  and isinstance(r["error"], str) and bool(r["error"]))

        expect_400("缺 signer_did", "", headers=TA)
        expect_400("signer_did 空值", "signer_did=", headers=TA)
        expect_400("signer_did 重复",
                   f"signer_did={signer_did}&signer_did=did:web:x",
                   headers=TA)
        expect_400("未知参数",
                   f"signer_did={signer_did}&limit=1", headers=TA)
        expect_400("after 空值", f"signer_did={signer_did}&after=",
                   headers=TA)
        expect_400("after 负数", f"signer_did={signer_did}&after=-1",
                   headers=TA)
        expect_400("after 小数", f"signer_did={signer_did}&after=1.5",
                   headers=TA)
        expect_400("after 布尔词", f"signer_did={signer_did}&after=true",
                   headers=TA)
        expect_400("after 含空白", f"signer_did={signer_did}&after=%201",
                   headers=TA)
        expect_400("after Unicode 数字",
                   f"signer_did={signer_did}&after=%E0%A7%A7", headers=TA)
        expect_400("after 重复",
                   f"signer_did={signer_did}&after=0&after=1", headers=TA)
        st, _ = changes_get(f"signer_did={signer_did}",
                            headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", st == 400)

        # ---------------------------------------------------------- #
        # 2. 404 / 409
        # ---------------------------------------------------------- #
        st, _ = changes_get("signer_did=did:web:unknown", headers=TA)
        check("未知签名 DID 404", st == 404)
        st, _ = changes_get(f"signer_did={signer_did}", headers=TB)
        check("他租户签名 DID 404", st == 404)

        # ---------------------------------------------------------- #
        # 3. 空流：200 空页、签名可验、next_after 缺省/透传
        # ---------------------------------------------------------- #
        body = fetch()
        check("空流 200 键序", list(body.keys()) == RESP_KEYS)
        check("空流 events 为空", body["events"] == [])
        check("空流 next_after=0", body["next_after"] == 0)
        check("signer 回显", body["signer_did"] == signer_did
              and body["signer_key_version"] == 1)
        try:
            verify_signature(body)
            sig_ok = True
        except Exception:
            sig_ok = False
        check("空流签名可验", sig_ok)

        body = fetch(after=999)
        check("空页 next_after=after", body["next_after"] == 999
              and body["events"] == [])

        # ---------------------------------------------------------- #
        # 4. 四类变更事件依序产生，字段值为变更后状态
        # ---------------------------------------------------------- #
        d1 = "did:web:anchor-one"
        pem1 = gen_pub_pem()
        pem2 = gen_pub_pem()

        # registered（省略 uses -> 全用途）
        add_anchor(d1, pem1, 1, TA)
        # rotated（继承全用途）
        st, raw = _http("POST", f"{base}/v1/trust/anchors/{d1}/rotate",
                        {"from_key_version": 1, "public_key": pem2}, TA)
        assert st in (200, 201), raw
        # 实际收紧 uses：全用途 -> ["vc","vp"] -> ["vc"]
        st, raw = _http("PUT", f"{base}/v1/trust/anchors/{d1}/2/uses",
                        {"from_uses": ALL_USES,
                         "uses": ["vc", "vp"]}, TA)
        assert st == 200, raw
        st, raw = _http("PUT", f"{base}/v1/trust/anchors/{d1}/2/uses",
                        {"from_uses": ["vc", "vp"], "uses": ["vc"]}, TA)
        assert st == 200, raw
        # 首次吊销旧版本 v1
        st, raw = _http("PUT", f"{base}/v1/trust/anchors/{d1}/1/status",
                        {"status": "revoked"}, TA)
        assert st == 200, raw

        body = fetch()
        events = body["events"]
        check("含事件响应键序",
              list(body.keys()) == RESP_KEYS)
        check("响应事件键序",
              all(list(ev.keys()) == EVENT_KEYS for ev in events))
        d1_events = [ev for ev in events if ev["did"] == d1]
        check("d1 共 5 条事件", len(d1_events) == 5)
        actions = [ev["action"] for ev in d1_events]
        check(f"动作依序（{actions}）",
              actions == ["registered", "rotated", "uses.updated",
                          "uses.updated", "revoked"])
        cursors = [ev["cursor"] for ev in events]
        check("页内 cursor 升序", cursors == sorted(cursors))
        check("cursor 为正整数", all(isinstance(c, int) and c >= 1
                                     for c in cursors))

        ev_reg = d1_events[0]
        check("registered 字段值",
              ev_reg["key_version"] == 1 and ev_reg["public_key"] == pem1
              and ev_reg["status"] == "active" and ev_reg["uses"] == ALL_USES)
        ev_rot = d1_events[1]
        check("rotated 字段值",
              ev_rot["key_version"] == 2 and ev_rot["public_key"] == pem2
              and ev_rot["status"] == "active" and ev_rot["uses"] == ALL_USES)
        check("uses.updated#1 变更后用途",
              d1_events[2]["status"] == "active"
              and d1_events[2]["uses"] == ["vc", "vp"])
        check("uses.updated#2 变更后用途",
              d1_events[3]["status"] == "active"
              and d1_events[3]["uses"] == ["vc"])
        ev_rev = d1_events[4]
        check("revoked 字段值（变更后状态）",
              ev_rev["key_version"] == 1 and ev_rev["public_key"] == pem1
              and ev_rev["status"] == "revoked"
              and ev_rev["uses"] == ALL_USES)
        check("next_after 取页末 cursor",
              body["next_after"] == events[-1]["cursor"])
        try:
            verify_signature(body)
            sig_ok = True
        except Exception:
            sig_ok = False
        check("变更流签名可验", sig_ok)
        crypto.validate_signature_format_strict(body["signature"])
        check("签名为 86 字符无填充 base64url", True)

        # ---------------------------------------------------------- #
        # 5. 幂等/冲突/失败不产生事件
        # ---------------------------------------------------------- #
        before_max = body["next_after"]
        # 幂等注册（同 did/版本/PEM/uses）
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": d1, "public_key": pem1, "key_version": 1}, TA)
        assert st == 200
        # 幂等轮换（同前置同 PEM）
        st, _ = _http("POST", f"{base}/v1/trust/anchors/{d1}/rotate",
                      {"from_key_version": 1, "public_key": pem2}, TA)
        assert st == 200
        # 重复吊销
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{d1}/1/status",
                      {"status": "revoked"}, TA)
        assert st == 200
        # 幂等收紧（目标等于当前值）
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{d1}/2/uses",
                      {"from_uses": ["vc"], "uses": ["vc"]}, TA)
        assert st == 200
        # 冲突：注册同版本不同 PEM
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": d1, "public_key": gen_pub_pem(),
                       "key_version": 1}, TA)
        assert st == 409
        # 冲突：收紧前置不匹配（目标与当前值不同，from_uses 也不等于当前值）
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{d1}/2/uses",
                      {"from_uses": ["vc", "vp"],
                       "uses": ["vp"]}, TA)
        assert st == 409
        # 非法/冲突：扩权收紧 409（目标非当前值真子集），不产生事件
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{d1}/2/uses",
                      {"from_uses": ["vc"], "uses": ["vc", "vp"]}, TA)
        assert st == 409

        body2 = fetch()
        check("幂等/冲突/失败后无新事件",
              body2["next_after"] == before_max
              and len(body2["events"]) == len(events))

        # ---------------------------------------------------------- #
        # 6. 分页：after 排除、next_after、租户独立
        # ---------------------------------------------------------- #
        first_cursor = d1_events[0]["cursor"]
        page = fetch(after=first_cursor)
        check("after 排除 cursor<=after",
              all(ev["cursor"] > first_cursor for ev in page["events"])
              and page["next_after"] == events[-1]["cursor"])

        # 租户隔离：tenant-b 独立游标从 1 计起
        signer_b, signer_b_pub = make_did("changes-signer-b", TB)
        pem_b = gen_pub_pem()
        add_anchor("did:web:b-only", pem_b, 7, TB)
        st, raw = changes_get(f"signer_did={signer_b}", headers=TB)
        assert st == 200, raw
        bb = json.loads(raw)
        check("租户隔离：B 仅见本租户事件",
              len(bb["events"]) == 1
              and bb["events"][0]["did"] == "did:web:b-only"
              and bb["events"][0]["cursor"] == 1
              and bb["events"][0]["key_version"] == 7)
        signed_b = {k: bb[k] for k in RESP_KEYS[:4]}
        try:
            crypto.verify(signed_b, bb["signature"], signer_b_pub)
            ok_b = True
        except Exception:
            ok_b = False
        check("B 租户签名由 B 签名者公钥可验", ok_b)
        # A 租户事件对 B 不可见、B 事件对 A 不可见
        check("跨租户不可见",
              all(ev["did"] != "did:web:b-only"
                  for ev in fetch()["events"]))

        # 200 上限：独立租户批量注册 205 个锚点版本
        TC = {"X-Tenant-ID": "tenant-c"}
        signer_c, _ = make_did("changes-signer-c", TC)
        bulk_pem = gen_pub_pem()
        for version in range(1, 206):
            add_anchor("did:web:bulk", bulk_pem, version, TC)
        st, raw = changes_get(f"signer_did={signer_c}", headers=TC)
        assert st == 200
        bulk1 = json.loads(raw)
        check("单页至多 200 项", len(bulk1["events"]) == 200)
        check("首页 next_after=200", bulk1["next_after"] == 200)
        st, raw = changes_get(f"signer_did={signer_c}&after=200",
                              headers=TC)
        assert st == 200
        bulk2 = json.loads(raw)
        check("次页返回剩余 5 项",
              len(bulk2["events"]) == 5
              and [ev["cursor"] for ev in bulk2["events"]] == [201, 202, 203,
                                                                204, 205]
              and bulk2["next_after"] == 205)

        # ---------------------------------------------------------- #
        # 7. GET 纯只读（审计不变）
        # ---------------------------------------------------------- #
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_n = len(json.loads(raw)["events"])
        fetch()
        fetch(after=3)
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        check("GET 变更流不记审计",
              len(json.loads(raw)["events"]) == audit_n)

        # ---------------------------------------------------------- #
        # 8. 已停用签名者 409
        # ---------------------------------------------------------- #
        st, _ = _http("POST", f"{base}/v1/dids/{signer_did}/deactivate",
                      {"reason": "机构业务终止"}, TA)
        assert st == 200
        st, _ = changes_get(f"signer_did={signer_did}", headers=TA)
        check("已停用签名 DID 409", st == 409)

        # ---------------------------------------------------------- #
        # 9. 重启稳定（cursor/事件持久）
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        # signer_did 已停用 -> 另起一个活动签名者读 A 租户
        signer_a2, _ = make_did("changes-signer-a2", TA)
        st, raw = changes_get(f"signer_did={signer_a2}", headers=TA)
        assert st == 200, raw
        after_restart = json.loads(raw)
        check("重启后 d1 事件不变",
              [ev for ev in after_restart["events"] if ev["did"] == d1]
              == [ev for ev in body2["events"] if ev["did"] == d1])
        st, raw = changes_get(f"signer_did={signer_c}", headers=TC)
        assert st == 200
        check("重启后 C 租户 205 条游标稳定",
              json.loads(raw)["next_after"] == 200)

        # ---------------------------------------------------------- #
        # 10. 旧锚点 snapshot 回填：另起旧格式状态文件
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        old_store = tempfile.mktemp(suffix=".json")
        old_pem = gen_pub_pem()
        old_payload = {
            "tenants": {
                "old": {
                    "trust_anchors": {
                        "did:web:zzz": {
                            "1": {"key_version": 1, "public_key": old_pem,
                                  "status": "active", "updated_at": None},
                            "2": {"key_version": 2, "public_key": old_pem,
                                  "status": "revoked",
                                  "updated_at": "2026-01-02T03:04:05Z"},
                        },
                        "did:web:aaa": {
                            "1": {"key_version": 1, "public_key": old_pem,
                                  "status": "active", "updated_at": None,
                                  "uses": ["vc"]},
                        },
                    }
                }
            }
        }
        with open(old_store, "w", encoding="utf-8") as fh:
            json.dump(old_payload, fh)
        env_old = dict(os.environ, VCBACKEND_STORE=old_store)
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env_old,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(port), "服务启动超时"
        TO = {"X-Tenant-ID": "old"}
        signer_o, signer_o_pub = make_did("old-signer", TO)

        def old_page():
            st, raw = changes_get(f"signer_did={signer_o}", headers=TO)
            assert st == 200, raw
            return json.loads(raw)

        snap_page = old_page()
        snap_events = snap_page["events"]
        check("旧锚点补 3 条 snapshot",
              [ev["action"] for ev in snap_events] == ["snapshot"] * 3
              and len(snap_events) == 3)
        check("snapshot 按 did/版本序补 cursor",
              [(ev["did"], ev["key_version"], ev["cursor"])
               for ev in snap_events] == [
                  ("did:web:aaa", 1, 1),
                  ("did:web:zzz", 1, 2),
                  ("did:web:zzz", 2, 3)])
        check("snapshot 值取当前状态",
              snap_events[0]["uses"] == ["vc"]
              and snap_events[0]["status"] == "active"
              and snap_events[2]["status"] == "revoked"
              and snap_events[2]["uses"] == ALL_USES
              and snap_events[2]["public_key"] == old_pem)
        try:
            crypto.verify({k: snap_page[k] for k in RESP_KEYS[:4]},
                          snap_page["signature"], signer_o_pub)
            ok_snap = True
        except Exception:
            ok_snap = False
        check("snapshot 页签名可验", ok_snap)

        # 重启后 cursor 与事件不变
        proc.terminate()
        proc.wait(timeout=10)
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env_old,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(port), "服务启动超时"
        check("snapshot 重启稳定", old_page()["events"] == snap_events)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        for path in (store, old_store):
            if path and os.path.exists(path):
                os.unlink(path)

    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    main()
