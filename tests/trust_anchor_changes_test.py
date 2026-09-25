#!/usr/bin/env python3
"""GET /v1/trust/anchor-changes 可签名锚点变更流端到端测试。

直接运行：python3 tests/trust_anchor_changes_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 查询参数仅收 after、signer_did 各一次：signer_did 非空必填，after
  缺省 0、须非负 ASCII 十进制；非法 400 且仅 {"error"}（非空中文）；
  显式空租户头 400；签名 DID 未知/他租户 404、已停用 409；
- 注册/轮换/首次吊销/用途实改依次产生 registered/rotated/revoked/
  uses.updated 事件；幂等与失败路径无事件；事件键序 cursor、action、
  did、key_version、public_key、status、uses，值为变更后状态；cursor
  租户内持久递增；返 cursor>after 前 200 项，空页 next_after=after；
- 200 键序 events、next_after、signer_did、signer_key_version、
  signature；签名可由签名 DID 当前公钥对前四键规范化 JSON 验签；
- 旧锚点按 did/版本序补 snapshot，重启不变；GET 纯只读（审计不变）；
  租户隔离。
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

FEED_PATH = "/v1/trust/anchor-changes"
RESP_KEYS = ["events", "next_after", "signer_did", "signer_key_version",
             "signature"]
EVENT_KEYS = ["cursor", "action", "did", "key_version", "public_key",
              "status", "uses"]
FULL_USES = ["generic", "vc", "vp", "proof", "did", "status", "deactivation"]


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


def main():
    port = 9023
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

    def feed_get(query="", headers=None):
        url = f"{base}{FEED_PATH}?{query}" if query else base + FEED_PATH
        return _http("GET", url, headers=headers)

    try:
        TA = {"X-Tenant-ID": "tenant-a"}
        TB = {"X-Tenant-ID": "tenant-b"}

        def make_did(label, headers):
            st, raw = _http("POST", f"{base}/v1/dids",
                            {"method": "web", "public_key": label}, headers)
            assert st == 201, raw
            body = json.loads(raw)
            return body["did"], body["public_key"]

        def add_anchor(did, pub, version, headers, uses=None):
            payload = {"did": did, "public_key": pub, "key_version": version}
            if uses is not None:
                payload["uses"] = uses
            return _http("POST", f"{base}/v1/trust/anchors", payload, headers)

        # 签名 DID（服务端托管密钥，当前版本 1）与锚点公钥。
        signer_did, signer_pub = make_did("changes-signer", TA)
        pem_a = crypto.public_key_pem_from_private(
            crypto.generate_private_key_pem())
        pem_b = crypto.public_key_pem_from_private(
            crypto.generate_private_key_pem())
        did_a = "did:web:alpha.example"
        did_b = "did:web:beta.example"

        # ---------------------------------------------------------- #
        # 1. 400 族：仅 {error} 非空中文
        # ---------------------------------------------------------- #
        def expect_400(name, query, headers=TA):
            st, raw = feed_get(query, headers=headers)
            try:
                r = json.loads(raw.decode() or "{}")
            except ValueError:
                r = {}
            check(f"400 仅 error: {name}",
                  st == 400 and list(r.keys()) == ["error"]
                  and isinstance(r["error"], str) and bool(r["error"]))

        expect_400("缺 signer_did", "")
        expect_400("仅 after", "after=0")
        expect_400("signer_did 空值", "signer_did=")
        expect_400("signer_did 重复",
                   f"signer_did={signer_did}&signer_did={did_a}")
        expect_400("after 重复", f"signer_did={signer_did}&after=1&after=2")
        expect_400("after 空值", f"signer_did={signer_did}&after=")
        expect_400("after 负号", f"signer_did={signer_did}&after=-1")
        expect_400("after 正号", f"signer_did={signer_did}&after=%2B1")
        expect_400("after 小数", f"signer_did={signer_did}&after=1.0")
        expect_400("after 空白", f"signer_did={signer_did}&after=%20")
        expect_400("after Unicode 数字",
                   f"signer_did={signer_did}&after=%D9%A1")
        expect_400("未知参数", f"signer_did={signer_did}&limit=1")
        st, _ = feed_get(f"signer_did={signer_did}",
                         headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", st == 400)

        # ---------------------------------------------------------- #
        # 2. 404 / 409
        # ---------------------------------------------------------- #
        st, _ = feed_get("signer_did=did:web:unknown", headers=TA)
        check("未知签名 DID 404", st == 404)
        st, _ = feed_get(f"signer_did={signer_did}", headers=TB)
        check("他租户签名 DID 404", st == 404)

        dead_did, _ = make_did("dead-changes-signer", TA)
        st, _ = _http("POST", f"{base}/v1/dids/{dead_did}/deactivate",
                      {"reason": "机构终止"}, TA)
        assert st == 200
        st, _ = feed_get(f"signer_did={dead_did}", headers=TA)
        check("已停用签名 DID 409", st == 409)

        # ---------------------------------------------------------- #
        # 3. 空页：无事件时 next_after=after
        # ---------------------------------------------------------- #
        st, raw = feed_get(f"signer_did={signer_did}", headers=TA)
        check("空变更流 200", st == 200)
        page = json.loads(raw)
        check("响应键序", list(page.keys()) == RESP_KEYS)
        check("空页 events 为空且 next_after=after",
              page["events"] == [] and page["next_after"] == 0)
        check("signer 字段回显",
              page["signer_did"] == signer_did
              and page["signer_key_version"] == 1)
        st, raw = feed_get(f"signer_did={signer_did}&after=7", headers=TA)
        page = json.loads(raw)
        check("空页 next_after 取请求 after",
              page["events"] == [] and page["next_after"] == 7)

        # ---------------------------------------------------------- #
        # 4. 变更事件：注册/轮换/吊销/用途实改；幂等与失败无事件
        # ---------------------------------------------------------- #
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_before = len(json.loads(raw)["events"])

        st, _ = add_anchor(did_a, pem_a, 1, TA)
        assert st == 201, _
        # 幂等重试（200）与冲突（409）均不产生事件
        st, _ = add_anchor(did_a, pem_a, 1, TA)
        assert st == 200, _
        st, _ = add_anchor(did_a, pem_b, 1, TA)
        assert st == 409, _
        # 轮换 did_a 到 v2（继承全用途）
        st, _ = _http("POST", f"{base}/v1/trust/anchors/{did_a}/rotate",
                      {"from_key_version": 1, "public_key": pem_b}, TA)
        assert st == 201, _
        # 幂等轮换重试不产生事件
        st, _ = _http("POST", f"{base}/v1/trust/anchors/{did_a}/rotate",
                      {"from_key_version": 1, "public_key": pem_b}, TA)
        assert st == 200, _
        # 注册 did_b v1（用途子集）并实改用途
        st, _ = add_anchor(did_b, pem_a, 1, TA, uses=["vc", "vp"])
        assert st == 201, _
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did_b}/1/uses",
                      {"from_uses": ["vc", "vp"], "uses": ["vc"]}, TA)
        assert st == 200, _
        # 幂等用途更新（目标等于当前）不产生事件
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did_b}/1/uses",
                      {"from_uses": ["vc"], "uses": ["vc"]}, TA)
        assert st == 200, _
        # 首次吊销 did_a v1；重复吊销与失败路径不产生事件
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did_a}/1/status",
                      {"status": "revoked"}, TA)
        assert st == 200, _
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did_a}/1/status",
                      {"status": "revoked"}, TA)
        assert st == 200, _
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did_a}/9/status",
                      {"status": "revoked"}, TA)
        assert st == 404, _

        st, raw = feed_get(f"signer_did={signer_did}", headers=TA)
        check("变更流 200", st == 200)
        page = json.loads(raw)
        events = page["events"]
        check("恰 5 条事件（幂等/失败不追加）", len(events) == 5)
        check("事件键序",
              all(list(e.keys()) == EVENT_KEYS for e in events))
        check("动作依次为 registered/rotated/registered/uses.updated/revoked",
              [e["action"] for e in events] == [
                  "registered", "rotated", "registered",
                  "uses.updated", "revoked"])
        cursors = [e["cursor"] for e in events]
        check("cursor 为自 1 起严格递增正整数",
              cursors == [1, 2, 3, 4, 5])
        check("next_after 取页末 cursor", page["next_after"] == 5)

        e1, e2, e3, e4, e5 = events
        check("registered 事件为变更后状态",
              e1["did"] == did_a and e1["key_version"] == 1
              and e1["public_key"] == pem_a
              and e1["status"] == "active" and e1["uses"] == FULL_USES)
        check("rotated 事件继承前置用途",
              e2["did"] == did_a and e2["key_version"] == 2
              and e2["public_key"] == pem_b
              and e2["status"] == "active" and e2["uses"] == FULL_USES)
        check("子集注册事件用途按规范序",
              e3["did"] == did_b and e3["uses"] == ["vc", "vp"])
        check("uses.updated 事件为变更后用途",
              e4["did"] == did_b and e4["key_version"] == 1
              and e4["status"] == "active" and e4["uses"] == ["vc"])
        check("revoked 事件状态为 revoked",
              e5["did"] == did_a and e5["key_version"] == 1
              and e5["status"] == "revoked" and e5["uses"] == FULL_USES)

        # 签名：前四键规范化 JSON，可由签名 DID 公钥验签。
        signed = {k: page[k] for k in RESP_KEYS[:4]}
        try:
            crypto.verify(signed, page["signature"], signer_pub)
            sig_ok = True
        except Exception:
            sig_ok = False
        check("签名可由签名 DID 公钥验签", sig_ok)
        try:
            crypto.validate_signature_format_strict(page["signature"])
            fmt_ok = True
        except Exception:
            fmt_ok = False
        check("签名为 86 字符无填充 base64url", fmt_ok)

        # 分页：after 排除 cursor 不大于其值的事件
        st, raw = feed_get(f"signer_did={signer_did}&after=2", headers=TA)
        page2 = json.loads(raw)
        check("after=2 自第 3 条起",
              [e["cursor"] for e in page2["events"]] == [3, 4, 5]
              and page2["next_after"] == 5)
        st, raw = feed_get(f"signer_did={signer_did}&after=5", headers=TA)
        page3 = json.loads(raw)
        check("末条之后为空页且 next_after=after",
              page3["events"] == [] and page3["next_after"] == 5)

        # GET 纯只读：审计计数不变（两次 GET 之间）
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_mid = len(json.loads(raw)["events"])
        feed_get(f"signer_did={signer_did}", headers=TA)
        feed_get(f"signer_did={signer_did}&after=2", headers=TA)
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        check("GET 变更流纯只读（审计不变）",
              len(json.loads(raw)["events"]) == audit_mid)
        check("变更操作本身记审计", audit_mid > audit_before)

        # ---------------------------------------------------------- #
        # 5. 租户隔离：他租户事件流独立、游标各自从 1 计起
        # ---------------------------------------------------------- #
        signer_b, _ = make_did("changes-signer-b", TB)
        st, _ = add_anchor(did_a, pem_a, 1, TB)
        assert st == 201, _
        st, raw = feed_get(f"signer_did={signer_b}", headers=TB)
        page_b = json.loads(raw)
        check("他租户仅见本租户事件且游标独立",
              [e["action"] for e in page_b["events"]] == ["registered"]
              and page_b["events"][0]["cursor"] == 1
              and page_b["next_after"] == 1)

        # ---------------------------------------------------------- #
        # 6. 页大小恒为 200
        # ---------------------------------------------------------- #
        TC = {"X-Tenant-ID": "tenant-c"}
        signer_c, _ = make_did("changes-signer-c", TC)
        for i in range(201):
            st, _ = add_anchor(f"did:web:batch{i:03d}.example", pem_a, 1, TC)
            assert st == 201, _
        st, raw = feed_get(f"signer_did={signer_c}", headers=TC)
        page_c = json.loads(raw)
        check("单页至多 200 条", len(page_c["events"]) == 200)
        check("首页 next_after 为第 200 条 cursor",
              page_c["next_after"] == 200)
        st, raw = feed_get(
            f"signer_did={signer_c}&after={page_c['next_after']}", headers=TC)
        page_c2 = json.loads(raw)
        check("第二页取余下事件",
              [e["cursor"] for e in page_c2["events"]] == [201]
              and page_c2["next_after"] == 201)

        # ---------------------------------------------------------- #
        # 7. 签名 DID 轮换后按当前版本签名
        # ---------------------------------------------------------- #
        st, raw = _http("POST",
                        f"{base}/v1/dids/{signer_did}/keys/rotate",
                        {"key_handle": "changes-signer-v2"}, TA)
        assert st == 200, raw
        signer_pub2 = json.loads(raw)["public_key"]
        st, raw = feed_get(f"signer_did={signer_did}", headers=TA)
        page_rot = json.loads(raw)
        check("轮换后 signer_key_version 为当前版本",
              page_rot["signer_key_version"] == 2)
        signed = {k: page_rot[k] for k in RESP_KEYS[:4]}
        try:
            crypto.verify(signed, page_rot["signature"], signer_pub2)
            sig_ok = True
        except Exception:
            sig_ok = False
        check("轮换后签名可由新公钥验签", sig_ok)

        # ---------------------------------------------------------- #
        # 8. 重启后事件流与游标稳定
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, raw = feed_get(f"signer_did={signer_did}", headers=TA)
        page_r = json.loads(raw)
        check("重启后事件流不变",
              [e["cursor"] for e in page_r["events"]] == [1, 2, 3, 4, 5]
              and [e["action"] for e in page_r["events"]] == [
                  "registered", "rotated", "registered",
                  "uses.updated", "revoked"])
        # 重启后新事件游标继续递增
        st, _ = add_anchor("did:web:gamma.example", pem_a, 1, TA)
        assert st == 201, _
        st, raw = feed_get(f"signer_did={signer_did}&after=5", headers=TA)
        page_r2 = json.loads(raw)
        check("重启后新事件游标继续递增",
              [e["cursor"] for e in page_r2["events"]] == [6]
              and page_r2["events"][0]["action"] == "registered"
              and page_r2["next_after"] == 6)

        # ---------------------------------------------------------- #
        # 9. 旧状态兼容：无变更流的旧锚点按 did/版本序补 snapshot
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        with open(store, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        tenant_a = data["tenants"]["tenant-a"]
        tenant_a.pop("trust_anchor_changes", None)
        data.pop("trust_anchor_change_cursors", None)
        with open(store, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False)
        proc = start()
        st, raw = feed_get(f"signer_did={signer_did}", headers=TA)
        page_s = json.loads(raw)
        events_s = page_s["events"]
        # tenant-a 锚点：did_a#1（已吊销）、did_a#2、did_b#1、
        # did:web:gamma.example#1，按 did 字典序、版本升序补 snapshot。
        expected_keys = sorted(
            [(did_a, 1), (did_a, 2), (did_b, 1),
             ("did:web:gamma.example", 1)])
        check("旧锚点全部补 snapshot",
              [e["action"] for e in events_s] == ["snapshot"] * 4)
        check("snapshot 按 did/版本序且游标自 1 递增",
              [(e["did"], e["key_version"]) for e in events_s]
              == expected_keys
              and [e["cursor"] for e in events_s] == [1, 2, 3, 4])
        snap_by_key = {(e["did"], e["key_version"]): e for e in events_s}
        check("snapshot 值为当前状态（吊销保留）",
              snap_by_key[(did_a, 1)]["status"] == "revoked"
              and snap_by_key[(did_a, 2)]["status"] == "active"
              and snap_by_key[(did_b, 1)]["uses"] == ["vc"])
        # 重启（无写操作）后重建为相同 cursor
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, raw = feed_get(f"signer_did={signer_did}", headers=TA)
        page_s2 = json.loads(raw)
        check("snapshot 补录跨重启稳定",
              [e["cursor"] for e in page_s2["events"]] == [1, 2, 3, 4]
              and [e["action"] for e in page_s2["events"]]
              == ["snapshot"] * 4)
        # 已有事件的版本不再重复补录；新变更游标继续递增
        st, _ = add_anchor("did:web:delta.example", pem_a, 1, TA)
        assert st == 201, _
        st, raw = feed_get(f"signer_did={signer_did}&after=4", headers=TA)
        page_s3 = json.loads(raw)
        check("补录后新事件游标继续递增",
              [e["cursor"] for e in page_s3["events"]] == [5]
              and page_s3["events"][0]["action"] == "registered")
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
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    main()
