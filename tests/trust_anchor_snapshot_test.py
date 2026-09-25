#!/usr/bin/env python3
"""GET/POST /v1/trust/anchors/snapshot 信任锚点快照验真端到端测试。

直接运行：python3 tests/trust_anchor_snapshot_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- GET：查询参数仅许唯一非空 signer_did（缺失/空值/重复/未知参数 400，
  仅 {"error"}；显式空租户头 400）；签名 DID 未知/他租户 404、已停用
  409；200 键序 anchors,signer_did,signer_key_version,signature；
  anchors 按 did 码点、key_version 升序（含已吊销锚点），项键序
  did,key_version,public_key,status,updated_at,uses；签名可由签名
  DID 公钥对前三键规范化 JSON 验签；租户隔离；纯只读（审计不变）；
- POST /verify：请求体须恰为 {"snapshot": 对象}，否则 400 仅 {error}；
  外层合法后按序返回 “快照非法”（键集/类型、anchors 顺序/重复）、
  “锚点不可用”（他租户/吊销/无 generic 用途）、“签名格式错误”、
  “签名校验失败”，成功仅 {"valid":true}；纯只读。
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

SNAPSHOT_PATH = "/v1/trust/anchors/snapshot"
VERIFY_PATH = "/v1/trust/anchors/snapshot/verify"
SNAPSHOT_KEYS = ["anchors", "signer_did", "signer_key_version", "signature"]
ITEM_KEYS = ["did", "key_version", "public_key", "status", "updated_at", "uses"]


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
    port = 9021
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

    def snapshot_get(query="", headers=None):
        url = f"{base}{SNAPSHOT_PATH}?{query}" if query else base + SNAPSHOT_PATH
        return _http("GET", url, headers=headers)

    def verify_post(payload, headers=None, raw_body=None):
        return _http("POST", base + VERIFY_PATH, payload,
                     headers=headers, raw_body=raw_body)

    try:
        TA = {"X-Tenant-ID": "tenant-a"}
        TB = {"X-Tenant-ID": "tenant-b"}

        def make_did(label, headers):
            _http("POST", f"{base}/v1/dids",
                  {"method": "web", "public_key": label}, headers)
            st, raw = _http("POST", f"{base}/v1/dids",
                            {"method": "web", "public_key": label}, headers)
            assert st == 201, raw
            body = json.loads(raw)
            return body["did"], body["public_key"]

        def add_anchor(did, pub, version, headers, uses=None):
            payload = {"did": did, "public_key": pub, "key_version": version}
            if uses is not None:
                payload["uses"] = uses
            st, raw = _http("POST", f"{base}/v1/trust/anchors", payload, headers)
            assert st == 201, raw
            return json.loads(raw)

        # 签名 DID（服务端托管密钥，当前版本 1）与三个锚点 DID。
        signer_did, signer_pub = make_did("snapshot-signer", TA)
        did_b, pub_b = make_did("anchor-b", TA)
        did_a, pub_a = make_did("anchor-a", TA)
        # did 码点序：注册顺序不代表快照序，先取字典序。
        ordered = sorted([signer_did, did_a, did_b])

        # 锚点：signer 自身 v1（验真用）；did_a 两个版本（v2 吊销）；
        # did_b 一个带用途子集的版本。
        add_anchor(signer_did, signer_pub, 1, TA)
        add_anchor(did_a, pub_a, 1, TA)
        add_anchor(did_a, pub_a, 2, TA)
        st, _ = _http(
            "PUT", f"{base}/v1/trust/anchors/{did_a}/2/status",
            {"status": "revoked"}, TA)
        assert st == 200, _
        add_anchor(did_b, pub_b, 3, TA, uses=["vc", "vp"])

        # 他租户同名 DID 的锚点不应出现在本租户快照；他租户 signer 锚点
        # 故意不含 generic 用途，供跨租户验真判“锚点不可用”。
        add_anchor(signer_did, signer_pub, 1, TB, uses=["vc"])
        add_anchor(did_a, pub_a, 9, TB)

        # ---------------------------------------------------------- #
        # 1. 400 族：仅 {error} 非空中文
        # ---------------------------------------------------------- #
        def expect_400(name, query, headers=None):
            st, raw = snapshot_get(query, headers=headers)
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
                   f"signer_did={signer_did}&signer_did={did_a}", headers=TA)
        expect_400("未知参数", f"signer_did={signer_did}&limit=1", headers=TA)
        st, _ = snapshot_get(f"signer_did={signer_did}",
                             headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", st == 400)

        # ---------------------------------------------------------- #
        # 2. 404 / 409
        # ---------------------------------------------------------- #
        st, _ = snapshot_get("signer_did=did:web:unknown", headers=TA)
        check("未知签名 DID 404", st == 404)
        st, _ = snapshot_get(f"signer_did={signer_did}", headers=TB)
        check("他租户签名 DID 404（他租户无此本地 DID）", st == 404)

        dead_did, _ = make_did("dead-signer", TA)
        st, _ = _http("POST", f"{base}/v1/dids/{dead_did}/deactivate",
                      {"reason": "机构终止"}, TA)
        assert st == 200
        st, _ = snapshot_get(f"signer_did={dead_did}", headers=TA)
        check("已停用签名 DID 409", st == 409)

        # ---------------------------------------------------------- #
        # 3. 200 快照：键序、排序、签名可验、租户隔离、只读
        # ---------------------------------------------------------- #
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        assert st == 200
        audit_before = len(json.loads(raw)["events"])

        st, raw = snapshot_get(f"signer_did={signer_did}", headers=TA)
        check("快照 200", st == 200)
        snap = json.loads(raw)
        check("快照键序", list(snap.keys()) == SNAPSHOT_KEYS)
        check("signer_did 回显", snap["signer_did"] == signer_did)
        check("signer_key_version 为当前版本",
              snap["signer_key_version"] == 1)

        anchors = snap["anchors"]
        check("快照含本租户全部 4 个锚点版本", len(anchors) == 4)
        check("锚点项键序",
              all(list(item.keys()) == ITEM_KEYS for item in anchors))
        keys = [(item["did"], item["key_version"]) for item in anchors]
        check("锚点按 did 码点、key_version 升序",
              keys == sorted(keys) and len(set(keys)) == len(keys))
        check("快照不含他租户锚点",
              all(item["did"] != did_a or item["key_version"] != 9
                  for item in anchors))
        by_key = {k: item for k, item in zip(keys, anchors)}
        revoked = by_key.get((did_a, 2))
        check("吊销锚点在快照中且带 updated_at",
              revoked is not None and revoked["status"] == "revoked"
              and isinstance(revoked["updated_at"], str)
              and bool(revoked["updated_at"]))
        subset = by_key.get((did_b, 3))
        check("用途子集按规范序", subset is not None
              and subset["uses"] == ["vc", "vp"])
        full = by_key.get((signer_did, 1))
        check("省略注册为全用途",
              full is not None
              and full["uses"] == ["generic", "vc", "vp", "proof", "did",
                                   "status", "deactivation"])
        check("active 锚点 updated_at 为 null",
              full is not None and full["updated_at"] is None)

        # 签名：前三键规范化 JSON，可由签名 DID 公钥验签。
        signed = {k: snap[k] for k in SNAPSHOT_KEYS[:3]}
        try:
            crypto.verify(signed, snap["signature"], signer_pub)
            sig_ok = True
        except Exception:
            sig_ok = False
        check("签名可由签名 DID 公钥验签", sig_ok)
        crypto.validate_signature_format_strict(snap["signature"])
        check("签名为 86 字符无填充 base64url", True)

        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_after = len(json.loads(raw)["events"])
        check("GET 快照纯只读（审计不变）", audit_before == audit_after)

        # ---------------------------------------------------------- #
        # 4. POST /verify 外层 400：仅 {error}
        # ---------------------------------------------------------- #
        def expect_verify_400(name, payload=None, raw_body=None):
            st, raw = verify_post(payload, raw_body=raw_body, headers=TA)
            try:
                r = json.loads(raw.decode() or "{}")
            except ValueError:
                r = {}
            check(f"verify 400 仅 error: {name}",
                  st == 400 and list(r.keys()) == ["error"]
                  and isinstance(r["error"], str) and bool(r["error"]))

        expect_verify_400("空体", raw_body=b"")
        expect_verify_400("非法 JSON", raw_body=b"{")
        expect_verify_400("非对象", payload=[1])
        expect_verify_400("缺 snapshot", payload={})
        expect_verify_400("多余字段",
                          payload={"snapshot": snap, "x": 1})
        expect_verify_400("snapshot 非对象", payload={"snapshot": "x"})

        # ---------------------------------------------------------- #
        # 5. verify 成功与分阶段失败
        # ---------------------------------------------------------- #
        st, raw = verify_post({"snapshot": snap}, headers=TA)
        r = json.loads(raw)
        check("verify 合法快照成功", st == 200 and r == {"valid": True})

        def expect_invalid(name, snapshot, reason, headers=TA):
            st, raw = verify_post({"snapshot": snapshot}, headers=headers)
            try:
                r = json.loads(raw.decode() or "{}")
            except ValueError:
                r = {}
            check(f"verify 200: {name}",
                  st == 200 and list(r.keys()) == ["valid", "reason"]
                  and r["valid"] is False and r["reason"] == reason)

        # 快照非法：键集/类型
        bad = dict(snap)
        del bad["signature"]
        expect_invalid("缺键", bad, "快照非法")
        bad = dict(snap, extra=1)
        expect_invalid("多键", bad, "快照非法")
        bad = dict(snap, anchors={})
        expect_invalid("anchors 非数组", bad, "快照非法")
        bad = dict(snap, signer_key_version=0)
        expect_invalid("signer_key_version 非正整数", bad, "快照非法")
        bad = dict(snap, signer_key_version=True)
        expect_invalid("signer_key_version 布尔", bad, "快照非法")
        bad = dict(snap, signer_did="")
        expect_invalid("signer_did 空", bad, "快照非法")
        item = dict(snap["anchors"][0])
        item["uses"] = ["vp", "vc"]
        bad = dict(snap, anchors=[item] + snap["anchors"][1:])
        expect_invalid("uses 非规范序", bad, "快照非法")
        item = dict(snap["anchors"][0])
        item["status"] = "unknown"
        bad = dict(snap, anchors=[item] + snap["anchors"][1:])
        expect_invalid("status 非法值", bad, "快照非法")
        item = dict(snap["anchors"][0])
        del item["uses"]
        bad = dict(snap, anchors=[item] + snap["anchors"][1:])
        expect_invalid("锚点项缺 uses", bad, "快照非法")

        # 快照非法：anchors 顺序/重复
        bad = dict(snap, anchors=list(reversed(snap["anchors"])))
        expect_invalid("anchors 逆序", bad, "快照非法")
        bad = dict(snap, anchors=snap["anchors"] + [snap["anchors"][-1]])
        expect_invalid("anchors 重复", bad, "快照非法")

        # 锚点不可用：他租户无 generic 全用途 active 锚点（他租户虽注册
        # 了 signer 锚点，但 did_a#9 快照签名对不上；先验证他租户场景）
        st, raw = snapshot_get(f"signer_did={signer_did}", headers=TB)
        # 他租户无本地 signer DID -> 404，改用本租户快照在他租户验真。
        check("他租户 GET 快照 404", st == 404)
        expect_invalid("他租户锚点不可用", snap, "锚点不可用", headers=TB)

        # 锚点不可用：签名 DID 锚点缺 generic 用途
        ng_did, ng_pub = make_did("no-generic-signer", TA)
        add_anchor(ng_did, ng_pub, 1, TA, uses=["vc"])
        st, raw = snapshot_get(f"signer_did={ng_did}", headers=TA)
        assert st == 200
        snap_ng = json.loads(raw)
        expect_invalid("锚点无 generic 用途", snap_ng, "锚点不可用")

        # 锚点不可用：签名 DID 锚点已吊销
        rv_did, rv_pub = make_did("revoked-signer", TA)
        add_anchor(rv_did, rv_pub, 1, TA)
        st, raw = snapshot_get(f"signer_did={rv_did}", headers=TA)
        assert st == 200
        snap_rv = json.loads(raw)
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{rv_did}/1/status",
                      {"status": "revoked"}, TA)
        assert st == 200
        expect_invalid("签名锚点已吊销", snap_rv, "锚点不可用")

        # 此后的 verify 调用之间不再有任何写操作。
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_verify_before = len(json.loads(raw)["events"])

        # 签名格式错误：结构合法、锚点可用，签名非规范格式
        bad = dict(snap, signature="not-a-signature")
        expect_invalid("签名非 base64url", bad, "签名格式错误")
        bad = dict(snap, signature="A" * 87)
        expect_invalid("签名长度非 86", bad, "签名格式错误")

        # 签名校验失败：格式合法但签名与内容不符
        item = dict(snap["anchors"][0])
        item["updated_at"] = "2026-01-01T00:00:00Z" if \
            snap["anchors"][0]["updated_at"] is None else None
        bad_anchors = [item] + snap["anchors"][1:]
        bad_anchors = sorted(bad_anchors,
                             key=lambda x: (x["did"], x["key_version"]))
        bad = dict(snap, anchors=bad_anchors)
        expect_invalid("篡改 anchors 内容", bad, "签名校验失败")
        other = crypto.sign({"anchors": [], "signer_did": signer_did,
                             "signer_key_version": 1},
                            crypto.generate_private_key_pem())
        bad = dict(snap, signature=other)
        expect_invalid("他钥签名", bad, "签名校验失败")

        # verify 纯只读（审计不变）
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        check("POST verify 纯只读（审计不变）",
              len(json.loads(raw)["events"]) == audit_verify_before)

        # ---------------------------------------------------------- #
        # 6. 跨重启稳定：重取快照仍可验真
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, raw = snapshot_get(f"signer_did={signer_did}", headers=TA)
        check("重启后快照 200", st == 200)
        snap2 = json.loads(raw)
        st, raw = verify_post({"snapshot": snap2}, headers=TA)
        check("重启后快照可验真",
              st == 200 and json.loads(raw) == {"valid": True})
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
