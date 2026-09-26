#!/usr/bin/env python3
"""GET/POST /v1/trust/ac-proof 锚点变更包含证明端到端测试。

直接运行：python3 tests/trust_ac_proof_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- GET 查询参数仅许唯一 cursor、唯一 snapshot 与唯一非空 signer_did
  （缺失/空值/重复/空白/符号/小数/布尔词/Unicode 数字/未知参数 400，
  仅 {"error"}；cursor>snapshot、snapshot 超过最大游标 400；显式空
  租户头 400）；签名 DID 未知/他租户 404、已停用 409；
- GET 200 键序 event,snapshot,root,path,signer_did,signer_key_version,
  signature；event 沿用变更流事件协议；root 为 64 位小写 hex；path
  自叶向根、项键序 side,hash；按 path 可重算 root；签名可由签名 DID
  当前公钥对前六键规范化 JSON 验签；单事件 path 为空、奇数末项复制；
  重启后 event/snapshot/root/path 逐字节一致；GET 纯只读不记审计；
- POST 请求体须恰含 proof 对象（否则 400 仅 {error}）；proof 须恰含
  七键；失败均 200 且 reason 依次为 证明非法/锚点不可用/签名格式错误/
  签名校验失败/包含证明校验失败；成功仅 {"valid":true}；跨租户隔离；
  POST 纯只读不记审计。
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

from vcbackend import crypto  # noqa: E402

AC_PROOF_PATH = "/v1/trust/ac-proof"
RESP_KEYS = [
    "event", "snapshot", "root", "path",
    "signer_did", "signer_key_version", "signature",
]
EVENT_KEYS = [
    "cursor", "action", "did", "key_version",
    "public_key", "status", "uses",
]
ALL_USES = ["generic", "vc", "vp", "proof", "did", "status", "deactivation"]
HEX64 = "0123456789abcdef" * 4


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
    return priv, crypto.public_key_pem_from_private(priv)


def leaf_hash(event_obj):
    return hashlib.sha256(
        b"\x00" + crypto.canonicalize(event_obj)
    ).digest()


def parent_hash(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def recompute_root(event_obj, path):
    current = leaf_hash(event_obj)
    for item in path:
        sibling = bytes.fromhex(item["hash"])
        if item["side"] == "left":
            current = parent_hash(sibling, current)
        else:
            current = parent_hash(current, sibling)
    return current.hex()


def main():
    port = 9047
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

    def ac_get(query="", headers=None):
        url = f"{base}{AC_PROOF_PATH}?{query}" if query else (
            base + AC_PROOF_PATH
        )
        return _http("GET", url, headers=headers)

    def ac_post(payload, headers=None, raw_body=None):
        return _http("POST", base + AC_PROOF_PATH, payload,
                     headers=headers, raw_body=raw_body)

    try:
        TA = {"X-Tenant-ID": "tenant-a"}
        TB = {"X-Tenant-ID": "tenant-b"}

        def make_did(label, headers):
            st, raw = _http("POST", f"{base}/v1/dids",
                            {"method": "web", "public_key": label}, headers)
            assert st in (200, 201), raw
            body = json.loads(raw)
            return body["did"], body["public_key"]

        def add_anchor(did, pub, version, headers, uses=None):
            payload = {"did": did, "public_key": pub,
                       "key_version": version}
            if uses is not None:
                payload["uses"] = uses
            st, raw = _http("POST", f"{base}/v1/trust/anchors",
                            payload, headers)
            assert st in (200, 201), raw
            return json.loads(raw)

        def audit_count(headers):
            st, raw = _http("GET", f"{base}/v1/audit?limit=200",
                            headers=headers)
            assert st == 200, raw
            return len(json.loads(raw)["events"])

        signer_did, signer_pub = make_did("ac-proof-signer", TA)

        def fetch(cursor, snapshot, signer=signer_did, headers=TA):
            qs = (f"cursor={cursor}&snapshot={snapshot}"
                  f"&signer_did={signer}")
            st, raw = ac_get(qs, headers=headers)
            assert st == 200, raw
            return json.loads(raw)

        # ---------------------------------------------------------- #
        # 1. GET 400 族：仅 {error} 非空中文
        # ---------------------------------------------------------- #
        def expect_400(name, query, headers=None):
            st, raw = ac_get(query, headers=headers)
            try:
                r = json.loads(raw.decode() or "{}")
            except ValueError:
                r = {}
            check(f"GET 400 仅 error: {name}",
                  st == 400 and list(r.keys()) == ["error"]
                  and isinstance(r["error"], str) and bool(r["error"]))

        expect_400("缺全部参数", "", headers=TA)
        expect_400("缺 cursor", "snapshot=1&signer_did=x", headers=TA)
        expect_400("缺 snapshot", "cursor=1&signer_did=x", headers=TA)
        expect_400("缺 signer_did", "cursor=1&snapshot=1", headers=TA)
        expect_400("cursor 空值", "cursor=&snapshot=1&signer_did=x",
                   headers=TA)
        expect_400("cursor 零", "cursor=0&snapshot=1&signer_did=x",
                   headers=TA)
        expect_400("cursor 负数", "cursor=-1&snapshot=1&signer_did=x",
                   headers=TA)
        expect_400("cursor 小数", "cursor=1.5&snapshot=2&signer_did=x",
                   headers=TA)
        expect_400("cursor 布尔词", "cursor=true&snapshot=2&signer_did=x",
                   headers=TA)
        expect_400("cursor 含空白", "cursor=%201&snapshot=2&signer_did=x",
                   headers=TA)
        expect_400("cursor Unicode 数字",
                   "cursor=%E0%A7%A7&snapshot=2&signer_did=x", headers=TA)
        expect_400("cursor 重复",
                   "cursor=1&cursor=1&snapshot=1&signer_did=x", headers=TA)
        expect_400("snapshot 空值", "cursor=1&snapshot=&signer_did=x",
                   headers=TA)
        expect_400("snapshot 零", "cursor=1&snapshot=0&signer_did=x",
                   headers=TA)
        expect_400("snapshot 重复",
                   "cursor=1&snapshot=1&snapshot=2&signer_did=x",
                   headers=TA)
        expect_400("signer_did 空值", "cursor=1&snapshot=1&signer_did=",
                   headers=TA)
        expect_400("signer_did 重复",
                   "cursor=1&snapshot=1&signer_did=x&signer_did=y",
                   headers=TA)
        expect_400("未知参数",
                   "cursor=1&snapshot=1&signer_did=x&after=0", headers=TA)
        expect_400("cursor>snapshot",
                   "cursor=3&snapshot=2&signer_did=x", headers=TA)
        st, _ = ac_get("cursor=1&snapshot=1&signer_did=x",
                       headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", st == 400)

        # 空流：任何正数 snapshot 均超过最大游标 0（400 优先于 404/409）
        expect_400("空流 snapshot 越界",
                   f"cursor=1&snapshot=1&signer_did={signer_did}",
                   headers=TA)
        expect_400("越界优先于未知签名 DID",
                   "cursor=1&snapshot=1&signer_did=did:web:unknown",
                   headers=TA)

        # ---------------------------------------------------------- #
        # 2. 构造变更事件：3 条（registered/rotated/uses.updated）
        # ---------------------------------------------------------- #
        d1 = "did:web:ac-anchor-one"
        _, pem1 = gen_pub_pem()
        _, pem2 = gen_pub_pem()
        add_anchor(d1, pem1, 1, TA)
        st, raw = _http("POST", f"{base}/v1/trust/anchors/{d1}/rotate",
                        {"from_key_version": 1, "public_key": pem2}, TA)
        assert st in (200, 201), raw
        st, raw = _http("PUT", f"{base}/v1/trust/anchors/{d1}/2/uses",
                        {"from_uses": ALL_USES, "uses": ["vc", "vp"]}, TA)
        assert st == 200, raw

        # 变更流事件（cursor 1..3）
        st, raw = _http(
            "GET",
            f"{base}/v1/trust/anchor-changes?signer_did={signer_did}",
            headers=TA)
        assert st == 200, raw
        stream_events = json.loads(raw)["events"]
        check("变更流共 3 条事件", len(stream_events) == 3)

        # ---------------------------------------------------------- #
        # 3. GET 404 / 409（参数合法后）
        # ---------------------------------------------------------- #
        # 他租户也构造一条事件，使跨租户判定落在签名 DID 而非越界
        _, pem_tb = gen_pub_pem()
        add_anchor("did:web:ac-tb-anchor", pem_tb, 1, TB)

        st, raw = ac_get(
            "cursor=1&snapshot=1&signer_did=did:web:unknown", headers=TA)
        check("未知签名 DID 404", st == 404
              and list(json.loads(raw).keys()) == ["error"])
        st, _ = ac_get(
            f"cursor=1&snapshot=1&signer_did={signer_did}", headers=TB)
        check("他租户签名 DID 404", st == 404)

        deactivated_did, _ = make_did("ac-proof-deactivated", TA)
        st, raw = _http(
            "POST", f"{base}/v1/dids/{deactivated_did}/deactivate",
            {}, TA)
        assert st == 200, raw
        st, _ = ac_get(
            f"cursor=1&snapshot=1&signer_did={deactivated_did}",
            headers=TA)
        check("已停用签名 DID 409", st == 409)

        # 他租户仅 1 条事件：snapshot=5 越界 400（租户隔离）
        expect_400("他租户 snapshot 越界",
                   f"cursor=1&snapshot=5&signer_did={signer_did}",
                   headers=TB)

        # ---------------------------------------------------------- #
        # 4. GET 200：键序、事件协议、Merkle 重算、签名可验
        # ---------------------------------------------------------- #
        audits_before = audit_count(TA)

        proof1 = fetch(1, 1)
        check("GET 200 键序", list(proof1.keys()) == RESP_KEYS)
        check("event 键序沿用变更流",
              list(proof1["event"].keys()) == EVENT_KEYS)
        check("event 与变更流一致", proof1["event"] == stream_events[0])
        check("snapshot 回显", proof1["snapshot"] == 1)
        check("root 为 64 位小写 hex",
              isinstance(proof1["root"], str)
              and len(proof1["root"]) == 64
              and all(c in "0123456789abcdef" for c in proof1["root"]))
        check("单叶 path 为空", proof1["path"] == [])
        check("单叶 root 为叶哈希",
              proof1["root"] == leaf_hash(proof1["event"]).hex())
        check("signer 回显", proof1["signer_did"] == signer_did
              and proof1["signer_key_version"] == 1)
        try:
            crypto.verify({k: proof1[k] for k in RESP_KEYS[:6]},
                          proof1["signature"], signer_pub)
            sig_ok = True
        except Exception:
            sig_ok = False
        check("GET 签名可验（前六键）", sig_ok)

        # 三叶树：cursor 1..3、snapshot 3，path 均可重算 root
        for cursor in (1, 2, 3):
            proof = fetch(cursor, 3)
            check(f"cursor={cursor} event 与变更流一致",
                  proof["event"] == stream_events[cursor - 1])
            check(f"cursor={cursor} path 项键序",
                  all(list(item.keys()) == ["side", "hash"]
                      for item in proof["path"]))
            check(f"cursor={cursor} path side 合法",
                  all(item["side"] in ("left", "right")
                      for item in proof["path"]))
            check(f"cursor={cursor} path 可重算 root",
                  recompute_root(proof["event"], proof["path"])
                  == proof["root"])
            try:
                crypto.verify({k: proof[k] for k in RESP_KEYS[:6]},
                              proof["signature"], signer_pub)
                sig_ok = True
            except Exception:
                sig_ok = False
            check(f"cursor={cursor} 签名可验", sig_ok)

        # 三叶树根：手工构建（叶 3 奇数复制）
        leaves = [leaf_hash(ev) for ev in stream_events]
        manual_root = parent_hash(
            parent_hash(leaves[0], leaves[1]),
            parent_hash(leaves[2], leaves[2]),
        ).hex()
        check("三叶 root 与手工构建一致",
              fetch(2, 3)["root"] == manual_root)
        # 中间叶路径：兄弟叶 1 在左，复制叶 3 在右
        proof_mid = fetch(2, 3)
        check("中间叶 path 长度与内容",
              proof_mid["path"] == [
                  {"side": "left", "hash": leaves[0].hex()},
                  {"side": "right",
                   "hash": parent_hash(leaves[2], leaves[2]).hex()},
              ])
        # 奇数末项复制：cursor=3 的兄弟即自身
        proof_last = fetch(3, 3)
        check("奇数末项复制", proof_last["path"][0] == {
            "side": "right", "hash": leaves[2].hex()})

        # snapshot 前缀：snapshot=2 的树与 snapshot=3 不同
        proof_s2 = fetch(2, 2)
        check("snapshot=2 root 为双叶树",
              proof_s2["root"]
              == parent_hash(leaves[0], leaves[1]).hex())
        check("snapshot=2 path", proof_s2["path"] == [
            {"side": "left", "hash": leaves[0].hex()}])

        check("GET 不记审计", audit_count(TA) == audits_before)

        # ---------------------------------------------------------- #
        # 5. POST 400 族：请求体须恰含 proof 对象
        # ---------------------------------------------------------- #
        def expect_post_400(name, payload=None, raw_body=None):
            st, raw = ac_post(payload, headers=TA, raw_body=raw_body)
            try:
                r = json.loads(raw.decode() or "{}")
            except ValueError:
                r = {}
            check(f"POST 400 仅 error: {name}",
                  st == 400 and list(r.keys()) == ["error"]
                  and isinstance(r["error"], str) and bool(r["error"]))

        expect_post_400("空体")
        expect_post_400("非法 JSON", raw_body=b"{not json")
        expect_post_400("非对象", raw_body=b"[1,2]")
        expect_post_400("空对象", {})
        expect_post_400("多余字段", {"proof": {}, "after": 0})
        expect_post_400("proof 非对象", {"proof": []})
        expect_post_400("proof 为 null", {"proof": None})

        # ---------------------------------------------------------- #
        # 6. POST 200 失败族：证明非法
        # ---------------------------------------------------------- #
        good = fetch(2, 3)

        def expect_invalid(name, mutate):
            proof = json.loads(json.dumps(good))
            mutate(proof)
            st, raw = ac_post({"proof": proof}, headers=TA)
            body = json.loads(raw)
            check(f"POST 200 证明非法: {name}",
                  st == 200 and body == {"valid": False,
                                         "reason": "证明非法"})

        expect_invalid("缺键", lambda p: p.pop("root"))
        expect_invalid("多键", lambda p: p.update(extra=1))
        expect_invalid("event 缺键",
                       lambda p: p["event"].pop("uses"))
        expect_invalid("event 多键",
                       lambda p: p["event"].update(foo=1))
        expect_invalid("event cursor 零",
                       lambda p: p["event"].update(cursor=0))
        expect_invalid("event action 非法",
                       lambda p: p["event"].update(action="x"))
        expect_invalid("event status 非法",
                       lambda p: p["event"].update(status="x"))
        expect_invalid("event uses 乱序",
                       lambda p: p["event"].update(uses=["vc", "generic"]))
        expect_invalid("snapshot 零", lambda p: p.update(snapshot=0))
        expect_invalid("snapshot 布尔", lambda p: p.update(snapshot=True))
        expect_invalid("root 非 hex", lambda p: p.update(root="zz"))
        expect_invalid("root 大写 hex",
                       lambda p: p.update(root=HEX64.upper()))
        expect_invalid("path 非数组", lambda p: p.update(path={}))
        expect_invalid("path 项多键",
                       lambda p: p["path"].append(
                           {"side": "left", "hash": HEX64, "x": 1}))
        expect_invalid("path side 非法",
                       lambda p: p["path"].append(
                           {"side": "up", "hash": HEX64}))
        expect_invalid("path hash 非 hex",
                       lambda p: p["path"].append(
                           {"side": "left", "hash": "zz"}))
        expect_invalid("signer_did 空", lambda p: p.update(signer_did=""))
        expect_invalid("signer_key_version 零",
                       lambda p: p.update(signer_key_version=0))
        expect_invalid("signature 空", lambda p: p.update(signature=""))

        # ---------------------------------------------------------- #
        # 7. POST：锚点不可用（未注册/吊销/无 generic/版本不符/跨租户）
        # ---------------------------------------------------------- #
        def expect_reason(name, proof, reason, headers=TA):
            st, raw = ac_post({"proof": proof}, headers=headers)
            body = json.loads(raw)
            check(f"POST 200 {reason}: {name}",
                  st == 200 and body == {"valid": False, "reason": reason})

        expect_reason("锚点未注册", good, "锚点不可用")

        # 注册签名 DID 的锚点（版本 1，公钥为 DID 当前公钥）
        add_anchor(signer_did, signer_pub, 1, TA)
        st, raw = ac_post({"proof": good}, headers=TA)
        check("POST 成功仅 valid:true",
              st == 200 and json.loads(raw) == {"valid": True})

        bad_version = dict(good, signer_key_version=2)
        expect_reason("锚点版本不存在", bad_version, "锚点不可用")

        # 无 generic 用途的锚点
        other_priv, other_pub = gen_pub_pem()
        add_anchor("did:web:ac-no-generic", other_pub, 1, TA,
                   uses=["vc", "vp"])
        crafted = dict(good, signer_did="did:web:ac-no-generic")
        expect_reason("锚点无 generic 用途", crafted, "锚点不可用")

        # 跨租户：tenant-b 无该锚点
        expect_reason("跨租户锚点不可用", good, "锚点不可用", headers=TB)

        # 吊销后不可用
        add_anchor("did:web:ac-revoked", other_pub, 1, TA)
        st, raw = _http(
            "PUT", f"{base}/v1/trust/anchors/did:web:ac-revoked/1/status",
            {"status": "revoked"}, TA)
        assert st == 200, raw
        crafted = dict(good, signer_did="did:web:ac-revoked")
        expect_reason("锚点已吊销", crafted, "锚点不可用")

        # ---------------------------------------------------------- #
        # 8. POST：签名格式错误 / 签名校验失败
        # ---------------------------------------------------------- #
        bad_fmt = dict(good, signature="not-base64url!!!")
        expect_reason("签名格式错误", bad_fmt, "签名格式错误")

        # 格式合法但内容被篡改（用 good 的签名）
        tampered = dict(good, snapshot=2)
        expect_reason("篡改后签名校验失败", tampered, "签名校验失败")

        # 用他钥签名（格式合法、锚点匹配 signer_did 但签名对不上）
        _, wrong_pub = gen_pub_pem()
        forged = dict(good)
        forged["signature"] = crypto.sign(
            {k: good[k] for k in RESP_KEYS[:6]}, other_priv)
        expect_reason("他钥签名校验失败", forged, "签名校验失败")

        # ---------------------------------------------------------- #
        # 9. POST：包含证明校验失败（签名合法但 path 重算不符）
        # ---------------------------------------------------------- #
        # 自持私钥注册锚点，对篡改 path 的证明重新签名
        self_priv, self_pub = gen_pub_pem()
        add_anchor("did:web:ac-self", self_pub, 1, TA)

        def resign(proof):
            proof["signer_did"] = "did:web:ac-self"
            proof["signer_key_version"] = 1
            proof["signature"] = crypto.sign(
                {k: proof[k] for k in RESP_KEYS[:6]}, self_priv)
            return proof

        broken_path = json.loads(json.dumps(good))
        broken_path["path"] = list(broken_path["path"])
        broken_path["path"][0] = {
            "side": broken_path["path"][0]["side"],
            "hash": HEX64,
        }
        expect_reason("path 哈希被换", resign(broken_path),
                      "包含证明校验失败")

        broken_root = json.loads(json.dumps(good))
        broken_root["root"] = HEX64
        expect_reason("root 被换", resign(broken_root), "包含证明校验失败")

        broken_event = json.loads(json.dumps(good))
        broken_event["event"]["uses"] = ["vc"]
        expect_reason("event 被换", resign(broken_event),
                      "包含证明校验失败")

        # 合法证明换用自持锚点签名也可验真
        resigned_good = resign(json.loads(json.dumps(good)))
        st, raw = ac_post({"proof": resigned_good}, headers=TA)
        check("自持锚点签名验真成功",
              st == 200 and json.loads(raw) == {"valid": True})

        # ---------------------------------------------------------- #
        # 10. GET/POST 纯只读：不记审计；结论重启稳定
        # ---------------------------------------------------------- #
        audits_before = audit_count(TA)
        fetch(1, 3)
        ac_post({"proof": good}, headers=TA)
        ac_post({"proof": broken_root}, headers=TA)
        ac_post({"proof": bad_fmt}, headers=TA)
        ac_post({"proof": {"x": 1}}, headers=TA)
        check("GET/POST 均不记审计", audit_count(TA) == audits_before)

        proc.terminate()
        proc.wait(timeout=10)
        proc = start()

        proof_after = fetch(2, 3)
        check("重启后 event/snapshot/root/path 一致",
              all(proof_after[k] == good[k]
                  for k in ("event", "snapshot", "root", "path")))
        st, raw = ac_post({"proof": good}, headers=TA)
        check("重启后证明仍可验真",
              st == 200 and json.loads(raw) == {"valid": True})
        st, raw = ac_post({"proof": broken_root}, headers=TA)
        check("重启后包含证明校验失败结论稳定",
              st == 200 and json.loads(raw) == {
                  "valid": False, "reason": "包含证明校验失败"})
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
        print(f"{len(failures)} 项失败")
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    main()
