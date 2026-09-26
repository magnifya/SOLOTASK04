#!/usr/bin/env python3
"""GET/POST /v1/trust/ac-proof 锚点变更证明端到端测试。

直接运行：python3 tests/trust_anchor_ac_proof_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

GET 覆盖：
- 查询参数仅许唯一 cursor、snapshot、signer_did；cursor/snapshot 为 ASCII
  正整数且 cursor<=snapshot<=本租户最大游标；缺失/空值/重复/空白/符号/
  小数/布尔词/Unicode 数字/未知参数/越界 400，仅 {"error"}；显式空租户
  头 400；签名 DID 未知（含他租户）404、已停用 409；事件不存在（游标
  缺口）404；
- 200 键序 event,snapshot,root,path,signer_did,signer_key_version,
  signature；event 沿用变更流事件协议；root/hash 为 64 位小写 hex；path
  自叶向根、项键序 side,hash、side 限 left/right；
- 以 cursor 升序 snapshot 前缀建树（0x00 叶、0x01 父、奇数末项复制），
  测试内独立重算 root 一致，且同 snapshot 各事件 root 相同、path 自洽；
- 签名由签名 DID 当前公钥对前六键规范化 JSON 验签；GET 只读不记审计；
  重启稳定。

POST 覆盖：
- 请求体须恰含 proof（JSON 对象），否则 400 仅 {"error"}；proof 须恰含
  七键；
- 200 原因依次为证明非法 -> 锚点不可用 -> 签名格式错误 -> 签名校验失败
  -> 包含证明校验失败；成功仅 {"valid":true}；
- 验真不依赖本地事件（远端锚点 + 自造事件可验），跨租户锚点不可用；
  纯只读。
"""

import copy
import hashlib
import json
import os
import re
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

PROOF_PATH = "/v1/trust/ac-proof"
RESP_KEYS = [
    "event", "snapshot", "root", "path",
    "signer_did", "signer_key_version", "signature",
]
SIGNED_KEYS = RESP_KEYS[:6]
EVENT_KEYS = [
    "cursor", "action", "did", "key_version",
    "public_key", "status", "uses",
]
ALL_USES = ["generic", "vc", "vp", "proof", "did", "status", "deactivation"]
HEX64 = re.compile(r"^[0-9a-f]{64}$")


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


def gen_keypair():
    priv = crypto.generate_private_key_pem()
    return priv, crypto.public_key_pem_from_private(priv)


def gen_pub_pem():
    return gen_keypair()[1]


# 测试内独立 Merkle 实现（不复测被测代码，避免自证）。
def leaf_hash(event_obj):
    body = json.dumps(
        event_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(b"\x00" + body).hexdigest()


def parent_hash(left_hex, right_hex):
    return hashlib.sha256(
        b"\x01" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)
    ).hexdigest()


def build_tree(leaf_hashes):
    """返回 (root, 每个叶 index 自叶向根的 path)；奇数末项复制。

    root 与目标无关，取首个叶计算值；各 path 单独按同一规则推导。
    """
    all_paths = []
    for index in range(len(leaf_hashes)):
        lvl = list(leaf_hashes)
        cur = index
        path = []
        while len(lvl) > 1:
            if len(lvl) % 2 == 1:
                lvl.append(lvl[-1])
            if cur % 2 == 0:
                path.append({"side": "right", "hash": lvl[cur + 1]})
            else:
                path.append({"side": "left", "hash": lvl[cur - 1]})
            lvl = [
                parent_hash(lvl[p], lvl[p + 1])
                for p in range(0, len(lvl), 2)
            ]
            cur //= 2
        all_paths.append(path)
    root = all_paths and _recompute(leaf_hashes[0], all_paths[0])
    return root, all_paths


def _recompute(leaf_hex, path):
    """测试辅助：按 path 从某叶哈希自叶向根重算 root。"""
    cur = leaf_hex
    for item in path:
        sibling = item["hash"]
        if item["side"] == "left":
            cur = parent_hash(sibling, cur)
        else:
            cur = parent_hash(cur, sibling)
    return cur


def main():
    port = 9055
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

    def proof_get(query="", headers=None):
        url = f"{base}{PROOF_PATH}?{query}" if query else base + PROOF_PATH
        return _http("GET", url, headers=headers)

    def proof_post(payload, headers=None, raw_body=None):
        return _http("POST", base + PROOF_PATH, payload,
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
            payload = {"did": did, "public_key": pub, "key_version": version}
            if uses is not None:
                payload["uses"] = uses
            st, raw = _http("POST", f"{base}/v1/trust/anchors",
                            payload, headers)
            assert st in (200, 201), raw
            return json.loads(raw)

        signer_did, signer_pub = make_did("ac-signer", TA)
        # 注册签名者为含 generic 的活动锚点（事件 1），再追加两条锚点
        # 版本（事件 2、3）。
        add_anchor(signer_did, signer_pub, 1, TA)
        pem2 = gen_pub_pem()
        pem3 = gen_pub_pem()
        add_anchor("did:web:ac-one", pem2, 1, TA)
        add_anchor("did:web:ac-one", pem3, 2, TA, uses=["generic", "vc"])

        def fetch_proof(cursor, snapshot, signer=signer_did, headers=TA):
            qs = f"cursor={cursor}&snapshot={snapshot}&signer_did={signer}"
            st, raw = proof_get(qs, headers=headers)
            return st, json.loads(raw) if st == 200 else raw

        # ---------------------------------------------------------- #
        # 1. GET 400 族：仅 {error} 非空中文
        # ---------------------------------------------------------- #
        def expect_400(name, query, headers=None):
            st, raw = proof_get(query, headers=headers)
            try:
                r = json.loads(raw.decode() or "{}")
            except ValueError:
                r = {}
            check(f"GET 400 仅 error: {name}",
                  st == 400 and list(r.keys()) == ["error"]
                  and isinstance(r["error"], str) and bool(r["error"]))

        expect_400("缺全部参数", "", headers=TA)
        expect_400("缺 snapshot", "cursor=1&signer_did=x", headers=TA)
        expect_400("缺 cursor", "snapshot=1&signer_did=x", headers=TA)
        expect_400("缺 signer_did", "cursor=1&snapshot=1", headers=TA)
        expect_400("未知参数",
                   "cursor=1&snapshot=1&signer_did=x&after=1", headers=TA)
        expect_400("cursor 空值", "cursor=&snapshot=1&signer_did=x",
                   headers=TA)
        expect_400("snapshot 空值", "cursor=1&snapshot=&signer_did=x",
                   headers=TA)
        expect_400("signer_did 空值", "cursor=1&snapshot=1&signer_did=",
                   headers=TA)
        expect_400("cursor 重复",
                   "cursor=1&cursor=2&snapshot=3&signer_did=x", headers=TA)
        expect_400("snapshot 重复",
                   "cursor=1&snapshot=2&snapshot=3&signer_did=x",
                   headers=TA)
        expect_400("signer_did 重复",
                   "cursor=1&snapshot=1&signer_did=x&signer_did=y",
                   headers=TA)
        expect_400("cursor=0", "cursor=0&snapshot=1&signer_did=x",
                   headers=TA)
        expect_400("snapshot=0", "cursor=1&snapshot=0&signer_did=x",
                   headers=TA)
        expect_400("cursor 负数", "cursor=-1&snapshot=1&signer_did=x",
                   headers=TA)
        expect_400("cursor 小数", "cursor=1.0&snapshot=1&signer_did=x",
                   headers=TA)
        expect_400("snapshot 小数", "cursor=1&snapshot=1.5&signer_did=x",
                   headers=TA)
        expect_400("cursor 布尔词", "cursor=true&snapshot=1&signer_did=x",
                   headers=TA)
        expect_400("cursor 含空白",
                   "cursor=%201&snapshot=1&signer_did=x", headers=TA)
        expect_400("cursor Unicode 数字",
                   "cursor=%E0%A7%A7&snapshot=1&signer_did=x", headers=TA)
        expect_400("cursor>snapshot",
                   "cursor=2&snapshot=1&signer_did=x", headers=TA)
        expect_400("snapshot>最大游标",
                   "cursor=1&snapshot=99&signer_did=x", headers=TA)
        st, _ = proof_get("cursor=1&snapshot=1&signer_did=x",
                          headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", st == 400)

        # ---------------------------------------------------------- #
        # 2. GET 404 / 409
        # ---------------------------------------------------------- #
        st, _ = proof_get("cursor=1&snapshot=3&signer_did=did:web:nope",
                          headers=TA)
        check("未知签名 DID 404", st == 404)
        # 租户 B 先注册锚点使其最大游标>=1，范围校验通过后签名 DID 仍属
        # 他租户 -> 404。
        b_did, _ = make_did("ac-b", TB)
        add_anchor(b_did, gen_pub_pem(), 1, TB)
        st, _ = proof_get(f"cursor=1&snapshot=1&signer_did={signer_did}",
                          headers=TB)
        check("他租户签名 DID 404", st == 404)

        # ---------------------------------------------------------- #
        # 3. GET 200：键序、事件协议、hex、签名、Merkle 自洽
        # ---------------------------------------------------------- #
        proofs = {}
        for cursor in (1, 2, 3):
            st, body = fetch_proof(cursor, 3)
            assert st == 200, body
            proofs[cursor] = body
            check(f"200 键序 (cursor={cursor})",
                  list(body.keys()) == RESP_KEYS)
            check(f"snapshot 回显 (cursor={cursor})",
                  body["snapshot"] == 3)
            check(f"signer 回显 (cursor={cursor})",
                  body["signer_did"] == signer_did
                  and body["signer_key_version"] == 1)
            check(f"event 键序 (cursor={cursor})",
                  list(body["event"].keys()) == EVENT_KEYS
                  and body["event"]["cursor"] == cursor)
            check(f"root 为 64 位小写 hex (cursor={cursor})",
                  isinstance(body["root"], str)
                  and bool(HEX64.fullmatch(body["root"])))
            check(f"path 项键序与 side (cursor={cursor})",
                  isinstance(body["path"], list)
                  and all(
                      list(item.keys()) == ["side", "hash"]
                      and item["side"] in ("left", "right")
                      and bool(HEX64.fullmatch(item["hash"]))
                      for item in body["path"]))
            signed = {key: body[key] for key in SIGNED_KEYS}
            try:
                crypto.verify(signed, body["signature"], signer_pub)
                sig_ok = True
            except Exception:  # noqa: BLE001
                sig_ok = False
            check(f"前六键 ES256 签名可验 (cursor={cursor})", sig_ok)
            crypto.validate_signature_format_strict(body["signature"])

        # 同 snapshot 三事件 root 相同
        check("同 snapshot 各事件 root 相同",
              proofs[1]["root"] == proofs[2]["root"] == proofs[3]["root"])

        # 用变更流取 snapshot 前缀全部事件，独立建树比对 root 与各 path。
        st, raw = _http("GET", f"{base}/v1/trust/anchor-changes"
                               f"?after=0&signer_did={signer_did}",
                        headers=TA)
        assert st == 200, raw
        changes = json.loads(raw)
        prefix_events = [ev for ev in changes["events"] if ev["cursor"] <= 3]
        check("snapshot 前缀恰 3 条", len(prefix_events) == 3)
        leaves = [leaf_hash(ev) for ev in prefix_events]
        expect_root, expect_paths = build_tree(leaves)
        check("服务 root 与独立建树一致",
              proofs[1]["root"] == expect_root)
        for index, cursor in enumerate((1, 2, 3)):
            check(f"path 自叶向根自洽 (cursor={cursor})",
                  proofs[cursor]["path"] == expect_paths[index])

        # 单叶前缀（snapshot=1）：path 为空，root 即叶哈希
        st, body = fetch_proof(1, 1)
        assert st == 200, body
        check("单叶 path 为空", body["path"] == [])
        check("单叶 root 即叶哈希",
              body["root"] == leaf_hash(prefix_events[0]))

        # snapshot 较小前缀：root 仅由 cursor<=snapshot 的事件决定
        st, body2 = fetch_proof(2, 2)
        assert st == 200, body2
        check("snapshot=2 前缀 root 独立一致",
              body2["root"] == build_tree(leaves[:2])[0])

        # event 内容沿用变更流协议（字段值一致）
        check("event 与变更流同序事件逐字节一致",
              all(proofs[c]["event"] == prefix_events[c - 1]
                  for c in (1, 2, 3)))

        # GET 只读（不记审计）
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_before = len(json.loads(raw)["events"])
        for cursor in (1, 2, 3):
            fetch_proof(cursor, 3)
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        check("GET ac-proof 不记审计",
              len(json.loads(raw)["events"]) == audit_before)

        # 已停用签名者 409
        st, _ = _http("POST", f"{base}/v1/dids/{signer_did}/deactivate",
                      {"reason": "机构调整"}, TA)
        assert st == 200
        st, _ = proof_get(f"cursor=1&snapshot=3&signer_did={signer_did}",
                          headers=TA)
        check("已停用签名 DID 409", st == 409)

        # ---------------------------------------------------------- #
        # 4. 重启稳定
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        signer_a2, signer_a2_pub = make_did("ac-signer-a2", TA)
        # 注册为含 generic 的活动锚点，POST 验真才能解析（追加为事件 4，
        # 不影响 snapshot=3 的证明）。
        add_anchor(signer_a2, signer_a2_pub, 1, TA)
        st, before = fetch_proof(1, 3, signer=signer_a2)
        assert st == 200, before
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, after = fetch_proof(1, 3, signer=signer_a2)
        assert st == 200, after
        check("重启后证明（root/path/event）稳定",
              after["root"] == before["root"]
              and after["path"] == before["path"]
              and after["event"] == before["event"])

        # ---------------------------------------------------------- #
        # 5. POST 400 族：请求体须恰含 proof 对象
        # ---------------------------------------------------------- #
        def post_400(name, payload=None, raw_body=None):
            st, raw = proof_post(payload, headers=TA, raw_body=raw_body)
            try:
                r = json.loads(raw.decode() or "{}")
            except ValueError:
                r = {}
            check(f"POST 400 仅 error: {name}",
                  st == 400 and list(r.keys()) == ["error"]
                  and isinstance(r["error"], str) and bool(r["error"]))

        post_400("空体", raw_body=b"")
        post_400("非法 JSON", raw_body=b"{")
        post_400("非对象", raw_body=b"[1]")
        post_400("缺 proof", {})
        post_400("多余字段", {"proof": {}, "x": 1})
        post_400("proof 为数组", {"proof": []})
        post_400("proof 为字符串", {"proof": "x"})
        post_400("proof 为数字", {"proof": 1})
        post_400("proof 为 null", {"proof": None})
        post_400("proof 为 true", {"proof": True})

        # ---------------------------------------------------------- #
        # 6. POST 200：成功往返（服务自己签的证明可验）
        # ---------------------------------------------------------- #
        valid_proof = after  # 重启后取得的合法证明

        def expect_valid(name, proof_obj, headers=TA):
            st, raw = proof_post({"proof": proof_obj}, headers=headers)
            try:
                body = json.loads(raw)
            except ValueError:
                body = None
            check(name, st == 200 and body == {"valid": True})

        def expect_reason(name, proof_obj, reason, headers=TA):
            st, raw = proof_post({"proof": proof_obj}, headers=headers)
            try:
                body = json.loads(raw)
            except ValueError:
                body = None
            check(name, st == 200
                  and body == {"valid": False, "reason": reason})

        expect_valid("合法证明 valid:true", valid_proof)
        check("成功响应恰为 {valid:true}", True)

        # ---------------------------------------------------------- #
        # 7. 证明非法：结构 / 七键 / 事件协议 / 类型 / 取值
        # ---------------------------------------------------------- #
        def malformed(name, mutate):
            obj = copy.deepcopy(valid_proof)
            mutate(obj)
            expect_reason(f"证明非法：{name}", obj, "证明非法")

        malformed("缺 event", lambda p: p.pop("event"))
        malformed("缺 signature", lambda p: p.pop("signature"))
        malformed("多余键", lambda p: p.update({"extra": 1}))
        malformed("event 非对象", lambda p: p.update(event=[]))
        malformed("event 缺键", lambda p: p["event"].pop("uses"))
        malformed("event 多键", lambda p: p["event"].update(x=1))
        malformed("event cursor 为 0",
                  lambda p: p["event"].update(cursor=0))
        malformed("event cursor 为字符串",
                  lambda p: p["event"].update(cursor="1"))
        malformed("event cursor 为布尔",
                  lambda p: p["event"].update(cursor=True))
        malformed("action 非法", lambda p: p["event"].update(action="nope"))
        malformed("did 为空", lambda p: p["event"].update(did=""))
        malformed("key_version 为 0",
                  lambda p: p["event"].update(key_version=0))
        malformed("public_key 为空",
                  lambda p: p["event"].update(public_key=""))
        malformed("status 非法", lambda p: p["event"].update(status="dead"))
        malformed("uses 含非法值",
                  lambda p: p["event"].update(uses=["generic", "nope"]))
        malformed("uses 为空", lambda p: p["event"].update(uses=[]))
        malformed("snapshot<event.cursor",
                  lambda p: p.update(snapshot=0))
        malformed("snapshot 为字符串",
                  lambda p: p.update(snapshot="3"))
        malformed("root 非 hex", lambda p: p.update(root="zzz"))
        malformed("root 大写", lambda p: p.update(root="A" * 64))
        malformed("root 长度错", lambda p: p.update(root="0" * 63))
        malformed("path 非数组", lambda p: p.update(path={}))
        malformed("path 项非对象", lambda p: p.update(path=[1]))
        malformed("path 项多键",
                  lambda p: p.update(path=[{"side": "left",
                                            "hash": "0" * 64, "x": 1}]))
        malformed("path side 非法",
                  lambda p: p.update(path=[{"side": "up",
                                            "hash": "0" * 64}]))
        malformed("path hash 非 hex",
                  lambda p: p.update(path=[{"side": "left", "hash": "z"}]))
        malformed("signer_did 为空", lambda p: p.update(signer_did=""))
        malformed("signer_key_version 为 0",
                  lambda p: p.update(signer_key_version=0))
        malformed("signature 为空", lambda p: p.update(signature=""))

        # ---------------------------------------------------------- #
        # 8. 锚点不可用：未知 / 他租户 / 吊销 / 无 generic
        #    （结构须合法，故这些证明已通过结构校验）
        # ---------------------------------------------------------- #
        remote_did = "did:web:ac-remote"
        r_priv, r_pub = gen_keypair()
        add_anchor(remote_did, r_pub, 1, TA)

        def remote_event(cursor=10, uses=None):
            return {
                "cursor": cursor,
                "action": "registered",
                "did": remote_did,
                "key_version": 1,
                "public_key": r_pub,
                "status": "active",
                "uses": list(ALL_USES if uses is None else uses),
            }

        def sign_proof(event_obj, snapshot, root, path, did=remote_did,
                       version=1, priv=r_priv):
            signed = {
                "event": event_obj,
                "snapshot": snapshot,
                "root": root,
                "path": path,
                "signer_did": did,
                "signer_key_version": version,
            }
            proof_obj = dict(signed)
            proof_obj["signature"] = crypto.sign(signed, priv)
            return proof_obj

        ev1 = remote_event()
        lh1 = leaf_hash(ev1)
        good_remote = sign_proof(ev1, 10, lh1, [])
        expect_valid("远端锚点自造事件（不依赖本地事件）valid", good_remote)

        # 未知签名 DID（结构合法、无锚点）
        expect_reason("未知签名锚点 -> 锚点不可用",
                      sign_proof(ev1, 10, lh1, [], did="did:web:no-anchor"),
                      "锚点不可用")
        # 他租户：锚点在 A，租户 B 验
        expect_reason("跨租户锚点 -> 锚点不可用",
                      good_remote, "锚点不可用", headers=TB)

        # 无 generic 用途的锚点
        vc_did = "did:web:ac-vc-only"
        _, vc_pub = gen_keypair()
        add_anchor(vc_did, vc_pub, 1, TA, uses=["vc"])
        expect_reason("无 generic 用途 -> 锚点不可用",
                      sign_proof(ev1, 10, lh1, [], did=vc_did),
                      "锚点不可用")

        # 已吊销锚点
        rev_did = "did:web:ac-revoked"
        rev_priv, rev_pub = gen_keypair()
        add_anchor(rev_did, rev_pub, 1, TA)
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{rev_did}/1/status",
                      {"status": "revoked"}, TA)
        assert st == 200
        expect_reason("已吊销锚点 -> 锚点不可用",
                      sign_proof(ev1, 10, lh1, [], did=rev_did,
                                 priv=rev_priv),
                      "锚点不可用")

        # 版本不匹配：存在 v1 但声明 v9
        expect_reason("锚点版本不存在 -> 锚点不可用",
                      sign_proof(ev1, 10, lh1, [], did=remote_did,
                                 version=9),
                      "锚点不可用")

        # ---------------------------------------------------------- #
        # 9. 签名格式错误 / 签名校验失败 / 包含证明校验失败
        # ---------------------------------------------------------- #
        # 签名格式错误（锚点可用、结构合法）
        fmt_bad = sign_proof(ev1, 10, lh1, [])
        fmt_bad["signature"] = "not-a-signature"
        expect_reason("签名非 base64url -> 签名格式错误",
                      fmt_bad, "签名格式错误")
        fmt_bad2 = sign_proof(ev1, 10, lh1, [])
        fmt_bad2["signature"] = "!" + "A" * 85  # 含非 base64url 字母表字符
        expect_reason("签名含字母表外字符 -> 签名格式错误",
                      fmt_bad2, "签名格式错误")

        # 签名校验失败（格式合法但内容不符）：换一把私钥重签
        other_priv, _ = gen_keypair()
        sig_bad = sign_proof(ev1, 10, lh1, [], priv=other_priv)
        expect_reason("签名与公钥不符 -> 签名校验失败",
                      sig_bad, "签名校验失败")
        # 86 字符但内容篡改：改 event.did 后用原签名（结构仍合法、
        # cursor<=snapshot）
        tamper = sign_proof(ev1, 10, lh1, [])
        tamper["event"] = dict(remote_event())
        tamper["event"]["did"] = "did:web:other"
        expect_reason("篡改 event -> 签名校验失败",
                      tamper, "签名校验失败")

        # 包含证明校验失败：签名合法，但 path 重算 root 不符
        incl_bad = sign_proof(
            ev1, 10, lh1,
            [{"side": "right", "hash": "0" * 64}],
        )
        expect_reason("path 重算不符 -> 包含证明校验失败",
                      incl_bad, "包含证明校验失败")
        # path 兄弟错放一侧（同为合法 hex，重算仍不符）
        incl_bad2 = sign_proof(
            ev1, 10, lh1,
            [{"side": "left", "hash": "1" * 64}],
        )
        expect_reason("path side 错置 -> 包含证明校验失败",
                      incl_bad2, "包含证明校验失败")

        # 两叶场景下用真实兄弟但 root 改成另一值：签名须仍合法，故对改后
        # 的 root 重签，此时 path 自洽到原叶根而非所声明 root。
        ev_a = remote_event(cursor=20)
        ev_b = remote_event(cursor=21)
        la, lb = leaf_hash(ev_a), leaf_hash(ev_b)
        real_root = parent_hash(la, lb)
        # ev_a 的兄弟应为 right=lb
        good_pair = sign_proof(
            ev_a, 21, real_root,
            [{"side": "right", "hash": lb}])
        expect_valid("两叶证明 valid", good_pair)
        # 伪造一个 root（其值合法 hex）并用合法签名 -> 包含失败
        bogus_root = "a" * 64
        incl_bad3 = sign_proof(
            ev_a, 21, bogus_root,
            [{"side": "right", "hash": lb}])
        expect_reason("声明 root 与 path 不一致 -> 包含证明校验失败",
                      incl_bad3, "包含证明校验失败")

        # ---------------------------------------------------------- #
        # 10. POST 只读（验真不写状态/审计）
        # ---------------------------------------------------------- #
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        n_before = len(json.loads(raw)["events"])
        proof_post({"proof": good_remote}, headers=TA)
        proof_post({"proof": incl_bad}, headers=TA)
        proof_post({"proof": {}}, headers=TA)
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        check("POST ac-proof 不记审计",
              len(json.loads(raw)["events"]) == n_before)

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
