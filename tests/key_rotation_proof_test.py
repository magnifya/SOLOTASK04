#!/usr/bin/env python3
"""DID 密钥轮换可独立验证证明端到端测试。

覆盖：
- 轮换入口 POST /v1/dids/{did}/keys/rotate 行为不变，每次成功轮换在
  同一次原子写中产出一条十二字段轮换证明：
  did、from_key_version、to_key_version、from_key_handle、to_key_handle、
  from_public_key、to_public_key、rotated_at、previous_proof_digest、
  from_proof、to_proof、proof_digest；仅含公钥，绝不暴露私钥；
- GET /v1/dids/{did}/keys/rotations?limit=&after= 恰返 did、events、
  next_after，事件按 to_key_version 升序，分页语义与 keys/history 一致，
  空 DID（尚无证明）返回空页；未知或跨租户 DID 404，非法参数 400，
  显式空租户头 400，只读不记审计；
- from_proof/to_proof 分别为旧、新私钥对去掉三个 proof 字段记录的
  ES256 签名；proof_digest 为去掉自身而含两个 proof 记录的 SHA-256
  小写 hex；previous_proof_digest 首条为 null、后续接上一条形成哈希链；
- POST /v1/dids/rotation-proofs/verify：合法协议 200，成功
  {"valid":true}，篡改按 DID 不一致、版本不连续、前序摘要不匹配、
  记录摘要不匹配、旧钥签名失败、新钥签名失败的优先级返回原因；
  缺字段、多余字段、JSON 非法、数组非 1..100 个对象、空 did 或显式空
  X-Tenant-ID、非法分页值返回 400 与 error；
- 证明独立于本地状态：跨租户/外系统提交同样可验；旧钥事后被吊销，
  证明仍有效；不替代密钥状态查询；
- 失败不写证明、不改版本/文档/历史/审计（落盘失败整体回滚）；
- 升级前已轮换的历史版本不补造证明，只保留原历史；重启后证明稳定。

直接运行：python3 tests/key_rotation_proof_test.py
"""

import copy
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
import hashlib  # noqa: E402

PORT = 8996
Z_RE = __import__("re").compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

PROOF_FIELDS = [
    "did",
    "from_key_version",
    "to_key_version",
    "from_key_handle",
    "to_key_handle",
    "from_public_key",
    "to_public_key",
    "rotated_at",
    "previous_proof_digest",
    "from_proof",
    "to_proof",
    "proof_digest",
]
SIGNED_FIELDS = PROOF_FIELDS[:9]
DIGEST_FIELDS = PROOF_FIELDS[:-1]
PAGE_FIELDS = {"did", "events", "next_after"}
PRIVATE_MARKER = "PRIVATE KEY-----"


def _http(method, url, payload=None, headers=None, raw=None):
    if raw is not None:
        data = raw
    else:
        data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
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


def start_server(port, store_path):
    env = dict(os.environ, VCBACKEND_STORE=store_path)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up(port), "服务启动超时"
    return proc


def digest_of(event):
    return hashlib.sha256(
        crypto.canonicalize({k: event[k] for k in DIGEST_FIELDS})
    ).hexdigest()


def signed_of(event):
    return {k: event[k] for k in SIGNED_FIELDS}


def main():
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    store_path = tempfile.mktemp(suffix=".json")
    proc = start_server(PORT, store_path)
    base = f"http://127.0.0.1:{PORT}"
    TA = {"X-Tenant-ID": "rp-a"}
    TB = {"X-Tenant-ID": "rp-b"}

    def rotations(did, headers=None, query=None):
        url = f"{base}/v1/dids/{did}/keys/rotations"
        if query is not None:
            url += f"?{query}"
        return _http("GET", url, headers=headers)

    def verify(body, headers=None, raw=None):
        return _http(
            "POST", f"{base}/v1/dids/rotation-proofs/verify",
            payload=body, headers=headers, raw=raw,
        )

    def audit(headers=None):
        return _http("GET", f"{base}/v1/audit?limit=200", headers=headers)

    try:
        # ---- 准备：A 租户 DID，轮换到 v3；B 租户独立 DID ----
        st, a = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "rp-h1"},
                      headers=TA)
        assert st == 201, a
        did_a = a["did"]
        st, rot2 = _http("POST", f"{base}/v1/dids/{did_a}/keys/rotate",
                         {"key_handle": "rp-h2"}, headers=TA)
        assert st == 200, rot2
        check("轮换入口响应字段保持不变",
              set(rot2) == {"did", "public_key", "key_mode",
                            "key_handle", "key_version"}
              and rot2["key_version"] == 2
              and rot2["key_handle"] == "rp-h2"
              and "BEGIN PUBLIC KEY" in rot2["public_key"]
              and PRIVATE_MARKER not in rot2["public_key"])
        st, rot3 = _http("POST", f"{base}/v1/dids/{did_a}/keys/rotate",
                         {"key_handle": "rp-h3"}, headers=TA)
        assert st == 200, rot3

        st, b = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "rp-other"},
                      headers=TB)
        assert st == 201, b
        did_b = b["did"]

        # ---- 1. 结构、字段、排序、无私钥 ----
        st, page = rotations(did_a, headers=TA)
        ok = (
            st == 200 and set(page) == PAGE_FIELDS and page["did"] == did_a
            and page["next_after"] == 3 and len(page["events"]) == 2
            and all(set(e) == set(PROOF_FIELDS) for e in page["events"])
        )
        check("200 恰含 did/events/next_after，2 条证明且各恰十二字段", ok)
        check("事件按 to_key_version 升序（2、3）",
              [e["to_key_version"] for e in page["events"]] == [2, 3]
              and [e["from_key_version"] for e in page["events"]] == [1, 2])
        check("输出绝不含私钥",
              PRIVATE_MARKER not in json.dumps(page, ensure_ascii=False))
        e1, e2 = page["events"]
        check("句柄/公钥与版本对应正确",
              e1["from_key_handle"] == "rp-h1"
              and e1["to_key_handle"] == "rp-h2"
              and e2["from_key_handle"] == "rp-h2"
              and e2["to_key_handle"] == "rp-h3"
              and "BEGIN PUBLIC KEY" in e1["from_public_key"]
              and "BEGIN PUBLIC KEY" in e2["to_public_key"])
        check("rotated_at 为 UTC 秒精度 Z",
              all(Z_RE.match(e["rotated_at"]) for e in page["events"]))

        # ---- 2. 哈希链 ----
        check("首条 previous_proof_digest 为 null，第二条等于首条摘要",
              e1["previous_proof_digest"] is None
              and e2["previous_proof_digest"] == e1["proof_digest"])

        # ---- 3. proof_digest 与双签可独立重算/验签 ----
        check("proof_digest 可对去自身含双 proof 的记录重算",
              digest_of(e1) == e1["proof_digest"]
              and digest_of(e2) == e2["proof_digest"]
              and len(e1["proof_digest"]) == 64
              and e1["proof_digest"] == e1["proof_digest"].lower())
        sig_ok = True
        for e in page["events"]:
            try:
                crypto.verify(signed_of(e), e["from_proof"],
                              e["from_public_key"])
                crypto.verify(signed_of(e), e["to_proof"], e["to_public_key"])
            except Exception:  # noqa: BLE001
                sig_ok = False
        check("from_proof/to_proof 分别经旧、新公钥 ES256 验签通过", sig_ok)
        # 交叉签名必须失败：from_proof 不经新钥验、to_proof 不经旧钥验
        cross_fail = False
        try:
            crypto.verify(signed_of(e1), e1["from_proof"],
                          e1["to_public_key"])
        except Exception:  # noqa: BLE001
            cross_fail = True
        check("旧钥签名不能用新公钥验过", cross_fail)

        # ---- 4. 空页表示尚无证明 ----
        st, empty = rotations(did_b, headers=TB)
        check("仅注册未轮换的 DID 空页且 next_after=0",
              st == 200 and empty == {"did": did_b, "events": [],
                                      "next_after": 0})
        st, empty = rotations(did_b, headers=TB, query="after=7")
        check("空页 next_after 等于传入 after",
              st == 200 and empty["events"] == []
              and empty["next_after"] == 7)

        # ---- 5. 分页语义与 keys/history 一致（以 to_key_version 为游标）----
        st, p1 = rotations(did_a, headers=TA, query="limit=1")
        check("limit=1 返回 1 项且 next_after=其 to_key_version(2)",
              st == 200 and len(p1["events"]) == 1
              and p1["events"][0]["to_key_version"] == 2
              and p1["next_after"] == 2)
        st, p2 = rotations(did_a, headers=TA, query="limit=1&after=2")
        check("after=2 取到 to=3 的第二条",
              st == 200 and [e["to_key_version"] for e in p2["events"]] == [3]
              and p2["next_after"] == 3)
        st, p3 = rotations(did_a, headers=TA, query="after=3")
        check("after=末版本空页且 next_after=3",
              st == 200 and p3["events"] == [] and p3["next_after"] == 3)

        def p400(query, name):
            st, r = rotations(did_a, headers=TA, query=query)
            check(name, st == 400 and isinstance(r.get("error"), str)
                  and r["error"])

        p400("limit=0", "limit=0 -> 400")
        p400("limit=201", "limit=201 -> 400")
        p400("limit=1&limit=2", "重复 limit -> 400")
        p400("after=1&after=2", "重复 after -> 400")
        p400("limit=", "空 limit -> 400")
        p400("after=", "空 after -> 400")
        p400("limit=1.5", "小数 limit -> 400")
        p400("limit=true", "布尔词 limit -> 400")
        p400("limit=-1", "符号 limit -> 400")
        p400("after=-1", "负 after -> 400")
        p400("after=abc", "字母 after -> 400")
        # 与 keys/history 一致：未知查询参数被忽略（200），不视为非法。
        st, r = rotations(did_a, headers=TA, query="unknown=1")
        check("未知查询参数与 keys/history 一致被忽略（200）", st == 200)

        # ---- 6. 租户隔离、404、租户头 ----
        st, _ = rotations(did_a, headers=TB)
        check("跨租户 DID 不可探测 -> 404", st == 404)
        st, _ = rotations(
            "did:example:00000000000000000000000000000000", headers=TA)
        check("未知 DID -> 404", st == 404)
        st, _ = rotations(did_a, headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400)

        # ---- 7. 只读不记审计 ----
        st, before = audit(headers=TA)
        n_before = len(before["events"])
        rotations(did_a, headers=TA)
        rotations(did_a, headers=TA, query="limit=1&after=1")
        rotations(did_b, headers=TB)
        st, after_au = audit(headers=TA)
        check("rotations 查询为只读：审计条数不增加",
              len(after_au["events"]) == n_before)

        # ---- 8. verify：合法链成功 ----
        st, r = verify({"did": did_a, "rotations": [e1, e2]}, headers=TA)
        check("完整链验证成功 {valid:true}", st == 200 and r == {"valid": True})
        # 逆序提交同样按版本升序验证成功
        st, r = verify({"did": did_a, "rotations": [e2, e1]}, headers=TA)
        check("逆序提交按 to_key_version 升序重排后仍成功",
              st == 200 and r == {"valid": True})
        # 单条（从版本 1 起）成功
        st, r = verify({"did": did_a, "rotations": [e1]}, headers=TA)
        check("仅首条 1->2 单记录验证成功", st == 200 and r["valid"] is True)
        # 跨租户/不依赖本地状态：B 租户甚至无此 DID，仍可验真
        st, r = verify({"did": did_a, "rotations": [e1, e2]}, headers=TB)
        check("证明独立于本地状态：他租户提交自包含证明仍 valid",
              st == 200 and r == {"valid": True})

        # ---- 9. verify：六类失败原因及优先级（单记录避免链干扰）----
        def expect_reason(mutate, reason, name):
            rr = copy.deepcopy([e1])
            mutate(rr[0])
            st, r = verify({"did": did_a, "rotations": rr}, headers=TA)
            ok = (
                st == 200 and r.get("valid") is False
                and r.get("reason") == reason
            )
            check(name, ok)

        expect_reason(lambda e: e.update(did="did:example:dead"),
                      "DID不一致", "篡改 did -> DID不一致")
        expect_reason(lambda e: e.update(to_key_version=3),
                      "版本不连续", "1->3 跳跃 -> 版本不连续")
        expect_reason(lambda e: e.update(previous_proof_digest="x"),
                      "前序摘要不匹配", "首条前序摘要非 null -> 前序摘要不匹配")
        expect_reason(lambda e: e.update(rotated_at="2020-01-01T00:00:00Z"),
                      "记录摘要不匹配", "篡改 rotated_at -> 记录摘要不匹配")

        def resign(e, field):
            # 用无关新私钥重签同一被签负载，再重算摘要使链自洽，
            # 从而隔离出纯粹的签名失败。
            e[field] = crypto.sign(signed_of(e),
                                   crypto.generate_private_key_pem())
            e["proof_digest"] = digest_of(e)

        expect_reason(lambda e: resign(e, "from_proof"),
                      "旧钥签名失败", "from_proof 非旧钥所签 -> 旧钥签名失败")
        expect_reason(lambda e: resign(e, "to_proof"),
                      "新钥签名失败", "to_proof 非新钥所签 -> 新钥签名失败")

        # 多记录链：第二条 previous_proof_digest 被改
        rr = copy.deepcopy([e1, e2])
        rr[1]["previous_proof_digest"] = (
            "0" * 64 if e1["proof_digest"] != "0" * 64 else "1" * 64)
        st, r = verify({"did": did_a, "rotations": rr}, headers=TA)
        check("第二条前序摘要不衔接 -> 前序摘要不匹配",
              st == 200 and r["valid"] is False
              and r["reason"] == "前序摘要不匹配")

        # 优先级：同时破坏 did 与版本 -> DID不一致 优先
        rr = copy.deepcopy([e1])
        rr[0]["did"] = "did:example:zz"
        rr[0]["to_key_version"] = 9
        st, r = verify({"did": did_a, "rotations": rr}, headers=TA)
        check("DID不一致 优先于 版本不连续",
              r["reason"] == "DID不一致")
        # 优先级：同时破坏前序摘要与记录摘要 -> 前序摘要优先
        rr = copy.deepcopy([e1])
        rr[0]["previous_proof_digest"] = "x"
        rr[0]["rotated_at"] = "2020-01-01T00:00:00Z"
        st, r = verify({"did": did_a, "rotations": rr}, headers=TA)
        check("前序摘要不匹配 优先于 记录摘要不匹配",
              r["reason"] == "前序摘要不匹配")
        # 优先级：记录摘要不匹配 优先于 旧钥签名失败（摘要先于验签）
        rr = copy.deepcopy([e1])
        rr[0]["rotated_at"] = "2020-01-01T00:00:00Z"
        rr[0]["from_proof"] = "bad"
        st, r = verify({"did": did_a, "rotations": rr}, headers=TA)
        check("记录摘要不匹配 优先于 旧钥签名失败",
              r["reason"] == "记录摘要不匹配")

        # 内容问题走 200 valid:false，而非 400
        st, r = verify({"did": did_a, "rotations": [{}]}, headers=TA)
        check("空对象元素属内容失败 -> 200 valid:false",
              st == 200 and r["valid"] is False and r["reason"])
        st, r = verify({"did": did_a, "rotations": [
            copy.deepcopy(e1) | {"from_key_version": "1"}]}, headers=TA)
        check("版本为字符串属内容失败 -> 200 版本不连续",
              st == 200 and r["reason"] == "版本不连续")

        # ---- 10. verify：协议非法一律 400 ----
        bad_bodies = [
            {},
            {"rotations": [e1]},
            {"did": did_a},
            {"did": did_a, "rotations": [e1], "extra": 1},
            {"did": "", "rotations": [e1]},
            {"did": 123, "rotations": [e1]},
            {"did": None, "rotations": [e1]},
            {"did": did_a, "rotations": []},
            {"did": did_a, "rotations": "x"},
            {"did": did_a, "rotations": [e1] * 101},
            {"did": did_a, "rotations": [1]},
            {"did": did_a, "rotations": ["x"]},
            {"did": did_a, "rotations": [None]},
        ]
        bad_ok = True
        for body in bad_bodies:
            st, r = verify(body, headers=TA)
            if not (st == 400 and isinstance(r.get("error"), str)
                    and r["error"]):
                bad_ok = False
                print("   未按 400 拒绝:", body if len(str(body)) < 120
                      else str(body)[:120], st, r)
        check("缺/多字段、空 did、空/超长/非对象数组等均 400 带 error",
              bad_ok)
        # 非法 JSON
        st, r = verify(None, headers=TA, raw=b"{not-json")
        check("非法 JSON -> 400 带 error",
              st == 400 and isinstance(r.get("error"), str) and r["error"])
        # 非对象 JSON 体
        st, r = verify(None, headers=TA, raw=b"[1,2]")
        check("JSON 数组请求体 -> 400", st == 400)
        # 显式空租户头
        st, r = verify({"did": did_a, "rotations": [e1]},
                       headers={"X-Tenant-ID": ""})
        check("verify 显式空 X-Tenant-ID -> 400", st == 400)

        # ---- 11. 旧钥吊销不使证明失效（证明不查密钥状态）----
        st, rv = _http("POST", f"{base}/v1/dids/{did_a}/keys/1/revoke",
                       {"reason": "轮换后旧钥正常吊销"}, headers=TA)
        assert st == 200, rv
        st, r = verify({"did": did_a, "rotations": [e1, e2]}, headers=TA)
        check("旧钥事后吊销，历史轮换证明仍 valid",
              st == 200 and r == {"valid": True})
        # 密钥状态查询接口与证明相互独立：v1 仍为 revoked
        st, ks = _http("GET",
                       f"{base}/v1/dids/{did_a}/keys/1/status", headers=TA)
        check("证明不替代密钥状态查询（v1 仍 revoked）",
              st == 200 and ks["status"] == "revoked")

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 12. 跨重启：证明稳定、仍可验真 ----
    proc = start_server(PORT, store_path)
    try:
        st, page = _http(
            "GET", f"{base}/v1/dids/{did_a}/keys/rotations", headers=TA)
        check("重启后两条证明与哈希链稳定",
              st == 200 and len(page["events"]) == 2
              and page["events"][0]["previous_proof_digest"] is None
              and page["events"][1]["previous_proof_digest"]
              == page["events"][0]["proof_digest"])
        st, r = _http("POST", f"{base}/v1/dids/rotation-proofs/verify",
                      {"did": did_a, "rotations": page["events"]},
                      headers=TA)
        check("重启后证明仍可验真", r == {"valid": True})
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 13. 升级前历史不补造：删除证明桶模拟旧状态 ----
    legacy_path = tempfile.mktemp(suffix=".json")
    lp = start_server(PORT + 1, legacy_path)
    lbase = f"http://127.0.0.1:{PORT + 1}"
    L = {"X-Tenant-ID": "legacy"}
    try:
        st, ld = _http("POST", f"{lbase}/v1/dids",
                       {"method": "example", "public_key": "leg-h1"},
                       headers=L)
        assert st == 201
        leg_did = ld["did"]
        st, _ = _http("POST", f"{lbase}/v1/dids/{leg_did}/keys/rotate",
                      {"key_handle": "leg-h2"}, headers=L)
        assert st == 200
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # 移除全部轮换证明，模拟升级前已轮换的旧状态文件。
    raw = json.load(open(legacy_path, encoding="utf-8"))
    raw["tenants"]["legacy"]["key_rotation_proofs"] = {}
    with open(legacy_path, "w", encoding="utf-8") as fh:
        json.dump(raw, fh)

    lp = start_server(PORT + 1, legacy_path)
    try:
        st, page = _http(
            "GET", f"{lbase}/v1/dids/{leg_did}/keys/rotations", headers=L)
        check("升级前已轮换版本不补造证明：空页",
              st == 200 and page["events"] == []
              and page["next_after"] == 0)
        # 原密钥生命周期历史保持不变（v1 created + v2 rotated）
        st, kh = _http(
            "GET", f"{lbase}/v1/dids/{leg_did}/keys/history", headers=L)
        check("升级前原密钥历史保持不变（2 条）",
              st == 200 and len(kh["events"]) == 2
              and [e["action"] for e in kh["events"]]
              == ["did.created", "key.rotated"])
        # 升级后再次轮换：新证明链独立从头（previous=null），不伪造旧签名
        st, _ = _http("POST", f"{lbase}/v1/dids/{leg_did}/keys/rotate",
                      {"key_handle": "leg-h3"}, headers=L)
        assert st == 200
        st, page = _http(
            "GET", f"{lbase}/v1/dids/{leg_did}/keys/rotations", headers=L)
        check("升级后首轮换产生 2->3 证明且 previous_proof_digest=null",
              st == 200 and len(page["events"]) == 1
              and page["events"][0]["from_key_version"] == 2
              and page["events"][0]["to_key_version"] == 3
              and page["events"][0]["previous_proof_digest"] is None)
        leg_proof = page["events"][0]
        # 该证明自身的摘要与双签均可独立重算/验真（自包含，不依赖旧签名）。
        leg_self_ok = digest_of(leg_proof) == leg_proof["proof_digest"]
        try:
            crypto.verify(signed_of(leg_proof), leg_proof["from_proof"],
                          leg_proof["from_public_key"])
            crypto.verify(signed_of(leg_proof), leg_proof["to_proof"],
                          leg_proof["to_public_key"])
        except Exception:  # noqa: BLE001
            leg_self_ok = False
        check("升级后新证明摘要与双签可独立重算/验真", leg_self_ok)
        # verify 端点要求从版本 1 起的连续记录；升级前缺失 1->2 证明，
        # 单独提交 2->3 记录按“版本不连续”处理（不补造、不冒充完整链）。
        st, r = _http("POST",
                      f"{lbase}/v1/dids/rotation-proofs/verify",
                      {"did": leg_did, "rotations": [leg_proof]},
                      headers=L)
        check("升级后孤立的 2->3 记录不冒充完整链：版本不连续",
              st == 200 and r["valid"] is False
              and r["reason"] == "版本不连续")
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # ---- 14. 直连 store：落盘失败时证明/版本/历史/审计全回滚 ----
    from vcbackend.store import VCStore

    direct_path = tempfile.mktemp(suffix=".json")
    store = VCStore(direct_path)
    d = store.create_did("rb", "example", "rb-h1")

    def _boom():
        raise OSError("模拟落盘失败")

    store._save_locked = _boom  # type: ignore[assignment]
    raised = False
    try:
        store.rotate_key("rb", d.did, "rb-h2")
    except OSError:
        raised = True
    check("含证明的轮换落盘失败抛错", raised)
    got = store.get_did("rb", d.did)
    check("回滚后当前版本仍为 1", got.key_version == 1)
    proofs, _ = store.list_key_rotation_proofs("rb", d.did, 0, 50)
    check("回滚后无任何轮换证明", proofs == [])
    events, _ = store.list_key_lifecycle("rb", d.did, 0, 50)
    check("回滚后生命周期仅 v1 一条",
          len(events) == 1 and events[0].action == "did.created")
    au = store.list_audit("rb", 0, 200)[0]
    check("回滚后不记 key.rotated 审计",
          all(e.action != "key.rotated" for e in au))

    del store._save_locked
    rec = store.rotate_key("rb", d.did, "rb-h2")
    check("恢复后轮换成功到 v2", rec.key_version == 2)
    proofs, _ = store.list_key_rotation_proofs("rb", d.did, 0, 50)
    check("恢复后产出 1->2 证明，首条 previous=null",
          len(proofs) == 1 and proofs[0].from_key_version == 1
          and proofs[0].to_key_version == 2
          and proofs[0].previous_proof_digest is None)
    # 再轮换：哈希链接续
    store.rotate_key("rb", d.did, "rb-h3")
    proofs, _ = store.list_key_rotation_proofs("rb", d.did, 0, 50)
    check("第二次轮换证明 previous_proof_digest 接上一条 proof_digest",
          len(proofs) == 2
          and proofs[1].previous_proof_digest == proofs[0].proof_digest)

    # 直连证明可独立验签/重算摘要
    ok = True
    for p in proofs:
        row = {f: getattr(p, f) for f in PROOF_FIELDS}
        if digest_of(row) != p.proof_digest:
            ok = False
        try:
            crypto.verify(signed_of(row), p.from_proof, p.from_public_key)
            crypto.verify(signed_of(row), p.to_proof, p.to_public_key)
        except Exception:  # noqa: BLE001
            ok = False
    check("直连产出的两条证明双签与摘要均正确", ok)

    for path in (store_path, legacy_path, direct_path):
        if os.path.exists(path):
            os.remove(path)

    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("密钥轮换可独立验证证明测试全部通过 ✔")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
