#!/usr/bin/env python3
"""只读消费历史 GET /v1/trust/proofs/consumptions 的端到端测试。

直接运行：python3 tests/trust_proof_consumptions_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import hashlib
import json
import os
import re
import shutil
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

UTC_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
ISSUER_A = "did:web:issuer-zpc-a.example"
ISSUER_B = "did:web:issuer-zpc-b.example"
SRC1 = "source-tenant-1"
SRC2 = "source-tenant-2"

DEFAULT_PREDS = [
    {"path": "/age", "op": "gte", "value": 18},
    {"path": "/role", "op": "eq", "value": "admin"},
    {"path": "/name", "op": "exists"},
]


def _http(method, url, payload=None, headers=None, raw=None):
    if raw is None:
        data = json.dumps(payload).encode() if payload is not None else None
    else:
        data = raw
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


def gen_keypair():
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


def start_server(port, store):
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up(port), "服务启动超时"
    return proc


def make_proof(proof_id, issuer_did, challenge="chal-1"):
    return {
        "proof_id": proof_id,
        "credential_id": "vc_zpc_0001",
        "issuer_did": issuer_did,
        "issuer_key_version": 1,
        "predicates": DEFAULT_PREDS,
        "results": [True, False, True],
        "challenge": challenge,
        "expires_at": "2099-01-01T00:00:00Z",
    }


def sign_proof(p, priv, source):
    """proof 覆盖去掉 proof 后的八字段并加入 tenant_id=source。"""
    p = dict(p)
    message = {k: v for k, v in p.items() if k != "proof"}
    message["tenant_id"] = source
    p["proof"] = crypto.sign(message, priv)
    return p


def main():
    port = 9357
    store = tempfile.mktemp(suffix=".json")
    proc = start_server(port, store)
    base = f"http://127.0.0.1:{port}"
    list_path = "/v1/trust/proofs/consumptions"
    consume_path = "/v1/trust/proofs/consume"
    batch_path = "/v1/trust/proofs/consume-batch"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def listing(qs="", headers=None):
        return _http("GET", f"{base}{list_path}{qs}", headers=headers)

    def consumed_audits(headers):
        st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=headers)
        assert st == 200
        return [e for e in r["events"]
                if e["action"] == "trust.proof.consumed"]

    def expect_400(name, qs="", headers=None):
        st, r = listing(qs, headers=headers)
        check(name, st == 400 and r == {"error": "请求非法"})

    try:
        T1 = {"X-Tenant-ID": "tzpc-hist-a"}
        T2 = {"X-Tenant-ID": "tzpc-hist-b"}

        # 空历史：200 恰返 events、next_after
        st, r = listing(headers=T1)
        check("空历史 -> 200 恰返 events,next_after 且空页 next_after=0",
              st == 200 and list(r.keys()) == ["events", "next_after"]
              and r["events"] == [] and r["next_after"] == 0)

        # 查询参数非法 -> 400 仅 {"error":"请求非法"}
        expect_400("未知参数 -> 400 请求非法", "?foo=1")
        expect_400("重复 limit -> 400", "?limit=1&limit=2")
        expect_400("重复 after -> 400", "?after=0&after=1")
        expect_400("重复 source_tenant_id -> 400",
                   "?source_tenant_id=a&source_tenant_id=b")
        expect_400("重复 issuer_did -> 400", "?issuer_did=a&issuer_did=b")
        expect_400("空 limit -> 400", "?limit=")
        expect_400("空 after -> 400", "?after=")
        expect_400("空 source_tenant_id -> 400", "?source_tenant_id=")
        expect_400("空 issuer_did -> 400", "?issuer_did=")
        expect_400("limit=0 -> 400", "?limit=0")
        expect_400("limit=201 -> 400", "?limit=201")
        expect_400("limit=-1 -> 400", "?limit=-1")
        expect_400("limit=+1 -> 400", "?limit=%2B1")
        expect_400("limit=1.0 -> 400", "?limit=1.0")
        expect_400("limit=true -> 400", "?limit=true")
        expect_400("limit 含空白 -> 400", "?limit=%201")
        expect_400("limit Unicode 数字 -> 400", "?limit=%E0%A5%91")
        expect_400("after=-1 -> 400", "?after=-1")
        expect_400("after=+1 -> 400", "?after=%2B1")
        expect_400("after 含空白 -> 400", "?after=%20")
        expect_400("after 小数 -> 400", "?after=1.5")
        expect_400("after Unicode 数字 -> 400", "?after=%D9%A1")
        expect_400("limit 与未知参数同现 -> 400", "?limit=1&foo=2")

        # 显式空租户头 -> 400 仅含非空 error
        st, r = listing(headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400 仅含非空 error",
              st == 400 and list(r.keys()) == ["error"]
              and isinstance(r["error"], str) and r["error"])

        # ---- 准备两接收租户的签发者锚点（来源租户无须注册）----
        iss_a_priv, iss_a_pub = gen_keypair()
        iss_b_priv, iss_b_pub = gen_keypair()
        for headers in (T1, T2):
            for did, pub in ((ISSUER_A, iss_a_pub), (ISSUER_B, iss_b_pub)):
                st, _ = _http(
                    "POST", f"{base}/v1/trust/anchors",
                    {"did": did, "public_key": pub, "key_version": 1},
                    headers=headers,
                )
                assert st == 201

        def make_req(pid, issuer_did, priv, source, challenge="chal-1"):
            proof = sign_proof(
                make_proof(pid, issuer_did, challenge), priv, source)
            return {"proof": proof, "challenge": challenge,
                    "source_tenant_id": source}

        def cid_of(req):
            return hashlib.sha256(crypto.canonicalize(req)).hexdigest()

        # 交替两个来源/签发者消费 5 个证明（第 4、5 个走批量入口，
        # 批内成功项顺序应与原审计一致）
        req1 = make_req("zp_" + "1" * 32, ISSUER_A, iss_a_priv, SRC1)
        req2 = make_req("zp_" + "2" * 32, ISSUER_B, iss_b_priv, SRC1)
        req3 = make_req("zp_" + "3" * 32, ISSUER_A, iss_a_priv, SRC2)
        req4 = make_req("zp_" + "4" * 32, ISSUER_B, iss_b_priv, SRC2)
        req5 = make_req("zp_" + "5" * 32, ISSUER_A, iss_a_priv, SRC1)

        st, r = _http("POST", f"{base}{consume_path}", req1, headers=T1)
        check("消费 req1 成功", st == 200 and r.get("valid") is True)
        st, r = _http("POST", f"{base}{consume_path}", req2, headers=T1)
        check("消费 req2 成功", st == 200 and r.get("valid") is True)
        st, r = _http("POST", f"{base}{consume_path}", req3, headers=T1)
        check("消费 req3 成功", st == 200 and r.get("valid") is True)
        st, r = _http("POST", f"{base}{batch_path}",
                      {"items": [req4, req5]}, headers=T1)
        check("批量消费 req4,req5 成功",
              st == 200
              and [x.get("valid") for x in r.get("results", [])]
              == [True, True])

        reqs = [req1, req2, req3, req4, req5]
        want_cids = [cid_of(x) for x in reqs]
        want_sources = [SRC1, SRC1, SRC2, SRC2, SRC1]
        want_issuers = [ISSUER_A, ISSUER_B, ISSUER_A, ISSUER_B, ISSUER_A]
        want_pids = [x["proof"]["proof_id"] for x in reqs]

        # cursor 应等于各次首次消费的 trust.proof.consumed 审计 seq
        audits = consumed_audits(T1)
        check("恰有五条消费审计", len(audits) == 5)
        seq_by_cid = {e["resource_id"]: e["seq"] for e in audits}
        want_cursors = [seq_by_cid[cid] for cid in want_cids]
        check("审计 seq 为正整数且递增",
              all(isinstance(s, int) and s > 0 for s in want_cursors)
              and want_cursors == sorted(want_cursors))

        # 全量查询
        st, r = listing("?limit=200", headers=T1)
        check("全量查询 -> 200", st == 200)
        check("响应键序恰为 events,next_after",
              list(r.keys()) == ["events", "next_after"])
        events = r["events"]
        check("五条消费事件", len(events) == 5)
        check("事件键序恰为 cursor,consumption_id,source_tenant_id,"
              "issuer_did,proof_id,consumed_at",
              all(list(e.keys()) == ["cursor", "consumption_id",
                                     "source_tenant_id", "issuer_did",
                                     "proof_id", "consumed_at"]
                  for e in events))
        check("cursor 为对应消费审计 seq 且升序",
              [e["cursor"] for e in events] == want_cursors)
        check("consumption_id 依次匹配且为 64 位小写 hex",
              [e["consumption_id"] for e in events] == want_cids
              and all(SHA256_HEX_RE.fullmatch(e["consumption_id"])
                      for e in events))
        check("source_tenant_id 依次匹配",
              [e["source_tenant_id"] for e in events] == want_sources)
        check("issuer_did 依次匹配",
              [e["issuer_did"] for e in events] == want_issuers)
        check("proof_id 依次匹配",
              [e["proof_id"] for e in events] == want_pids)
        check("consumed_at 均为 UTC 秒精度 Z 字符串",
              all(isinstance(e["consumed_at"], str)
                  and UTC_Z_RE.fullmatch(e["consumed_at"])
                  for e in events))
        check("next_after 为末项 cursor",
              r["next_after"] == want_cursors[-1])

        # source_tenant_id 精确过滤
        st, r = listing(f"?limit=200&source_tenant_id={SRC1}", headers=T1)
        check("source1 过滤得三条且为第 1/2/5 条",
              st == 200
              and [e["cursor"] for e in r["events"]]
              == [want_cursors[0], want_cursors[1], want_cursors[4]]
              and all(e["source_tenant_id"] == SRC1 for e in r["events"]))
        check("过滤后 next_after 为末项 cursor",
              r["next_after"] == want_cursors[4])

        # issuer_did 精确过滤
        st, r = listing(f"?limit=200&issuer_did={ISSUER_A}", headers=T1)
        check("issuer_a 过滤得三条且为第 1/3/5 条",
              st == 200
              and [e["cursor"] for e in r["events"]]
              == [want_cursors[0], want_cursors[2], want_cursors[4]])

        # 双筛选取交集
        st, r = listing(
            f"?limit=200&source_tenant_id={SRC1}&issuer_did={ISSUER_A}",
            headers=T1)
        check("source1+issuer_a 交集为第 1/5 条",
              st == 200
              and [e["cursor"] for e in r["events"]]
              == [want_cursors[0], want_cursors[4]]
              and r["next_after"] == want_cursors[4])
        st, r = listing(
            f"?source_tenant_id={SRC2}&issuer_did={ISSUER_A}", headers=T1)
        check("source2+issuer_a 交集为第 3 条",
              [e["cursor"] for e in r["events"]] == [want_cursors[2]])

        # 筛选未命中 -> 空页
        st, r = listing("?source_tenant_id=nobody", headers=T1)
        check("无匹配来源 -> 空页 next_after=0",
              st == 200 and r["events"] == [] and r["next_after"] == 0)
        st, r = listing("?issuer_did=did:web:nobody.example", headers=T1)
        check("无匹配签发者 -> 空页 next_after=0",
              st == 200 and r["events"] == [] and r["next_after"] == 0)

        # after 超出已有游标 -> 空页且 next_after 保持 after
        st, r = listing(f"?after={want_cursors[-1] + 100}", headers=T1)
        check("after 超出已有游标 -> 空页 next_after=after",
              st == 200 and r["events"] == []
              and r["next_after"] == want_cursors[-1] + 100)

        # 分页：limit=2
        st, p1 = listing("?limit=2", headers=T1)
        check("第一页两条 next_after=次项 cursor",
              st == 200
              and [e["cursor"] for e in p1["events"]] == want_cursors[:2]
              and p1["next_after"] == want_cursors[1])
        st, p2 = listing(f"?limit=2&after={p1['next_after']}", headers=T1)
        check("第二页两条 next_after=末项 cursor",
              st == 200
              and [e["cursor"] for e in p2["events"]] == want_cursors[2:4]
              and p2["next_after"] == want_cursors[3])
        st, p3 = listing(f"?limit=2&after={p2['next_after']}", headers=T1)
        check("第三页一条 next_after=末项 cursor",
              st == 200
              and [e["cursor"] for e in p3["events"]] == want_cursors[4:]
              and p3["next_after"] == want_cursors[4])
        st, p4 = listing(f"?limit=2&after={p3['next_after']}", headers=T1)
        check("空页 next_after 保持 after",
              st == 200 and p4["events"] == []
              and p4["next_after"] == want_cursors[4])

        # 过滤 + 分页：after=首项 cursor 仅来源 1
        st, r = listing(
            f"?after={want_cursors[0]}&source_tenant_id={SRC1}",
            headers=T1)
        check("after=首项 + source1 仅得第 2/5 条",
              [e["cursor"] for e in r["events"]]
              == [want_cursors[1], want_cursors[4]]
              and r["next_after"] == want_cursors[4])

        # 缺省 limit=50
        st, r = listing(headers=T1)
        check("缺省 limit 返回全部五条",
              st == 200 and len(r["events"]) == 5)

        # 纯只读：重复查询一致且不追加审计
        audits_before = consumed_audits(T1)
        st1, r1 = listing("?limit=1", headers=T1)
        st2, r2 = listing("?limit=1", headers=T1)
        check("重复只读查询结果一致", r1 == r2 and st1 == st2 == 200)
        check("查询不记消费审计", consumed_audits(T1) == audits_before)

        # 重放不追加历史
        st, r = _http("POST", f"{base}{consume_path}", req1, headers=T1)
        check("重放 -> 外部证明已消费",
              st == 200
              and r == {"valid": False, "reason": "外部证明已消费"})
        st, r = listing("?limit=200", headers=T1)
        check("重放不追加历史事件",
              st == 200
              and [e["cursor"] for e in r["events"]] == want_cursors)

        # 验真失败不可见
        bad = dict(req1["proof"], proof="!!!bad!!!")
        st, r = _http("POST", f"{base}{consume_path}",
                      {"proof": bad, "challenge": "chal-1",
                       "source_tenant_id": SRC1}, headers=T1)
        check("验真失败 -> 200 valid:false",
              st == 200 and r.get("valid") is False)
        st, r = listing("?limit=200", headers=T1)
        check("验真失败不产生历史事件", len(r["events"]) == 5)

        # 落盘失败不可见：消费回滚后可重试，历史不变
        req6 = make_req("zp_" + "6" * 32, ISSUER_A, iss_a_priv, SRC1)
        os.unlink(store)
        os.mkdir(store)
        try:
            st, r = _http("POST", f"{base}{consume_path}", req6, headers=T1)
            check("落盘失败 -> 500 仅 {error:存储失败}",
                  st == 500 and r == {"error": "存储失败"})
        finally:
            os.rmdir(store)
        st, r = listing("?limit=200", headers=T1)
        check("落盘失败不产生历史事件",
              st == 200
              and [e["cursor"] for e in r["events"]] == want_cursors)

        # 租户隔离：T2 空历史；同键独立消费互不可见；来源筛选不能
        # 切换接收租户或读取其他租户数据
        st, r = listing(headers=T2)
        check("租户 B 初始空历史",
              st == 200 and r["events"] == [] and r["next_after"] == 0)
        st, r = _http("POST", f"{base}{consume_path}", req1, headers=T2)
        check("租户 B 同键独立消费成功",
              st == 200 and r.get("valid") is True)
        st, r = listing(f"?source_tenant_id={SRC1}", headers=T2)
        t2_audits = consumed_audits(T2)
        check("租户 B 按来源筛选仅见自身记录",
              len(r["events"]) == 1
              and r["events"][0]["cursor"] == t2_audits[0]["seq"]
              and r["events"][0]["consumption_id"] == want_cids[0]
              and r["next_after"] == t2_audits[0]["seq"])
        st, r = listing(f"?source_tenant_id={SRC2}", headers=T2)
        check("租户 B 按他人来源筛选为空页",
              st == 200 and r["events"] == [] and r["next_after"] == 0)
        st, r = listing("?limit=200", headers=T1)
        check("租户 A 历史不受租户 B 影响",
              [e["cursor"] for e in r["events"]] == want_cursors)

        # 证明事后过期不隐藏历史（历史反映消费时的事实）
        st, r = listing("?limit=200", headers=T1)
        check("消费后历史不受证明后续状态影响",
              st == 200 and len(r["events"]) == 5)

        # 重启后游标稳定、历史一致
        snap_before = listing("?limit=200", headers=T1)[1]
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server(port, store)
        st, r = listing("?limit=200", headers=T1)
        check("重启后历史与游标不变", st == 200 and r == snap_before)
        st, r = listing("?limit=200", headers=T2)
        check("重启后租户 B 历史不变",
              st == 200 and len(r["events"]) == 1
              and r["events"][0]["cursor"] == t2_audits[0]["seq"])

        # 重启后新消费继续在既有审计 seq 之上递增
        st, r = _http("POST", f"{base}{consume_path}", req6, headers=T1)
        check("重启后落盘失败键可重试成功",
              st == 200 and r.get("valid") is True)
        new_audits = consumed_audits(T1)
        st, r = listing("?limit=200", headers=T1)
        check("重启后新事件 cursor 为新审计 seq 且大于既有",
              [e["cursor"] for e in r["events"]]
              == want_cursors + [new_audits[-1]["seq"]]
              and new_audits[-1]["seq"] > want_cursors[-1]
              and r["events"][-1]["consumption_id"] == cid_of(req6))

    finally:
        proc.terminate()
        proc.wait(timeout=10)
        if os.path.isdir(store):
            shutil.rmtree(store)
        elif os.path.exists(store):
            os.unlink(store)

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
