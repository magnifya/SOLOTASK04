#!/usr/bin/env python3
"""GET /v1/trust/presentation-sync/history 已同步演示消费事件历史测试。

直接运行：python3 tests/trust_presentation_sync_history_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

数据来源与 trust_presentation_sync_test 相同：来源租户先经
/v1/trust/presentations/consume 产生真实外部演示消费历史，再由 export
（NDJSON）与 manifest（签名清单）导出；目标租户登记同 did/公钥（含 vp
用途）的信任锚点后通过 presentation-sync 同步，随后只读查询 history。

来源 cursor 为首次消费审计 seq（稀疏严格递增），不硬编码游标，全部从
export 实际行读取。

覆盖：
- 参数协议：仅 signer_did/at/limit/after 四项且唯一；signer_did 必填
  非空；at 缺省取检查点、须为非负 ASCII 整数；limit 缺省 50、限
  1–200；after 缺省 0、须为非负 ASCII 整数；空值、重复、符号、小数、
  空白、布尔词、Unicode 数字、越界、未知参数、after>at 均 400 且恰返
  {"error":"请求非法"}；显式空租户头 400；
- 404：来源未同步（未知 signer）、跨租户均恰返
  {"error":"同步来源不存在"}；
- 409：at 超检查点恰返 {"error":"同步游标冲突"}；
- 200 键序恰为 signer_did/at/events/next_after；事件键序恰为
  cursor/consumption_id/issuer_did/presentation_id/consumed_at
  （cursor 正整数，余四非空字符串，consumed_at 为 UTC 秒精度 Z）；
  以请求初原子快照 cursor<=at、cursor>after 升序取前 limit 项，非空
  页 next_after 为末项 cursor，空页等于 after；at 分页不受后续同步
  影响；
- 只读：不推进检查点（重放/续页行为不变）、不改判重索引、不记审计；
- 租户隔离；跨重启逐字节稳定；
- 直连 VCStore：404/409/after>at 异常与纯只读（内存、磁盘、审计均不
  变）。
"""

import copy
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

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402
from vcbackend.store import (  # noqa: E402
    ConflictError,
    NotFoundError,
    ValidationError,
    VCStore,
)

SYNC_PATH = "/v1/trust/presentation-sync"
HISTORY_PATH = "/v1/trust/presentation-sync/history"
EXPORT_PATH = "/v1/trust/presentations/consumptions/export"
MANIFEST_PATH = "/v1/trust/presentations/consumptions/manifest"
CONSUME_PATH = "/v1/trust/presentations/consume"
ANCHORS_PATH = "/v1/trust/anchors"
OK_KEYS = ["signer_did", "at", "events", "next_after"]
EVENT_KEYS = [
    "cursor",
    "consumption_id",
    "issuer_did",
    "presentation_id",
    "consumed_at",
]

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


def _http(method, url, payload=None, headers=None, raw_body=None):
    if raw_body is not None:
        data = raw_body
    else:
        data = (
            json.dumps(payload).encode("utf-8")
            if payload is not None
            else None
        )
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


ISSUER_DID = "did:web:pres-hist-issuer.example"


def make_presentation(priv, index, presentation_id=None,
                      issuer_did=None, challenge=None):
    p = {
        "presentation_id": presentation_id or f"vp_hist_{index:03d}",
        "credential_id": f"vc_hist_{index:03d}",
        "issuer_did": issuer_did or ISSUER_DID,
        "issuer_key_version": 1,
        "disclose": ["/role"],
        "claims": {"role": "admin", "seq": index},
        "challenge": challenge or f"chal-hist-{index}",
        "expires_at": "2099-01-01T00:00:00Z",
    }
    p["proof"] = crypto.sign(dict(p), priv)
    return p, p["challenge"]


def test_http():
    port = 9071
    store_path = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store_path)

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

    def post(path, payload=None, headers=None, raw_body=None):
        return _http("POST", base + path, payload=payload,
                     headers=headers, raw_body=raw_body)

    def get(path, headers=None):
        return _http("GET", base + path, headers=headers)

    try:
        SRC = {"X-Tenant-ID": "hist-src"}
        DST = {"X-Tenant-ID": "hist-dst"}
        OTHER = {"X-Tenant-ID": "hist-other"}

        issuer_priv, issuer_pub = _keypair()

        st, _ = post(ANCHORS_PATH,
                     {"did": ISSUER_DID, "public_key": issuer_pub,
                      "key_version": 1}, SRC)
        assert st == 201, st
        st, raw = post("/v1/dids",
                          {"method": "web",
                           "public_key": "presentation-history-signer-handle"},
                          SRC)
        assert st == 201, (st, raw)
        did_rec = json.loads(raw)
        signer_did = did_rec["did"]
        signer_pub = did_rec["public_key"]

        with open(store_path, "r", encoding="utf-8") as fh:
            state = json.load(fh)
        signer_priv = state["tenants"]["hist-src"]["dids"][signer_did][
            "key_history"][0]["private_key_pem"]

        for headers in (DST, OTHER):
            st, _ = post(ANCHORS_PATH,
                         {"did": signer_did, "public_key": signer_pub,
                          "key_version": 1}, headers)
            assert st in (200, 201), st

        def consume_one(index):
            presentation, challenge = make_presentation(issuer_priv, index)
            st, raw = post(CONSUME_PATH,
                              {"presentation": presentation,
                               "challenge": challenge}, SRC)
            assert st == 200 and json.loads(raw)["valid"] is True, raw

        for i in range(1, 6):
            consume_one(i)

        def export_page(after, limit, snapshot, headers=SRC):
            st, raw = get(
                f"{EXPORT_PATH}?after={after}&limit={limit}"
                f"&snapshot={snapshot}", headers=headers)
            assert st == 200, (st, raw)
            return raw.decode("utf-8")

        def manifest_page(after, limit, snapshot, headers=SRC):
            st, raw = get(
                f"{MANIFEST_PATH}?after={after}&limit={limit}"
                f"&snapshot={snapshot}&signer_did={signer_did}",
                headers=headers)
            assert st == 200, (st, raw)
            return json.loads(raw)

        def current_snapshot():
            req = urllib.request.Request(
                base + f"{EXPORT_PATH}?after=0&limit=1", method="GET")
            req.add_header("X-Tenant-ID", "hist-src")
            with urllib.request.urlopen(req) as resp:
                return int(resp.headers["X-Snapshot-Cursor"])

        def sync(manifest_obj, ndjson_text, headers=DST):
            return post(SYNC_PATH,
                        {"manifest": manifest_obj, "ndjson": ndjson_text},
                        headers=headers)

        def get_history(query, headers=None):
            return get(HISTORY_PATH + query, headers=headers)

        s5 = current_snapshot()
        nd1 = export_page(0, 2, s5)
        m1 = manifest_page(0, 2, s5)
        page1_rows = [json.loads(line) for line in nd1.strip().split("\n")]
        c1, c2 = (r["cursor"] for r in page1_rows)
        nd2 = export_page(c2, 3, s5)
        m2 = manifest_page(c2, 3, s5)
        page2_rows = [json.loads(line) for line in nd2.strip().split("\n")]
        c3, c4, c5 = (r["cursor"] for r in page2_rows)
        assert c1 < c2 < c3 < c4 < c5 == s5
        all_rows = page1_rows + page2_rows

        # ---------------------------------------------------------- #
        # 1. 400 族：同步前未知来源也须先过参数校验（400 优先于 404）
        # ---------------------------------------------------------- #
        def expect_400(name, query, headers=None):
            st, raw = get_history(query, headers=headers)
            check(name,
                  st == 400
                  and json.loads(raw.decode() or "{}")
                  == {"error": "请求非法"})

        expect_400("缺 signer_did 400", "?limit=10")
        expect_400("空 signer_did 400", "?signer_did=")
        expect_400("重复 signer_did 400", "?signer_did=a&signer_did=b")
        expect_400("重复 at 400",
                   f"?signer_did={signer_did}&at=1&at=2")
        expect_400("重复 limit 400",
                   f"?signer_did={signer_did}&limit=1&limit=2")
        expect_400("重复 after 400",
                   f"?signer_did={signer_did}&after=1&after=2")
        expect_400("未知参数 400", f"?signer_did={signer_did}&foo=1")
        expect_400("空 at 400", f"?signer_did={signer_did}&at=")
        expect_400("空 limit 400", f"?signer_did={signer_did}&limit=")
        expect_400("空 after 400", f"?signer_did={signer_did}&after=")
        expect_400("at 负号 400", f"?signer_did={signer_did}&at=-1")
        expect_400("at 正号 400", f"?signer_did={signer_did}&at=%2B5")
        expect_400("at 小数 400", f"?signer_did={signer_did}&at=1.5")
        expect_400("at 布尔词 400", f"?signer_did={signer_did}&at=true")
        expect_400("at 空白 400", f"?signer_did={signer_did}&at=%205")
        expect_400("at Unicode 数字 400",
                   f"?signer_did={signer_did}&at=%EF%BC%95")
        expect_400("limit 越界 0 400",
                   f"?signer_did={signer_did}&limit=0")
        expect_400("limit 越界 201 400",
                   f"?signer_did={signer_did}&limit=201")
        expect_400("limit 符号 400",
                   f"?signer_did={signer_did}&limit=%2B5")
        expect_400("after 负号 400",
                   f"?signer_did={signer_did}&after=-1")
        expect_400("after Unicode 数字 400",
                   f"?signer_did={signer_did}&after=%D9%A1")
        expect_400("after>at 400",
                   f"?signer_did={signer_did}&at={c2}&after={c3}")
        # at 缺省时其值取自检查点：来源不存在则无检查点可解析，404
        # 先于 after>at（与既有 synced-state 顺序一致）；显式 at 的
        # after>at 已在上文覆盖，且对未同步来源同样 400 先于 404。
        st, raw = get_history(
            "?signer_did=did:web:nobody&at=1&after=2")
        check("未同步来源+显式 after>at 仍 400 优先",
              st == 400
              and json.loads(raw) == {"error": "请求非法"})
        st, raw = get_history("?signer_did=did:web:nobody&after=1")
        check("未同步来源+缺省 at 无法解析检查点 -> 404",
              st == 404
              and json.loads(raw) == {"error": "同步来源不存在"})
        st, raw = get_history(
            f"?signer_did={signer_did}", headers={"X-Tenant-ID": ""})
        body = json.loads(raw.decode() or "{}")
        check("显式空租户头 400",
              st == 400 and set(body) == {"error"}
              and isinstance(body["error"], str) and body["error"])

        # ---------------------------------------------------------- #
        # 2. 同步前：404
        # ---------------------------------------------------------- #
        def expect_404(name, query, headers=None):
            st, raw = get_history(query, headers=headers)
            check(name,
                  st == 404
                  and json.loads(raw.decode() or "{}")
                  == {"error": "同步来源不存在"})

        expect_404("未同步来源 404", f"?signer_did={signer_did}",
                   headers=DST)
        expect_404("未知来源 404", "?signer_did=did:web:nobody",
                   headers=DST)
        # 缺省租户头 -> default，与显式租户隔离（default 未同步）。
        expect_404("缺省租户头隔离 default 404",
                   f"?signer_did={signer_did}")

        # ---------------------------------------------------------- #
        # 3. 同步两页到 DST（201/200）
        # ---------------------------------------------------------- #
        st, raw = sync(m1, nd1)
        assert st == 201, raw
        st, raw = sync(m2, nd2)
        assert st == 200, raw

        # 409：at 超检查点
        st, raw = get_history(
            f"?signer_did={signer_did}&at={s5 + 1}", headers=DST)
        check("at 超检查点 409",
              st == 409
              and json.loads(raw) == {"error": "同步游标冲突"})
        st, raw = get_history(
            f"?signer_did={signer_did}&at=999999999999", headers=DST)
        check("at 远大检查点 409",
              st == 409
              and json.loads(raw) == {"error": "同步游标冲突"})

        # 跨租户仍 404
        expect_404("跨租户 404", f"?signer_did={signer_did}",
                   headers=OTHER)

        # ---------------------------------------------------------- #
        # 4. 200：键序、类型、事件原文与分页
        # ---------------------------------------------------------- #
        st, raw = get_history(f"?signer_did={signer_did}", headers=DST)
        body = json.loads(raw)
        check("200 顶层键序恰为 signer_did/at/events/next_after",
              st == 200 and list(body.keys()) == OK_KEYS)
        check("缺省 at 取检查点 next_after、默认 limit 返全部 5 项",
              body["signer_did"] == signer_did
              and body["at"] == c5
              and len(body["events"]) == 5
              and body["next_after"] == c5)
        check("顶层类型 str/非负整数/数组/非负整数",
              isinstance(body["signer_did"], str)
              and isinstance(body["at"], int)
              and not isinstance(body["at"], bool) and body["at"] >= 0
              and isinstance(body["events"], list)
              and isinstance(body["next_after"], int)
              and not isinstance(body["next_after"], bool)
              and body["next_after"] >= 0)
        check("事件键序与落盘原文一致",
              [list(e.keys()) for e in body["events"]]
              == [EVENT_KEYS] * 5)
        check("事件值与来源导出行一致（含 UTC 秒精度 Z 时间）",
              body["events"] == all_rows)
        type_ok = all(
            isinstance(e["cursor"], int)
            and not isinstance(e["cursor"], bool)
            and e["cursor"] > 0
            and all(isinstance(e[k], str) and e[k]
                    for k in EVENT_KEYS[1:])
            and e["consumed_at"].endswith("Z")
            and len(e["consumed_at"]) == 20
            for e in body["events"]
        )
        check("事件类型：cursor 正整数、四个非空字符串", type_ok)
        check("事件按 cursor 升序",
              [e["cursor"] for e in body["events"]] == [c1, c2, c3, c4, c5])

        # at 截断
        st, raw = get_history(
            f"?signer_did={signer_did}&at={c3}", headers=DST)
        body = json.loads(raw)
        check("at=c3 仅含 cursor<=c3 三项且 at 回显 c3",
              st == 200 and body["at"] == c3
              and [e["cursor"] for e in body["events"]] == [c1, c2, c3]
              and body["next_after"] == c3)

        # limit 截断
        st, raw = get_history(
            f"?signer_did={signer_did}&limit=2", headers=DST)
        body = json.loads(raw)
        check("limit=2 取前 2 项，next_after 为末项 cursor",
              [e["cursor"] for e in body["events"]] == [c1, c2]
              and body["next_after"] == c2)

        # after 过滤
        st, raw = get_history(
            f"?signer_did={signer_did}&after={c2}", headers=DST)
        body = json.loads(raw)
        check("after=c2 取 cursor>c2",
              [e["cursor"] for e in body["events"]] == [c3, c4, c5]
              and body["next_after"] == c5)

        # after + limit + at 组合
        st, raw = get_history(
            f"?signer_did={signer_did}&at={c4}&after={c2}&limit=1",
            headers=DST)
        body = json.loads(raw)
        check("at=c4&after=c2&limit=1 仅取 c3",
              st == 200 and body["at"] == c4
              and [e["cursor"] for e in body["events"]] == [c3]
              and body["next_after"] == c3)

        # 空页：next_after 等于 after
        st, raw = get_history(
            f"?signer_did={signer_did}&after={c5}", headers=DST)
        body = json.loads(raw)
        check("空页 next_after 等于 after",
              st == 200 and body["events"] == []
              and body["next_after"] == c5 and body["at"] == c5)
        st, raw = get_history(
            f"?signer_did={signer_did}&at={c2}&after={c2}", headers=DST)
        body = json.loads(raw)
        check("at=after 空页 next_after=after=at",
              st == 200 and body["events"] == []
              and body["next_after"] == c2 and body["at"] == c2)
        st, raw = get_history(
            f"?signer_did={signer_did}&at=0", headers=DST)
        body = json.loads(raw)
        check("at=0 稀疏游标空间无事件，空页 next_after=0",
              st == 200 and body["events"] == []
              and body["next_after"] == 0 and body["at"] == 0)

        # 边界 limit
        st, _ = get_history(
            f"?signer_did={signer_did}&limit=1", headers=DST)
        check("limit=1 合法", st == 200)
        st, _ = get_history(
            f"?signer_did={signer_did}&limit=200", headers=DST)
        check("limit=200 合法", st == 200)

        # ---------------------------------------------------------- #
        # 5. 只读：不推进检查点、不记审计；at 分页不受并发同步影响
        # ---------------------------------------------------------- #
        st, raw = sync(m2, nd2)
        check("查询后同页仍为幂等重放 200（检查点未推进）",
              st == 200 and json.loads(raw)["count"] == 3
              and json.loads(raw)["next_after"] == c5)

        # 来源新增 3 条 -> 新快照 s8，合法续页
        for i in range(6, 9):
            consume_one(i)
        s8 = current_snapshot()
        nd8 = export_page(c5, 3, s8)
        m8 = manifest_page(c5, 3, s8)
        new_rows = [json.loads(line) for line in nd8.strip().split("\n")]
        c6, c7, c8 = (r["cursor"] for r in new_rows)
        assert c5 < c6 < c7 < c8 == s8
        st, raw = sync(m8, nd8)
        check("查询后续页从原游标继续 200",
              st == 200 and json.loads(raw)["next_after"] == c8
              and json.loads(raw)["count"] == 3)

        # 新同步后，旧 at=c5 的分页逐字节不变（at 分页不受并发影响）
        st, raw = get_history(
            f"?signer_did={signer_did}&at={c5}&limit=2", headers=DST)
        body = json.loads(raw)
        expected_old = {
            "signer_did": signer_did,
            "at": c5,
            "events": all_rows[:2],
            "next_after": c2,
        }
        check("at=c5 分页不受后续同步影响",
              st == 200 and body == expected_old)
        # 缺省 at 现在取新检查点 c8，共 8 项
        st, raw = get_history(f"?signer_did={signer_did}", headers=DST)
        body = json.loads(raw)
        check("缺省 at 跟随检查点推进至 c8",
              st == 200 and body["at"] == c8
              and [e["cursor"] for e in body["events"]]
              == [c1, c2, c3, c4, c5, c6, c7, c8]
              and body["next_after"] == c8)
        # 旧检查点之上现在合法
        st, _ = get_history(
            f"?signer_did={signer_did}&at={s5}", headers=DST)
        check("at=旧快照 s5 同步后合法 200", st == 200)
        # 超新检查点仍 409
        st, raw = get_history(
            f"?signer_did={signer_did}&at={s8 + 1}", headers=DST)
        check("新检查点之上仍 409",
              st == 409
              and json.loads(raw) == {"error": "同步游标冲突"})

        st, raw = get("/v1/audit?limit=200", headers=DST)
        audit_events = json.loads(raw).get("events", [])
        check("查询不记审计",
              not any("presentation-sync/history"
                      in json.dumps(e, ensure_ascii=False)
                      for e in audit_events))

        # ---------------------------------------------------------- #
        # 6. 租户隔离：OTHER 仅同步首页 -> 只见 2 项
        # ---------------------------------------------------------- #
        nd_iso = export_page(0, 2, s5)
        m_iso = manifest_page(0, 2, s5)
        st, raw = sync(m_iso, nd_iso, headers=OTHER)
        check("他租户首次同步独立 201", st == 201)
        st, raw = get_history(f"?signer_did={signer_did}", headers=OTHER)
        body = json.loads(raw)
        check("租户隔离：OTHER 仅见 2 项且 at 为其检查点 c2",
              st == 200 and body["at"] == c2
              and [e["cursor"] for e in body["events"]] == [c1, c2]
              and body["next_after"] == c2)
        st, raw = get_history(
            f"?signer_did={signer_did}&at={c3}", headers=OTHER)
        check("OTHER at 超其检查点 409（按租户检查点隔离）",
              st == 409
              and json.loads(raw) == {"error": "同步游标冲突"})

        # ---------------------------------------------------------- #
        # 7. 重启稳定
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, raw = get_history(
            f"?signer_did={signer_did}&at={c5}&limit=2", headers=DST)
        check("重启后 at=c5 分页逐字节一致",
              st == 200 and json.loads(raw) == expected_old)
        st, raw = get_history(f"?signer_did={signer_did}", headers=DST)
        body = json.loads(raw)
        check("重启后缺省 at/全部事件一致",
              st == 200 and body["at"] == c8
              and len(body["events"]) == 8
              and body["next_after"] == c8)
        st, raw = get_history(
            f"?signer_did={signer_did}&at={s8 + 1}", headers=DST)
        check("重启后 409 仍成立", st == 409)
        expect_404("重启后跨租户 404 仍成立",
                   f"?signer_did=did:web:nobody", headers=DST)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store_path):
            os.unlink(store_path)


def test_store_direct():
    """直连 VCStore：异常语义与纯只读。"""
    path = tempfile.mktemp(suffix=".json")
    tenant = "hist-store-ta"
    signer = "did:web:hist-store-signer"
    try:
        store = VCStore(path)

        def row(cursor, pid):
            return {
                "cursor": cursor,
                "consumption_id": f"{cursor:064d}",
                "issuer_did": "did:web:hist-store-issuer",
                "presentation_id": pid,
                "consumed_at": "2099-01-01T00:00:00Z",
            }

        events = [row(1, "vp_h_1"), row(2, "vp_h_2"), row(3, "vp_h_3")]
        try:
            store.list_presentation_sync_history(tenant, signer)
            check("直连：未同步来源 NotFoundError", False)
        except NotFoundError:
            check("直连：未同步来源 NotFoundError", True)

        created, snapshot, next_after, count = (
            store.sync_trust_presentation_consumptions(
                tenant, signer, 3, 0, events)
        )
        check("直连：同步基线 201",
              (created, snapshot, next_after, count) == (True, 3, 3, 3))

        at, out, page_after = store.list_presentation_sync_history(
            tenant, signer)
        check("直连：缺省 at=检查点、全量、升序",
              at == 3 and [e["cursor"] for e in out] == [1, 2, 3]
              and page_after == 3
              and all(list(e.keys()) == EVENT_KEYS for e in out))
        at, out, page_after = store.list_presentation_sync_history(
            tenant, signer, at=2, after=1, limit=1)
        check("直连：at/after/limit 组合",
              at == 2 and [e["cursor"] for e in out] == [2]
              and page_after == 2)
        at, out, page_after = store.list_presentation_sync_history(
            tenant, signer, at=1, after=1)
        check("直连：空页 next_after=after",
              at == 1 and out == [] and page_after == 1)
        try:
            store.list_presentation_sync_history(tenant, signer, at=4)
            check("直连：at 超检查点 ConflictError", False)
        except ConflictError:
            check("直连：at 超检查点 ConflictError", True)
        try:
            store.list_presentation_sync_history(
                tenant, signer, at=2, after=3)
            check("直连：after>at ValidationError", False)
        except ValidationError:
            check("直连：after>at ValidationError", True)
        try:
            store.list_presentation_sync_history("other-tenant", signer)
            check("直连：跨租户 NotFoundError", False)
        except NotFoundError:
            check("直连：跨租户 NotFoundError", True)

        # 纯只读：连续查询不改变内存、磁盘与审计。
        before = {
            "tenants": copy.deepcopy(store._tenants),  # noqa: SLF001
            "checkpoints": copy.deepcopy(  # noqa: SLF001
                store._presentation_sync_checkpoints),
            "audit": copy.deepcopy(store._audit),  # noqa: SLF001
        }
        disk_before = Path(path).read_bytes()
        for _ in range(3):
            store.list_presentation_sync_history(tenant, signer, at=2)
            store.list_presentation_sync_history(tenant, signer, at=3)
        check("只读：内存租户桶不变",
              store._tenants == before["tenants"])  # noqa: SLF001
        check("只读：检查点不变",
              store._presentation_sync_checkpoints  # noqa: SLF001
              == before["checkpoints"])
        check("只读：审计不变",
              store._audit == before["audit"])  # noqa: SLF001
        check("只读：不触发落盘（磁盘字节不变）",
              Path(path).read_bytes() == disk_before)

        reloaded = VCStore(path)
        at, out, page_after = reloaded.list_presentation_sync_history(
            tenant, signer)
        check("直连：重启后结果一致",
              at == 3 and [e["cursor"] for e in out] == [1, 2, 3]
              and page_after == 3)
    finally:
        if os.path.exists(path):
            os.unlink(path)


def main():
    test_http()
    test_store_direct()
    if failures:
        print(f"\n{len(failures)} 项失败: {failures}")
        sys.exit(1)
    print("\n全部通过")


if __name__ == "__main__":
    main()
