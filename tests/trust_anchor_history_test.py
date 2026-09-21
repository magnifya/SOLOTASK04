#!/usr/bin/env python3
"""信任锚点生命周期历史（只读）的端到端测试。

覆盖 GET /v1/trust/anchors/{did}/history?limit=&after=：
- 200 响应恰含 {did,events,next_after}，事件恰含
  {key_version,action,status,updated_at,cursor}；action 沿用既有审计动作名
  trust.anchor.registered / trust.anchor.rotated / trust.anchor.revoked；
- 注册新版本/轮换目标版本追加 active、updated_at=null；首次吊销追加
  revoked（updated_at 为首次吊销 UTC 秒精度 Z 时间）；幂等重试与任何
  失败（400/404/409）均不追加；
- 事件按 cursor 升序，cursor 为租户内跨 DID 共享的持久化正整数；
- limit 默认 50、限 1–200，after 默认 0、须非负，二者唯一且须为非空
  ASCII 数字，否则 400；after 排除 cursor≤其值的事件，next_after 取
  页末 cursor，空页等于 after；
- 未知/跨租户 DID 404，空租户头 400；只读不记审计；
- 跨重启历史与 cursor 稳定；旧状态（锚点存在但无历史）按版本稳定补
  注册/轮换事件、吊销版本另补吊销事件，无写重启 cursor 仍稳定；
- 落盘失败时锚点、历史、游标、审计共同回滚；
- 原锚点列表、验真、幂等响应与审计规则不变。

直接运行：python3 tests/trust_anchor_history_test.py
"""

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

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402

PORT = 8985
Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

PAGE_FIELDS = {"did", "events", "next_after"}
EVENT_FIELDS = {"key_version", "action", "status", "updated_at", "cursor"}

ACT_REGISTERED = "trust.anchor.registered"
ACT_ROTATED = "trust.anchor.rotated"
ACT_REVOKED = "trust.anchor.revoked"


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


def gen_pem():
    public_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def main():
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    store_path = tempfile.mktemp(suffix=".json")
    proc = start_server(PORT, store_path)
    base = f"http://127.0.0.1:{PORT}"
    H = {"X-Tenant-ID": "ta-hist-a"}
    H2 = {"X-Tenant-ID": "ta-hist-b"}
    P = gen_pem

    def register(did, version, pem, headers=None):
        return _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pem, "key_version": version},
            headers=headers or H,
        )

    def rotate(did, from_version, pem, headers=None):
        return _http(
            "POST", f"{base}/v1/trust/anchors/{did}/rotate",
            {"from_key_version": from_version, "public_key": pem},
            headers=headers or H,
        )

    def revoke(did, version, headers=None):
        return _http(
            "PUT",
            f"{base}/v1/trust/anchors/{did}/{version}/status",
            {"status": "revoked"}, headers=headers or H,
        )

    def history(did, headers=None, query=None):
        url = f"{base}/v1/trust/anchors/{did}/history"
        if query is not None:
            url += f"?{query}"
        return _http("GET", url, headers=headers or H)

    def audit(headers=None, query="limit=200"):
        return _http(
            "GET", f"{base}/v1/audit?{query}", headers=headers or H
        )[1]["events"]

    try:
        p1, p2, p4 = P(), P(), P()
        did_x = "did:web:anchor-x"

        # ---- 1. 注册/轮换/吊销的生命周期事件 ----
        st, _ = register(did_x, 1, p1)
        check("注册 v1 201", st == 201)
        st, _ = register(did_x, 1, p1)
        check("注册幂等重试 200", st == 200)
        st, h = history(did_x)
        evs = h.get("events", [])
        check(
            "仅新版本注册追加一条 active 事件（幂等不追加）",
            st == 200 and set(h) == PAGE_FIELDS and len(evs) == 1
            and set(evs[0]) == EVENT_FIELDS
            and evs[0] == {
                "key_version": 1,
                "action": ACT_REGISTERED,
                "status": "active",
                "updated_at": None,
                "cursor": 1,
            },
        )

        st, _ = rotate(did_x, 1, p2)
        check("轮换 v2 201", st == 201)
        st, _ = rotate(did_x, 1, p2)
        check("轮换幂等重试 200", st == 200)
        st, h = history(did_x)
        evs = h.get("events", [])
        check(
            "轮换目标版本追加 active 事件（幂等不追加）",
            st == 200 and len(evs) == 2
            and evs[1]["key_version"] == 2
            and evs[1]["action"] == ACT_ROTATED
            and evs[1]["status"] == "active"
            and evs[1]["updated_at"] is None
            and evs[1]["cursor"] == 2
            and h["next_after"] == 2,
        )

        # 直接注册 v4（跳版本）：动作仍为 registered
        st, _ = register(did_x, 4, p4)
        check("直接注册 v4 201", st == 201)

        st, _ = revoke(did_x, 1)
        check("首次吊销 v1 200", st == 200)
        st, repeat_body = revoke(did_x, 1)
        check("重复吊销 v1 200", st == 200)
        st, h = history(did_x)
        evs = h.get("events", [])
        revoked_event = evs[-1] if evs else {}
        check(
            "首次吊销追加 revoked 事件（重复不追加）",
            st == 200 and len(evs) == 4
            and [e["action"] for e in evs] == [
                ACT_REGISTERED, ACT_ROTATED, ACT_REGISTERED, ACT_REVOKED
            ]
            and [e["key_version"] for e in evs] == [1, 2, 4, 1]
            and [e["status"] for e in evs] == [
                "active", "active", "active", "revoked"
            ]
            and all(e["updated_at"] is None for e in evs[:3])
            and revoked_event.get("updated_at")
            == repeat_body["updated_at"]
            and bool(Z_RE.match(revoked_event.get("updated_at") or ""))
            and [e["cursor"] for e in evs] == [1, 2, 3, 4]
            and set(revoked_event) == EVENT_FIELDS
            and h["next_after"] == 4,
        )

        # ---- 2. cursor 租户内跨 DID 共享、租户间独立 ----
        p_y = P()
        did_y = "did:web:anchor-y"
        st, _ = register(did_y, 1, p_y)
        st, hy = history(did_y)
        check(
            "同租户新 DID 事件沿用共享游标空间",
            st == 200 and len(hy["events"]) == 1
            and hy["events"][0]["cursor"] == 5,
        )
        st, hx = history(did_x, query="limit=200")
        p_z = P()
        st2, _ = register("did:web:anchor-z", 1, p_z, headers=H2)
        st2, hz = history("did:web:anchor-z", headers=H2)
        check(
            "游标按租户隔离：另一租户从 1 重新计起",
            st2 == 200 and hz["events"][0]["cursor"] == 1,
        )
        # 同租户两 DID 游标合并唯一且连续
        all_cursors = sorted(
            [e["cursor"] for e in hx["events"]]
            + [e["cursor"] for e in hy["events"]]
        )
        check(
            "租户内跨 DID 游标唯一且连续递增",
            all_cursors == list(range(1, 6)),
        )

        # ---- 3. 失败路径不追加历史 ----
        before = len(history(did_x, query="limit=200")[1]["events"])
        # 409：同版本不同 PEM
        st, _ = register(did_x, 4, P())
        n409_reg = st
        # 400：非法 key_version
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did_x, "public_key": P(), "key_version": 0}, headers=H,
        )
        n400_reg = st
        # 404：轮换未知 DID
        st, _ = rotate("did:web:no-such", 1, P())
        n404_rot = st
        # 400：from_key_version 非当前最高（v2 active 但最高为 v4，目标 v3 缺失）
        st, _ = rotate(did_x, 2, P())
        n400_rot = st
        # 409：轮换目标已被其他 PEM/前置占用（v4 经注册接口直接创建）
        st, _ = rotate(did_x, 3, P())
        n409_rot = st
        # 404：吊销未知版本
        st, _ = revoke(did_x, 99)
        n404_rev = st
        # 400：路径版本非正整数
        st, _ = _http(
            "PUT", f"{base}/v1/trust/anchors/{did_x}/0/status",
            {"status": "revoked"}, headers=H,
        )
        n400_rev = st
        after = len(history(did_x, query="limit=200")[1]["events"])
        check(
            "注册/轮换/吊销失败（400/404/409）均不追加历史",
            (n409_reg, n400_reg, n404_rot, n400_rot, n409_rot,
             n404_rev, n400_rev)
            == (409, 400, 404, 400, 409, 404, 400)
            and before == after == 4,
        )
        # 400：前置版本已吊销且目标版本缺失（锚点允许吊销当前版本）
        st, _ = register("did:web:anchor-fail", 1, P())
        assert st == 201
        st, _ = revoke("did:web:anchor-fail", 1)
        assert st == 200
        st, _ = rotate("did:web:anchor-fail", 1, P())
        check(
            "前置已吊销且目标缺失时轮换 400，且失败不追加额外事件",
            st == 400
            and len(history("did:web:anchor-fail", query="limit=200")
                    [1]["events"]) == 2,
        )

        # ---- 4. 分页与参数校验 ----
        # 默认 50：专用 DID 注册 51 个版本
        did_page = "did:web:anchor-page"
        for version in range(1, 52):
            st, _ = register(did_page, version, P())
            assert st == 201, (version, st)
        st, hp = history(did_page)
        check(
            "limit 默认 50",
            st == 200 and len(hp["events"]) == 50
            and hp["events"][0]["cursor"] == 8
            and hp["next_after"] == hp["events"][-1]["cursor"],
        )
        first_next = hp["next_after"]
        st, hp2 = history(did_page, query=f"after={first_next}")
        check(
            "after 翻到末页且 next_after 取页末 cursor",
            st == 200 and len(hp2["events"]) == 1
            and hp2["events"][0]["cursor"] > first_next
            and hp2["next_after"] == hp2["events"][0]["cursor"],
        )
        last_cursor = hp2["next_after"]
        st, he = history(did_page, query=f"after={last_cursor}")
        check(
            "空页 events=[] 且 next_after 等于 after",
            st == 200 and he["events"] == []
            and he["next_after"] == last_cursor,
        )
        st, _ = history(did_page, query="limit=1")
        one = _
        check(
            "limit=1 只返一项",
            st == 200 and len(one["events"]) == 1
            and one["events"][0]["cursor"] == 8,
        )
        st, hb = history(did_page, query="limit=200")
        check("limit=200 合法且取全部", st == 200 and len(hb["events"]) == 51)
        st, hb = history(did_page, query="after=3")
        check(
            "after 排除 cursor 不大于其值的事件（该 DID 事件 cursor 8 起，不受影响）",
            st == 200 and len(hb["events"]) == 50
            and hb["events"][0]["cursor"] == 8,
        )
        st, hb = history(did_page, query="after=8&limit=1")
        check(
            "after=8 排除 cursor=8",
            st == 200 and [e["cursor"] for e in hb["events"]] == [9],
        )

        bad_queries = [
            "limit=0", "limit=201", "limit=-1", "limit=abc", "limit=1.5",
            "limit=true", "limit=%20", "limit=", "limit=1&limit=2",
            "after=-1", "after=abc", "after=1.0", "after=%20", "after=",
            "after=1&after=2", "after=%DB111",  # 非 ASCII
        ]
        bad_results = []
        for query in bad_queries:
            st, _ = history(did_page, query=query)
            bad_results.append(st)
        check(
            "limit/after 重复、空白、布尔词、小数、符号、Unicode 等一律 400",
            bad_results == [400] * len(bad_queries),
        )
        # 合法的前导零与超大非负 after
        st, _ = history(did_page, query="limit=01")
        c1 = st
        st, hb = history(did_page, query="after=99999999999999999999")
        check(
            "前导零数字接受；超大非负 after 返回空页且保持 after",
            c1 == 200 and st == 200 and hb["events"] == []
            and hb["next_after"] == 99999999999999999999,
        )

        # ---- 5. 404 / 租户 / 头校验 ----
        st, _ = history("did:web:not-registered")
        check("未知 DID 404", st == 404)
        st, _ = history(did_x, headers=H2)
        check("跨租户 DID 404（不可探测）", st == 404)
        st, _ = history(did_x, headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", st == 400)

        # ---- 6. 只读不记审计 ----
        before_audit = audit()
        history(did_x, query="limit=200")
        history(did_y, query="after=3&limit=1")
        history("did:web:not-registered")
        after_audit = audit()
        check("历史查询（含 404）不记审计", before_audit == after_audit)

        # ---- 7. 既有接口协议不变 ----
        st, anchors = _http(
            "GET", f"{base}/v1/trust/anchors/{did_x}", headers=H
        )
        check(
            "GET 锚点列表仍按版本升序、字段不变",
            st == 200 and [a["key_version"] for a in anchors] == [1, 2, 4]
            and [set(a) == {
                "did", "public_key", "key_version", "status", "updated_at"
            } for a in anchors] == [True, True, True]
            and anchors[0]["status"] == "revoked"
            and anchors[0]["updated_at"] == repeat_body["updated_at"]
            and anchors[1]["status"] == "active"
            and anchors[1]["updated_at"] is None,
        )
        # 幂等注册仍返回既有记录（含已吊销状态）
        st, idem = register(did_x, 1, p1)
        check(
            "幂等注册响应不变（200、保持吊销状态与首次时间）",
            st == 200 and idem["status"] == "revoked"
            and idem["updated_at"] == repeat_body["updated_at"],
        )
        # 幂等轮换响应不变
        st, idem = rotate(did_x, 1, p2)
        check(
            "幂等轮换响应不变（200，目标版本仍 active）",
            st == 200 and idem["key_version"] == 2
            and idem["status"] == "active",
        )
        # 审计动作名与次数不变：注册 v1/v4、轮换 v2、吊销 v1 各首次一次，
        # 另加重试产生的注册/轮换/吊销审计。
        anchor_audit = [
            e for e in audit()
            if e["resource_id"].startswith(f"{did_x}#")
        ]
        action_counts = {}
        for event in anchor_audit:
            action_counts[event["action"]] = (
                action_counts.get(event["action"], 0) + 1
            )
        check(
            "历史动作名沿用审计动作名且原审计规则不变（幂等每次仍记）",
            action_counts.get(ACT_REGISTERED, 0) == 4   # v1 首次+2 次重试、v4
            and action_counts.get(ACT_ROTATED, 0) == 3  # 首次 + 2 次幂等
            and action_counts.get(ACT_REVOKED, 0) == 2  # 首次 + 重复
            and {e["resource_type"] for e in anchor_audit}
            == {"trust_anchor"},
        )
        # 验真：active 版本可验、revoked 版本被拒
        priv = ec.generate_private_key(ec.SECP256R1())
        verify_pem = priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        did_v = "did:web:anchor-verify"
        st, _ = register(did_v, 1, verify_pem)
        assert st == 201
        payload = {"issuer_did": did_v, "issuer_key_version": 1,
                   "payload": {"x": 1}}
        signed = dict(payload, signature=crypto.sign(
            {k: v for k, v in payload.items()},
            priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode(),
        ))
        st, ok = _http(
            "POST", f"{base}/v1/trust/verify", signed, headers=H
        )
        check("active 锚点验真仍成功", st == 200 and ok == {"valid": True})
        revoke(did_v, 1)
        st, bad = _http(
            "POST", f"{base}/v1/trust/verify", signed, headers=H
        )
        check(
            "吊销后验真仍 200/valid:false，且验签不记审计",
            st == 200 and bad.get("valid") is False
            and bool(bad.get("reason")),
        )
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 8. 跨重启：历史与 cursor 稳定，新事件继续递增 ----
    proc = start_server(PORT, store_path)
    try:
        st, h = _http(
            "GET", f"{base}/v1/trust/anchors/did:web:anchor-x/history"
            "?limit=200",
            headers=H,
        )
        ok = (
            st == 200 and len(h["events"]) == 4
            and [e["cursor"] for e in h["events"]] == [1, 2, 3, 4]
            and [e["action"] for e in h["events"]] == [
                ACT_REGISTERED, ACT_ROTATED, ACT_REGISTERED, ACT_REVOKED
            ]
        )
        check("重启后历史与 cursor 稳定", ok)

        # 新事件在租户内继续递增（x/y/page/fail/verify 各事件已用到 60）
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": "did:web:anchor-y", "public_key": P(),
             "key_version": 2},
            headers=H,
        )
        st, hy = _http(
            "GET", f"{base}/v1/trust/anchors/did:web:anchor-y/history"
            "?limit=200",
            headers=H,
        )
        check(
            "重启后新注册事件游标在租户内继续递增",
            st == 200 and [e["cursor"] for e in hy["events"]] == [5, 61],
        )
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 9. 旧状态补录：删除历史命名空间与游标后重启 ----
    legacy_path = tempfile.mktemp(suffix=".json")
    lp = start_server(PORT, legacy_path)
    legacy_tenant = {"X-Tenant-ID": "ta-legacy"}
    try:
        lp1, lp2, lp3 = P(), P(), P()
        # v1 注册 -> v2 轮换 -> v3 直接注册；吊销 v1
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": "did:web:old", "public_key": lp1, "key_version": 1},
            headers=legacy_tenant,
        )
        assert st == 201
        st, body_v2 = _http(
            "POST", f"{base}/v1/trust/anchors/did:web:old/rotate",
            {"from_key_version": 1, "public_key": lp2},
            headers=legacy_tenant,
        )
        assert st == 201
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": "did:web:old", "public_key": lp3, "key_version": 3},
            headers=legacy_tenant,
        )
        assert st == 201
        st, body_rev = _http(
            "PUT", f"{base}/v1/trust/anchors/did:web:old/1/status",
            {"status": "revoked"}, headers=legacy_tenant,
        )
        assert st == 200
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    raw = json.load(open(legacy_path, encoding="utf-8"))
    for bucket in raw["tenants"].values():
        bucket["trust_anchor_history"] = {}
    raw.pop("trust_anchor_history_cursors", None)
    with open(legacy_path, "w", encoding="utf-8") as fh:
        json.dump(raw, fh)

    def legacy_history(query=None):
        url = f"{base}/v1/trust/anchors/did:web:old/history"
        if query:
            url += f"?{query}"
        return _http("GET", url, headers=legacy_tenant)

    lp = start_server(PORT, legacy_path)
    try:
        st, h = legacy_history("limit=200")
        expect = [
            (1, ACT_REGISTERED, "active", None),
            (1, ACT_REVOKED, "revoked", body_rev["updated_at"]),
            (2, ACT_ROTATED, "active", None),
            (3, ACT_REGISTERED, "active", None),
        ]
        got = [
            (e["key_version"], e["action"], e["status"], e["updated_at"])
            for e in h.get("events", [])
        ]
        cursors = [e["cursor"] for e in h.get("events", [])]
        check(
            "旧状态按版本稳定补注册/轮换事件，吊销版本另补吊销事件",
            st == 200 and got == expect
            and cursors == [1, 2, 3, 4]
            and h["next_after"] == 4
            and all(set(e) == EVENT_FIELDS for e in h["events"]),
        )
        compat_cursors = cursors
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # 无写操作直接重启：补录 cursor 必须重建为相同值
    lp = start_server(PORT, legacy_path)
    try:
        st, h = legacy_history("limit=200")
        check(
            "补录 cursor 无写重启仍稳定",
            st == 200
            and [e["cursor"] for e in h["events"]] == compat_cursors
            and [
                (e["key_version"], e["action"], e["status"])
                for e in h["events"]
            ] == [
                (1, ACT_REGISTERED, "active"),
                (1, ACT_REVOKED, "revoked"),
                (2, ACT_ROTATED, "active"),
                (3, ACT_REGISTERED, "active"),
            ],
        )
        # 触发一次新变更（轮换 v3 -> v4），使补录随原子写落盘
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors/did:web:old/rotate",
            {"from_key_version": 3, "public_key": P()},
            headers=legacy_tenant,
        )
        assert st == 201
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    lp = start_server(PORT, legacy_path)
    try:
        st, h = legacy_history("limit=200")
        check(
            "补录随原子写持久化后重启全部稳定，新事件追加在后",
            st == 200
            and [e["cursor"] for e in h["events"][:4]] == compat_cursors
            and len(h["events"]) == 5
            and h["events"][-1]["action"] == ACT_ROTATED
            and h["events"][-1]["cursor"] == 5,
        )
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # ---- 10. 直连 store：已有 DID 空历史空页 + 落盘失败共同回滚 ----
    from vcbackend.store import VCStore

    direct_path = tempfile.mktemp(suffix=".json")
    store = VCStore(direct_path)
    d1, d2 = P(), P()
    rec, created = store.register_trust_anchor("rt", "did:web:rb", d1, 1)
    assert created
    # 加载补录后再手工清空该租户历史，模拟“DID 存在但无历史”
    bucket = store._bucket_locked("rt")  # noqa: SLF001
    bucket["trust_anchor_history"] = {}
    events, next_after = store.list_trust_anchor_history(
        "rt", "did:web:rb", 7, 50
    )
    check(
        "已有 DID 无历史返回空页且 next_after 等于 after",
        events == [] and next_after == 7,
    )
    del store  # 不落盘该内存态

    store = VCStore(direct_path)
    audit0 = len(store.list_audit("rt", 0, 200)[0])
    events0, _ = store.list_trust_anchor_history(
        "rt", "did:web:rb", 0, 200
    )
    cursor0 = store._trust_anchor_history_cursors.get("rt", 0)  # noqa: SLF001

    def _boom():
        raise OSError("模拟落盘失败")

    # 注册新版本落盘失败：锚点/历史/游标/审计共同回滚
    store._save_locked = _boom  # type: ignore[assignment]
    raised = False
    try:
        store.register_trust_anchor("rt", "did:web:rb", P(), 2)
    except OSError:
        raised = True
    check("注册新版本落盘失败时抛错", raised)
    anchors = {a.key_version for a in store.list_trust_anchors(
        "rt", "did:web:rb"
    )}
    events1, _ = store.list_trust_anchor_history("rt", "did:web:rb", 0, 200)
    check(
        "注册失败回滚：无新版本、无历史、游标不前进、无审计",
        anchors == {1} and len(events1) == len(events0)
        and store._trust_anchor_history_cursors.get("rt", 0) == cursor0  # noqa: SLF001,E501
        and len(store.list_audit("rt", 0, 200)[0]) == audit0,
    )

    # 轮换落盘失败共同回滚
    raised = False
    try:
        store.rotate_trust_anchor("rt", "did:web:rb", 1, P())
    except OSError:
        raised = True
    check("轮换落盘失败时抛错", raised)
    events2, _ = store.list_trust_anchor_history("rt", "did:web:rb", 0, 200)
    check(
        "轮换失败回滚：无新版本事件、游标不前进、无审计",
        len(events2) == len(events0)
        and store._trust_anchor_history_cursors.get("rt", 0) == cursor0  # noqa: SLF001,E501
        and len(store.list_audit("rt", 0, 200)[0]) == audit0,
    )

    # 首次吊销落盘失败共同回滚
    raised = False
    try:
        store.revoke_trust_anchor("rt", "did:web:rb", 1)
    except OSError:
        raised = True
    check("首次吊销落盘失败时抛错", raised)
    rec = store.list_trust_anchors("rt", "did:web:rb")[0]
    events3, _ = store.list_trust_anchor_history("rt", "did:web:rb", 0, 200)
    check(
        "吊销失败回滚：状态仍 active、无 revoked 事件、游标不前进、无审计",
        rec.status == "active" and rec.updated_at is None
        and len(events3) == len(events0)
        and store._trust_anchor_history_cursors.get("rt", 0) == cursor0  # noqa: SLF001,E501
        and len(store.list_audit("rt", 0, 200)[0]) == audit0,
    )

    # 恢复落盘后各操作成功并与历史、审计一致
    del store._save_locked  # type: ignore[attr-defined]
    rec, created = store.register_trust_anchor("rt", "did:web:rb", P(), 2)
    assert created
    rec, created = store.rotate_trust_anchor("rt", "did:web:rb", 2, P())
    assert created
    rec = store.revoke_trust_anchor("rt", "did:web:rb", 1)
    assert rec.status == "revoked"
    events_final, na = store.list_trust_anchor_history(
        "rt", "did:web:rb", 0, 200
    )
    check(
        "恢复后注册/轮换/吊销成功：历史含 4 条新事件且游标连续",
        [e.action for e in events_final] == [
            ACT_REGISTERED,  # 补录的 v1（加载时补）
            ACT_REGISTERED, ACT_ROTATED, ACT_REVOKED,
        ]
        and [e.key_version for e in events_final] == [1, 2, 3, 1]
        and [e.cursor for e in events_final]
        == [cursor0, cursor0 + 1, cursor0 + 2, cursor0 + 3],
    )

    # 落盘后的回滚场景重新加载仍一致
    reloaded = VCStore(direct_path)
    events_r, _ = reloaded.list_trust_anchor_history(
        "rt", "did:web:rb", 0, 200
    )
    check(
        "回滚场景成功落盘后跨进程重载，历史与游标稳定",
        [(e.key_version, e.action, e.status) for e in events_r]
        == [(e.key_version, e.action, e.status) for e in events_final],
    )

    for path in (store_path, legacy_path, direct_path):
        if os.path.exists(path):
            os.remove(path)

    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
