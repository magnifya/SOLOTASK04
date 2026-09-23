#!/usr/bin/env python3
"""DID 密钥生命周期历史 GET /v1/dids/{did}/keys/history 的端到端测试。

覆盖：
- 200 恰含 did/events/next_after；事件恰含 key_version、key_handle、
  public_key、action、status、updated_at、audit_seq、audit_timestamp、
  cursor，按 cursor 升序；响应绝不包含私钥；
- 新版本追加 active：v1 为 did.created（updated_at 取 DID created_at），
  轮换为 key.rotated（updated_at 为轮换成功时刻 UTC 秒 Z，
  audit_timestamp 为同 Unix 秒）；首次吊销追加 revoked/key.revoked
  并与吊销同秒；重复/失败/幂等不追加，active 历史不改写；
- cursor 租户内跨 DID 持久递增，且与 keys/revocations 吊销历史游标
  相互隔离；
- 分页参数沿用 keys/revocations（limit 默认 50/限 1–200，after 默认
  0/须非负，重复/空白/布尔词/小数/符号/Unicode 数字 400），空页
  next_after=after；
- 租户头缺省 default，显式空值 400，未知/跨租户 DID 404，已有 DID
  无历史空页；查询只读不记审计；
- 跨重启历史与 cursor 稳定；旧状态按 DID 序、版本序、同版本 active
  后 revoked 补齐（v1 active 取 created_at，其余 active=null，revoked
  取 revoked_at 或 null，迁移 audit=null），无写重启 cursor 稳定；
- 新建/轮换/吊销落盘失败时状态/历史/游标/审计全部回滚。

直接运行：python3 tests/key_history_test.py
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

PORT = 8985
Z_FMT = "%Y-%m-%dT%H:%M:%SZ"

HISTORY_FIELDS = {"did", "events", "next_after"}
EVENT_FIELDS = {
    "key_version",
    "key_handle",
    "public_key",
    "action",
    "status",
    "updated_at",
    "audit_seq",
    "audit_timestamp",
    "cursor",
}
PUB_KEY_PREFIX = "-----BEGIN PUBLIC KEY-----"


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


def main():
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    store_path = tempfile.mktemp(suffix=".json")
    proc = start_server(PORT, store_path)
    base = f"http://127.0.0.1:{PORT}"
    T1 = {"X-Tenant-ID": "kh-a"}
    T2 = {"X-Tenant-ID": "kh-b"}

    def history(did, headers=None, query=None):
        url = f"{base}/v1/dids/{did}/keys/history"
        if query is not None:
            url += f"?{query}"
        return _http("GET", url, headers=headers)

    def revocations(did, headers=None, query=None):
        url = f"{base}/v1/dids/{did}/keys/revocations"
        if query is not None:
            url += f"?{query}"
        return _http("GET", url, headers=headers)

    def revoke(did, version, payload=None, headers=None):
        return _http(
            "POST",
            f"{base}/v1/dids/{did}/keys/{version}/revoke",
            payload, headers=headers,
        )

    def rotate(did, handle, headers=None):
        return _http(
            "POST", f"{base}/v1/dids/{did}/keys/rotate",
            {"key_handle": handle}, headers=headers,
        )

    def audit_events(headers):
        st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=headers)
        assert st == 200, r
        return {e["seq"]: e for e in r["events"]}

    try:
        # ---- 准备：A 注册（带 T1），B 注册（缺省租户 default） ----
        st, a = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "kh-handle-a"}, headers=T1,
        )
        assert st == 201, a
        did_a = a["did"]
        st, ag = _http("GET", f"{base}/v1/dids/{did_a}", headers=T1)
        assert st == 200, ag
        a_created = ag["created_at"]

        st, b = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "kh-handle-default"},
        )
        assert st == 201, b
        did_default = b["did"]

        # ---- 1. v1 active：字段恰九项、did.created、关联审计、无私钥 ----
        st, h = history(did_a, headers=T1)
        audit_map = audit_events(T1)
        ok_v1 = False
        if st == 200 and set(h) == HISTORY_FIELDS and h["did"] == did_a:
            if len(h["events"]) == 1:
                ev = h["events"][0]
                linked = audit_map.get(ev["audit_seq"])
                ok_v1 = (
                    set(ev) == EVENT_FIELDS
                    and ev["key_version"] == 1
                    and ev["key_handle"] == "kh-handle-a"
                    and isinstance(ev["public_key"], str)
                    and ev["public_key"].startswith(PUB_KEY_PREFIX)
                    and "PRIVATE KEY-----" not in ev["public_key"]
                    and ev["action"] == "did.created"
                    and ev["status"] == "active"
                    and ev["updated_at"] == a_created
                    and isinstance(ev["cursor"], int) and ev["cursor"] == 1
                    and isinstance(ev["audit_seq"], int)
                    and isinstance(ev["audit_timestamp"], int)
                    and linked is not None
                    and linked["action"] == "did.created"
                    and linked["timestamp"] == ev["audit_timestamp"]
                    and linked["resource_type"] == "did"
                    and linked["resource_id"] == did_a
                    and h["next_after"] == ev["cursor"]
                )
        check("v1 active 事件字段恰九项且关联 did.created 审计", ok_v1)

        # 缺省租户头 = default：T1 查不到 did_default（跨租户 404），
        # 不带租户头能查到。
        st, _ = history(did_default, headers=T1)
        check("default 租户与显式租户隔离 -> 404", st == 404)
        st, h = history(did_default)
        check("租户头缺省 default 可查", st == 200
              and len(h["events"]) == 1
              and h["events"][0]["action"] == "did.created")

        # ---- 2. 幂等重复注册：记审计但不追加历史、active 不改写 ----
        st, _ = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "kh-handle-a"}, headers=T1,
        )
        assert st == 201
        st, h = history(did_a, headers=T1)
        audit_after_idem = audit_events(T1)
        check(
            "幂等注册不追加历史但仍记 did.created 审计",
            len(h["events"]) == 1
            and sum(
                1 for e in audit_after_idem.values()
                if e["action"] == "did.created"
            ) == 2,
        )

        # ---- 3. 轮换追加 active key.rotated，updated_at=轮换时刻 ----
        st, rot = rotate(did_a, "kh-handle-a-v2", headers=T1)
        assert st == 200, rot
        st, h = history(did_a, headers=T1)
        audit_map = audit_events(T1)
        ok_rot = False
        if len(h["events"]) == 2:
            ev1, ev2 = h["events"]
            linked = audit_map.get(ev2["audit_seq"])
            import datetime as _dt
            parsed_ts = int(
                _dt.datetime.strptime(
                    ev2["updated_at"], Z_FMT
                ).replace(tzinfo=_dt.timezone.utc).timestamp()
            )
            ok_rot = (
                [e["cursor"] for e in h["events"]] == [1, 2]
                and ev1["action"] == "did.created"
                and ev2["key_version"] == 2
                and ev2["key_handle"] == "kh-handle-a-v2"
                and ev2["public_key"].startswith(PUB_KEY_PREFIX)
                and "PRIVATE KEY-----" not in ev2["public_key"]
                and ev2["action"] == "key.rotated"
                and ev2["status"] == "active"
                and linked is not None
                and linked["action"] == "key.rotated"
                and parsed_ts == ev2["audit_timestamp"]
                and linked["timestamp"] == ev2["audit_timestamp"]
                and h["next_after"] == 2
            )
        check("轮换追加 active key.rotated 且审计同 Unix 秒", ok_rot)

        # 与 DID 文档公开的版本公钥/句柄一致
        st, doc = _http("GET", f"{base}/v1/dids/{did_a}/document",
                        headers=T1)
        check(
            "history 公钥/句柄与 DID 文档版本一致",
            st == 200
            and [
                (m["key_version"], m["key_handle"], m["public_key"])
                for m in doc["verification_methods"]
            ]
            == [
                (e["key_version"], e["key_handle"], e["public_key"])
                for e in h["events"]
                if e["status"] == "active"
            ],
        )

        # ---- 4. 首次吊销追加 revoked/key.revoked，同秒、cursor 升序 ----
        st, rv = revoke(did_a, 1, {"reason": " v1 泄漏 "}, headers=T1)
        assert st == 200, rv
        st, h = history(did_a, headers=T1)
        audit_map = audit_events(T1)
        ok_rev = False
        if len(h["events"]) == 3:
            import datetime as _dt
            evs = h["events"]
            linked = audit_map.get(evs[2]["audit_seq"])
            parsed_ts = int(
                _dt.datetime.strptime(
                    evs[2]["updated_at"], Z_FMT
                ).replace(tzinfo=_dt.timezone.utc).timestamp()
            )
            ok_rev = (
                [e["cursor"] for e in evs] == [1, 2, 3]
                and evs[2]["key_version"] == 1
                and evs[2]["key_handle"] == "kh-handle-a"
                and evs[2]["public_key"] == evs[0]["public_key"]
                and evs[2]["action"] == "key.revoked"
                and evs[2]["status"] == "revoked"
                and evs[2]["updated_at"] == rv["updated_at"]
                and parsed_ts == evs[2]["audit_timestamp"]
                and linked is not None
                and linked["action"] == "key.revoked"
                and linked["timestamp"] == evs[2]["audit_timestamp"]
                and linked["resource_id"] == f"{did_a}#1"
            )
        check("首次吊销追加 revoked 事件且与审计同秒", ok_rev)

        # ---- 5. 重复吊销与失败路径不追加；active 历史不改写 ----
        active_before = [
            (e["key_version"], e["action"], e["updated_at"], e["cursor"])
            for e in h["events"] if e["status"] == "active"
        ]
        st, _ = revoke(did_a, 1, {"reason": "另一原因"}, headers=T1)
        assert st == 200
        st, _ = revoke(did_a, 2, {"reason": "当前版本"}, headers=T1)
        check("吊销当前版本 -> 409", st == 409)
        st, _ = revoke(did_a, 0, {"reason": "x"}, headers=T1)
        check("吊销坏版本 -> 400", st == 400)
        st, _ = revoke(
            "did:example:00000000000000000000000000000000", 1,
            {"reason": "x"}, headers=T1,
        )
        check("吊销未知 DID -> 404", st == 404)
        # 失败轮换（停用后轮换 409、重复句柄 400）也不追加
        st, _ = _http(
            "POST", f"{base}/v1/dids/{did_a}/deactivate",
            {"reason": "停用"}, headers=T1,
        )
        assert st == 200
        st, _ = rotate(did_a, "kh-handle-fail", headers=T1)
        check("停用后轮换 -> 409", st == 409)
        st, h2 = history(did_a, headers=T1)
        check(
            "重复吊销/失败路径不追加且 active 历史不改写",
            len(h2["events"]) == 3
            and [
                (e["key_version"], e["action"], e["updated_at"], e["cursor"])
                for e in h2["events"] if e["status"] == "active"
            ] == active_before
            and h2["events"][0]["updated_at"] == a_created,
        )

        # ---- 6. cursor 租户内跨 DID 递增，与吊销历史隔离 ----
        # 新 DID（T2 租户）：其生命周期 cursor 独立从 1 计起。
        st, c = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "kh-handle-c"}, headers=T2,
        )
        assert st == 201, c
        did_c = c["did"]
        st, hc = history(did_c, headers=T2)
        check("不同租户 cursor 各自从 1 计起",
              st == 200 and len(hc["events"]) == 1
              and hc["events"][0]["cursor"] == 1)

        # T1 内再注册一个 DID：生命周期游标跨 DID 接续（4），
        # 同时吊销历史游标空间独立（该 DID 尚无吊销）。
        st, d = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "kh-handle-d"}, headers=T1,
        )
        assert st == 201
        did_d = d["did"]
        st, hd = history(did_d, headers=T1)
        st, rd = revocations(did_d, headers=T1)
        check(
            "生命周期 cursor 租户内跨 DID 接续且与吊销历史隔离",
            st == 200 and len(hd["events"]) == 1
            and hd["events"][0]["cursor"] == 4
            and rd == {"did": did_d, "events": [], "next_after": 0},
        )
        # did_a 的吊销历史只有一条且 cursor=1（独立游标空间）
        st, ra = revocations(did_a, headers=T1)
        check("吊销历史游标独立（v1 吊销 cursor=1）",
              st == 200 and [e["cursor"] for e in ra["events"]] == [1]
              and [e["key_version"] for e in ra["events"]] == [1])

        # ---- 7. 已有 DID 无历史/未知/跨租户/空租户头 ----
        st, h = history(did_d, headers=T1)
        check("新建 DID 也有 v1 历史（非空页）",
              st == 200 and len(h["events"]) == 1)
        st, _ = history(
            "did:example:00000000000000000000000000000000", headers=T1)
        check("未知 DID history -> 404", st == 404)
        st, _ = history(did_a, headers=T2)
        check("跨租户 history 不可探测 -> 404", st == 404)
        st, _ = history(did_a, headers={"X-Tenant-ID": ""})
        check("显式空租户头 history -> 400", st == 400)

        # ---- 8. 分页：limit/after/空页 ----
        st, pg = history(did_a, headers=T1, query="limit=2")
        check("limit=2 返回前两项",
              st == 200 and [e["cursor"] for e in pg["events"]] == [1, 2]
              and pg["next_after"] == 2)
        st, pg = history(did_a, headers=T1, query="limit=2&after=2")
        check("after 排除不大于其值的 cursor",
              st == 200 and [e["cursor"] for e in pg["events"]] == [3]
              and pg["next_after"] == 3)
        st, pg = history(did_a, headers=T1, query="after=999999")
        check("空页 next_after 等于 after",
              st == 200 and pg["events"] == []
              and pg["next_after"] == 999999)

        def hist_400(query, name):
            st, r = history(did_a, headers=T1, query=query)
            check(name, st == 400 and isinstance(r.get("error"), str)
                  and r["error"])

        hist_400("limit=0", "limit=0 -> 400")
        hist_400("limit=201", "limit=201 -> 400")
        hist_400("limit=-1", "limit=-1 -> 400")
        hist_400("limit=1.5", "limit=1.5 -> 400")
        hist_400("limit=true", "limit=true -> 400")
        hist_400("limit=", "空 limit -> 400")
        hist_400("limit=%20", "空白 limit -> 400")
        hist_400("limit=abc", "字母 limit -> 400")
        hist_400("limit=%E0%A5%91", "Unicode 数字 limit -> 400")
        hist_400("limit=1&limit=2", "重复 limit -> 400")
        hist_400("after=-1", "after=-1 -> 400")
        hist_400("after=1.0", "after=1.0 -> 400")
        hist_400("after=abc", "字母 after -> 400")
        hist_400("after=", "空 after -> 400")
        hist_400("after=%20", "空白 after -> 400")
        hist_400("after=0&after=1", "重复 after -> 400")
        # 未知查询参数沿用 keys/revocations 行为（忽略，不影响查询）
        st, pg = history(did_a, headers=T1, query="bogus=1&limit=1")
        check("未知查询参数沿用 revocations 行为（忽略）",
              st == 200 and len(pg["events"]) == 1)

        # ---- 9. 只读：查询不记审计 ----
        before = audit_events(T1)
        for _ in range(3):
            history(did_a, headers=T1)
            history(did_d, headers=T1, query="limit=1")
        after = audit_events(T1)
        check("history 查询只读、不记审计", after == before)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 10. 跨重启：历史与 cursor 稳定，新事件继续递增 ----
    proc = start_server(PORT, store_path)
    try:
        st, h = history(did_a, headers=T1)
        check(
            "重启后历史与 cursor 稳定",
            st == 200
            and [
                (e["key_version"], e["action"], e["status"], e["cursor"])
                for e in h["events"]
            ]
            == [
                (1, "did.created", "active", 1),
                (2, "key.rotated", "active", 2),
                (1, "key.revoked", "revoked", 3),
            ]
            and all(e["audit_seq"] is not None for e in h["events"]),
        )
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 11. 旧状态补录：DID 序、版本序、active 后 revoked ----
    legacy_path = tempfile.mktemp(suffix=".json")
    lp = start_server(PORT + 1, legacy_path)
    lbase = f"http://127.0.0.1:{PORT + 1}"
    L = {"X-Tenant-ID": "legacy"}
    try:
        st, ld = _http("POST", f"{lbase}/v1/dids",
                       {"method": "example", "public_key": "leg-a"},
                       headers=L)
        assert st == 201
        leg_did = ld["did"]
        st, lg = _http("GET", f"{lbase}/v1/dids/{leg_did}", headers=L)
        assert st == 200
        leg_created = lg["created_at"]
        _http("POST", f"{lbase}/v1/dids/{leg_did}/keys/rotate",
              {"key_handle": "leg-a2"}, headers=L)
        _http("POST", f"{lbase}/v1/dids/{leg_did}/keys/1/revoke",
              {"reason": "旧吊销"}, headers=L)
        _http("POST", f"{lbase}/v1/dids/{leg_did}/keys/rotate",
              {"key_handle": "leg-a3"}, headers=L)
        # 第二个 DID：字典序排在前/后取决于随机 hex，补录顺序按 DID 序。
        st, ld2 = _http("POST", f"{lbase}/v1/dids",
                        {"method": "example", "public_key": "leg-b"},
                        headers=L)
        assert st == 201
        leg_did2 = ld2["did"]
        st, lg2 = _http("GET", f"{lbase}/v1/dids/{leg_did2}", headers=L)
        assert st == 200
        leg_created2 = lg2["created_at"]
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    raw = json.load(open(legacy_path, encoding="utf-8"))
    for bucket in raw["tenants"].values():
        bucket["key_history_events"] = {}
    raw.pop("key_history_cursors", None)
    with open(legacy_path, "w", encoding="utf-8") as fh:
        json.dump(raw, fh)

    lp = start_server(PORT + 1, legacy_path)
    try:
        st, h1 = _http(
            "GET", f"{lbase}/v1/dids/{leg_did}/keys/history", headers=L)
        st2, h2 = _http(
            "GET", f"{lbase}/v1/dids/{leg_did2}/keys/history", headers=L)
        assert st == 200 and st2 == 200
        # 期望补录顺序：按 DID 字典序，每个 DID 内版本序、同版本
        # active 后 revoked。leg_did 有 4 条，leg_did2 有 1 条。
        by_did = {leg_did: h1, leg_did2: h2}
        created_at_by_did = {
            leg_did: leg_created, leg_did2: leg_created2}
        expected_rows = []  # (did, key_version, action, status, updated_at)
        for did in sorted((leg_did, leg_did2)):
            expected_rows.append(
                (did, 1, "did.created", "active",
                 created_at_by_did[did])
            )
            if did == leg_did:
                # v1 revoked 的 updated_at 取自实际补录值（revoked_at）
                expected_rows.append(
                    (did, 1, "key.revoked", "revoked",
                     by_did[did]["events"][1]["updated_at"])
                )
                expected_rows.append(
                    (did, 2, "key.rotated", "active", None)
                )
                expected_rows.append(
                    (did, 3, "key.rotated", "active", None)
                )
        # 按补录后的全局 cursor 顺序拼接实际行
        merged = []
        for did in (leg_did, leg_did2):
            for e in by_did[did]["events"]:
                merged.append((e["cursor"], did, e["key_version"],
                               e["action"], e["status"], e["updated_at"],
                               e["audit_seq"], e["audit_timestamp"]))
        merged.sort(key=lambda row: row[0])
        ok_compat = (
            len(merged) == 5
            and [row[0] for row in merged] == [1, 2, 3, 4, 5]
            and all(row[6] is None and row[7] is None for row in merged)
            and [
                (row[1], row[2], row[3], row[4], row[5]) for row in merged
            ]
            == expected_rows
        )
        check("旧状态补录：DID 序、版本序、active 后 revoked；v1 取 "
              "created_at、其余 active=null、revoked 取 revoked_at、"
              "audit=null、cursor 连续", ok_compat)
        compat_cursors_a = [e["cursor"] for e in h1["events"]]
        compat_cursors_b = [e["cursor"] for e in h2["events"]]

        # 吊销历史补录与生命周期补录游标互不影响（各自独立）
        st, ra = _http(
            "GET", f"{lbase}/v1/dids/{leg_did}/keys/revocations", headers=L)
        check("吊销历史补录游标与生命周期隔离",
              st == 200 and [e["cursor"] for e in ra["events"]] == [1])
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # 无写操作再重启：补录 cursor 重建为相同值
    lp = start_server(PORT + 1, legacy_path)
    try:
        st, h1 = _http(
            "GET", f"{lbase}/v1/dids/{leg_did}/keys/history", headers=L)
        st2, h2 = _http(
            "GET", f"{lbase}/v1/dids/{leg_did2}/keys/history", headers=L)
        check(
            "无写重启补录 cursor 稳定",
            st == 200 and st2 == 200
            and [e["cursor"] for e in h1["events"]] == compat_cursors_a
            and [e["cursor"] for e in h2["events"]] == compat_cursors_b,
        )
        # 新轮换事件在补录最大值之后接续
        st, _ = _http("POST", f"{lbase}/v1/dids/{leg_did2}/keys/rotate",
                      {"key_handle": "leg-b2"}, headers=L)
        assert st == 200
        st, h2 = _http(
            "GET", f"{lbase}/v1/dids/{leg_did2}/keys/history", headers=L)
        max_compat = max(compat_cursors_a + compat_cursors_b)
        check("新事件 cursor 在补录项之后接续且关联审计",
              st == 200 and h2["events"][-1]["cursor"] == max_compat + 1
              and h2["events"][-1]["action"] == "key.rotated"
              and h2["events"][-1]["audit_seq"] is not None)
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # ---- 12. 直连 store：落盘失败全回滚（新建/轮换/吊销） ----
    from vcbackend.store import VCStore

    direct_path = tempfile.mktemp(suffix=".json")
    store = VCStore(direct_path)

    def _boom():
        raise OSError("模拟落盘失败")

    # 新建失败：无 DID、无历史、游标未前进、无审计
    store._save_locked = _boom  # type: ignore[assignment]
    raised = False
    try:
        store.create_did("dt", "example", "rollback-new")
    except OSError:
        raised = True
    check("落盘失败时新建抛错", raised)
    check("新建回滚：租户桶无该 DID 且无生命周期事件",
          "rollback-new" not in [
              r.get("submitted_public_key")
              for r in store._tenants.get("dt", {}).get("dids", {}).values()
          ])
    check("新建回滚：生命周期游标未前进",
          store._key_history_cursors.get("dt", 0) == 0)
    check("新建回滚：不记审计",
          all(e.action != "did.created"
              for e in store.list_audit("dt", 0, 200)[0]))

    del store._save_locked
    d = store.create_did("dt", "example", "rollback-kh")
    cursors_after_create = list(store._key_history_cursors.values())

    # 轮换失败
    store._save_locked = _boom  # type: ignore[assignment]
    raised = False
    try:
        store.rotate_key("dt", d.did, "rollback-kh2")
    except OSError:
        raised = True
    check("落盘失败时轮换抛错", raised)
    rec = store.get_did("dt", d.did)
    events, _ = store.list_key_history("dt", d.did, 0, 50)
    check("轮换回滚：版本不变、历史仅 v1、游标不前进",
          rec.key_version == 1 and len(events) == 1
          and list(store._key_history_cursors.values())
          == cursors_after_create
          and all(e.action != "key.rotated"
                  for e in store.list_audit("dt", 0, 200)[0]))

    # 吊销失败（先正常轮换）
    del store._save_locked
    store.rotate_key("dt", d.did, "rollback-kh2")
    store._save_locked = _boom  # type: ignore[assignment]
    raised = False
    try:
        store.revoke_key_version("dt", d.did, 1, reason="回滚吊销")
    except OSError:
        raised = True
    check("落盘失败时吊销抛错", raised)
    status = store.get_key_version_status("dt", d.did, 1)
    events, _ = store.list_key_history("dt", d.did, 0, 50)
    rev_events, _ = store.list_key_revocations("dt", d.did, 0, 50)
    check(
        "吊销回滚：版本仍 active、两类历史均无 revoked、游标不前进",
        status.status == "active"
        and [e.action for e in events] == ["did.created", "key.rotated"]
        and rev_events == []
        and all(e.action != "key.revoked"
                for e in store.list_audit("dt", 0, 200)[0]),
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
    print("密钥生命周期历史测试全部通过 ✔")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
