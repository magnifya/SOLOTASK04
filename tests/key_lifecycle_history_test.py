#!/usr/bin/env python3
"""DID 密钥生命周期历史（只读）端到端测试。

覆盖 GET /v1/dids/{did}/keys/history?limit=&after=：
- 200 响应恰含 did、events、next_after；事件恰含
  {key_version,key_handle,public_key,action,status,updated_at,
  audit_seq,audit_timestamp,cursor}，按 cursor 升序，仅含公钥（禁止
  私钥）；
- 新建版本追加 active：v1 为 did.created（updated_at 取 created_at），
  轮换为 key.rotated（updated_at 取轮换成功时刻）；首次吊销追加
  revoked/key.revoked 且与吊销 updated_at、审计 timestamp 同秒；
  重复吊销/失败/幂等创建不追加，active 历史不改写；
- audit_seq/audit_timestamp 关联对应审计事件，audit_timestamp 与
  updated_at 为同一 Unix 秒；
- cursor 租户内跨 DID 持久递增、租户间各自从 1 计起，并与吊销历史
  （keys/revocations）游标空间隔离；
- limit/after 分页规则与 keys/revocations 一致，空页 next_after=after，
  各类非法参数 400；未知/跨租户 DID 404，显式空租户头 400，缺省
  default；
- 纯只读不记审计；跨重启事件与 cursor 稳定；
- 旧历史按 DID 序、版本序、同版本 active 后 revoked 补齐：v1 active
  取 created_at，其余 active 的 updated_at 为 null，revoked 取
  revoked_at 或 null，迁移项 audit 为 null；无写重启 cursor 稳定；
- 新建/轮换/吊销变更与历史、游标、审计同锁原子落盘，失败全回滚。

直接运行：python3 tests/key_lifecycle_history_test.py
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PORT = 8987
Z_RE = __import__("re").compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

HISTORY_FIELDS = {"did", "events", "next_after"}
EVENT_FIELDS = {
    "key_version", "key_handle", "public_key", "action", "status",
    "updated_at", "audit_seq", "audit_timestamp", "cursor",
}
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


def unix_seconds(z_text):
    return int(
        datetime.strptime(z_text, "%Y-%m-%dT%H:%M:%SZ")
        .replace(tzinfo=timezone.utc).timestamp()
    )


def main():
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    store_path = tempfile.mktemp(suffix=".json")
    proc = start_server(PORT, store_path)
    base = f"http://127.0.0.1:{PORT}"
    T1 = {"X-Tenant-ID": "kl-a"}
    T2 = {"X-Tenant-ID": "kl-b"}

    def history(did, headers=None, query=None):
        url = f"{base}/v1/dids/{did}/keys/history"
        if query is not None:
            url += f"?{query}"
        return _http("GET", url, headers=headers)

    def revocations(did, headers=None):
        return _http(
            "GET", f"{base}/v1/dids/{did}/keys/revocations", headers=headers
        )

    def audit(headers=None, query="limit=200"):
        return _http("GET", f"{base}/v1/audit?{query}", headers=headers)

    try:
        # ---- 准备：T1 下 DID A（轮换 v2、吊销 v1），DID B（仅 v1）----
        st, a = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "kl-handle-a"},
                      headers=T1)
        assert st == 201, a
        did_a = a["did"]
        st, ag = _http("GET", f"{base}/v1/dids/{did_a}", headers=T1)
        assert st == 200, ag
        created_at_a = ag["created_at"]
        st, rot = _http("POST", f"{base}/v1/dids/{did_a}/keys/rotate",
                        {"key_handle": "kl-handle-a-v2"}, headers=T1)
        assert st == 200, rot
        st, rv = _http("POST", f"{base}/v1/dids/{did_a}/keys/1/revoke",
                       {"reason": "  v1 泄漏  "}, headers=T1)
        assert st == 200, rv
        revoked_at_a = rv["updated_at"]

        st, b = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "kl-handle-b"},
                      headers=T1)
        assert st == 201, b
        did_b = b["did"]
        st, bg = _http("GET", f"{base}/v1/dids/{did_b}", headers=T1)
        assert st == 200, bg
        created_at_b = bg["created_at"]

        st, c = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "kl-handle-c"},
                      headers=T2)
        assert st == 201, c
        did_c = c["did"]

        # ---- 1. 响应结构、字段、顺序、无私钥 ----
        st, h = history(did_a, headers=T1)
        ok = (
            st == 200 and set(h) == HISTORY_FIELDS and h["did"] == did_a
            and len(h["events"]) == 3
            and all(set(e) == EVENT_FIELDS for e in h["events"])
        )
        check("200 恰含 did/events/next_after，3 事件且各恰九字段", ok)
        cursors = [e["cursor"] for e in h["events"]] if ok else []
        check("事件按 cursor 升序", cursors == sorted(cursors)
              and len(set(cursors)) == 3)
        check("所有事件 public_key 均为公钥 PEM、无任何私钥标记",
              all("BEGIN PUBLIC KEY" in e["public_key"]
                  and PRIVATE_MARKER not in e["public_key"]
                  for e in h.get("events", [])))
        check("next_after 为末项 cursor",
              h.get("next_after") == cursors[-1] if cursors else False)

        e1, e2, e3 = h["events"]
        check(
            "v1 事件 did.created/active，句柄/版本/created_at 正确",
            e1["key_version"] == 1
            and e1["key_handle"] == "kl-handle-a"
            and e1["action"] == "did.created"
            and e1["status"] == "active"
            and e1["updated_at"] == created_at_a
            and bool(Z_RE.match(e1["updated_at"])),
        )
        check(
            "v2 事件 key.rotated/active，句柄/UTC 秒 Z 正确",
            e2["key_version"] == 2
            and e2["key_handle"] == "kl-handle-a-v2"
            and e2["action"] == "key.rotated"
            and e2["status"] == "active"
            and bool(Z_RE.match(e2["updated_at"] or "")),
        )
        check(
            "v1 吊销事件 key.revoked/revoked，时间为首次吊销时刻",
            e3["key_version"] == 1
            and e3["action"] == "key.revoked"
            and e3["status"] == "revoked"
            and e3["updated_at"] == revoked_at_a
            and e3["key_handle"] == "kl-handle-a"
            and "BEGIN PUBLIC KEY" in e3["public_key"],
        )

        # ---- 2. audit_seq/audit_timestamp 关联审计且严格同秒 ----
        st, au = audit(headers=T1)
        assert st == 200
        audit_by_seq = {ev["seq"]: ev for ev in au["events"]}
        linked_ok = True
        for event, want_action in (
            (e1, "did.created"), (e2, "key.rotated"), (e3, "key.revoked"),
        ):
            seq = event["audit_seq"]
            ev = audit_by_seq.get(seq)
            if (
                not isinstance(seq, int)
                or ev is None
                or ev["action"] != want_action
                or event["audit_timestamp"] != ev["timestamp"]
                or unix_seconds(event["updated_at"]) != ev["timestamp"]
            ):
                linked_ok = False
        check("audit_seq/audit_timestamp 关联审计且 updated_at 同 Unix 秒",
              linked_ok)

        # ---- 3. 重复吊销 / 幂等创建 / 失败路径不追加，active 不改写 ----
        active_before = [(e["key_version"], e["action"], e["updated_at"],
                          e["cursor"]) for e in h["events"]
                         if e["status"] == "active"]
        st, _ = _http("POST", f"{base}/v1/dids/{did_a}/keys/1/revoke",
                      {"reason": "另一个原因"}, headers=T1)
        assert st == 200
        st, _ = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "kl-handle-a"},
                      headers=T1)
        assert st == 201 or st == 200
        # 失败路径：吊销当前版本 409、未知 DID 404、非法 reason 400
        st, _ = _http("POST", f"{base}/v1/dids/{did_a}/keys/2/revoke",
                      {}, headers=T1)
        check("吊销当前版本 -> 409", st == 409)
        st, _ = _http("POST", f"{base}/v1/dids/did:example:00000000000000000000000000000000/keys/1/revoke",
                      {}, headers=T1)
        check("吊销未知 DID -> 404", st == 404)
        st, _ = _http("POST", f"{base}/v1/dids/{did_a}/keys/1/revoke",
                      {"reason": "   "}, headers=T1)
        check("对已吊销版本的非法 reason 被忽略仍 200（幂等）", st == 200)
        st, h2 = history(did_a, headers=T1)
        check("重复吊销/幂等创建/失败后事件数不变（仍 3 条）",
              st == 200 and len(h2["events"]) == 3)
        check("active 历史不改写（内容与 cursor 保持首次值）",
              [(e["key_version"], e["action"], e["updated_at"], e["cursor"])
               for e in h2["events"] if e["status"] == "active"]
              == active_before)
        check("revoked 事件仍为首次吊销时间",
              [e for e in h2["events"]
               if e["action"] == "key.revoked"][0]["updated_at"]
              == revoked_at_a)

        # 全新 DID 仅一条 v1 active
        st, hb = history(did_b, headers=T1)
        check(
            "新 DID 历史仅 v1 did.created 且取 created_at",
            st == 200 and len(hb["events"]) == 1
            and hb["events"][0]["action"] == "did.created"
            and hb["events"][0]["key_version"] == 1
            and hb["events"][0]["updated_at"] == created_at_b,
        )

        # ---- 4. cursor 租户内跨 DID 递增、与吊销历史隔离、租户间独立 ----
        cursor_a = [e["cursor"] for e in h2["events"]]
        cursor_b = hb["events"][0]["cursor"]
        check("租户内跨 DID cursor 单调递增（B 在 A 之后）",
              cursor_b > max(cursor_a))
        st, rc = revocations(did_a, headers=T1)
        check("生命周期与吊销历史游标空间隔离（吊销仅 1 条且 cursor 独立）",
              st == 200 and len(rc["events"]) == 1
              and rc["events"][0]["cursor"] == 1)
        st, hc = history(did_c, headers=T2)
        check("另一租户 cursor 从 1 重新计起",
              st == 200 and len(hc["events"]) == 1
              and hc["events"][0]["cursor"] == 1)
        st, _ = history(did_a, headers=T2)
        check("跨租户 DID 不可探测 -> 404", st == 404)
        st, _ = history(did_a, headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400)
        st, _ = history("did:example:00000000000000000000000000000000",
                        headers=T1)
        check("未知 DID -> 404", st == 404)
        # 缺省租户头 => default
        st, d0 = _http("POST", f"{base}/v1/dids",
                       {"method": "example", "public_key": "kl-default"})
        assert st == 201, d0
        st, h0 = history(d0["did"])
        check("缺省租户头按 default 且可查", st == 200
              and len(h0["events"]) == 1 and h0["events"][0]["cursor"] == 1)

        # ---- 5. 分页参数（沿用 keys/revocations）----
        st, page = history(did_a, headers=T1, query="limit=1")
        check("limit=1 返回 1 项且 next_after 为该项 cursor",
              st == 200 and len(page["events"]) == 1
              and page["events"][0]["cursor"] == cursor_a[0]
              and page["next_after"] == cursor_a[0])
        st, page = history(did_a, headers=T1,
                           query=f"limit=1&after={cursor_a[0]}")
        check("after 排除不大于其值的 cursor",
              st == 200 and len(page["events"]) == 1
              and page["events"][0]["cursor"] == cursor_a[1]
              and page["next_after"] == cursor_a[1])
        st, page = history(did_a, headers=T1, query="after=999999")
        check("空页 events=[] 且 next_after 等于 after",
              st == 200 and page["events"] == []
              and page["next_after"] == 999999)
        st, page = history(did_b, headers=T1, query="after=5")
        check("after=5 空页 next_after=5",
              st == 200 and page["events"] == []
              and page["next_after"] == 5)

        def p400(query, name):
            st, r = history(did_a, headers=T1, query=query)
            check(name, st == 400 and isinstance(r.get("error"), str)
                  and r["error"])

        p400("limit=0", "limit=0 -> 400")
        p400("limit=201", "limit=201 -> 400")
        p400("limit=1&limit=2", "重复 limit -> 400")
        p400("after=1&after=2", "重复 after -> 400")
        p400("limit=", "空 limit -> 400")
        p400("after=", "空 after -> 400")
        p400("limit=01%20", "limit 尾随空白 -> 400")
        p400("limit=1.5", "小数 limit -> 400")
        p400("limit=true", "布尔词 limit -> 400")
        p400("limit=-1", "符号 limit -> 400")
        p400("limit=%E0%A5%91", "Unicode 数字 limit -> 400")
        p400("after=-1", "负 after -> 400")
        p400("after=abc", "字母 after -> 400")

        # limit 默认 50：单 DID 事件少，显式构造多版本后仍一页返回
        for idx in range(3, 6):
            st, _ = _http(
                "POST", f"{base}/v1/dids/{did_a}/keys/rotate",
                {"key_handle": f"kl-handle-a-v{idx}"}, headers=T1,
            )
            assert st == 200
        st, hall = history(did_a, headers=T1)
        check("默认 limit=50 一页返回全部 6 条",
              st == 200 and len(hall["events"]) == 6
              and [e["cursor"] for e in hall["events"]]
              == sorted(e["cursor"] for e in hall["events"]))

        # ---- 6. 只读不记审计：查询前后 T1 审计条数一致 ----
        st, before = audit(headers=T1)
        n_before = len(before["events"])
        for query in ("", "limit=2", "after=1", "limit=1&after=2"):
            history(did_a, headers=T1, query=query)
        history(did_b, headers=T1)
        history("did:example:00000000000000000000000000000000", headers=T1)
        st, after_au = audit(headers=T1)
        check("历史查询为只读：审计条数不增加",
              len(after_au["events"]) == n_before)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 7. 跨重启：事件与 cursor 稳定，新版本接续递增 ----
    proc = start_server(PORT, store_path)
    try:
        st, h = history(did_a, headers=T1)
        saved_cursors = [e["cursor"] for e in h["events"]]
        check("重启后 A 的全部事件与 cursor 稳定",
              st == 200 and len(h["events"]) == 6
              and all(set(e) == EVENT_FIELDS for e in h["events"]))
        st, _ = _http("POST", f"{base}/v1/dids/{did_a}/keys/rotate",
                      {"key_handle": "kl-handle-a-v6"}, headers=T1)
        assert st == 200
        st, h = history(did_a, headers=T1)
        check("重启后新轮换 cursor 在旧值之后递增",
              len(h["events"]) == 7
              and h["events"][-1]["action"] == "key.rotated"
              and h["events"][-1]["cursor"] == max(saved_cursors) + 1)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 8. 旧状态迁移：补录顺序、updated_at、audit=null、cursor 稳定 ----
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
        assert st == 200, lg
        leg_created = lg["created_at"]
        _http("POST", f"{lbase}/v1/dids/{leg_did}/keys/rotate",
              {"key_handle": "leg-a2"}, headers=L)
        _http("POST", f"{lbase}/v1/dids/{leg_did}/keys/1/revoke",
              {"reason": "旧吊销"}, headers=L)
        _http("POST", f"{lbase}/v1/dids/{leg_did}/keys/rotate",
              {"key_handle": "leg-a3"}, headers=L)
        # v3 吊销后手工构造“无 revoked_at”的极端旧状态
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    raw = json.load(open(legacy_path, encoding="utf-8"))
    lbucket = raw["tenants"]["legacy"]
    # 第二个 DID（字典序靠后）：仅 v1 且无吊销，验证 DID 间排序
    second_did = "did:example:ffffffffffffffffffffffffffffffff"
    lbucket["dids"][second_did] = {
        "method": "example",
        "public_key": "PUB-Z",
        "submitted_public_key": "leg-z",
        "created_at": "2025-05-05T00:00:00Z",
        "private_key_pem": "priv-z",
        "key_mode": "server",
        "key_handle": "leg-z",
        "key_version": 1,
        "key_history": [
            {"version": 1, "key_handle": "leg-z",
             "public_key": "PUB-Z", "private_key_pem": "priv-z"}
        ],
    }
    # 极端旧状态：v2 已吊销但缺 revoked_at/revoke_reason
    for entry in lbucket["dids"][leg_did]["key_history"]:
        if entry["version"] == 2:
            entry["status"] = "revoked"
            entry.pop("revoked_at", None)
            entry.pop("revoke_reason", None)
    # 删除生命周期命名空间与游标，模拟旧版本状态文件
    lbucket["key_lifecycle"] = {}
    raw.pop("key_lifecycle_cursors", None)
    with open(legacy_path, "w", encoding="utf-8") as fh:
        json.dump(raw, fh)

    lp = start_server(PORT + 1, legacy_path)
    try:
        st, h = _http(
            "GET", f"{lbase}/v1/dids/{leg_did}/keys/history", headers=L
        )
        compat = None
        ok_compat = False
        if st == 200 and len(h["events"]) == 5:
            evs = h["events"]
            compat = evs
            # v1 active(did.created,created_at) -> v1 revoked ->
            # v2 active(key.rotated,null) -> v2 revoked(revoked_at null)
            # -> v3 active(key.rotated,null)
            ok_compat = (
                [(e["key_version"], e["action"], e["status"]) for e in evs]
                == [
                    (1, "did.created", "active"),
                    (1, "key.revoked", "revoked"),
                    (2, "key.rotated", "active"),
                    (2, "key.revoked", "revoked"),
                    (3, "key.rotated", "active"),
                ]
                and evs[0]["updated_at"] == leg_created
                and evs[1]["updated_at"] is not None
                and bool(Z_RE.match(evs[1]["updated_at"]))
                and evs[2]["updated_at"] is None
                and evs[3]["updated_at"] is None
                and evs[4]["updated_at"] is None
                and all(e["audit_seq"] is None
                        and e["audit_timestamp"] is None for e in evs)
                and [e["cursor"] for e in evs] == [1, 2, 3, 4, 5]
                and all(PRIVATE_MARKER not in e["public_key"] for e in evs)
            )
        check("旧历史按版本序、active 后 revoked 补齐且字段规则正确",
              ok_compat)

        # DID 字典序：第二个 DID 的 v1 补录 cursor 为 6
        st, hz = _http(
            "GET", f"{lbase}/v1/dids/{second_did}/keys/history", headers=L
        )
        check("DID 字典序补录：后一 DID 的 cursor 接续（6）",
              st == 200 and len(hz["events"]) == 1
              and hz["events"][0]["updated_at"] == "2025-05-05T00:00:00Z"
              and hz["events"][0]["cursor"] == 6
              and hz["events"][0]["audit_seq"] is None)

        saved_compat_cursors = [e["cursor"] for e in compat]
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # 不触发任何写操作直接重启：cursor 必须重建为相同值
    lp = start_server(PORT + 1, legacy_path)
    try:
        st, h = _http(
            "GET", f"{lbase}/v1/dids/{leg_did}/keys/history", headers=L
        )
        check("无写重启后补录 cursor 稳定",
              st == 200
              and [e["cursor"] for e in h["events"]]
              == saved_compat_cursors)
        # GET 不触发落盘
        raw2 = json.load(open(legacy_path, encoding="utf-8"))
        check("只读查询不触发落盘（内存补录未写入）",
              "key_lifecycle_cursors" not in raw2
              and raw2["tenants"]["legacy"]["key_lifecycle"] == {})
        # 触发一次写（吊销 v3 前需先轮换到 v4），补录随原子写落盘，
        # 新事件 cursor 接续
        st, _ = _http("POST", f"{lbase}/v1/dids/{leg_did}/keys/rotate",
                      {"key_handle": "leg-a4"}, headers=L)
        assert st == 200
        st, _ = _http("POST", f"{lbase}/v1/dids/{leg_did}/keys/3/revoke",
                      {"reason": "新吊销"}, headers=L)
        assert st == 200
        st, h = _http(
            "GET", f"{lbase}/v1/dids/{leg_did}/keys/history", headers=L
        )
        check("新事件在补录 cursor 之后接续（7/8）并关联审计",
              st == 200 and len(h["events"]) == 7
              and [e["cursor"] for e in h["events"]][-2:] == [7, 8]
              and h["events"][-2]["action"] == "key.rotated"
              and h["events"][-1]["action"] == "key.revoked"
              and h["events"][-1]["audit_seq"] is not None
              and h["events"][-1]["audit_timestamp"] is not None
              and unix_seconds(h["events"][-1]["updated_at"])
              == h["events"][-1]["audit_timestamp"])
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # ---- 9. 直连 store：原子落盘失败时历史/游标/审计全回滚 ----
    from vcbackend.store import VCStore

    direct_path = tempfile.mktemp(suffix=".json")
    store = VCStore(direct_path)

    def _boom():
        raise OSError("模拟落盘失败")

    # 轮换落盘失败：无 active 事件、cursor 不动、审计不记
    d = store.create_did("rb", "example", "rb-handle")
    store._save_locked = _boom  # type: ignore[assignment]
    raised = False
    try:
        store.rotate_key("rb", d.did, "rb-handle-v2")
    except OSError:
        raised = True
    check("轮换落盘失败抛错", raised)
    got = store.get_did("rb", d.did)
    check("回滚后当前版本仍为 1", got.key_version == 1)
    events, _ = store.list_key_lifecycle("rb", d.did, 0, 50)
    check("回滚后生命周期仅 v1 一条",
          len(events) == 1 and events[0].action == "did.created")
    check("回滚后生命周期游标未前进",
          store._key_lifecycle_cursors.get("rb", 0) == 1)  # noqa: SLF001
    au = store.list_audit("rb", 0, 200)[0]
    check("回滚后不记 key.rotated 审计",
          all(e.action != "key.rotated" for e in au))

    del store._save_locked
    store.rotate_key("rb", d.did, "rb-handle-v2")

    # 吊销落盘失败：revoked 事件/吊销历史/游标/审计全部回滚
    store._save_locked = _boom  # type: ignore[assignment]
    raised = False
    try:
        store.revoke_key_version("rb", d.did, 1, reason="吊销回滚测试")
    except OSError:
        raised = True
    check("吊销落盘失败抛错", raised)
    rec = store.get_key_version_status("rb", d.did, 1)
    check("回滚后 v1 仍 active", rec.status == "active")
    events, _ = store.list_key_lifecycle("rb", d.did, 0, 50)
    check("回滚后无 revoked 生命周期事件",
          all(e.action != "key.revoked" for e in events)
          and len(events) == 2)
    rev_events, _ = store.list_key_revocations("rb", d.did, 0, 50)
    check("回滚后吊销历史同样为空", rev_events == [])
    check("回滚后两类游标均停在 2",
          store._key_lifecycle_cursors.get("rb", 0) == 2  # noqa: SLF001
          and store._key_revocation_cursors.get("rb", 0) == 0)  # noqa: SLF001
    au = store.list_audit("rb", 0, 200)[0]
    check("回滚后不记 key.revoked 审计",
          all(e.action != "key.revoked" for e in au))

    # 恢复后吊销成功并跨进程持久化
    del store._save_locked
    rec = store.revoke_key_version("rb", d.did, 1, reason="吊销回滚测试")
    check("恢复后吊销成功", rec.status == "revoked")
    events, _ = store.list_key_lifecycle("rb", d.did, 0, 50)
    check("恢复后生命周期含 revoked 且 cursor=3",
          len(events) == 3 and events[-1].action == "key.revoked"
          and events[-1].cursor == 3)

    dp = start_server(PORT + 2, direct_path)
    try:
        db = f"http://127.0.0.1:{PORT + 2}"
        st, h = _http("GET", f"{db}/v1/dids/{d.did}/keys/history",
                      headers={"X-Tenant-ID": "rb"})
        check("回滚场景重启后生命周期与 cursor 一致",
              st == 200 and len(h["events"]) == 3
              and [e["cursor"] for e in h["events"]] == [1, 2, 3]
              and [e["action"] for e in h["events"]]
              == ["did.created", "key.rotated", "key.revoked"])
    finally:
        dp.terminate()
        dp.wait(timeout=10)

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
