#!/usr/bin/env python3
"""外部凭证状态历史查询 GET
/v1/trust/credential-status/{credential_id}/history?issuer_did=...&limit=&after=
的端到端测试。

覆盖：
- 仅首次同步与 updated_at 严格更新追加历史；重放、更早日、同时间冲突、
  验签/字段失败均不追加；
- 事件按 updated_at 升序、同值按 cursor；每项含 status、reason、
  updated_at、issuer_key_version、audit_seq、audit_timestamp、cursor，
  audit 关联触发追加的同步事件，兼容项为 null；
- cursor 为持久化正整数并按追加递增；after 排除 ≤ 其值记录，
  next_after 为末项 cursor，空页保持 after；
- issuer_did 唯一非空（缺失/重复/空值 400），limit 默认 50、1–200
  ASCII 十进制，after 默认 0、非负 ASCII 十进制，重复/非法 400；
- 响应含 issuer_did、credential_id、events、next_after；租户隔离、
  只读（GET 不记审计）；
- 旧状态缺历史时补兼容项（cursor 持久化、audit 字段 null）；
- 历史/状态/审计原子落盘，重启保留，cursor 接续；不改变同步语义。

直接运行：python3 tests/trust_credential_status_history_test.py
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
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402

SYNC_PATH = "/v1/trust/credential-status/sync"


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


def wait_up(proc, port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
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


def start(port, store_path):
    env = dict(os.environ, VCBACKEND_STORE=store_path)
    return subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def main():
    port = 8963
    store_path = tempfile.mktemp(suffix=".json")
    proc = start(port, store_path)
    base = f"http://127.0.0.1:{port}"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def sync(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{SYNC_PATH}", payload,
                     headers=headers, raw=raw)

    def history(credential_id, headers=None, query=None):
        url = (f"{base}/v1/trust/credential-status/"
               f"{quote(credential_id)}/history")
        if query is not None:
            url += f"?{query}"
        return _http("GET", url, headers=headers)

    def audit_events(headers):
        st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=headers)
        assert st == 200, r
        return r["events"]

    try:
        assert wait_up(proc, port), "服务启动超时"

        T1 = {"X-Tenant-ID": "h-a"}
        T2 = {"X-Tenant-ID": "h-b"}

        priv1, pub1 = gen_keypair()
        priv2, pub2 = gen_keypair()
        did = "did:web:issuer-history.example"
        cred_id = "vc_hist_1"

        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1}, headers=T1,
        )
        check("注册锚点 v1 -> 201", st == 201)
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub2, "key_version": 2}, headers=T1,
        )
        check("注册锚点 v2 -> 201", st == 201)

        def make_body(credential_id=cred_id, status="active",
                      updated="2026-09-01T00:00:00Z", version=1,
                      reason=_UNSET, issuer=did):
            b = {
                "issuer_did": issuer,
                "credential_id": credential_id,
                "status": status,
                "updated_at": updated,
                "issuer_key_version": version,
            }
            if reason is not _UNSET:
                b["reason"] = reason
            return b

        def signed(body, priv=priv1):
            return {"body": body, "signature": crypto.sign(body, priv)}

        def n_synced_audit():
            return sum(
                1 for e in audit_events(T1)
                if e["action"] == "trust.credential.status.synced"
            )

        # ---- 1. 首次同步：追加一条历史，audit 关联同步事件 ----
        st, r = sync(signed(make_body()), headers=T1)
        check("首次同步 -> 201", st == 201)
        st, h = history(cred_id, headers=T1,
                        query=f"issuer_did={quote(did)}")
        synced = [
            e for e in audit_events(T1)
            if e["action"] == "trust.credential.status.synced"
        ]
        check(
            "首次同步历史仅一条且字段齐全，audit 关联同步事件",
            st == 200
            and set(h) == {"issuer_did", "credential_id", "events",
                           "next_after"}
            and h["issuer_did"] == did
            and h["credential_id"] == cred_id
            and len(h["events"]) == 1
            and h["events"][0] == {
                "status": "active",
                "reason": None,
                "updated_at": "2026-09-01T00:00:00Z",
                "issuer_key_version": 1,
                "audit_seq": synced[0]["seq"],
                "audit_timestamp": synced[0]["timestamp"],
                "cursor": 1,
            },
        )

        # ---- 2. 重放 / 更早日 / 同时间冲突 / 验签失败 / 字段 400
        #         均不追加 ----
        st, _ = sync(signed(make_body()), headers=T1)
        check("相同重放 -> 200", st == 200)
        st, _ = sync(signed(
            make_body(updated="2020-01-01T00:00:00Z")
        ), headers=T1)
        check("更早日 -> 200 被忽略", st == 200)
        st, _ = sync(signed(
            make_body(status="revoked"), priv1
        ), headers=T1)
        check("同时间不同内容 -> 409", st == 409)
        # 锚点缺失（T2 无锚点）：200 valid:false
        st, r = sync(signed(
            make_body(status="revoked", updated="2026-09-02T00:00:00Z")
        ), headers=T2)
        check("无锚点 -> 200 valid:false",
              st == 200 and r.get("valid") is False)
        # 字段非法 -> 400
        st, r = sync({"body": {}, "signature": "x"}, headers=T1)
        check("字段非法 -> 400", st == 400)
        st, h = history(cred_id, headers=T1,
                        query=f"issuer_did={quote(did)}")
        check(
            "重放/更早/冲突/验签失败/400 均不追加",
            len(h["events"]) == 1 and h["events"][0]["cursor"] == 1,
        )

        # ---- 3. 严格更新追加；updated_at 升序；cursor 按追加递增 ----
        st, r = sync(signed(
            make_body(status="unknown", updated="2026-09-02T00:00:00Z"),
            priv1,
        ), headers=T1)
        check("严格更新（09-02 unknown）-> 200", st == 200)
        st, r = sync(signed(
            make_body(status="revoked", updated="2026-09-03T00:00:00Z",
                      version=2, reason="原因 B"),
            priv2,
        ), headers=T1)
        check("严格更新（09-03 revoked）-> 200", st == 200)
        st, h = history(cred_id, headers=T1,
                        query=f"issuer_did={quote(did)}&limit=200")
        events = h["events"]
        check(
            "历史按 updated_at 升序、cursor 按追加递增（1/2/3）",
            [e["updated_at"] for e in events] == [
                "2026-09-01T00:00:00Z",
                "2026-09-02T00:00:00Z",
                "2026-09-03T00:00:00Z",
            ]
            and [e["cursor"] for e in events] == [1, 2, 3],
        )
        check(
            "各事件 audit_seq/timestamp 关联对应同步事件，字段正确",
            all(e["audit_seq"] is not None and e["audit_timestamp"]
                is not None for e in events)
            and events[1]["status"] == "unknown"
            and events[1]["reason"] is None
            and events[1]["issuer_key_version"] == 1
            and events[2]["status"] == "revoked"
            and events[2]["reason"] == "原因 B"
            and events[2]["issuer_key_version"] == 2,
        )
        # audit_seq 指向的审计事件确为同步事件且 resource_id 匹配
        audit_by_seq = {e["seq"]: e for e in audit_events(T1)}
        check(
            "audit_seq 关联的审计事件为同步事件",
            all(
                audit_by_seq[e["audit_seq"]]["action"]
                == "trust.credential.status.synced"
                and audit_by_seq[e["audit_seq"]]["resource_id"]
                == f"{did}#{cred_id}"
                and audit_by_seq[e["audit_seq"]]["timestamp"]
                == e["audit_timestamp"]
                for e in events
            ),
        )

        # ---- 4. 分页：limit/after/next_after/空页 ----
        st, p1 = history(cred_id, headers=T1,
                         query=f"issuer_did={quote(did)}&limit=2")
        check("limit=2 返回前两条，next_after 为末项 cursor",
              st == 200 and [e["cursor"] for e in p1["events"]] == [1, 2]
              and p1["next_after"] == 2)
        st, p2 = history(
            cred_id, headers=T1,
            query=f"issuer_did={quote(did)}&limit=2&after={p1['next_after']}",
        )
        check("after 排除 ≤ 其值记录，返回剩余",
              st == 200 and [e["cursor"] for e in p2["events"]] == [3]
              and p2["next_after"] == 3)
        st, p3 = history(
            cred_id, headers=T1,
            query=f"issuer_did={quote(did)}&after={p2['next_after']}",
        )
        check("空页 events 为空且 next_after 保持 after",
              st == 200 and p3["events"] == [] and p3["next_after"] == 3)
        st, p0 = history(cred_id, headers=T1,
                         query=f"issuer_did={quote(did)}&after=0")
        check("after 默认/显式 0 返回全部",
              st == 200 and len(p0["events"]) == 3)
        st, pd = history(cred_id, headers=T1,
                         query=f"issuer_did={quote(did)}")
        check("limit 默认 50（3 条一页全返回）",
              st == 200 and len(pd["events"]) == 3)
        check("cursor 均为正整数",
              all(isinstance(e["cursor"], int) and e["cursor"] >= 1
                  for e in pd["events"]))

        # ---- 5. 参数校验 400 ----
        def expect_400(name, query):
            st, r = history(cred_id, headers=T1, query=query)
            check(name, st == 400 and isinstance(r.get("error"), str)
                  and r["error"])

        expect_400("缺 issuer_did", "limit=10")
        expect_400("重复 issuer_did", "issuer_did=a&issuer_did=b")
        expect_400("空 issuer_did", "issuer_did=")
        expect_400("limit=0", f"issuer_did={quote(did)}&limit=0")
        expect_400("limit=201", f"issuer_did={quote(did)}&limit=201")
        expect_400("limit=-1", f"issuer_did={quote(did)}&limit=-1")
        expect_400("limit=1.5", f"issuer_did={quote(did)}&limit=1.5")
        expect_400("limit=true", f"issuer_did={quote(did)}&limit=true")
        expect_400("limit 空白", f"issuer_did={quote(did)}&limit=%20")
        expect_400("重复 limit",
                   f"issuer_did={quote(did)}&limit=1&limit=2")
        expect_400("after=-1", f"issuer_did={quote(did)}&after=-1")
        expect_400("after=x", f"issuer_did={quote(did)}&after=x")
        expect_400("after=1.0", f"issuer_did={quote(did)}&after=1.0")
        expect_400("after 空白", f"issuer_did={quote(did)}&after=%20")
        expect_400("重复 after",
                   f"issuer_did={quote(did)}&after=0&after=1")
        # 未知参数不影响（仅按已知参数解析）—— 这里确认不因此 400/500
        st, r = history(
            cred_id, headers=T1,
            query=f"issuer_did={quote(did)}&foo=bar",
        )
        check("无关查询参数不报错", st == 200)

        # ---- 6. 404：未同步双键 / 跨租户不可探测 ----
        st, _ = history("vc_not_synced", headers=T1,
                        query=f"issuer_did={quote(did)}")
        check("未同步凭证 -> 404", st == 404)
        st, _ = history(cred_id, headers=T1,
                        query="issuer_did=did:web:other.example")
        check("未知 issuer 双键 -> 404", st == 404)
        st, _ = history(cred_id, headers=T2,
                        query=f"issuer_did={quote(did)}")
        check("跨租户不可探测 -> 404", st == 404)

        # ---- 7. 只读：GET history 不记审计 ----
        n_before = len(audit_events(T1))
        for _ in range(3):
            history(cred_id, headers=T1,
                    query=f"issuer_did={quote(did)}")
        check("只读：GET history 不记审计",
              len(audit_events(T1)) == n_before)

        # ---- 8. 跨租户独立历史（T2 注册锚点并同步同双键）----
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1}, headers=T2,
        )
        check("T2 注册自己的锚点 -> 201", st == 201)
        st, _ = sync(signed(
            make_body(status="revoked", updated="2026-09-10T00:00:00Z")
        ), headers=T2)
        check("T2 独立首次同步 -> 201", st == 201)
        st, h1 = history(cred_id, headers=T1,
                         query=f"issuer_did={quote(did)}")
        st, h2 = history(cred_id, headers=T2,
                         query=f"issuer_did={quote(did)}")
        check(
            "历史按租户隔离（各自条数/内容独立，cursor 全局递增）",
            len(h1["events"]) == 3
            and [e["updated_at"] for e in h1["events"]][-1]
            == "2026-09-03T00:00:00Z"
            and len(h2["events"]) == 1
            and h2["events"][0]["updated_at"] == "2026-09-10T00:00:00Z"
            and h2["events"][0]["cursor"] > h1["events"][-1]["cursor"],
        )

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 9. 重启保留：历史、cursor、next_after 接续 ----
    proc = start(port, store_path)
    try:
        assert wait_up(proc, port), "服务重启超时"
        T1 = {"X-Tenant-ID": "h-a"}
        st, h = history(cred_id, headers=T1,
                        query=f"issuer_did={quote(did)}&limit=200")
        check("重启后历史保留且顺序不变",
              st == 200 and [e["cursor"] for e in h["events"]] == [1, 2, 3]
              and h["next_after"] == 3)
        check("重启后 audit 关联保留",
              all(e["audit_seq"] is not None for e in h["events"]))
        # 再做一次严格更新：cursor 在全局最大值后接续（本凭证前三条为
        # 1/2/3，T2 首次同步占用 4，故新条 cursor 为 5），持久化递增。
        st, r = sync(signed(
            make_body(status="revoked", updated="2026-09-20T00:00:00Z",
                      version=2, reason="重启后更新"),
            priv2,
        ), headers=T1)
        check("重启后严格更新 -> 200", st == 200)
        st, h = history(cred_id, headers=T1,
                        query=f"issuer_did={quote(did)}&limit=200")
        check(
            "重启后追加的 cursor 持久化接续全局递增",
            [e["cursor"] for e in h["events"]] == [1, 2, 3, 5]
            and h["events"][-1]["reason"] == "重启后更新",
        )
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 10. 旧状态缺历史：补兼容项（cursor 持久化、audit null）----
    legacy_path = tempfile.mktemp(suffix=".json")
    legacy_did = "did:web:legacy.example"
    legacy_cred = "vc_legacy_1"
    legacy_store = {
        "tenants": {
            "default": {
                "dids": {},
                "credentials": {},
                "presentations": {},
                "proofs": {},
                "trust_anchors": {},
                "credential_status_sync": {
                    legacy_did: {
                        legacy_cred: {
                            "status": "revoked",
                            "updated_at": "2026-08-01T00:00:00Z",
                            "issuer_key_version": 1,
                            "reason": "旧状态原因",
                        }
                    }
                },
            }
        },
        "audit": [],
        "audit_seq": 0,
    }
    with open(legacy_path, "w", encoding="utf-8") as fh:
        json.dump(legacy_store, fh)
    proc = start(port + 1, legacy_path)
    try:
        assert wait_up(proc, port + 1), "兼容服务启动超时"
        base2 = f"http://127.0.0.1:{port + 1}"

        def hist2(query):
            return _http(
                "GET",
                f"{base2}/v1/trust/credential-status/"
                f"{quote(legacy_cred)}/history?{query}",
            )

        st, h = hist2(f"issuer_did={quote(legacy_did)}")
        check(
            "旧状态补一条兼容项：audit 字段 null、cursor 为正整数",
            st == 200 and len(h["events"]) == 1
            and h["events"][0] == {
                "status": "revoked",
                "reason": "旧状态原因",
                "updated_at": "2026-08-01T00:00:00Z",
                "issuer_key_version": 1,
                "audit_seq": None,
                "audit_timestamp": None,
                "cursor": 1,
            },
        )
        # 兼容项也按 cursor 返回，after=1 后为空页且保持游标
        st, h2 = hist2(f"issuer_did={quote(legacy_did)}&after=1")
        check("audit_seq 为 null 的兼容项按 cursor 分页",
              st == 200 and h2["events"] == [] and h2["next_after"] == 1)
        check("兼容项 audit_seq null 仍可在第一页取到",
              hist2(f"issuer_did={quote(legacy_did)}&after=0")[1]
              ["events"][0]["audit_seq"] is None)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 再重启：兼容项 cursor 已持久化，保持为 1 且不重复补
    proc = start(port + 1, legacy_path)
    try:
        assert wait_up(proc, port + 1), "兼容服务重启超时"
        base2 = f"http://127.0.0.1:{port + 1}"
        st, h = _http(
            "GET",
            f"{base2}/v1/trust/credential-status/"
            f"{quote(legacy_cred)}/history?issuer_did={quote(legacy_did)}",
        )
        check(
            "兼容项跨重启保留、cursor 稳定且不重复补",
            st == 200 and len(h["events"]) == 1
            and h["events"][0]["cursor"] == 1
            and h["events"][0]["audit_seq"] is None,
        )
        with open(legacy_path, "r", encoding="utf-8") as fh:
            on_disk = json.load(fh)
        check(
            "兼容项已落盘（历史与全局 cursor 持久化）",
            on_disk.get("credential_status_history_seq") == 1
            and on_disk["tenants"]["default"]["credential_status_history"]
            [legacy_did][legacy_cred][0]["audit_seq"] is None,
        )
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        if os.path.exists(legacy_path):
            os.remove(legacy_path)
        if os.path.exists(store_path):
            os.remove(store_path)

    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("全部通过")
    return 0


_UNSET = object()

if __name__ == "__main__":
    raise SystemExit(main())
