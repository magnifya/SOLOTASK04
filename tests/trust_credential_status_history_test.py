#!/usr/bin/env python3
"""GET /v1/trust/credential-status/{credential_id}/history 只读历史查询
的端到端测试（含与同步语义的兼容）。

直接运行：python3 tests/trust_credential_status_history_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
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


def start_server(port, env):
    return subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


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


def main():
    port = 8961
    store_path = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store_path)
    proc = start_server(port, env)
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

    try:
        assert wait_up(proc, port), "服务启动超时"

        T1 = {"X-Tenant-ID": "hist-a"}
        T2 = {"X-Tenant-ID": "hist-b"}

        priv1, pub1 = gen_keypair()
        priv2, pub2 = gen_keypair()
        did = "did:web:issuer-hist.example"
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
                      updated="2026-09-21T00:00:00Z", version=1,
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

        did_q = f"issuer_did={quote(did)}"

        # ---- 1. 首次同步后历史恰一项，字段齐全，关联审计 ----
        st, r = sync(signed(make_body()), headers=T1)
        check("首次同步 -> 201", st == 201)
        st, audit0 = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        sync_events = [
            e for e in audit0["events"]
            if e["action"] == "trust.credential.status.synced"
        ]
        st, h = history(cred_id, headers=T1, query=did_q)
        first_cursor = None
        ok_first = False
        if st == 200 and set(h) == {
            "issuer_did", "credential_id", "events", "next_after"
        }:
            if (h["issuer_did"] == did and h["credential_id"] == cred_id
                    and len(h["events"]) == 1):
                ev = h["events"][0]
                first_cursor = ev["cursor"]
                linked = sync_events[-1]
                ok_first = (
                    set(ev) == {
                        "status", "reason", "updated_at",
                        "issuer_key_version", "audit_seq",
                        "audit_timestamp", "cursor",
                    }
                    and ev["status"] == "active"
                    and ev["reason"] is None
                    and ev["updated_at"] == "2026-09-21T00:00:00Z"
                    and ev["issuer_key_version"] == 1
                    and isinstance(ev["cursor"], int) and ev["cursor"] >= 1
                    and ev["audit_seq"] == linked["seq"]
                    and ev["audit_timestamp"] == linked["timestamp"]
                    and h["next_after"] == ev["cursor"]
                )
        check("首次历史项字段齐全且关联同步审计", ok_first)

        # ---- 2. 相同重放不追加历史 ----
        st, _ = sync(signed(make_body()), headers=T1)
        check("重放 -> 200", st == 200)
        st, h = history(cred_id, headers=T1, query=did_q)
        check("重放不追加历史", st == 200 and len(h["events"]) == 1
              and h["events"][0]["cursor"] == first_cursor)

        # ---- 3. 同 updated_at 内容冲突不追加 ----
        st, _ = sync(signed(make_body(status="revoked")), headers=T1)
        check("同时间不同内容 -> 409", st == 409)
        st, h = history(cred_id, headers=T1, query=did_q)
        check("冲突不追加历史", st == 200 and len(h["events"]) == 1)

        # ---- 4. 更早 updated_at 不追加 ----
        st, _ = sync(
            signed(make_body(updated="2020-01-01T00:00:00Z")), headers=T1
        )
        st, h = history(cred_id, headers=T1, query=did_q)
        check("更早状态不追加历史", st == 200 and len(h["events"]) == 1)

        # ---- 5. 锚点/验签失败不追加 ----
        st, _ = sync(
            {"body": make_body(
                credential_id="vc_hist_bad",
                status="revoked", updated="2026-09-24T00:00:00Z"),
             "signature": "!!!bad!!!"},
            headers=T1,
        )
        check("坏签名 -> 200 valid:false", st == 200)
        st, _ = history("vc_hist_bad", headers=T1, query=did_q)
        check("验签失败双键不可见（404）", st == 404)

        # ---- 6. 严格更新追加，updated_at 升序、cursor 递增 ----
        body_rev = make_body(
            status="revoked", updated="2026-09-22T00:00:00Z",
            version=2, reason="  违规  ",
        )
        st, r = sync(signed(body_rev, priv2), headers=T1)
        check("严格更新 -> 200", st == 200)
        st, h = history(cred_id, headers=T1, query=did_q)
        ok_two = False
        second_cursor = None
        if st == 200 and len(h["events"]) == 2:
            e1, e2 = h["events"]
            second_cursor = e2["cursor"]
            ok_two = (
                e1["updated_at"] == "2026-09-21T00:00:00Z"
                and e1["status"] == "active"
                and e2["updated_at"] == "2026-09-22T00:00:00Z"
                and e2["status"] == "revoked"
                and e2["reason"] == "  违规  "
                and e2["issuer_key_version"] == 2
                and e2["cursor"] > e1["cursor"]
                and e2["audit_seq"] > e1["audit_seq"]
                and e2["audit_timestamp"] is not None
                and h["next_after"] == e2["cursor"]
            )
        check("严格更新追加且升序、cursor/audit 递增", ok_two)

        body_unk = make_body(
            status="unknown", updated="2026-09-23T00:00:00Z", version=2)
        st, _ = sync(signed(body_unk, priv2), headers=T1)
        check("第三次同步 -> 200/201", st in (200, 201))
        st, h = history(cred_id, headers=T1, query=did_q)
        check("历史增至 3 项且按 updated_at 升序",
              st == 200 and len(h["events"]) == 3
              and [e["updated_at"] for e in h["events"]] == [
                  "2026-09-21T00:00:00Z",
                  "2026-09-22T00:00:00Z",
                  "2026-09-23T00:00:00Z",
              ]
              and [e["cursor"] for e in h["events"]]
              == sorted(e["cursor"] for e in h["events"]))

        # ---- 7. 分页：limit/after/next_after，空页保持 after ----
        st, pg = history(cred_id, headers=T1, query=f"{did_q}&limit=2")
        check("limit=2 返回 2 项",
              st == 200 and len(pg["events"]) == 2
              and pg["next_after"] == pg["events"][-1]["cursor"])
        cursor2 = pg["events"][-1]["cursor"]
        st, pg2 = history(
            cred_id, headers=T1,
            query=f"{did_q}&limit=2&after={cursor2}")
        check("after 排除 ≤cursor 记录",
              st == 200 and len(pg2["events"]) == 1
              and pg2["events"][0]["cursor"] > cursor2
              and pg2["next_after"] == pg2["events"][0]["cursor"])
        st, pge = history(
            cred_id, headers=T1, query=f"{did_q}&after=999999")
        check("空页 next_after 保持 after",
              st == 200 and pge["events"] == []
              and pge["next_after"] == 999999)
        st, pg0 = history(cred_id, headers=T1, query=did_q)
        check("limit 缺省 50（全量返回）",
              st == 200 and len(pg0["events"]) == 3)
        st, pg1 = history(
            cred_id, headers=T1, query=f"{did_q}&limit=1&after=0")
        check("after=0 与 limit=1 边界",
              st == 200 and len(pg1["events"]) == 1
              and pg1["events"][0]["cursor"] == first_cursor)

        # ---- 8. 查询参数校验 -> 400 ----
        def expect_400(name, query):
            st, r = history(cred_id, headers=T1, query=query)
            check(name, st == 400 and isinstance(r.get("error"), str)
                  and r["error"])

        expect_400("缺 issuer_did", "")
        expect_400("重复 issuer_did", "issuer_did=a&issuer_did=b")
        expect_400("空 issuer_did", "issuer_did=")
        expect_400("limit=0", f"{did_q}&limit=0")
        expect_400("limit=201", f"{did_q}&limit=201")
        expect_400("limit=-1", f"{did_q}&limit=-1")
        expect_400("limit=1.5", f"{did_q}&limit=1.5")
        expect_400("limit=true", f"{did_q}&limit=true")
        expect_400("limit 空白", f"{did_q}&limit=%20")
        expect_400("重复 limit", f"{did_q}&limit=1&limit=2")
        expect_400("after=-1", f"{did_q}&after=-1")
        expect_400("after=1.0", f"{did_q}&after=1.0")
        expect_400("after 非数字", f"{did_q}&after=abc")
        expect_400("重复 after", f"{did_q}&after=0&after=1")
        # limit=1 合法边界
        st, _ = history(cred_id, headers=T1, query=f"{did_q}&limit=1")
        check("limit=1 合法", st == 200)
        st, _ = history(cred_id, headers=T1, query=f"{did_q}&limit=200")
        check("limit=200 合法", st == 200)

        # ---- 9. 未同步 / 跨租户 -> 404 ----
        st, _ = history("vc_not_synced", headers=T1, query=did_q)
        check("未同步双键 -> 404", st == 404)
        st, _ = history(cred_id, headers=T1,
                        query="issuer_did=did:web:other.example")
        check("未知 issuer 双键 -> 404", st == 404)
        st, _ = history(cred_id, headers=T2, query=did_q)
        check("跨租户不可探测 -> 404", st == 404)
        st, _ = history(cred_id, headers={"X-Tenant-ID": ""}, query=did_q)
        check("显式空租户头 -> 400", st == 400)

        # ---- 10. 只读：查询历史不记审计 ----
        st, audit_before = _http("GET", f"{base}/v1/audit?limit=200",
                                 headers=T1)
        n_before = len(audit_before["events"])
        for _ in range(3):
            history(cred_id, headers=T1, query=did_q)
        st, audit_after = _http("GET", f"{base}/v1/audit?limit=200",
                                headers=T1)
        check("历史查询只读、不记审计",
              len(audit_after["events"]) == n_before)

        # ---- 11. 跨租户独立历史 ----
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1}, headers=T2,
        )
        check("T2 注册同 DID 锚点 -> 201", st == 201)
        st, _ = sync(
            signed(make_body(status="revoked",
                             updated="2026-09-25T00:00:00Z")),
            headers=T2,
        )
        check("T2 独立同步 -> 201", st == 201)
        st, h1 = history(cred_id, headers=T1, query=did_q)
        st, h2 = history(cred_id, headers=T2, query=did_q)
        check("租户历史隔离",
              len(h1["events"]) == 3 and len(h2["events"]) == 1
              and h2["events"][0]["updated_at"] == "2026-09-25T00:00:00Z"
              and h2["events"][0]["audit_seq"] is not None)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 12. 跨重启持久化：cursor 与历史保留 ----
    proc = start_server(port, env)
    try:
        assert wait_up(proc, port), "服务重启超时"
        T1 = {"X-Tenant-ID": "hist-a"}
        st, h = history(cred_id, headers=T1, query=did_q)
        check(
            "重启后历史与 cursor 保留",
            st == 200
            and [e["updated_at"] for e in h["events"]] == [
                "2026-09-21T00:00:00Z",
                "2026-09-22T00:00:00Z",
                "2026-09-23T00:00:00Z",
            ]
            and [e["cursor"] for e in h["events"]]
            == sorted(e["cursor"] for e in h["events"]),
        )
        # 重启后再严格更新：cursor 在既有最大值之后继续递增
        body4 = make_body(
            status="revoked", updated="2026-09-24T00:00:00Z", version=2,
            reason="again")
        st, r = sync(signed(body4, priv2), headers=T1)
        check("重启后严格更新 -> 200", st == 200)
        st, h = history(cred_id, headers=T1, query=did_q)
        cursors = [e["cursor"] for e in h["events"]]
        check("重启后 cursor 继续单调递增",
              len(h["events"]) == 4 and cursors == sorted(cursors)
              and len(set(cursors)) == 4
              and h["events"][-1]["audit_seq"] is not None)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 13. 旧状态缺历史：补兼容项（audit 为 null，cursor 持久化）----
    legacy_path = tempfile.mktemp(suffix=".json")
    legacy_env = dict(os.environ, VCBACKEND_STORE=legacy_path)
    lp = start_server(port + 1, legacy_env)
    try:
        assert wait_up(lp, port + 1), "旧状态服务启动超时"
        lbase = f"http://127.0.0.1:{port + 1}"
        L = {"X-Tenant-ID": "legacy"}
        st, _ = _http(
            "POST", f"{lbase}/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1}, headers=L,
        )
        assert st == 201
        lb = make_body(credential_id="vc_legacy",
                       updated="2026-09-18T00:00:00Z")
        st, _ = _http(
            "POST", f"{lbase}/v1/trust/credential-status/sync",
            signed(lb), headers=L,
        )
        assert st == 201
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # 手工删除历史命名空间与游标计数，模拟旧版本状态文件
    raw = json.load(open(legacy_path, encoding="utf-8"))
    for bucket in raw["tenants"].values():
        bucket["credential_status_history"] = {}
    raw.pop("credential_status_history_cursor", None)
    with open(legacy_path, "w", encoding="utf-8") as fh:
        json.dump(raw, fh)

    lp = start_server(port + 1, legacy_env)
    try:
        assert wait_up(lp, port + 1), "旧状态服务重启超时"
        lbase = f"http://127.0.0.1:{port + 1}"
        L = {"X-Tenant-ID": "legacy"}
        lq = f"issuer_did={quote(did)}"
        st, h = _http(
            "GET",
            f"{lbase}/v1/trust/credential-status/vc_legacy/history?{lq}",
            headers=L,
        )
        compat_cursor = None
        ok_compat = (
            st == 200 and len(h["events"]) == 1
            and h["events"][0]["status"] == "active"
            and h["events"][0]["reason"] is None
            and h["events"][0]["updated_at"] == "2026-09-18T00:00:00Z"
            and h["events"][0]["issuer_key_version"] == 1
            and h["events"][0]["audit_seq"] is None
            and h["events"][0]["audit_timestamp"] is None
            and isinstance(h["events"][0]["cursor"], int)
            and h["events"][0]["cursor"] >= 1
        )
        if ok_compat:
            compat_cursor = h["events"][0]["cursor"]
        check("旧状态补兼容项：audit null、cursor 正整数、内容取旧状态",
              ok_compat)

        # 兼容项仍可按 cursor 分页
        st, hp = _http(
            "GET",
            f"{lbase}/v1/trust/credential-status/vc_legacy/history"
            f"?{lq}&after={compat_cursor or 0}",
            headers=L,
        )
        check("audit_seq 为 null 的兼容项仍按 cursor 分页",
              st == 200 and hp["events"] == []
              and hp["next_after"] == compat_cursor)

        # 触发一次严格更新，使兼容项随原子写落盘
        lb2 = make_body(credential_id="vc_legacy", status="revoked",
                        updated="2026-09-19T00:00:00Z", reason="x")
        st, _ = _http(
            "POST", f"{lbase}/v1/trust/credential-status/sync",
            {"body": lb2, "signature": crypto.sign(lb2, priv1)}, headers=L,
        )
        assert st == 200
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # 再重启：兼容项 cursor 持久化不变，新事件 cursor 更大
    lp = start_server(port + 1, legacy_env)
    try:
        assert wait_up(lp, port + 1), "旧状态服务二次重启超时"
        lbase = f"http://127.0.0.1:{port + 1}"
        L = {"X-Tenant-ID": "legacy"}
        lq = f"issuer_did={quote(did)}"
        st, h = _http(
            "GET",
            f"{lbase}/v1/trust/credential-status/vc_legacy/history?{lq}",
            headers=L,
        )
        check(
            "兼容项随原子写持久化、cursor 稳定，新事件追加在后",
            st == 200 and len(h["events"]) == 2
            and h["events"][0]["cursor"] == compat_cursor
            and h["events"][0]["audit_seq"] is None
            and h["events"][1]["updated_at"] == "2026-09-19T00:00:00Z"
            and h["events"][1]["cursor"] > compat_cursor
            and h["events"][1]["audit_seq"] is not None,
        )
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    for path in (store_path, legacy_path):
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


_UNSET = object()

if __name__ == "__main__":
    raise SystemExit(main())
