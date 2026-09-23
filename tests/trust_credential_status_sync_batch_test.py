#!/usr/bin/env python3
"""外部凭证状态批量同步 POST /v1/trust/credential-status/sync-batch
的端到端测试。

直接运行：python3 tests/trust_credential_status_sync_batch_test.py
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
from vcbackend.store import VCStore  # noqa: E402

BATCH_PATH = "/v1/trust/credential-status/sync-batch"
SYNC_PATH = "/v1/trust/credential-status/sync"

FAIL_KEYS = ["valid", "http_status", "reason"]
SUCCESS_KEYS = [
    "valid", "http_status", "issuer_did", "credential_id", "status",
    "reason", "updated_at", "issuer_key_version",
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


def main():
    port = 8963
    store_path = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store_path)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def batch(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{BATCH_PATH}", payload,
                     headers=headers, raw=raw)

    def sync_one(payload, headers):
        return _http("POST", f"{base}{SYNC_PATH}", payload, headers=headers)

    def get_status(credential_id, headers, issuer):
        url = (f"{base}/v1/trust/credential-status/"
               f"{quote(credential_id)}?issuer_did={quote(issuer)}")
        return _http("GET", url, headers=headers)

    def audit_events(headers):
        st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=headers)
        assert st == 200
        return r["events"]

    try:
        assert wait_up(proc, port), "服务启动超时"

        T1 = {"X-Tenant-ID": "tb-a"}
        T2 = {"X-Tenant-ID": "tb-b"}

        priv1, pub1 = gen_keypair()
        priv2, pub2 = gen_keypair()
        did = "did:web:issuer-batch.example"
        other_did = "did:web:no-anchor-batch.example"

        # 显式空租户头在进入批处理前判 400
        st, r = batch({"items": []}, headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400 and r.get("error"))

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

        def make_body(credential_id, status="active",
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

        # ---- 1. 请求级非法：一律 200 + {"results":[],"reason":"请求..."} ----
        def expect_bad_request(name, payload=None, raw=None):
            st, r = batch(payload=payload, raw=raw, headers=T1)
            check(
                name,
                st == 200 and r.get("results") == []
                and isinstance(r.get("reason"), str)
                and r["reason"].startswith("请求")
                and list(r.keys()) == ["results", "reason"],
            )

        expect_bad_request("空请求体", raw=b"")
        expect_bad_request("非法 JSON", raw=b"not-json")
        expect_bad_request("JSON 非对象（数组）", raw=b"[1]")
        expect_bad_request("缺 items", {})
        expect_bad_request("顶层多余字段", {"items": [], "x": 1})
        expect_bad_request("items 非数组", {"items": {}})
        expect_bad_request("items 空数组", {"items": []})
        expect_bad_request("items 101 项超上限",
                           {"items": [signed(make_body(f"vc_over_{i}"))
                                      for i in range(101)]})

        # 请求级非法（超上限）不处理任何一项：无同步、无审计
        st, r = get_status("vc_over_0", T1, did)
        check("超上限不写入（GET 404）", st == 404)
        check("超上限不记审计",
              all(e["action"] != "trust.credential.status.synced"
                  for e in audit_events(T1)))

        # ---- 2. 混合批：成功/400/锚点/签名/409/重放/更早/严格更新，不短路 ----
        body_a = make_body("vc_b1")                                  # 首次 201
        item_bad_field = {"body": dict(body_a, status="bogus"),
                          "signature": "x"}                          # 字段 400
        item_not_object = [1, 2, 3]                                  # 400
        item_bad_sig = {"body": make_body("vc_b1", version=2),
                        "signature": "!!!bad!!!"}                    # 签名格式 200
        item_no_anchor = signed(
            make_body("vc_b_anchor", issuer=other_did))              # 锚点 200
        item_conflict = signed(make_body("vc_b1", status="revoked"))  # 同秒冲突 409
        item_replay = signed(make_body("vc_b1"))                     # 重放 200
        item_older = signed(
            make_body("vc_b1", updated="2020-01-01T00:00:00Z"))      # 更早 200
        body_update = make_body(
            "vc_b1", status="revoked", updated="2026-09-22T00:00:00Z",
            version=2, reason="批量严格更新",
        )
        item_update = signed(body_update, priv2)                     # 严格更新 200

        items = [
            signed(body_a),
            item_bad_field,
            item_not_object,
            item_bad_sig,
            item_no_anchor,
            item_conflict,
            item_replay,
            item_older,
            item_update,
        ]
        st, r = batch({"items": items}, headers=T1)
        check("混合批 HTTP 200 且 results 等长同序",
              st == 200 and list(r.keys()) == ["results"]
              and len(r["results"]) == len(items))
        if len(r.get("results", [])) == len(items):
            res = r["results"]

            def fail_at(idx, http_status, prefix):
                row = res[idx]
                return (
                    list(row.keys()) == FAIL_KEYS
                    and row["valid"] is False
                    and row["http_status"] == http_status
                    and isinstance(row["reason"], str)
                    and row["reason"]
                    and row["reason"].startswith(prefix)
                )

            check("results[0] 首次 201 且键序/字段正确",
                  list(res[0].keys()) == SUCCESS_KEYS
                  and res[0]["valid"] is True
                  and res[0]["http_status"] == 201
                  and res[0]["issuer_did"] == did
                  and res[0]["credential_id"] == "vc_b1"
                  and res[0]["status"] == "active"
                  and res[0]["reason"] is None
                  and res[0]["updated_at"] == "2026-09-21T00:00:00Z"
                  and res[0]["issuer_key_version"] == 1)
            check("results[1] 字段错误 400", fail_at(1, 400, "body 字段 status"))
            check("results[2] 项非对象 400",
                  fail_at(2, 400, "请求体"))
            check("results[3] 签名格式错误 200",
                  fail_at(3, 200, "签名格式错误"))
            check("results[4] 锚点缺失 200", fail_at(4, 200, "锚点"))
            check("results[5] 同秒冲突 409", fail_at(5, 409, "凭证状态"))
            check("results[6] 重放 200 保持首值",
                  res[6]["valid"] is True and res[6]["http_status"] == 200
                  and list(res[6].keys()) == SUCCESS_KEYS
                  and res[6]["status"] == "active")
            check("results[7] 更早日 200 忽略（保持 active）",
                  res[7]["valid"] is True and res[7]["http_status"] == 200
                  and res[7]["status"] == "active"
                  and res[7]["updated_at"] == "2026-09-21T00:00:00Z")
            check("results[8] 严格更新 200（revoked/reason/v2）",
                  res[8]["valid"] is True and res[8]["http_status"] == 200
                  and list(res[8].keys()) == SUCCESS_KEYS
                  and res[8]["status"] == "revoked"
                  and res[8]["reason"] == "批量严格更新"
                  and res[8]["updated_at"] == "2026-09-22T00:00:00Z"
                  and res[8]["issuer_key_version"] == 2)

        # 失败项不写入
        st, _ = get_status("vc_b_anchor", T1, other_did)
        check("锚点失败项不写入（404）", st == 404)
        # vc_b1 最终为严格更新后的 revoked
        st, r = get_status("vc_b1", T1, did)
        check("vc_b1 最终为 revoked（严格更新生效）",
              st == 200 and r["status"] == "revoked"
              and r["updated_at"] == "2026-09-22T00:00:00Z"
              and r["reason"] == "批量严格更新")

        # 审计：vc_b1 恰好两条（首次 + 严格更新），失败项无审计
        synced = [e for e in audit_events(T1)
                  if e["action"] == "trust.credential.status.synced"
                  and e["resource_id"] == f"{did}#vc_b1"]
        check("vc_b1 审计恰两条（首次+严格更新）", len(synced) == 2)
        check("失败项不记同步审计",
              all(e["resource_id"] != f"{other_did}#vc_b_anchor"
                  for e in audit_events(T1)))

        # ---- 3. 同一批内顺序效应：201→严格更新→更早忽略→同秒冲突→重放 ----
        seq_items = [
            signed(make_body("vc_seq", updated="2026-10-01T00:00:00Z")),
            signed(make_body("vc_seq", status="revoked",
                             updated="2026-10-02T00:00:00Z", version=2),
                   priv2),
            signed(make_body("vc_seq", updated="2026-09-01T00:00:00Z")),
            signed(make_body("vc_seq", status="unknown",
                             updated="2026-10-02T00:00:00Z", version=2),
                   priv2),
            signed(make_body("vc_seq", status="revoked",
                             updated="2026-10-02T00:00:00Z", version=2),
                   priv2),
        ]
        st, r = batch({"items": seq_items}, headers=T1)
        check("顺序批 HTTP 200、等长",
              st == 200 and len(r["results"]) == 5)
        if len(r.get("results", [])) == 5:
            s = r["results"]
            check("顺序: 201/200/200/409/200",
                  [x["http_status"] for x in s] == [201, 200, 200, 409, 200]
                  and [x["valid"] for x in s]
                  == [True, True, True, False, True])
            check("更早项返回当前值（revoked 10-02）",
                  s[2]["status"] == "revoked"
                  and s[2]["updated_at"] == "2026-10-02T00:00:00Z")
            check("同秒冲突 reason 非空", bool(s[3]["reason"]))
        synced_seq = [e for e in audit_events(T1)
                      if e["action"] == "trust.credential.status.synced"
                      and e["resource_id"] == f"{did}#vc_seq"]
        check("顺序批仅首次与严格更新记审计（2 条）", len(synced_seq) == 2)

        # ---- 4. 100 项上限（含 1 个坏项不短路）----
        ok_items = [signed(make_body(f"vc_ok_{i}")) for i in range(99)]
        ok_items.append({"body": [], "signature": "x"})  # 第 100 项坏
        st, r = batch({"items": ok_items}, headers=T1)
        check("100 项批合法且等长", st == 200 and len(r["results"]) == 100)
        check("100 项批：前 99 成功、末项 400，失败不短路",
              all(x["valid"] for x in r["results"][:99])
              and not r["results"][99]["valid"]
              and r["results"][99]["http_status"] == 400)

        # ---- 5. 单项接口行为不受批量影响（抽验 201/200/409）----
        st, r = sync_one(signed(make_body("vc_single_only")), T1)
        check("单项接口仍 201", st == 201 and r["status"] == "active")
        st, r = batch({"items": [signed(make_body("vc_single_only"))]}, T1)
        check("经批量重放单项已建凭证 -> 200",
              st == 200 and r["results"][0]["http_status"] == 200)

        # ---- 6. 批量同步不改变本租户凭证状态 ----
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "local-handle-b"},
                      headers=T1)
        local_did = r["did"]
        st, r = _http(
            "POST", f"{base}/v1/credentials",
            {"issuer_did": local_did, "subject_did": local_did,
             "claims": {"k": "v"}},
            headers=T1,
        )
        local_cred = r["credential_id"]
        st, _ = _http("PUT",
                      f"{base}/v1/credentials/{local_cred}/status",
                      {"status": "active"}, headers=T1)
        assert st in (200, 201)
        ext_same = signed(make_body(local_cred, status="revoked",
                                    updated="2026-11-01T00:00:00Z",
                                    version=2), priv2)
        st, r = batch({"items": [ext_same]}, headers=T1)
        check("外部同名状态经批量同步成功",
              st == 200 and r["results"][0]["valid"] is True)
        st, r = _http("GET",
                      f"{base}/v1/credentials/{local_cred}/status",
                      headers=T1)
        check("本租户凭证状态仍为 active",
              st == 200 and r["status"] == "active")

        # ---- 7. 跨租户隔离 ----
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1}, headers=T2,
        )
        check("T2 注册自己的同 DID 锚点 -> 201", st == 201)
        t2_body = make_body("vc_b1", status="revoked",
                            updated="2026-12-01T00:00:00Z")
        st, r = batch({"items": [signed(t2_body)]}, headers=T2)
        check("T2 独立首次同步同双键 -> 201",
              st == 200 and r["results"][0]["http_status"] == 201
              and r["results"][0]["status"] == "revoked")
        st, r1 = get_status("vc_b1", T1, did)
        st2, r2 = get_status("vc_b1", T2, did)
        check("T1/T2 双键视图隔离",
              r1["updated_at"] == "2026-09-22T00:00:00Z"
              and r2["updated_at"] == "2026-12-01T00:00:00Z"
              and st == st2 == 200)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 8. 跨重启持久化（状态与审计）----
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(proc, port), "服务重启超时"
        T1 = {"X-Tenant-ID": "tb-a"}
        st, r = get_status("vc_b1", T1, did)
        check(
            "重启后批量同步状态保留",
            st == 200 and r == {
                "status": "revoked",
                "reason": "批量严格更新",
                "updated_at": "2026-09-22T00:00:00Z",
            },
        )
        st, r = get_status("vc_seq", T1, did)
        check("重启后顺序批状态保留",
              st == 200 and r["status"] == "revoked"
              and r["updated_at"] == "2026-10-02T00:00:00Z")
        check("重启后审计保留",
              sum(1 for e in audit_events(T1)
                  if e["action"] == "trust.credential.status.synced") >= 4)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 9. 落盘失败：该项回滚，不写状态、不记审计 ----
    rollback_path = tempfile.mktemp(suffix=".json")
    try:
        rs = VCStore(rollback_path)
        rs.register_trust_anchor("rb", did, pub1, 1)

        def _boom():
            raise OSError("模拟落盘失败")

        rs._save_locked = _boom  # type: ignore[assignment]
        rb_body = make_body("vc_batch_rollback")
        try:
            rs.sync_credential_status_batch(
                "rb", {"items": [{"body": rb_body,
                                  "signature": crypto.sign(rb_body, priv1)}]}
            )
            check("落盘失败时批量同步抛错", False)
        except OSError:
            check("落盘失败时批量同步抛错", True)
        try:
            rs.get_synced_credential_status("rb", did, "vc_batch_rollback")
            check("落盘失败回滚（状态不写入）", False)
        except Exception:
            check("落盘失败回滚（状态不写入）", True)
        events, _ = rs.list_audit("rb", 0, 200)
        check("落盘失败不记同步审计",
              all(e.action != "trust.credential.status.synced"
                  for e in events))
    finally:
        if os.path.exists(rollback_path):
            os.remove(rollback_path)

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
