#!/usr/bin/env python3
"""凭证状态签名发布 POST /v1/credentials/status-export 的端到端测试。

验证：
- 请求体恰为 {"credential_ids": [字符串...]}，数组 1..100 项、值非空且
  不重复；结构/类型/数量非法 400 恰返 {"error":"请求非法"}；
- 任一凭证未知或跨租户 404 恰返 {"error":"资源不存在"}；签发 DID 停用
  409 恰返 {"error":"签发DID已停用"}；均整批失败；
- 成功 200 仅返 {"items":[...]}，等长同序；项键序 body、signature，
  body 键序 issuer_did、credential_id、status、updated_at、
  issuer_key_version，suspended/revoked 末加 reason；
- 未登记状态按 active、updated_at 取 issued_at；其余取当前状态、状态
  时间与保存原因；issuer_key_version 取签发 DID 当前版本；
- 签名按既有状态同步协议覆盖 body，导出项可被
  /v1/trust/credential-status/sync-batch 直接接受；
- 纯只读：不写状态、历史或审计；租户头缺省/空值/隔离规则沿用既有。

直接运行：python3 tests/credential_status_export_test.py
"""

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vcbackend import crypto  # noqa: E402

EXPORT_PATH = "/v1/credentials/status-export"
SYNC_BATCH_PATH = "/v1/trust/credential-status/sync-batch"

ITEM_KEYS = ["body", "signature"]
BODY_BASE_KEYS = [
    "issuer_did", "credential_id", "status", "updated_at",
    "issuer_key_version",
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
            raw_body = resp.read().decode()
            return resp.status, (json.loads(raw_body) if raw_body else None), raw_body
    except urllib.error.HTTPError as exc:
        raw_body = exc.read().decode()
        return exc.code, (json.loads(raw_body) if raw_body else None), raw_body


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


def main():
    port = 8971
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

    def export(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{EXPORT_PATH}", payload,
                     headers=headers, raw=raw)

    def audit_events(headers):
        events = []
        after = 0
        while True:
            st, r, _ = _http(
                "GET", f"{base}/v1/audit?limit=200&after={after}",
                headers=headers,
            )
            assert st == 200
            page = r["events"]
            events.extend(page)
            if not page:
                break
            after = r["next_after"]
        return events

    try:
        assert wait_up(proc, port), "服务启动超时"

        T1 = {"X-Tenant-ID": "ex-a"}
        T2 = {"X-Tenant-ID": "ex-b"}

        # ---- 搭建两个本租户签发者；A 轮换到 v2（当前版本不同于签发版本）----
        st, r, _ = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "issuer-a-handle"},
            headers=T1,
        )
        assert st == 201, r
        did_a = r["did"]
        st, r, _ = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "issuer-b-handle"},
            headers=T1,
        )
        assert st == 201, r
        did_b = r["did"]

        st, r, _ = _http(
            "POST", f"{base}/v1/dids/{did_a}/keys/rotate",
            {"key_handle": "issuer-a-handle-v2"}, headers=T1,
        )
        assert st == 200, r
        did_a_current_version = r["key_version"]
        check("签发者 A 轮换后当前版本为 2", did_a_current_version == 2)

        def current_public_pem(did, version, headers):
            st, doc, _ = _http(
                "GET", f"{base}/v1/dids/{quote(did)}/document",
                headers=headers,
            )
            assert st == 200, doc
            methods = {m["key_version"]: m["public_key"]
                       for m in doc["verification_methods"]}
            return methods[version]

        # 以两个签发者当前版本公钥注册信任锚点（全用途，含 status）。
        for did, version in ((did_a, did_a_current_version), (did_b, 1)):
            pem = current_public_pem(did, version, T1)
            st, _, _ = _http(
                "POST", f"{base}/v1/trust/anchors",
                {"did": did, "public_key": pem, "key_version": version},
                headers=T1,
            )
            check(f"注册锚点 {did}#{version} -> 201", st == 201)

        def issue(issuer, subject, claims=None):
            st, r, _ = _http(
                "POST", f"{base}/v1/credentials",
                {"issuer_did": issuer, "subject_did": subject,
                 "claims": claims or {"k": "v"}},
                headers=T1,
            )
            assert st == 201, r
            return r["credential_id"]

        def get_credential(cid):
            st, r, _ = _http(
                "GET", f"{base}/v1/credentials/{quote(cid)}", headers=T1
            )
            assert st == 200, r
            return r

        def get_local_status(cid):
            st, r, _ = _http(
                "GET", f"{base}/v1/credentials/{quote(cid)}/status",
                headers=T1,
            )
            assert st == 200, r
            return r

        c_none = issue(did_a, did_b)                 # 未登记状态
        c_active = issue(did_a, did_b)               # 显式 active
        c_susp = issue(did_a, did_b)                 # suspended
        c_rev = issue(did_b, did_a)                  # revoked（签发者 B）
        issued_none = get_credential(c_none)["body"]["issued_at"]

        st, _, _ = _http(
            "PUT", f"{base}/v1/credentials/{c_active}/status",
            {"status": "active"}, headers=T1,
        )
        assert st in (200, 201)
        active_updated = get_local_status(c_active)["updated_at"]

        suspend_reason = "违规调查中，暂停服务"
        st, _, _ = _http(
            "PUT", f"{base}/v1/credentials/{c_susp}/status",
            {"status": "suspended", "reason": f"  {suspend_reason}  "},
            headers=T1,
        )
        assert st == 200
        susp_updated = get_local_status(c_susp)["updated_at"]

        revoke_reason = "持证人造假，吊销凭证"
        st, r, _ = _http(
            "POST", f"{base}/v1/credentials/{c_rev}/revoke",
            {"reason": revoke_reason}, headers=T1,
        )
        assert st == 200, r
        rev_updated = r["updated_at"]

        # ---- 1. 成功导出：键序、等长同序、取值、版本与签名 ----
        ids = [c_none, c_active, c_susp, c_rev]
        audit_before_export = audit_events(T1)
        st, r, raw = export({"credential_ids": ids}, headers=T1)
        audit_after_export = audit_events(T1)
        check("导出本身不记审计",
              len(audit_after_export) == len(audit_before_export))
        check("导出 HTTP 200 且仅含 items",
              st == 200 and list(r.keys()) == ["items"]
              and len(r["items"]) == 4)
        check("响应体无多余缩进外键（恰 {items}）",
              json.loads(raw) == r and isinstance(r["items"], list))

        if st == 200 and len(r.get("items", [])) == 4:
            items = r["items"]

            def check_item(idx, cid, issuer, status, updated, version,
                           reason=_UNSET):
                item = items[idx]
                ok = list(item.keys()) == ITEM_KEYS
                body = item["body"]
                expected_body_keys = list(BODY_BASE_KEYS)
                if reason is not _UNSET:
                    expected_body_keys.append("reason")
                ok = ok and list(body.keys()) == expected_body_keys
                ok = ok and body["issuer_did"] == issuer
                ok = ok and body["credential_id"] == cid
                ok = ok and body["status"] == status
                ok = ok and body["updated_at"] == updated
                ok = ok and body["issuer_key_version"] == version
                if reason is _UNSET:
                    ok = ok and "reason" not in body
                else:
                    ok = ok and body["reason"] == reason
                # 签名可用签发 DID 当前版本公钥（即注册锚点公钥）验真。
                pem = current_public_pem(issuer, version, T1)
                try:
                    crypto.verify(body, item["signature"], pem)
                    sig_ok = True
                except Exception:  # noqa: BLE001
                    sig_ok = False
                return ok and sig_ok

            check("未登记 -> active、updated_at=issued_at、v2、无 reason",
                  check_item(0, c_none, did_a, "active", issued_none, 2))
            check("已登记 active -> 取状态时间、v2、无 reason",
                  check_item(1, c_active, did_a, "active", active_updated, 2))
            check("suspended -> 状态时间+裁剪原因、v2",
                  check_item(2, c_susp, did_a, "suspended", susp_updated, 2,
                             reason=suspend_reason))
            check("revoked -> 状态时间+保存原因、签发者 B v1",
                  check_item(3, c_rev, did_b, "revoked", rev_updated, 1,
                             reason=revoke_reason))

            # ---- 2. 导出项可直接提交 sync-batch 并被接受（首次 201）----
            st2, r2, _ = _http(
                "POST", f"{base}{SYNC_BATCH_PATH}",
                {"items": items}, headers=T1,
            )
            check("导出项提交 sync-batch HTTP 200、等长同序",
                  st2 == 200 and list(r2.keys()) == ["results"]
                  and len(r2["results"]) == 4)
            if st2 == 200 and len(r2.get("results", [])) == 4:
                check("逐项首次同步均 valid:true、http 201",
                      all(row["valid"] is True and row["http_status"] == 201
                          for row in r2["results"]))

            # 同步落盘值与导出 body 一致（外部状态命名空间，独立于本地凭证）。
            for idx, cid in enumerate(ids):
                issuer = items[idx]["body"]["issuer_did"]
                st3, r3, _ = _http(
                    "GET",
                    f"{base}/v1/trust/credential-status/"
                    f"{quote(cid)}?issuer_did={quote(issuer)}",
                    headers=T1,
                )
                body = items[idx]["body"]
                check(
                    f"外部状态落盘一致 {cid}",
                    st3 == 200
                    and r3["status"] == body["status"]
                    and r3["updated_at"] == body["updated_at"]
                    and r3.get("reason") == body.get("reason"),
                )

            # 再次导出同批并提交：相同内容重放 200、仍全部有效。
            st3, r3, _ = export({"credential_ids": ids}, headers=T1)
            st4, r4, _ = _http(
                "POST", f"{base}{SYNC_BATCH_PATH}",
                {"items": r3["items"]}, headers=T1,
            )
            check("重复导出项重放 sync-batch -> 200",
                  st4 == 200
                  and all(row["valid"] is True and row["http_status"] == 200
                          for row in r4["results"]))

        # ---- 3. 纯只读：本地状态不变、不写状态历史 ----
        check("导出后未登记凭证本地仍无状态时间",
              get_local_status(c_none)["status"] == "active"
              and get_local_status(c_none)["updated_at"] is None)
        check("导出后 suspended 本地状态保持",
              get_local_status(c_susp)["status"] == "suspended"
              and get_local_status(c_susp)["updated_at"] == susp_updated)

        # ---- 4. 400：结构、类型、数量非法，恰返 {"error":"请求非法"} ----
        def expect_400(name, payload=None, raw=None, headers=T1):
            st, r, _ = export(payload=payload, raw=raw, headers=headers)
            check(name, st == 400 and r == {"error": "请求非法"})

        expect_400("空请求体", raw=b"")
        expect_400("非法 JSON", raw=b"not-json")
        expect_400("JSON 非对象（数组）", raw=b"[1]")
        expect_400("缺 credential_ids", {})
        expect_400("顶层多余字段",
                   {"credential_ids": [c_none], "x": 1})
        expect_400("credential_ids 非数组", {"credential_ids": {}})
        expect_400("credential_ids 空数组", {"credential_ids": []})
        expect_400("元素非字符串", {"credential_ids": [c_none, 1]})
        expect_400("元素为空串", {"credential_ids": [""]})
        expect_400("元素重复", {"credential_ids": [c_none, c_none]})
        expect_400("101 项超上限",
                   {"credential_ids": [c_none] + [f"vc_x_{i}"
                                                  for i in range(100)]})

        # 显式空租户头：沿用既有规则 400（整批不处理）。
        st, r, _ = export({"credential_ids": [c_none]},
                          headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400",
              st == 400 and isinstance(r.get("error"), str) and r["error"])

        # ---- 5. 404：未知凭证 / 跨租户凭证，整批失败，恰返资源不存在 ----
        st, r, _ = export({"credential_ids": ["vc_unknown_xyz"]}, headers=T1)
        check("未知凭证 -> 404 资源不存在",
              st == 404 and r == {"error": "资源不存在"})

        # T2 自有凭证，T1 请求按不存在处理，且整批失败（无部分返回）。
        st, r, _ = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "t2-handle"}, headers=T2,
        )
        t2_did = r["did"]
        st, r, _ = _http(
            "POST", f"{base}/v1/credentials",
            {"issuer_did": t2_did, "subject_did": t2_did,
             "claims": {"k": "v"}},
            headers=T2,
        )
        t2_cred = r["credential_id"]
        st, r, _ = export(
            {"credential_ids": [c_none, t2_cred, c_active]}, headers=T1
        )
        check("含跨租户凭证整批 404 资源不存在",
              st == 404 and r == {"error": "资源不存在"})

        # ---- 6. 409：签发 DID 停用，整批失败，恰返签发DID已停用 ----
        st, r, _ = _http(
            "POST", f"{base}/v1/dids/{did_b}/deactivate",
            {"reason": "机构业务终止"}, headers=T1,
        )
        assert st == 200, r
        st, r, _ = export({"credential_ids": [c_none, c_rev]}, headers=T1)
        check("含停用签发者凭证整批 409",
              st == 409 and r == {"error": "签发DID已停用"})
        # 停用不影响其他签发者：仅 A 的凭证仍可导出。
        st, r, _ = export({"credential_ids": [c_none]}, headers=T1)
        check("其他活动签发者凭证仍可导出", st == 200 and len(r["items"]) == 1)

        # ---- 7. 缺省租户 default 可用；租户隔离 ----
        st, r, _ = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "default-handle"},
        )
        default_did = r["did"]
        st, r, _ = _http(
            "POST", f"{base}/v1/credentials",
            {"issuer_did": default_did, "subject_did": default_did,
             "claims": {"k": "v"}},
        )
        assert st == 201, r
        default_cred = r["credential_id"]
        st, r, _ = export({"credential_ids": [default_cred]})
        check("缺省租户 default 导出成功",
              st == 200 and len(r["items"]) == 1
              and r["items"][0]["body"]["issuer_did"] == default_did)
        st, r, _ = export({"credential_ids": [default_cred]}, headers=T1)
        check("default 租户凭证对 T1 不可见 -> 404",
              st == 404 and r == {"error": "资源不存在"})

        # ---- 8. 并发导出/状态变更：无 500，无混合时点的部分错误 ----
        c_conc = issue(did_a, did_b)
        errors_500 = []
        stop = threading.Event()

        def worker_export():
            while not stop.is_set():
                try:
                    st, _, _ = export(
                        {"credential_ids": [c_conc, c_none]}, headers=T1
                    )
                    # did_a 未停用：只可能 200。
                    if st not in (200,):
                        if st == 500:
                            errors_500.append(st)
                except Exception:  # noqa: BLE001
                    errors_500.append("exc")

        def worker_toggle():
            # 对另一张凭证反复暂停/恢复，不影响导出批的原子快照。
            c_other = issue(did_a, did_b)
            for i in range(30):
                reason = f"并发暂停 {i}"
                _http("PUT", f"{base}/v1/credentials/{c_other}/status",
                      {"status": "suspended", "reason": reason}, headers=T1)
                _http("PUT", f"{base}/v1/credentials/{c_other}/status",
                      {"status": "active"}, headers=T1)

        t_export = threading.Thread(target=worker_export)
        t_toggle = threading.Thread(target=worker_toggle)
        t_export.start()
        t_toggle.start()
        t_toggle.join(timeout=30)
        stop.set()
        t_export.join(timeout=5)
        check("并发导出无 500/异常（批初原子快照）", not errors_500)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

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
