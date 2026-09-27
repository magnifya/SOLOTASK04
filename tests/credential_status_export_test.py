#!/usr/bin/env python3
"""凭证状态签名发布 POST /v1/credentials/status-export 的端到端测试。

直接运行：python3 tests/credential_status_export_test.py
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

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vcbackend import crypto  # noqa: E402

EXPORT_PATH = "/v1/credentials/status-export"
SYNC_BATCH_PATH = "/v1/trust/credential-status/sync-batch"


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
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def _json(method, url, payload=None, headers=None, raw=None):
    status, text = _http(method, url, payload, headers, raw)
    return status, json.loads(text or "{}"), text


def _pairs(payload):
    """按 JSON 出现顺序返回对象的 (键, 值) 列表（含嵌套 body/items）。"""
    return json.loads(
        json.dumps(payload), object_pairs_hook=lambda pairs: pairs
    )


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
    port = 8977
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
        return _json("POST", f"{base}{EXPORT_PATH}", payload, headers, raw)

    def audit_events(headers):
        st, r, _ = _json("GET", f"{base}/v1/audit?limit=200", headers=headers)
        assert st == 200
        return r["events"]

    try:
        assert wait_up(proc, port), "服务启动超时"

        T1 = {"X-Tenant-ID": "ex-a"}
        T2 = {"X-Tenant-ID": "ex-b"}

        # ---- 准备：签发者 DID 与三张不同状态的凭证 ----
        st, r, _ = _json("POST", f"{base}/v1/dids",
                         {"method": "example", "public_key": "issuer-handle"},
                         headers=T1)
        assert st == 201, r
        issuer = r["did"]
        issuer_pub_v1 = r["public_key"]

        def issue():
            st, r, _ = _json(
                "POST", f"{base}/v1/credentials",
                {"issuer_did": issuer, "subject_did": issuer,
                 "claims": {"role": "admin"}},
                headers=T1,
            )
            assert st == 201, r
            cid = r["credential_id"]
            st, body, _ = _json(
                "GET", f"{base}/v1/credentials/{cid}", headers=T1
            )
            assert st == 200
            return cid, body["body"]["issued_at"]

        cid_active, issued_active = issue()          # 未登记状态
        cid_registered, issued_registered = issue()  # 登记 active
        cid_susp, issued_susp = issue()
        cid_rev, issued_rev = issue()

        st, r, _ = _json(
            "PUT", f"{base}/v1/credentials/{cid_registered}/status",
            {"status": "active"}, headers=T1,
        )
        assert st in (200, 201), r
        registered_at = r["updated_at"]

        st, r, _ = _json(
            "PUT", f"{base}/v1/credentials/{cid_susp}/status",
            {"status": "suspended", "reason": " 违规调查中 "}, headers=T1,
        )
        assert st == 200, r
        susp_at = r["updated_at"]

        st, r, _ = _json(
            "POST", f"{base}/v1/credentials/{cid_rev}/revoke",
            {"reason": " 持证人造假 "}, headers=T1,
        )
        assert st == 200, r
        rev_at = r["updated_at"]

        # ---- 1. 请求非法：400 且恰返 {"error":"请求非法"} ----
        def expect_400(name, payload=None, raw=None, headers=T1):
            st, r, text = export(payload, headers, raw)
            check(
                name,
                st == 400 and r == {"error": "请求非法"}
                and list(_pairs(json.loads(text))) == [("error", "请求非法")],
            )

        expect_400("空请求体", raw=b"")
        expect_400("非法 JSON", raw=b"not-json")
        expect_400("JSON 非对象（数组）", raw=b"[]")
        expect_400("缺 credential_ids", {})
        expect_400("顶层多余字段",
                   {"credential_ids": [cid_active], "x": 1})
        expect_400("credential_ids 非数组", {"credential_ids": {}})
        expect_400("credential_ids 空数组", {"credential_ids": []})
        expect_400("数组 101 项超上限",
                   {"credential_ids": [f"vc_{i}" for i in range(101)]})
        expect_400("项非字符串（数字）", {"credential_ids": [1]})
        expect_400("项非字符串（null）", {"credential_ids": [None]})
        expect_400("项为空字符串", {"credential_ids": [""]})
        expect_400("项重复",
                   {"credential_ids": [cid_active, cid_active]})
        expect_400("一项非法整批 400",
                   {"credential_ids": [cid_active, ""]})
        # 显式空租户头在进入处理前判 400
        st, r, _ = export({"credential_ids": [cid_active]},
                          headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400 and "error" in r)

        # ---- 2. 未知/跨租户凭证：404 恰返 {"error":"资源不存在"} ----
        st, r, _ = export({"credential_ids": ["vc_unknown_xyz"]}, T1)
        check("未知凭证 -> 404 资源不存在",
              st == 404 and r == {"error": "资源不存在"})
        st, r, _ = export(
            {"credential_ids": [cid_active, "vc_unknown_xyz"]}, T1
        )
        check("批内任一未知整批 404",
              st == 404 and r == {"error": "资源不存在"})
        st, r, _ = export({"credential_ids": [cid_active]}, T2)
        check("跨租户凭证 -> 404",
              st == 404 and r == {"error": "资源不存在"})

        # ---- 3. 签发 DID 停用：409 恰返 {"error":"签发DID已停用"} ----
        st, r, _ = _json("POST", f"{base}/v1/dids",
                         {"method": "example", "public_key": "dead-handle"},
                         headers=T1)
        assert st == 201
        dead_issuer = r["did"]
        st, r, _ = _json(
            "POST", f"{base}/v1/credentials",
            {"issuer_did": dead_issuer, "subject_did": dead_issuer,
             "claims": {"k": "v"}},
            headers=T1,
        )
        assert st == 201
        cid_dead = r["credential_id"]
        st, _, _ = _json(
            "POST", f"{base}/v1/dids/{dead_issuer}/deactivate",
            {"reason": "机构业务终止"}, headers=T1,
        )
        assert st == 200
        st, r, _ = export({"credential_ids": [cid_dead]}, T1)
        check("签发 DID 已停用 -> 409",
              st == 409 and r == {"error": "签发DID已停用"})
        st, r, _ = export(
            {"credential_ids": [cid_active, cid_dead]}, T1
        )
        check("批内任一签发 DID 停用整批 409",
              st == 409 and r == {"error": "签发DID已停用"})
        # 未知凭证优先于停用判定（404 先于 409）
        st, r, _ = export(
            {"credential_ids": ["vc_unknown_dead", cid_dead]}, T1
        )
        check("未知凭证优先 404（先于 409）",
              st == 404 and r == {"error": "资源不存在"})

        # ---- 4. 成功导出：200 仅 {"items":[...]}，等长同序、键序固定 ----
        order = [cid_rev, cid_active, cid_susp, cid_registered]
        audit_before = len(audit_events(T1))
        st, r, text = export({"credential_ids": order}, T1)
        check("成功 200 且顶层仅 items",
              st == 200 and list(r.keys()) == ["items"]
              and [k for k, _ in _pairs(json.loads(text))] == ["items"])
        check("items 与输入等长同序",
              [item["body"]["credential_id"] for item in r["items"]]
              == order)

        body_by_cid = {}
        for item, cid in zip(r["items"], order):
            check(f"项键序恰为 body,signature（{cid}）",
                  list(item.keys()) == ["body", "signature"])
            body = item["body"]
            body_by_cid[cid] = body
            check(f"signature 为非空字符串（{cid}）",
                  isinstance(item["signature"], str)
                  and bool(item["signature"]))

        b = body_by_cid[cid_active]
        check("未登记状态：键序五字段",
              list(b.keys()) == [
                  "issuer_did", "credential_id", "status",
                  "updated_at", "issuer_key_version",
              ])
        check("未登记状态按 active、updated_at 取 issued_at、版本 1",
              b["issuer_did"] == issuer and b["status"] == "active"
              and b["updated_at"] == issued_active
              and b["issuer_key_version"] == 1)

        b = body_by_cid[cid_registered]
        check("已登记 active：取当前状态时间、不带 reason",
              list(b.keys()) == [
                  "issuer_did", "credential_id", "status",
                  "updated_at", "issuer_key_version",
              ]
              and b["status"] == "active"
              and b["updated_at"] == registered_at)

        b = body_by_cid[cid_susp]
        check("suspended：末加 reason、状态时间与裁剪原因",
              list(b.keys()) == [
                  "issuer_did", "credential_id", "status",
                  "updated_at", "issuer_key_version", "reason",
              ]
              and b["status"] == "suspended"
              and b["updated_at"] == susp_at
              and b["reason"] == "违规调查中")

        b = body_by_cid[cid_rev]
        check("revoked：末加 reason、吊销时间与裁剪原因",
              list(b.keys()) == [
                  "issuer_did", "credential_id", "status",
                  "updated_at", "issuer_key_version", "reason",
              ]
              and b["status"] == "revoked"
              and b["updated_at"] == rev_at
              and b["reason"] == "持证人造假")

        # ---- 5. 签名按既有状态同步协议：可被 sync-batch 直接接受 ----
        # 注册与签发 DID 同公钥的 status 用途信任锚点（缺省全用途）。
        st, _, _ = _json("POST", f"{base}/v1/trust/anchors",
                         {"did": issuer, "public_key": issuer_pub_v1,
                          "key_version": 1},
                         headers=T2)
        assert st == 201
        st, sr, _ = _json(
            "POST", f"{base}{SYNC_BATCH_PATH}", {"items": r["items"]}, headers=T2
        )
        check("导出项被 sync-batch 直接接受（T2 首次 201）",
              st == 200 and list(sr.keys()) == ["results"]
              and len(sr["results"]) == len(order)
              and all(x["valid"] and x["http_status"] == 201
                      for x in sr["results"]))
        # 落盘值与导出 body 完全一致
        st, synced, _ = _json(
            "GET",
            f"{base}/v1/trust/credential-status/{cid_susp}"
            f"?issuer_did={issuer}",
            headers=T2,
        )
        check("同步落盘 suspended 状态/原因/时间一致",
              st == 200 and synced["status"] == "suspended"
              and synced["reason"] == "违规调查中"
              and synced["updated_at"] == susp_at)

        # ---- 6. 只读：不写状态、历史或审计 ----
        check("导出不记审计（事件数不变）",
              len(audit_events(T1)) == audit_before)
        st, cur, _ = _json(
            "GET", f"{base}/v1/credentials/{cid_susp}/status", headers=T1
        )
        check("导出后本地状态不变",
              cur["status"] == "suspended" and cur["updated_at"] == susp_at)
        # 再次导出：active 项字节稳定（issued_at 不随时间变化）
        st, r2, _ = export({"credential_ids": [cid_active]}, T1)
        check("重复导出 active 项 body 稳定",
              r2["items"][0]["body"] == body_by_cid[cid_active])

        # ---- 7. 轮换后版本取签发 DID 当前版本，并用当前私钥签名 ----
        st, _, _ = _json(
            "POST", f"{base}/v1/dids/{issuer}/keys/rotate",
            {"key_handle": "issuer-handle-v2"}, headers=T1,
        )
        assert st == 200
        st, did_rec, _ = _json(
            "GET", f"{base}/v1/dids/{issuer}", headers=T1
        )
        issuer_pub_v2 = did_rec["public_key"]
        assert did_rec["key_version"] == 2
        st, r3, _ = export({"credential_ids": [cid_active, cid_rev]}, T1)
        check("轮换后导出按当前版本 v2 签名",
              all(item["body"]["issuer_key_version"] == 2
                  for item in r3["items"]))
        st, _, _ = _json("POST", f"{base}/v1/trust/anchors",
                         {"did": issuer, "public_key": issuer_pub_v2,
                          "key_version": 2},
                         headers=T2)
        assert st == 201
        # 既有 T2 检查点同 updated_at 但版本变化 -> 同步协议 409（同秒异内容）
        st, sr, _ = _json(
            "POST", f"{base}{SYNC_BATCH_PATH}",
            {"items": r3["items"]}, headers=T2
        )
        check("v2 项对同秒旧检查点按同步协议 409（版本不同）",
              st == 200 and len(sr["results"]) == 2
              and all(not x["valid"] and x["http_status"] == 409
                      for x in sr["results"]))
        # 新消费方租户仅注册 v2 锚点：导出项作为首次同步被直接接受。
        T3 = {"X-Tenant-ID": "ex-c"}
        st, _, _ = _json("POST", f"{base}/v1/trust/anchors",
                         {"did": issuer, "public_key": issuer_pub_v2,
                          "key_version": 2},
                         headers=T3)
        assert st == 201
        st, sr, _ = _json(
            "POST", f"{base}{SYNC_BATCH_PATH}",
            {"items": r3["items"]}, headers=T3
        )
        check("v2 签名项被新消费方 sync-batch 直接接受（首次 201）",
              st == 200 and len(sr["results"]) == 2
              and all(x["valid"] and x["http_status"] == 201
                      for x in sr["results"]))

        # ---- 8. 100 项边界 ----
        many = [issue()[0] for _ in range(100)]
        st, r4, _ = export({"credential_ids": many}, T1)
        check("100 项批成功且等长",
              st == 200 and len(r4["items"]) == 100
              and [i["body"]["credential_id"] for i in r4["items"]]
              == many)

        # ---- 9. 签名可独立密码学验真（当前版本公钥）----
        item = r4["items"][0]
        try:
            crypto.verify(item["body"], item["signature"], issuer_pub_v2)
            verify_ok = True
        except Exception:  # noqa: BLE001
            verify_ok = False
        check("以签发 DID 当前公钥验签通过", verify_ok)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 10. 跨重启：结论稳定（active 的 issued_at、签名仍可验）----
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(proc, port), "服务重启超时"
        T1 = {"X-Tenant-ID": "ex-a"}
        st, did_rec, _ = _json(
            "GET", f"{base}/v1/dids/{issuer}", headers=T1
        )
        assert st == 200 and did_rec["key_version"] == 2
        st, r, _ = export(
            {"credential_ids": [cid_active, cid_susp, cid_rev]}, T1
        )
        check("重启后导出成功", st == 200 and len(r["items"]) == 3)
        if st == 200:
            check("重启后 active 的 updated_at 仍为 issued_at",
                  r["items"][0]["body"]["updated_at"] == issued_active
                  and r["items"][0]["body"]["issuer_key_version"] == 2)
            check("重启后 suspended/revoked 原因保持",
                  r["items"][1]["body"]["reason"] == "违规调查中"
                  and r["items"][2]["body"]["reason"] == "持证人造假")
            try:
                crypto.verify(
                    r["items"][0]["body"],
                    r["items"][0]["signature"],
                    did_rec["public_key"],
                )
                restart_ok = True
            except Exception:  # noqa: BLE001
                restart_ok = False
            check("重启后签名仍可验真", restart_ok)
        # 状态/审计只读在重启后仍成立
        st, cur, _ = _json(
            "GET", f"{base}/v1/credentials/{cid_rev}/status", headers=T1
        )
        check("重启后本地 revoked 状态不变",
              st == 200 and cur["status"] == "revoked")
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


if __name__ == "__main__":
    raise SystemExit(main())
