#!/usr/bin/env python3
"""POST /v1/credentials/revoke-batch 批量原子吊销端到端测试。

覆盖：
- 请求级 400：空体、非法 JSON、非对象、外层缺/多 items、items 非数组、
  空数组、超过 100、项非对象、项缺 credential_id/多余字段/类型错误、
  credential_id 为空、批内重复、reason 非字符串或裁剪后为空（含已吊销
  凭证上的非法 reason），响应均为非空 error；
- 显式空 X-Tenant-ID 400；未知凭证 404、跨租户 404，且 400/404 均整批
  不产生任何状态、历史、游标或审计变化；
- 成功 200：results 与输入等长同序、键序同单张吊销；reason 省略走
  “持证人主动吊销”，提供时裁剪保存；已暂停凭证直接吊销且暂停原因清除；
- 已吊销凭证保留首次 reason/revoked_at/updated_at，不追加历史、不推进
  游标，但每次重复请求仍记 credential.revoked 审计；
- 首次吊销按输入顺序追加历史、推进租户内共享游标并记审计；
- 并发（单张 revoke 与批次混合）下同一凭证只有一个首次吊销结果；
- 重启后状态、历史、游标、审计顺序与重试结论稳定；
- 直连 VCStore：落盘失败时状态、历史、游标、审计整体回滚，磁盘不变，
  故障排除后重试成功且事件不重复。

直接运行：python3 tests/credential_revoke_batch_test.py
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vcbackend.store import REASON_UNSET, VCStore  # noqa: E402

PORT = 8991
Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
DEFAULT_REVOKE_REASON = "持证人主动吊销"
RESULT_KEYS = ["credential_id", "status", "reason",
               "revoked_at", "updated_at"]


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
            time.sleep(0.1)
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
    T1 = {"X-Tenant-ID": "rb-a"}
    T2 = {"X-Tenant-ID": "rb-b"}

    def issue(headers):
        st, did_body = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example",
             "public_key": f"handle-{time.time_ns()}"},
            headers=headers,
        )
        assert st == 201, did_body
        did = did_body["did"]
        st, cred_body = _http(
            "POST", f"{base}/v1/credentials",
            {"issuer_did": did, "subject_did": did,
             "claims": {"role": "admin"}},
            headers=headers,
        )
        assert st == 201, cred_body
        return cred_body["credential_id"]

    def batch(payload=None, headers=None, raw=None):
        return _http(
            "POST", f"{base}/v1/credentials/revoke-batch",
            payload=payload, headers=headers or T1, raw=raw,
        )

    def status(cid, headers=None):
        return _http("GET", f"{base}/v1/credentials/{cid}/status",
                     headers=headers or T1)

    def history(cid, headers=None):
        st, body = _http(
            "GET", f"{base}/v1/credentials/{cid}/status/history",
            headers=headers or T1,
        )
        assert st == 200, body
        return body["events"]

    def revoke_audits(headers):
        st, body = _http("GET", f"{base}/v1/audit?limit=200",
                         headers=headers or T1)
        assert st == 200, body
        return [e for e in body["events"]
                if e["action"] == "credential.revoked"]

    def suspend(cid, reason):
        return _http(
            "PUT", f"{base}/v1/credentials/{cid}/status",
            {"status": "suspended", "reason": reason}, headers=T1)

    try:
        cid1 = issue(T1)
        cid2 = issue(T1)
        cid3 = issue(T1)
        cid4 = issue(T1)
        cid_other = issue(T2)

        # ---- 1. 请求级 400 ----
        bad_requests = [
            ("空体", None, b"", T1),
            ("非法 JSON", None, b"{", T1),
            ("非对象", None, b"[1,2]", T1),
            ("缺少 items", {}, None, T1),
            ("外层多余字段", {"items": [], "x": 1}, None, T1),
            ("items 非数组", {"items": {}}, None, T1),
            ("items 为空", {"items": []}, None, T1),
            ("items 超 100",
             {"items": [{"credential_id": "vc_x"}] * 101}, None, T1),
            ("项非对象", {"items": ["x"]}, None, T1),
            ("项缺少 credential_id",
             {"items": [{"reason": "r"}]}, None, T1),
            ("项多余字段",
             {"items": [{"credential_id": "vc_x", "x": 1}]}, None, T1),
            ("credential_id 非字符串",
             {"items": [{"credential_id": 1}]}, None, T1),
            ("credential_id 为空",
             {"items": [{"credential_id": ""}]}, None, T1),
            ("批内重复",
             {"items": [{"credential_id": "vc_x"},
                        {"credential_id": "vc_x"}]}, None, T1),
            ("reason 非字符串",
             {"items": [{"credential_id": "vc_x", "reason": 1}]},
             None, T1),
            ("reason 为 null",
             {"items": [{"credential_id": "vc_x", "reason": None}]},
             None, T1),
            ("reason 裁剪后为空",
             {"items": [{"credential_id": "vc_x", "reason": "   "}]},
             None, T1),
        ]
        for name, payload, raw_body, headers in bad_requests:
            if raw_body is not None:
                st, body = batch(raw=raw_body, headers=headers)
            else:
                st, body = batch(payload, headers)
            check(f"{name} -> 400 非空 error",
                  st == 400 and isinstance(body.get("error"), str)
                  and body["error"])

        st, body = batch({"items": [{"credential_id": cid1}]},
                         headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400",
              st == 400 and bool(body.get("error")))

        st, s1 = status(cid1)
        check("400 后凭证仍为无状态 active",
              st == 200 and s1["status"] == "active"
              and s1["updated_at"] is None)
        check("400 后无吊销审计", revoke_audits(T1) == [])
        check("400 后无状态历史", history(cid1) == [])

        # ---- 2. 资源级 404，整批不变 ----
        cid_fresh = issue(T1)
        st, body = batch(
            {"items": [
                {"credential_id": "vc_0000000000000000000000000000none"},
                {"credential_id": cid_fresh}]})
        check("批内未知凭证 -> 404",
              st == 404 and bool(body.get("error")))
        st, sf = status(cid_fresh)
        check("404 整批不变（fresh 仍 active）",
              st == 200 and sf["status"] == "active"
              and sf["updated_at"] is None)
        st, body = batch({"items": [{"credential_id": cid_other}]},
                         headers=T1)
        check("跨租户凭证 -> 404",
              st == 404 and bool(body.get("error")))
        check("404 不记审计", revoke_audits(T1) == [])

        # ---- 3. 成功批次：默认原因/裁剪原因/暂停态吊销 ----
        st, sp = suspend(cid3, "调查中")
        assert st == 200, sp
        st, body = batch(
            {"items": [
                {"credential_id": cid1},
                {"credential_id": cid2, "reason": "  持证人造假  "},
                {"credential_id": cid3, "reason": "终态吊销"},
            ]})
        check("混合批次 -> 200", st == 200)
        results = body.get("results")
        check("响应恰含 results", set(body) == {"results"})
        check("results 等长", isinstance(results, list) and len(results) == 3)
        check("results 同序",
              [r.get("credential_id") for r in results]
              == [cid1, cid2, cid3])
        check("每项键序同单张吊销",
              [list(r) for r in results] == [RESULT_KEYS] * 3)
        r1, r2, r3 = results
        check("默认 reason + revoked 字段",
              r1["status"] == "revoked"
              and r1["reason"] == DEFAULT_REVOKE_REASON
              and r1["revoked_at"] == r1["updated_at"]
              and bool(Z_RE.match(r1["revoked_at"])))
        check("自定义 reason 裁剪保存",
              r2["reason"] == "持证人造假"
              and r2["revoked_at"] == r2["updated_at"])
        check("暂停态凭证吊销结果",
              r3["status"] == "revoked" and r3["reason"] == "终态吊销")

        st, s2 = status(cid2)
        check("GET status 为 revoked",
              st == 200 and s2["status"] == "revoked")
        h1, h2, h3 = history(cid1), history(cid2), history(cid3)
        check("首次吊销各追加一条 revoked 历史",
              [e["status"] for e in h1] == ["revoked"]
              and [e["status"] for e in h2] == ["revoked"]
              and [e["status"] for e in h3] == ["suspended", "revoked"])
        check("历史保存首次原因与 revoked_at",
              h1[0]["reason"] == DEFAULT_REVOKE_REASON
              and h2[0]["reason"] == "持证人造假"
              and h3[1]["reason"] == "终态吊销"
              and h3[1]["revoked_at"] == h3[1]["updated_at"]
              and h3[1]["cursor"] > h3[0]["cursor"])
        check("批内游标按输入顺序递增",
              h1[0]["cursor"] < h2[0]["cursor"] < h3[1]["cursor"])
        check("历史事件关联审计序号",
              all(isinstance(e["audit_seq"], int)
                  and isinstance(e["audit_timestamp"], int)
                  for e in h1 + h2 + [h3[1]]))
        audits = revoke_audits(T1)
        check("首次吊销每项各一条审计",
              [(a["resource_type"], a["resource_id"]) for a in audits]
              == [("credential", cid1), ("credential", cid2),
                  ("credential", cid3)])

        # ---- 4. 重复吊销：保持首次结果，仅留审计不追加历史 ----
        first = r1
        st, body = batch(
            {"items": [{"credential_id": cid1, "reason": "   "}]})
        check("已吊销凭证上非法 reason 仍 400",
              st == 400 and bool(body.get("error")))
        check("非法重复请求不记审计",
              len(revoke_audits(T1)) == 3 and len(history(cid1)) == 1)

        st, body = batch({"items": [
            {"credential_id": cid1, "reason": "别的原因"},
            {"credential_id": cid4},
        ]})
        check("重复+首次混合批次 200", st == 200)
        rr1, rr4 = body["results"]
        check("重复项保持首次 reason/时间",
              rr1["reason"] == first["reason"]
              and rr1["revoked_at"] == first["revoked_at"]
              and rr1["updated_at"] == first["updated_at"])
        check("新凭证首次吊销",
              rr4["status"] == "revoked"
              and rr4["reason"] == DEFAULT_REVOKE_REASON)
        check("重复不追加历史", len(history(cid1)) == 1)
        check("重复不推进游标（新事件游标继续递增）",
              history(cid4)[0]["cursor"] > h3[1]["cursor"])
        audits = revoke_audits(T1)
        check("重复请求仍记一条审计、顺序为 cid1 后 cid4",
              [a["resource_id"] for a in audits[-2:]] == [cid1, cid4])

        # ---- 5. 100 项形状合法后才进入资源校验 ----
        st, _ = batch(
            {"items": [{"credential_id": f"vc_dummy_{i}"}
                       for i in range(100)]})
        check("100 项 -> 404（非 400）", st == 404)

        # ---- 6. 并发：单张与批次混合，只有一个首次吊销 ----
        cid_conc = issue(T1)
        barrier = threading.Barrier(8)
        outcomes = []
        lock = threading.Lock()

        def worker(idx):
            barrier.wait()
            if idx % 2 == 0:
                st, resp = _http(
                    "POST", f"{base}/v1/credentials/{cid_conc}/revoke",
                    {"reason": f"并发原因{idx}"}, headers=T1)
            else:
                st, resp = batch(
                    {"items": [{"credential_id": cid_conc,
                                "reason": f"并发原因{idx}"}]},
                    headers=T1)
            with lock:
                outcomes.append((st, resp))

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        check("并发请求全部 200",
              len(outcomes) == 8 and all(st == 200 for st, _ in outcomes))
        payloads = [resp for _, resp in outcomes]
        if payloads:
            p0 = (payloads[0] if "results" not in payloads[0]
                  else payloads[0]["results"][0])
            normalized = [
                p if "results" not in p else p["results"][0]
                for p in payloads
            ]
            check("并发结果全部等于同一个首次吊销结果",
                  all(p == p0 for p in normalized))
        check("并发后仅一条 revoked 历史",
              len(history(cid_conc)) == 1)
        check("并发后每个请求各留一条审计（共 8 条）",
              len([a for a in revoke_audits(T1)
                   if a["resource_id"] == cid_conc]) == 8)

        # ---- 7. 重启稳定 ----
        h4_before = history(cid4)
        audits_before = revoke_audits(T1)
        cid_rb1 = issue(T1)
        cid_rb2 = issue(T1)
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server(PORT, store_path)
        st, sc = status(cid4)
        check("重启后吊销状态保持",
              st == 200 and sc["status"] == "revoked")
        check("重启后历史与游标逐字一致",
              history(cid4) == h4_before)
        check("重启后审计顺序一致", revoke_audits(T1) == audits_before)
        st, body = batch({"items": [{"credential_id": cid4}]})
        check("重启后重试为重复吊销、首次结果不变",
              st == 200
              and body["results"][0]["revoked_at"]
              == h4_before[0]["revoked_at"]
              and len(history(cid4)) == 1)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    # ---- 8. 落盘失败整体回滚（直连 VCStore）----
    direct = VCStore(store_path)
    audit_before = len(direct._audit)  # noqa: SLF001
    cursor_before = dict(
        direct._local_credential_status_history_cursors  # noqa: SLF001
    )
    with open(store_path, encoding="utf-8") as fh:
        disk_before = fh.read()

    real_save = direct._save_locked  # noqa: SLF001

    def boom():
        raise OSError("模拟落盘失败")

    direct._save_locked = boom  # type: ignore[assignment]  # noqa: SLF001
    raised = False
    try:
        direct.revoke_credentials_batch(
            "rb-a",
             [(cid_rb1, REASON_UNSET),
             (cid_rb2, "回滚原因")],
        )
    except OSError:
        raised = True
    check("落盘失败原样抛 OSError", raised)

    bucket = direct._tenants["rb-a"]  # noqa: SLF001
    rec1 = bucket["credentials"][cid_rb1]
    rec2 = bucket["credentials"][cid_rb2]
    check("内存态状态回滚（仍非 revoked）",
          rec1.get("status") != "revoked"
          and rec2.get("status") != "revoked"
          and "revoke_reason" not in rec1)
    check("内存态历史/游标/审计回滚",
          not bucket["local_credential_status_history"].get(cid_rb1)
          and not bucket["local_credential_status_history"].get(cid_rb2)
          and len(direct._audit) == audit_before  # noqa: SLF001
          and dict(direct._local_credential_status_history_cursors)  # noqa: SLF001
          == cursor_before)
    with open(store_path, encoding="utf-8") as fh:
        check("磁盘文件字节不变", fh.read() == disk_before)

    reloaded = VCStore(store_path)
    rrec = reloaded._tenants["rb-a"]["credentials"][cid_rb1]  # noqa: SLF001
    check("重新加载无半写状态", rrec.get("status") != "revoked")

    # 故障排除后重试：一次成功，事件不重复
    direct._save_locked = real_save  # type: ignore[assignment]  # noqa: SLF001
    records = direct.revoke_credentials_batch(
        "rb-a",
        [(cid_rb1, REASON_UNSET), (cid_rb2, "回滚原因")],
    )
    check("回滚后重试成功且等长同序",
          len(records) == 2
          and [r.credential_id for r in records] == [cid_rb1, cid_rb2]
          and records[0].reason == DEFAULT_REVOKE_REASON
          and records[1].reason == "回滚原因")
    check("重试仅各追加一次历史与审计",
          len(direct._tenants["rb-a"][  # noqa: SLF001
              "local_credential_status_history"][cid_rb1]) == 1
          and len(direct._tenants["rb-a"][  # noqa: SLF001
              "local_credential_status_history"][cid_rb2]) == 1
          and len(direct._audit) == audit_before + 2)  # noqa: SLF001
    # 暂停原因清除验证
    cid3_rec = direct._tenants["rb-a"]["credentials"][cid3]  # noqa: SLF001
    check("已暂停凭证吊销后暂停原因清除",
          cid3_rec["status"] == "revoked"
          and cid3_rec.get("suspend_reason") is None)

    if failures:
        print(f"\n{len(failures)} 项失败")
        sys.exit(1)
    print("\n全部通过")


if __name__ == "__main__":
    main()
