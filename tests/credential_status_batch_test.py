#!/usr/bin/env python3
"""PUT /v1/credentials/status-batch 整批原子状态变更端到端测试。

覆盖：
- 请求级 400：空体、非法 JSON、非对象、外层缺/多 items、items 非数组、
  空数组、超过 100、项非对象、项缺 credential_id/status、多余字段、
  credential_id 非字符串/为空/批内重复、status 取值非法、active 项携带
  reason、suspended 项缺 reason、reason 非字符串/裁剪后为空/超过 256
  码点，响应均仅含非空 error；
- 显式空 X-Tenant-ID 400；未知凭证 404、跨租户 404；格式校验先于存在性
  （整批格式非法即 400 而非 404）；按输入顺序首个失败项决定响应
  （前冲突后缺失 409、前缺失后冲突 404）；400/404/409 均整批不落盘；
- 409：已吊销凭证变更状态、已暂停凭证以不同裁剪原因再暂停；
- 成功 200：混合批次（首次登记 active、直接暂停、暂停已登记、恢复、
  active 幂等、suspended 同原因幂等）results 与输入等长同序、每项恰含
  credential_id/status/updated_at；幂等项保持首次 updated_at；
- 首次登记/暂停/恢复各追加一条状态历史并推进租户内游标（批内按输入
  顺序递增），幂等项不追加历史不推进游标；每个成功项（含幂等）按输入
  顺序各记一条 status.updated 审计，历史事件关联对应审计序号与时间；
- 恢复后暂停原因清除（可以不同原因再次暂停）；凭证正文与签名不变；
  新状态可经 GET status、状态历史与 status-export 观察；
- 整批重放幂等结论稳定；重启后状态、历史、游标、审计顺序稳定；
- 直连 VCStore：落盘失败时状态、历史、游标、审计整体回滚（审计序号
  不占用），磁盘不变，故障排除后重试成功且事件不重复。

直接运行：python3 tests/credential_status_batch_test.py
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

from vcbackend.store import REASON_UNSET, VCStore  # noqa: E402

PORT = 8992
Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
RESULT_KEYS = ["credential_id", "status", "updated_at"]


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
    T1 = {"X-Tenant-ID": "sb-a"}
    T2 = {"X-Tenant-ID": "sb-b"}

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
            "PUT", f"{base}/v1/credentials/status-batch",
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

    def status_audits(headers=None):
        st, body = _http("GET", f"{base}/v1/audit?limit=200",
                         headers=headers or T1)
        assert st == 200, body
        return [e for e in body["events"]
                if e["action"] == "status.updated"]

    def put_status(cid, payload, headers=None):
        return _http("PUT", f"{base}/v1/credentials/{cid}/status",
                     payload, headers=headers or T1)

    def get_credential(cid, headers=None):
        st, body = _http("GET", f"{base}/v1/credentials/{cid}",
                         headers=headers or T1)
        assert st == 200, body
        return body

    try:
        cid_other = issue(T2)

        # ---- 1. 请求级 400，响应仅含非空 error ----
        bad_requests = [
            ("空体", None, b""),
            ("非法 JSON", None, b"{"),
            ("非对象", None, b"[1,2]"),
            ("缺少 items", {}, None),
            ("外层多余字段", {"items": [{"credential_id": "vc_x",
                                        "status": "active"}],
                              "x": 1}, None),
            ("items 非数组", {"items": {}}, None),
            ("items 为空", {"items": []}, None),
            ("items 超 100",
             {"items": [{"credential_id": f"vc_{i}", "status": "active"}
                        for i in range(101)]}, None),
            ("项非对象", {"items": ["x"]}, None),
            ("项缺少 credential_id",
             {"items": [{"status": "active"}]}, None),
            ("项缺少 status",
             {"items": [{"credential_id": "vc_x"}]}, None),
            ("项多余字段",
             {"items": [{"credential_id": "vc_x", "status": "active",
                         "x": 1}]}, None),
            ("credential_id 非字符串",
             {"items": [{"credential_id": 1, "status": "active"}]}, None),
            ("credential_id 为空",
             {"items": [{"credential_id": "", "status": "active"}]}, None),
            ("批内重复",
             {"items": [{"credential_id": "vc_x", "status": "active"},
                        {"credential_id": "vc_x",
                         "status": "suspended", "reason": "r"}]}, None),
            ("status 取值非法",
             {"items": [{"credential_id": "vc_x", "status": "revoked"}]},
             None),
            ("status 非字符串",
             {"items": [{"credential_id": "vc_x", "status": 1}]}, None),
            ("status 为 null",
             {"items": [{"credential_id": "vc_x", "status": None}]}, None),
            ("active 项携带 reason",
             {"items": [{"credential_id": "vc_x", "status": "active",
                         "reason": "r"}]}, None),
            ("suspended 项缺 reason",
             {"items": [{"credential_id": "vc_x",
                         "status": "suspended"}]}, None),
            ("reason 非字符串",
             {"items": [{"credential_id": "vc_x", "status": "suspended",
                         "reason": 1}]}, None),
            ("reason 为 null",
             {"items": [{"credential_id": "vc_x", "status": "suspended",
                         "reason": None}]}, None),
            ("reason 裁剪后为空",
             {"items": [{"credential_id": "vc_x", "status": "suspended",
                         "reason": "   "}]}, None),
            ("reason 超 256 码点",
             {"items": [{"credential_id": "vc_x", "status": "suspended",
                         "reason": "长" * 257}]}, None),
        ]
        for name, payload, raw_body in bad_requests:
            if raw_body is not None:
                st, body = batch(raw=raw_body)
            else:
                st, body = batch(payload)
            check(f"{name} -> 400 仅含非空 error",
                  st == 400 and set(body) == {"error"}
                  and isinstance(body["error"], str) and body["error"])

        st, body = batch({"items": [{"credential_id": "vc_x",
                                     "status": "active"}]},
                         headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400 and bool(body.get("error")))

        check("400 后不记审计", status_audits() == [])

        # reason 恰好 256 码点合法：进入资源检查 -> 404（非 400）
        st, body = batch({"items": [
            {"credential_id": "vc_0000000000000000000000000000none",
             "status": "suspended", "reason": "长" * 256}]})
        check("reason 256 码点合法（未知凭证 -> 404）", st == 404)

        # ---- 2. 资源级 404 与失败顺序 ----
        cid_a = issue(T1)  # 将首次登记 active
        cid_b = issue(T1)  # 将直接暂停
        cid_c = issue(T1)  # 先登记 active，批内暂停
        cid_d = issue(T1)  # 先暂停，批内恢复
        cid_e = issue(T1)  # 先登记 active，批内幂等
        cid_f = issue(T1)  # 先暂停，批内同原因幂等
        cid_g = issue(T1)  # 冲突测试用
        cid_h = issue(T1)  # 吊销后变更 -> 409

        st, body = batch({"items": [{"credential_id": cid_other,
                                     "status": "active"}]})
        check("跨租户凭证 -> 404 仅含 error",
              st == 404 and set(body) == {"error"} and body["error"])
        st, body = batch({"items": [
            {"credential_id": "vc_0000000000000000000000000000none",
             "status": "active"},
            {"credential_id": cid_a, "status": "active"}]})
        check("批内未知凭证 -> 404", st == 404 and bool(body.get("error")))
        st, sa = status(cid_a)
        check("404 整批不变（cid_a 仍无状态）",
              st == 200 and sa["status"] == "active"
              and sa["updated_at"] is None)
        check("404 不记审计", status_audits() == [])

        # 格式校验先于存在性：首项未知、次项格式非法 -> 400
        st, body = batch({"items": [
            {"credential_id": "vc_0000000000000000000000000000none",
             "status": "active"},
            {"credential_id": "vc_y"}]})
        check("格式错误先于存在性（400 而非 404）", st == 400)

        # 准备冲突场景：cid_g 暂停（原因甲），cid_h 吊销
        st, body = put_status(cid_g, {"status": "suspended",
                                      "reason": "原因甲"})
        assert st == 200, body
        st, body = _http("POST", f"{base}/v1/credentials/{cid_h}/revoke",
                         {"reason": "终态"}, headers=T1)
        assert st == 200, body

        st, body = batch({"items": [
            {"credential_id": cid_g, "status": "suspended",
             "reason": "原因乙"},
            {"credential_id": cid_a, "status": "active"}]})
        check("已暂停凭证不同原因 -> 409 仅含 error",
              st == 409 and set(body) == {"error"} and body["error"])
        st, sa = status(cid_a)
        check("409 整批不变（cid_a 仍无状态）",
              st == 200 and sa["updated_at"] is None)

        st, body = batch({"items": [
            {"credential_id": cid_h, "status": "active"}]})
        check("已吊销凭证变更状态 -> 409", st == 409)
        st, body = batch({"items": [
            {"credential_id": cid_h, "status": "suspended",
             "reason": "r"}]})
        check("已吊销凭证暂停 -> 409", st == 409)

        # 按输入顺序首个失败项决定响应
        st, body = batch({"items": [
            {"credential_id": cid_g, "status": "suspended",
             "reason": "原因乙"},
            {"credential_id": "vc_0000000000000000000000000000none",
             "status": "active"}]})
        check("前冲突后缺失 -> 409", st == 409)
        st, body = batch({"items": [
            {"credential_id": "vc_0000000000000000000000000000none",
             "status": "active"},
            {"credential_id": cid_g, "status": "suspended",
             "reason": "原因乙"}]})
        check("前缺失后冲突 -> 404", st == 404)
        check("409/404 均不新增审计", len(status_audits()) == 1)  # 仅 cid_g 单张暂停

        # ---- 3. 成功混合批次 ----
        st, body = put_status(cid_c, {"status": "active"})
        assert st == 201, body
        st, body = put_status(cid_d, {"status": "suspended",
                                      "reason": "预先暂停"})
        assert st == 200, body
        st, body = put_status(cid_e, {"status": "active"})
        assert st == 201, body
        e_updated = body["updated_at"]
        st, body = put_status(cid_f, {"status": "suspended",
                                      "reason": "保持原因"})
        assert st == 200, body
        f_updated = body["updated_at"]
        audits_before = status_audits()
        cred_b_before = get_credential(cid_b)
        cred_d_before = get_credential(cid_d)

        st, body = batch({"items": [
            {"credential_id": cid_a, "status": "active"},
            {"credential_id": cid_b, "status": "suspended",
             "reason": "  批内暂停  "},
            {"credential_id": cid_c, "status": "suspended",
             "reason": "批内再暂停"},
            {"credential_id": cid_d, "status": "active"},
            {"credential_id": cid_e, "status": "active"},
            {"credential_id": cid_f, "status": "suspended",
             "reason": "保持原因"},
        ]})
        check("混合批次 -> 200", st == 200)
        check("响应恰含 results", set(body) == {"results"})
        results = body.get("results")
        check("results 等长", isinstance(results, list) and len(results) == 6)
        check("results 同序",
              [r.get("credential_id") for r in results]
              == [cid_a, cid_b, cid_c, cid_d, cid_e, cid_f])
        check("每项恰含 credential_id/status/updated_at",
              [list(r) for r in results] == [RESULT_KEYS] * 6)
        ra, rb, rc, rd, re_, rf = results
        check("各项状态正确",
              [r["status"] for r in results]
              == ["active", "suspended", "suspended",
                  "active", "active", "suspended"])
        check("变更项 updated_at 为 UTC 秒精度 Z",
              all(Z_RE.match(r["updated_at"])
                  for r in (ra, rb, rc, rd)))
        check("幂等项保持首次 updated_at",
              re_["updated_at"] == e_updated
              and rf["updated_at"] == f_updated)

        st, sb = status(cid_b)
        check("GET status 可观察暂停",
              st == 200 and sb["status"] == "suspended")
        st, sd = status(cid_d)
        check("GET status 可观察恢复",
              st == 200 and sd["status"] == "active")

        ha = history(cid_a)
        hb = history(cid_b)
        hc = history(cid_c)
        hd = history(cid_d)
        he = history(cid_e)
        hf = history(cid_f)
        check("首次登记/暂停/恢复各追加一条历史",
              [e["status"] for e in ha] == ["active"]
              and [e["status"] for e in hb] == ["suspended"]
              and [e["status"] for e in hc] == ["active", "suspended"]
              and [e["status"] for e in hd] == ["suspended", "active"])
        check("幂等项不追加历史",
              [e["status"] for e in he] == ["active"]
              and [e["status"] for e in hf] == ["suspended"])
        check("历史保存裁剪原因、恢复清除原因",
              hb[0]["reason"] == "批内暂停"
              and hc[1]["reason"] == "批内再暂停"
              and hd[1]["reason"] is None
              and hd[1]["revoked_at"] is None)
        check("批内游标按输入顺序递增",
              ha[0]["cursor"] < hb[0]["cursor"]
              < hc[1]["cursor"] < hd[1]["cursor"])
        check("幂等项不推进游标（后续事件游标继续递增）",
              he[0]["cursor"] < ha[0]["cursor"]
              and hf[0]["cursor"] < ha[0]["cursor"])

        audits = status_audits()
        new_audits = audits[len(audits_before):]
        check("每个成功项（含幂等）各记一条审计、按输入顺序",
              [(a["resource_type"], a["resource_id"]) for a in new_audits]
              == [("credential", cid) for cid in
                  (cid_a, cid_b, cid_c, cid_d, cid_e, cid_f)])
        audit_by_res = {a["resource_id"]: a for a in new_audits}
        check("历史事件关联对应审计序号与时间",
              ha[0]["audit_seq"] == audit_by_res[cid_a]["seq"]
              and ha[0]["audit_timestamp"]
              == audit_by_res[cid_a]["timestamp"]
              and hb[0]["audit_seq"] == audit_by_res[cid_b]["seq"]
              and hc[1]["audit_seq"] == audit_by_res[cid_c]["seq"]
              and hd[1]["audit_seq"] == audit_by_res[cid_d]["seq"])

        # 凭证正文与签名不变
        cred_b_after = get_credential(cid_b)
        cred_d_after = get_credential(cid_d)
        check("状态变更后凭证正文与签名不变",
              cred_b_after == cred_b_before
              and cred_d_after == cred_d_before)

        # 状态签名发布接口可观察新状态
        st, body = _http(
            "POST", f"{base}/v1/credentials/status-export",
            {"credential_ids": [cid_a, cid_b, cid_d]}, headers=T1)
        check("status-export 可观察新状态",
              st == 200
              and [i["body"]["status"] for i in body["items"]]
              == ["active", "suspended", "active"]
              and body["items"][1]["body"]["reason"] == "批内暂停")

        # ---- 4. 整批重放：幂等结论稳定 ----
        audits_before_replay = status_audits()
        st, body = batch({"items": [
            {"credential_id": cid_a, "status": "active"},
            {"credential_id": cid_b, "status": "suspended",
             "reason": "批内暂停"},
            {"credential_id": cid_c, "status": "suspended",
             "reason": "批内再暂停"},
            {"credential_id": cid_d, "status": "active"},
            {"credential_id": cid_e, "status": "active"},
            {"credential_id": cid_f, "status": "suspended",
             "reason": "保持原因"},
        ]})
        check("整批重放 -> 200 且结果逐项一致",
              st == 200
              and body["results"] == [ra, rb, rc, rd, re_, rf])
        check("重放不追加历史",
              len(history(cid_a)) == 1 and len(history(cid_b)) == 1
              and len(history(cid_c)) == 2 and len(history(cid_f)) == 1)
        check("重放每项仍各记一条审计",
              len(status_audits()) == len(audits_before_replay) + 6)

        # 恢复后暂停原因已清除：可以不同原因再次暂停
        st, body = put_status(cid_d, {"status": "suspended",
                                      "reason": "新的原因"})
        check("恢复后可以不同原因再次暂停", st == 200)
        st, body = put_status(cid_d, {"status": "active"})
        assert st == 200, body

        # ---- 5. 重启稳定 ----
        hb_before = history(cid_b)
        audits_before_restart = status_audits()
        cid_rb1 = issue(T1)
        cid_rb2 = issue(T1)
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server(PORT, store_path)
        st, sb2 = status(cid_b)
        check("重启后暂停状态保持",
              st == 200 and sb2["status"] == "suspended")
        check("重启后历史与游标逐字一致", history(cid_b) == hb_before)
        check("重启后审计顺序一致",
              status_audits() == audits_before_restart)
        st, body = batch({"items": [
            {"credential_id": cid_b, "status": "suspended",
             "reason": "批内暂停"}]})
        check("重启后重放仍为幂等",
              st == 200
              and body["results"][0]["updated_at"] == rb["updated_at"]
              and len(history(cid_b)) == 1)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    # ---- 6. 落盘失败整体回滚（直连 VCStore）----
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
        direct.set_credential_status_batch(
            "sb-a",
            [(cid_rb1, "suspended", "回滚暂停"),
             (cid_rb2, "active", REASON_UNSET)],
        )
    except OSError:
        raised = True
    check("落盘失败原样抛 OSError", raised)

    bucket = direct._tenants["sb-a"]  # noqa: SLF001
    rec1 = bucket["credentials"][cid_rb1]
    rec2 = bucket["credentials"][cid_rb2]
    check("内存态状态回滚（仍无状态）",
          rec1.get("status") is None and rec2.get("status") is None
          and "suspend_reason" not in rec1)
    check("内存态历史/游标/审计回滚（审计序号不占用）",
          not bucket["local_credential_status_history"].get(cid_rb1)
          and not bucket["local_credential_status_history"].get(cid_rb2)
          and len(direct._audit) == audit_before  # noqa: SLF001
          and dict(direct._local_credential_status_history_cursors)  # noqa: SLF001
          == cursor_before)
    with open(store_path, encoding="utf-8") as fh:
        check("磁盘文件字节不变", fh.read() == disk_before)

    reloaded = VCStore(store_path)
    rrec = reloaded._tenants["sb-a"]["credentials"][cid_rb1]  # noqa: SLF001
    check("重新加载无半写状态", rrec.get("status") is None)

    # 故障排除后重试：一次成功，事件不重复
    direct._save_locked = real_save  # type: ignore[assignment]  # noqa: SLF001
    records = direct.set_credential_status_batch(
        "sb-a",
        [(cid_rb1, "suspended", "回滚暂停"),
         (cid_rb2, "active", REASON_UNSET)],
    )
    check("回滚后重试成功且等长同序",
          len(records) == 2
          and [r.credential_id for r in records] == [cid_rb1, cid_rb2]
          and records[0].status == "suspended"
          and records[0].reason == "回滚暂停"
          and records[1].status == "active")
    check("重试仅各追加一次历史与审计",
          len(direct._tenants["sb-a"][  # noqa: SLF001
              "local_credential_status_history"][cid_rb1]) == 1
          and len(direct._tenants["sb-a"][  # noqa: SLF001
              "local_credential_status_history"][cid_rb2]) == 1
          and len(direct._audit) == audit_before + 2)  # noqa: SLF001

    if failures:
        print(f"\n{len(failures)} 项失败")
        sys.exit(1)
    print("\n全部通过")


if __name__ == "__main__":
    main()
