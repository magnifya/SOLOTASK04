#!/usr/bin/env python3
"""DID 密钥版本吊销（POST /v1/dids/{did}/keys/{ver}/revoke）端到端测试。

覆盖：
- 路径 key_version 须为 ASCII 十进制正整数（0/负/小数/字母/空 400）；
- 空体或 {} 省略 reason（默认原因），非空须恰含 reason，裁剪后非空字符串，
  显式 null/数字/空白 400，多余字段 400；
- DID/版本（含他租户）不存在 404，当前版本 409；
- 旧版本首次 200 返回 did/key_version/status/reason/updated_at（UTC 秒 Z），
  重复吊销忽略任何 reason（含非法值）返回首次结果；
- 审计 key.revoked（resource_type=did、resource_id=<did>#<ver>），失败不记；
- 吊销版本仍在 document 历史中；轮换版本照常签发；
- 凭证 verify 验签后按 签发密钥→有效期→凭证吊销 判定；
- 演示 verify：已消费/演示过期优先，其次签发密钥、持有者密钥，失败不消费；
- 谓词证明 verify 验签后查签发密钥，失败不消费；
- present/prove 遇吊销签发（或绑定 holder）版本 400 且不留记录/审计；
- 旧凭证缺 issuer_key_version 按版本 1 兼容；租户隔离；重启保留；
- 落盘失败回滚（版本不变、审计不记）。

直接运行：python3 tests/key_revocation_test.py
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PORT = 8961
STORE = tempfile.mktemp(suffix=".json")
BASE = f"http://127.0.0.1:{PORT}"

Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
REVOKE_KEY_FIELDS = {"did", "key_version", "status", "reason", "updated_at"}


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


def start_server():
    env = dict(os.environ, VCBACKEND_STORE=STORE)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(PORT), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up(PORT), "服务启动超时"
    return proc


def run_direct_store_checks(failures, check):
    """直连 VCStore 覆盖 HTTP 不易构造的路径。"""
    from vcbackend.crypto import sign
    from vcbackend.store import (
        VCStore, ValidationError, DEFAULT_KEY_REVOKE_REASON,
    )

    # 1. 落盘失败回滚：吊销不生效、审计不记录
    path = tempfile.mktemp(suffix=".json")
    store = VCStore(path)
    d = store.create_did("dt", "example", "rollback-did")
    store.rotate_key("dt", d.did, "rb2")

    def _boom():
        raise OSError("模拟落盘失败")

    store._save_locked = _boom  # type: ignore[assignment]
    raised = False
    try:
        store.revoke_key_version("dt", d.did, 1, reason="x")
    except OSError:
        raised = True
    check("落盘失败时 revoke_key_version 抛错", raised)
    events = store.list_audit("dt", 0, 200)[0]
    check("落盘失败不记 key.revoked 审计",
          all(e.action != "key.revoked" for e in events))
    _, entry = store._key_history_entry_locked(  # noqa: SLF001
        store._bucket_locked("dt"), d.did, 1  # noqa: SLF001
    )
    check("落盘失败吊销标记回滚（版本不变）", entry.get("status") != "revoked")

    # 2. 旧凭证缺 issuer_key_version 按版本 1：吊销 v1 后 verify 拦截
    path2 = tempfile.mktemp(suffix=".json")
    s2 = VCStore(path2)
    iss = s2.create_did("dt", "example", "legacy-issuer")
    sub = s2.create_did("dt", "example", "legacy-sub")
    raw_cred = s2.create_credential("dt", iss.did, sub.did, {"k": 1})
    legacy_body = dict(raw_cred.body)
    legacy_body.pop("issuer_key_version", None)  # 旧凭证正文不带版本
    legacy_sig = sign(legacy_body,
                      s2._private_key_for_version_locked(  # noqa: SLF001
                          s2._bucket_locked("dt"), iss.did, 1))  # noqa: SLF001
    s2._bucket_locked("dt")["credentials"][raw_cred.credential_id] = {  # noqa: SLF001
        "body": legacy_body, "signature": legacy_sig,
    }
    s2.rotate_key("dt", iss.did, "legacy-issuer-v2")
    ok, why = s2.verify_credential(
        "dt", raw_cred.credential_id, legacy_body, legacy_sig)
    check("旧凭证（缺版本）吊销前仍 valid", ok and why == "")
    s2.revoke_key_version("dt", iss.did, 1, reason="旧版泄漏")
    ok, why = s2.verify_credential(
        "dt", raw_cred.credential_id, legacy_body, legacy_sig)
    check("旧凭证缺版本按 1：签发密钥吊销优先",
          (not ok) and why == "签发密钥已吊销：旧版泄漏")

    # 3. 密钥吊销优先于凭证有效期：构造已到期凭证 + 已吊销签发密钥
    path3 = tempfile.mktemp(suffix=".json")
    s3 = VCStore(path3)
    i3 = s3.create_did("dt", "example", "exp-issuer")
    b3 = s3.create_did("dt", "example", "exp-sub")
    c3 = s3.create_credential("dt", i3.did, b3.did, {"k": 1})
    body = dict(c3.body)
    body["expires_at"] = "2000-01-01T00:00:00Z"  # 早已到期
    sig = sign(body, s3._private_key_for_version_locked(  # noqa: SLF001
        s3._bucket_locked("dt"), i3.did, 1))  # noqa: SLF001
    s3._bucket_locked("dt")["credentials"][c3.credential_id] = {  # noqa: SLF001
        "body": body, "signature": sig,
    }
    s3.rotate_key("dt", i3.did, "exp-issuer-v2")
    s3.revoke_key_version("dt", i3.did, 1, reason="key-first")
    ok, why = s3.verify_credential("dt", c3.credential_id, body, sig)
    check("签发密钥吊销优先于凭证有效期",
          (not ok) and why == "签发密钥已吊销：key-first")

    # 4. 防御路径：绑定生成时持有者“当前版本”条目被直接标记吊销 -> 400
    path4 = tempfile.mktemp(suffix=".json")
    s4 = VCStore(path4)
    i4 = s4.create_did("dt", "example", "bh-issuer")
    h4 = s4.create_did("dt", "example", "bh-holder")
    c4 = s4.create_credential("dt", i4.did, h4.did, {"k": 1})
    _, h_entry = s4._key_history_entry_locked(  # noqa: SLF001
        s4._bucket_locked("dt"), h4.did, 1)  # noqa: SLF001
    h_entry["status"] = "revoked"
    h_entry["revoke_reason"] = "直接标记"
    h_entry["revoked_at"] = "2026-01-01T00:00:00Z"
    raised = False
    try:
        s4.create_presentation(
            "dt", c4.credential_id, [], challenge="c",
            expires_in=300, holder_binding=True)
    except ValidationError as exc:
        raised = "持有者密钥版本已吊销" in str(exc)
    check("绑定持有者版本吊销时 present 400", raised)
    check("绑定持有者版本吊销不留演示记录",
          not s4._bucket_locked("dt")["presentations"])  # noqa: SLF001
    check("默认密钥吊销原因非空", bool(DEFAULT_KEY_REVOKE_REASON))


def main():
    if os.path.exists(STORE):
        os.unlink(STORE)
    proc = start_server()
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def revoke(did, version, payload=None, headers=None, raw=None):
        url = (f"{BASE}/v1/dids/{urllib.parse.quote(did, safe='')}/keys/"
               f"{urllib.parse.quote(str(version), safe='')}/revoke")
        return _http("POST", url, payload=payload, headers=headers, raw=raw)

    def issue(issuer, subject, claims, headers=None):
        st, r = _http("POST", f"{BASE}/v1/credentials",
                      {"issuer_did": issuer, "subject_did": subject,
                       "claims": claims}, headers=headers)
        assert st == 201, (st, r)
        return r["credential_id"], r["signature"], r["issuer_key_version"]

    def get_cred(cid, headers=None):
        st, r = _http("GET", f"{BASE}/v1/credentials/{cid}", headers=headers)
        assert st == 200, (st, r)
        return r["body"], r["signature"]

    def verify_cred(cid, body, signature, headers=None):
        return _http("POST", f"{BASE}/v1/credentials/{cid}/verify",
                     {"body": body, "signature": signature}, headers=headers)

    def present(cid, disclose, challenge, expires_in=300,
                holder_binding=None, headers=None):
        body = {"disclose": disclose, "challenge": challenge,
                "expires_in": expires_in}
        if holder_binding is not None:
            body["holder_binding"] = holder_binding
        return _http("POST", f"{BASE}/v1/credentials/{cid}/present",
                     body, headers=headers)

    def verify_vp(vp_id, vp, challenge, headers=None):
        return _http("POST",
                     f"{BASE}/v1/presentations/{vp_id}/verify",
                     {"presentation": vp, "challenge": challenge},
                     headers=headers)

    def prove(cid, predicates, challenge, expires_in=300, headers=None):
        return _http("POST", f"{BASE}/v1/credentials/{cid}/prove",
                     {"predicates": predicates, "challenge": challenge,
                      "expires_in": expires_in}, headers=headers)

    def verify_proof(pid, pfo, challenge, headers=None):
        return _http("POST", f"{BASE}/v1/proofs/{pid}/verify",
                     {"proof": pfo, "challenge": challenge}, headers=headers)

    def audit(headers=None):
        st, r = _http("GET", f"{BASE}/v1/audit?limit=200", headers=headers)
        assert st == 200, (st, r)
        return r["events"]

    try:
        T1 = {"X-Tenant-ID": "kr-a"}
        T2 = {"X-Tenant-ID": "kr-b"}

        # ---- 注册 DID 与用 v1 签发的凭证/演示/证明 ----
        st, alice = _http("POST", f"{BASE}/v1/dids",
                          {"method": "example", "public_key": "kr-alice"},
                          headers=T1)
        assert st == 201, (st, alice)
        alice_did = alice["did"]
        st, bob = _http("POST", f"{BASE}/v1/dids",
                        {"method": "example", "public_key": "kr-bob"},
                        headers=T1)
        assert st == 201, (st, bob)
        bob_did = bob["did"]
        st, carol = _http("POST", f"{BASE}/v1/dids",
                          {"method": "example", "public_key": "kr-carol"},
                          headers=T1)
        assert st == 201, (st, carol)
        carol_did = carol["did"]

        c1, _, c1ver = issue(alice_did, bob_did,
                             {"role": "admin", "age": 30}, headers=T1)
        assert c1ver == 1

        # 各类待验对象（在吊销前生成）
        st, vp1 = present(c1, ["/role"], "ch1", headers=T1)
        assert st == 201, (st, vp1)
        st, vpb = present(c1, [], "chb", holder_binding=True, headers=T1)
        assert st == 201 and vpb["holder_key_version"] == 1, (st, vpb)
        st, zp1 = prove(c1, [{"path": "/age", "op": "gte", "value": 18}],
                        "chp", headers=T1)
        assert st == 201, (st, zp1)
        # 1 秒后过期的演示：用于“演示过期优先于密钥吊销”
        st, vpx = present(c1, ["/role"], "chx", expires_in=1, headers=T1)
        assert st == 201, (st, vpx)

        # 轮换 alice（当前 v2）、bob（当前 v2），再用新密钥签发
        st, r = _http("POST", f"{BASE}/v1/dids/{alice_did}/keys/rotate",
                      {"key_handle": "kr-alice-v2"}, headers=T1)
        assert st == 200 and r["key_version"] == 2, (st, r)
        st, r = _http("POST", f"{BASE}/v1/dids/{bob_did}/keys/rotate",
                      {"key_handle": "kr-bob-v2"}, headers=T1)
        assert st == 200 and r["key_version"] == 2, (st, r)
        c2, _, c2ver = issue(alice_did, bob_did, {"role": "new"}, headers=T1)
        assert c2ver == 2

        # ---- 1. 吊销接口基础协议 ----
        st, r = revoke(alice_did, 1, raw=b"", headers=T1)
        check("空体吊销旧版本 200", st == 200)
        check("响应字段恰为五项", set(r) == REVOKE_KEY_FIELDS)
        check("返回 did/key_version/status",
              r.get("did") == alice_did and r.get("key_version") == 1
              and r.get("status") == "revoked")
        check("默认 reason", r.get("reason") == "密钥版本主动吊销")
        check("updated_at 为 UTC 秒精度 Z",
              bool(Z_RE.match(r.get("updated_at", ""))))
        first_updated = r["updated_at"]

        # 重复吊销：{}、空体、自定义 reason、非法 reason 全部忽略
        for label, payload, raw in (
            ("{} 省略", {}, None),
            ("空体省略", None, b""),
            ("自定义 reason 被忽略", {"reason": "  别的原因  "}, None),
            ("数字 reason 被忽略", {"reason": 123}, None),
            ("空白 reason 被忽略", {"reason": "   "}, None),
            ("null reason 被忽略", {"reason": None}, None),
        ):
            st, rr = revoke(alice_did, 1, payload=payload, raw=raw, headers=T1)
            check(f"重复吊销（{label}）200 且返回首次结果",
                  st == 200 and rr.get("status") == "revoked"
                  and rr.get("reason") == "密钥版本主动吊销"
                  and rr.get("updated_at") == first_updated
                  and set(rr) == REVOKE_KEY_FIELDS)

        # 首次吊销的非法 reason 400（bob v1 尚未吊销）
        for label, payload in (
            ("null", {"reason": None}),
            ("数字", {"reason": 1}),
            ("空白串", {"reason": "   "}),
        ):
            st, rr = revoke(bob_did, 1, payload=payload, headers=T1)
            check(f"首次吊销非法 reason（{label}）400",
                  st == 400 and bool(rr.get("error")))
        st, rr = revoke(bob_did, 1, payload={"foo": 1}, headers=T1)
        check("多余字段 400", st == 400 and bool(rr.get("error")))
        st, rr = revoke(bob_did, 1, raw=b"not-json", headers=T1)
        check("非法 JSON 400", st == 400 and bool(rr.get("error")))
        st, rr = revoke(bob_did, 1, raw=b"[1,2]", headers=T1)
        check("非对象请求体 400", st == 400 and bool(rr.get("error")))

        # 路径参数
        for bad in ("0", "-1", "1.0", "abc", "+1", "１"):
            st, rr = revoke(alice_did, bad, payload={}, headers=T1)
            check(f"key_version={bad!r} 400",
                  st == 400 and bool(rr.get("error")))
        st, rr = _http(
            "POST",
            f"{BASE}/v1/dids/{alice_did}/keys//revoke",
            payload={}, headers=T1)
        check("空 key_version 400", st == 400 and bool(rr.get("error")))

        # 404 / 409
        st, rr = revoke("did:example:deadbeef", 1, payload={}, headers=T1)
        check("未知 DID 404", st == 404 and bool(rr.get("error")))
        st, rr = revoke(alice_did, 99, payload={}, headers=T1)
        check("未知版本 404", st == 404 and bool(rr.get("error")))
        st, rr = revoke(alice_did, 2, payload={}, headers=T1)
        check("当前版本 409", st == 409 and bool(rr.get("error")))
        st, rr = revoke(alice_did, 1, payload={}, headers=T2)
        check("他租户吊销按 404（不可探测）",
              st == 404 and bool(rr.get("error")))

        # 审计：首次 1 次 + 重复 6 次 = 7 条 key.revoked（alice#1）
        events = audit(T1)
        key_events = [e for e in events if e["action"] == "key.revoked"]
        check("首次与重复均记 key.revoked（7 条）", len(key_events) == 7)
        check("审计 resource_type=did、resource_id=<did>#1",
              all(e["resource_type"] == "did"
                  and e["resource_id"] == f"{alice_did}#1"
                  for e in key_events))
        n_key_events = len(key_events)
        # 失败路径（400/404/409）不记审计
        st, _ = revoke(alice_did, 2, payload={}, headers=T1)
        st, _ = revoke(alice_did, 99, payload={"reason": "x"}, headers=T1)
        st, _ = revoke(bob_did, 1, payload={"reason": 9}, headers=T1)
        events = audit(T1)
        check("400/404/409 失败不记审计",
              len([e for e in events if e["action"] == "key.revoked"])
              == n_key_events)

        # 吊销版本仍在 DID 文档历史，proof 由当前版签发
        st, doc = _http("GET",
                        f"{BASE}/v1/dids/{alice_did}/document", headers=T1)
        versions = [m["key_version"] for m in doc["verification_methods"]]
        check("吊销版本保留在 document 历史", versions == [1, 2])
        check("文档不暴露私钥",
              all("private_key" not in json.dumps(m)
                  for m in doc["verification_methods"]))
        st, doc = _http("GET",
                        f"{BASE}/v1/dids/{alice_did}/document?version=1",
                        headers=T1)
        check("历史版本文档仍可取", st == 200
              and [m["key_version"] for m in doc["verification_methods"]] == [1])

        # ---- 2. 凭证 verify：签发密钥吊销 ----
        body, sig = get_cred(c1, headers=T1)
        st, r = verify_cred(c1, body, sig, headers=T1)
        check("凭证验签后签发密钥吊销 -> 200 valid:false",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "签发密钥已吊销：密钥版本主动吊销")
        # 凭证本身也吊销：密钥原因仍优先
        st, _ = _http("POST", f"{BASE}/v1/credentials/{c1}/revoke",
                      {"reason": "凭证原因"}, headers=T1)
        assert st == 200
        st, r = verify_cred(c1, body, sig, headers=T1)
        check("签发密钥吊销优先于凭证吊销",
              r.get("reason") == "签发密钥已吊销：密钥版本主动吊销")
        # 篡改签名 -> 签名类原因优先
        st, r = verify_cred(c1, body, sig[:-2] + "AA", headers=T1)
        check("签名失败优先于密钥吊销",
              st == 200 and r.get("valid") is False
              and r["reason"].startswith("签名校验失败"))
        # 新版本签发的凭证照常有效
        body2, sig2 = get_cred(c2, headers=T1)
        st, r = verify_cred(c2, body2, sig2, headers=T1)
        check("轮换版本照常签发且 verify valid:true",
              st == 200 and r == {"valid": True})
        # 他租户验签：资源不可见，200 valid:false
        st, r = verify_cred(c1, body, sig, headers=T2)
        check("他租户 verify 凭证不存在",
              st == 200 and r.get("valid") is False
              and "凭证不存在" in r.get("reason", ""))

        # ---- 3. 演示 verify：顺序与不消费 ----
        st, r = verify_vp(vp1["presentation_id"], vp1, "ch1", headers=T1)
        check("演示 issuer 密钥吊销",
              r.get("valid") is False
              and r.get("reason") == "签发密钥已吊销：密钥版本主动吊销")
        st, r = verify_vp(vp1["presentation_id"], vp1, "ch1", headers=T1)
        check("密钥吊销失败可重复（非已消费）",
              r.get("reason") == "签发密钥已吊销：密钥版本主动吊销")
        # 不留消费标记：无 presentation.consumed 审计
        ev = audit(T1)
        check("密钥吊销失败不记消费审计",
              not any(e["action"] == "presentation.consumed"
                      and e["resource_id"] == vp1["presentation_id"]
                      for e in ev))
        # 错误 challenge / 篡改等先置失败优先于密钥吊销
        st, r = verify_vp(vp1["presentation_id"], vp1, "wrong", headers=T1)
        check("challenge 不一致优先返回锚定原因",
              r.get("valid") is False and "锚定" in r.get("reason", ""))

        # 持有者密钥吊销（签发者 carol 未吊销；绑定 bob v2）
        c3, _, _ = issue(carol_did, bob_did, {"role": "h"}, headers=T1)
        st, vph = present(c3, [], "chh", holder_binding=True, headers=T1)
        assert st == 201 and vph["holder_key_version"] == 2, (st, vph)
        # 再生成一张同样绑定 bob v2 但不消费的演示，供吊销后验证
        st, vph2 = present(c3, ["/role"], "chh2", holder_binding=True,
                           headers=T1)
        assert st == 201 and vph2["holder_key_version"] == 2, (st, vph2)
        st, r = verify_vp(vph["presentation_id"], vph, "chh", headers=T1)
        check("未吊销双签名 valid:true", st == 200 and r == {"valid": True})
        # 已消费后再吊销：已消费优先
        st, _ = _http("POST", f"{BASE}/v1/dids/{bob_did}/keys/rotate",
                      {"key_handle": "kr-bob-v3"}, headers=T1)
        assert st == 200
        st, _ = revoke(bob_did, 2, payload={"reason": "bob v2 泄漏"},
                       headers=T1)
        assert st == 200
        st, r = verify_vp(vph["presentation_id"], vph, "chh", headers=T1)
        check("已消费优先于持有者密钥吊销",
              r.get("valid") is False and r.get("reason") == "演示已消费")
        # 未消费的 v2 绑定演示 -> 持有者密钥吊销
        st, r = verify_vp(vph2["presentation_id"], vph2, "chh2", headers=T1)
        check("持有者密钥吊销 valid:false",
              r.get("valid") is False
              and r.get("reason") == "持有者密钥已吊销：bob v2 泄漏")
        # 再吊销签发者 carol v1：签发密钥优先于持有者密钥
        st, _ = _http("POST", f"{BASE}/v1/dids/{carol_did}/keys/rotate",
                      {"key_handle": "kr-carol-v2"}, headers=T1)
        assert st == 200
        st, _ = revoke(carol_did, 1, payload={"reason": "carol v1"},
                       headers=T1)
        assert st == 200
        st, r = verify_vp(vph2["presentation_id"], vph2, "chh2", headers=T1)
        check("签发密钥吊销优先于持有者密钥吊销",
              r.get("reason") == "签发密钥已吊销：carol v1")

        # 演示过期优先于密钥吊销（vpx 1 秒过期，alice v1 已吊销）
        time.sleep(1.2)
        st, r = verify_vp(vpx["presentation_id"], vpx, "chx", headers=T1)
        check("演示过期优先于签发密钥吊销",
              r.get("valid") is False and r.get("reason") == "演示已过期")
        check("过期失败不消费",
              not any(e["action"] == "presentation.consumed"
                      and e["resource_id"] == vpx["presentation_id"]
                      for e in audit(T1)))

        # ---- 4. 谓词证明 verify ----
        st, r = verify_proof(zp1["proof_id"], zp1, "chp", headers=T1)
        check("谓词证明签发密钥吊销",
              r.get("valid") is False
              and r.get("reason") == "签发密钥已吊销：密钥版本主动吊销")
        check("谓词证明吊销失败不记消费审计",
              not any(e["action"] == "proof.consumed"
                      and e["resource_id"] == zp1["proof_id"]
                      for e in audit(T1)))

        # ---- 5. present/prove 生成拦截 400 ----
        before_created = [
            e for e in audit(T1) if e["action"] in
            ("presentation.created", "proof.created")]
        st, r = present(c1, ["/role"], "late", headers=T1)
        check("签发密钥吊销后 present 400",
              st == 400 and bool(r.get("error")))
        st, r = prove(c1, [{"path": "/role", "op": "exists"}],
                      "late", headers=T1)
        check("签发密钥吊销后 prove 400",
              st == 400 and bool(r.get("error")))
        # carol v1 也已吊销：其凭证的绑定演示同样 400
        st, r = present(c3, [], "late", holder_binding=True, headers=T1)
        check("吊销签发密钥后绑定 present 400", st == 400)
        after_created = [
            e for e in audit(T1) if e["action"] in
            ("presentation.created", "proof.created")]
        check("400 不记 created 审计",
              len(before_created) == len(after_created))

        # 未吊销密钥的生成不受影响（bob 当前 v3、carol v2 均活跃；
        # 用新签发者重新走一遍）
        st, dave = _http("POST", f"{BASE}/v1/dids",
                         {"method": "example", "public_key": "kr-dave"},
                         headers=T1)
        assert st == 201
        c4, _, _ = issue(dave["did"], bob_did, {"role": "ok"}, headers=T1)
        st, r = present(c4, ["/role"], "okc", headers=T1)
        check("活跃密钥仍可 present", st == 201)
        st, r = prove(c4, [{"path": "/role", "op": "exists"}],
                      "okp", headers=T1)
        check("活跃密钥仍可 prove", st == 201)

        # ---- 6. 已消费优先（用 alice v2 的凭证演示）----
        st, vpc2 = present(c2, ["/role"], "consume-ch", headers=T1)
        assert st == 201, (st, vpc2)
        st, r = verify_vp(vpc2["presentation_id"], vpc2, "consume-ch",
                          headers=T1)
        check("吊销前演示消费成功", st == 200 and r == {"valid": True})
        st, _ = _http("POST", f"{BASE}/v1/dids/{alice_did}/keys/rotate",
                      {"key_handle": "kr-alice-v3"}, headers=T1)
        assert st == 200
        st, _ = revoke(alice_did, 2, payload={"reason": "alice v2"},
                       headers=T1)
        assert st == 200
        st, r = verify_vp(vpc2["presentation_id"], vpc2, "consume-ch",
                          headers=T1)
        check("消费后密钥被吊销：演示已消费优先",
              r.get("valid") is False and r.get("reason") == "演示已消费")

        # ---- 7. 重启保留 ----
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server()

        st, r = revoke(alice_did, 1, payload={"reason": "重启后改原因"},
                       headers=T1)
        check("重启后吊销状态保留（幂等返回首次 reason/updated_at）",
              st == 200 and r.get("reason") == "密钥版本主动吊销"
              and r.get("updated_at") == first_updated)
        body, sig = get_cred(c1, headers=T1)
        st, r = verify_cred(c1, body, sig, headers=T1)
        check("重启后签发密钥吊销结论一致",
              r.get("reason") == "签发密钥已吊销：密钥版本主动吊销")
        st, r = verify_vp(vpb["presentation_id"], vpb, "chb", headers=T1)
        check("重启后持有者历史绑定仍可走到密钥吊销判定",
              r.get("reason") == "签发密钥已吊销：密钥版本主动吊销")

    finally:
        run_direct_store_checks(failures, check)
        proc.terminate()
        proc.wait(timeout=10)

    if failures:
        print(f"\n{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        sys.exit(1)
    print("\n密钥版本吊销测试全部通过 ✔")


if __name__ == "__main__":
    main()
