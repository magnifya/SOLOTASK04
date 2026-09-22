#!/usr/bin/env python3
"""DID 生命周期停用（POST /v1/dids/{did}/deactivate、
GET /v1/dids/{did}/status）端到端测试。

覆盖：
- 活动 DID status:"active"、reason/updated_at 为 null；
- 停用请求体仅允许空体、{} 或恰含可选 reason；reason 裁剪后非空字符串，
  缺省“DID 主动停用”；非法请求（null/数字/空白/多余字段/非法 JSON/非对象）400；
  未知或跨租户 DID 404；
- 首次停用 200，响应恰含 did、status:"deactivated"、reason、updated_at；
  重复请求忽略新 reason（含非法值），幂等返回首次结果；
- did.deactivated 审计（resource_type=did、resource_id=did），首次与幂等
  均记，失败不记；
- 停用 DID 不得再轮换密钥、作为 issuer 签发凭证、为其凭证生成演示或谓词
  证明，均 409 且不写记录；
- 凭证/演示/谓词证明验签在锚定和签名成功后检查 issuer DID：停用返回
  HTTP 200 valid:false 与“签发DID已停用：<reason>”，优先于有效期与凭证
  吊销；签名/锚定失败仍按原分类协议；失败不消费；
- 历史 DID 文档、公钥状态与既有凭证查询保持可读；
- 跨租户隔离、重启后结论稳定；落盘失败状态与审计共同回滚。

直接运行：python3 tests/did_deactivation_test.py
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

PORT = 8965
STORE = tempfile.mktemp(suffix=".json")
BASE = f"http://127.0.0.1:{PORT}"

Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
DID_STATUS_FIELDS = {"did", "status", "reason", "updated_at"}
DEACT_REASON = "签发DID已停用："
DEFAULT_REASON = "DID 主动停用"


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


def start_server(store=STORE, port=PORT):
    env = dict(os.environ, VCBACKEND_STORE=store)
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
        if cond:
            print("PASS:", name)
        else:
            print("FAIL:", name)
            failures.append(name)

    proc = start_server()
    try:
        T = {}
        OT = {"X-Tenant-ID": "other"}

        def register(handle, headers=T):
            st, r = _http(
                "POST", f"{BASE}/v1/dids",
                {"method": "example", "public_key": handle},
                headers=headers,
            )
            assert st == 201, (st, r)
            return r["did"]

        alice = register("alice-key")
        bob = register("bob-key")
        carol = register("carol-key")

        def deact(did, payload=None, raw=None, headers=T):
            return _http(
                "POST", f"{BASE}/v1/dids/{did}/deactivate",
                payload=payload, raw=raw, headers=headers,
            )

        def status(did, headers=T):
            return _http(
                "GET", f"{BASE}/v1/dids/{did}/status", headers=headers
            )

        # ---------------------------------------------------------- #
        # 1. 活动状态
        # ---------------------------------------------------------- #
        st, r = status(alice)
        check("活动 DID 200 active/null/null",
              st == 200 and r == {
                  "did": alice, "status": "active",
                  "reason": None, "updated_at": None,
              })

        # ---------------------------------------------------------- #
        # 2. 请求体与 reason 校验
        # ---------------------------------------------------------- #
        for raw in (b"", b"{}"):
            st2, r2 = deact(carol, raw=raw)
            check(f"空体/{{}} 接受并停用（{raw!r}）",
                  st2 == 200 and r2.get("status") == "deactivated"
                  and r2.get("reason") == DEFAULT_REASON
                  and Z_RE.match(r2.get("updated_at", "")))
        st, r = deact(carol, {"reason": "其他"})  # 幂等，忽略新原因
        check("重复停用忽略新 reason，返回首次默认原因",
              st == 200 and r.get("reason") == DEFAULT_REASON)

        # 首次停用的非法 reason 一律 400
        bad_bodies = [
            ("null", b"null"),
            ("数组", b"[]"),
            ("非法 JSON", b"{oops"),
            ("reason null", {"reason": None}),
            ("reason 数字", {"reason": 123}),
            ("reason 空白", {"reason": "   "}),
            ("多余字段", {"reason": "x", "y": 1}),
            ("无 reason 的非空对象", {"y": 1}),
        ]
        for label, body in bad_bodies:
            if isinstance(body, bytes):
                st2, r2 = deact(bob, raw=body)
            else:
                st2, r2 = deact(bob, body)
            check(f"非法请求 400: {label}", st2 == 400 and "error" in r2)

        # bob 仍活动（非法请求不改变状态、不记审计）
        st, r = status(bob)
        check("400 后 DID 仍活动", r.get("status") == "active")

        # 未知 / 跨租户 404
        unknown = "did:example:" + "0" * 32
        check("未知 DID 停用 404", deact(unknown)[0] == 404)
        check("未知 DID 状态 404", status(unknown)[0] == 404)
        check("跨租户停用按不存在 404", deact(alice, {}, headers=OT)[0] == 404)
        check("跨租户状态按不存在 404", status(alice, headers=OT)[0] == 404)

        # ---------------------------------------------------------- #
        # 3. 首次停用响应严格字段、裁剪与时间
        # ---------------------------------------------------------- #
        st, r = deact(bob, {"reason": "  业务终止  "})
        first_ts = r.get("updated_at")
        check("首次停用 200 严格四字段、裁剪 reason、秒精度 Z",
              st == 200 and set(r) == DID_STATUS_FIELDS
              and r["did"] == bob and r["status"] == "deactivated"
              and r["reason"] == "业务终止" and Z_RE.match(first_ts))

        # 幂等：任意 reason（含非法值）均返回首次结果
        for body in ({"reason": "新理由"}, {"reason": None},
                     {"reason": "   "}, {}):
            st2, r2 = deact(bob, body)
            check(f"幂等返回首次值: {body}",
                  st2 == 200 and r2.get("reason") == "业务终止"
                  and r2.get("updated_at") == first_ts)
        st, r = status(bob)
        check("GET status 返回首次值",
              st == 200 and set(r) == DID_STATUS_FIELDS
              and r["reason"] == "业务终止" and r["updated_at"] == first_ts)

        # ---------------------------------------------------------- #
        # 4. 审计 did.deactivated（失败不记）
        # ---------------------------------------------------------- #
        def audit(after=0, limit=200, headers=T):
            st2, r2 = _http(
                "GET",
                f"{BASE}/v1/audit?limit={limit}&after={after}",
                headers=headers,
            )
            assert st2 == 200, (st2, r2)
            return r2["events"]

        events = audit()
        did_events = [
            e for e in events
            if e.get("action") == "did.deactivated"
            and e.get("resource_id") == bob
        ]
        # carol 两次（空体、{}）+ bob 首次 + 3 个合法/非法幂等体共 5 次
        check("bob did.deactivated 审计共 5 次（首次+4 次幂等）",
              len(did_events) == 5)
        check("审计 resource_type=did、字段完整",
              all(e.get("resource_type") == "did"
                  and isinstance(e.get("seq"), int)
                  and isinstance(e.get("timestamp"), int)
                  and e.get("tenant_id") == "default"
                  for e in did_events))
        check("失败请求不记 did.deactivated",
              all(e.get("resource_id") != alice for e in events
                  if e.get("action") == "did.deactivated")
              and len([
                  e for e in events
                  if e.get("action") == "did.deactivated"
                  and e.get("resource_id") == bob
              ]) == 5)

        # ---------------------------------------------------------- #
        # 5. 停用后禁止轮换 / 签发 / present / prove（409 不写）
        # ---------------------------------------------------------- #
        st, r = _http(
            "POST", f"{BASE}/v1/dids/{bob}/keys/rotate",
            {"key_handle": "bob-v2"},
        )
        check("停用 DID 轮换 409", st == 409)

        st, r = _http(
            "POST", f"{BASE}/v1/credentials",
            {"issuer_did": bob, "subject_did": alice, "claims": {"k": 1}},
        )
        check("停用 issuer 签发 409", st == 409)

        # 停用 DID 作为 subject 不影响他人向其签发（规格只禁 issuer）
        st, r = _http(
            "POST", f"{BASE}/v1/credentials",
            {"issuer_did": alice, "subject_did": bob, "claims": {"k": 1}},
        )
        check("活动 issuer 向停用 subject 签发仍 201", st == 201)

        # alice 先签发一张凭证并做演示/证明，随后停用
        st, issued = _http(
            "POST", f"{BASE}/v1/credentials",
            {"issuer_did": alice, "subject_did": carol,
             "claims": {"age": 20, "role": "admin"},
             "expires_at": "2030-01-01T00:00:00Z"},
        )
        assert st == 201, (st, issued)
        cid = issued["credential_id"]
        # 吊销凭证（用于验证停用优先于吊销）
        st, _ = _http(
            "POST", f"{BASE}/v1/credentials/{cid}/revoke",
            {"reason": "凭证侧吊销"},
        )
        assert st == 200, st

        # 停用 alice
        st, r = deact(alice, {"reason": "机构关停"})
        assert st == 200 and r["reason"] == "机构关停", (st, r)
        # 以停用后最新审计 seq 为界，409 不得再产生任何写入类事件
        seq_before = audit()[-1]["seq"]

        st, r = _http(
            "POST", f"{BASE}/v1/dids/{alice}/keys/rotate",
            {"key_handle": "alice-v2"},
        )
        check("停用后轮换仍 409", st == 409)
        st, r = _http(
            "POST", f"{BASE}/v1/credentials",
            {"issuer_did": alice, "subject_did": carol, "claims": {}},
        )
        check("停用后签发仍 409", st == 409)
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cid}/present",
            {"disclose": ["/age"], "challenge": "c1", "expires_in": 300},
        )
        check("停用后 present 409", st == 409)
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cid}/prove",
            {"predicates": [{"path": "/age", "op": "gte", "value": 18}],
             "challenge": "c1", "expires_in": 300},
        )
        check("停用后 prove 409", st == 409)

        # 409 不写演示/证明/凭证/轮换记录，也不记任何审计
        events_after = audit(after=seq_before)
        check("409 不写任何状态变更或创建审计",
              events_after == [])

        # ---------------------------------------------------------- #
        # 6. 既有凭证验签：停用原因、优先级、不消费
        # ---------------------------------------------------------- #
        st, got = _http("GET", f"{BASE}/v1/credentials/{cid}")
        assert st == 200
        body, sig = got["body"], got["signature"]

        # 停用优先于凭证吊销
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cid}/verify",
            {"body": body, "signature": sig},
        )
        check("凭证验签停用优先于吊销",
              st == 200 and r == {
                  "valid": False,
                  "reason": "签发DID已停用：机构关停"})

        # 签名/锚定失败仍按原分类
        tampered = dict(body)
        tampered["claims"] = {"age": 21, "role": "admin"}
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cid}/verify",
            {"body": tampered, "signature": sig},
        )
        check("篡改仍按签名校验失败分类",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名校验失败"))
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cid}/verify",
            {"body": body, "signature": "!!!"},
        )
        check("坏签名仍按签名格式错误分类",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名格式错误"))

        # 停用优先于有效期：给 alice 一张停用前签发的短期凭证无法构造
        # （已过期必在停用前），改用直接存储层补充该优先级见 direct checks。

        # 演示与谓词证明：停用前生成，停用后验签返回停用原因、不消费
        # —— 用独立的活动签发者 dave 流程
        dave = register("dave-key")
        st, issued2 = _http(
            "POST", f"{BASE}/v1/credentials",
            {"issuer_did": dave, "subject_did": carol,
             "claims": {"age": 30, "role": "user"},
             "expires_at": "2030-01-01T00:00:00Z"},
        )
        cid2 = issued2["credential_id"]
        st, vp = _http(
            "POST", f"{BASE}/v1/credentials/{cid2}/present",
            {"disclose": ["/age"], "challenge": "ch", "expires_in": 300},
        )
        assert st == 201, (st, vp)
        vpid = vp["presentation_id"]
        st, zp = _http(
            "POST", f"{BASE}/v1/credentials/{cid2}/prove",
            {"predicates": [{"path": "/age", "op": "gte", "value": 18}],
             "challenge": "ch", "expires_in": 300},
        )
        assert st == 201, (st, zp)
        zpid = zp["proof_id"]

        assert deact(dave, {"reason": "dave 关停"})[0] == 200

        st, r = _http(
            "POST", f"{BASE}/v1/presentations/{vpid}/verify",
            {"presentation": vp, "challenge": "ch"},
        )
        check("演示验签返回签发DID停用",
              st == 200 and r == {
                  "valid": False, "reason": "签发DID已停用：dave 关停"})
        st, r = _http(
            "POST", f"{BASE}/v1/presentations/{vpid}/verify",
            {"presentation": vp, "challenge": "ch"},
        )
        check("停用不消费（重复不是“演示已消费”）",
              r.get("reason") == "签发DID已停用：dave 关停")

        st, r = _http(
            "POST", f"{BASE}/v1/proofs/{zpid}/verify",
            {"proof": zp, "challenge": "ch"},
        )
        check("谓词证明验签返回签发DID停用",
              st == 200 and r == {
                  "valid": False, "reason": "签发DID已停用：dave 关停"})
        st, r = _http(
            "POST", f"{BASE}/v1/proofs/{zpid}/verify",
            {"proof": zp, "challenge": "ch"},
        )
        check("停用证明不消费（重复不是“证明已消费”）",
              r.get("reason") == "签发DID已停用：dave 关停")

        # 持有者绑定演示：issuer 停用时返回停用原因
        erin = register("erin-key")
        holder = register("holder-key")
        st, issued3 = _http(
            "POST", f"{BASE}/v1/credentials",
            {"issuer_did": erin, "subject_did": holder,
             "claims": {"v": 1}, "expires_at": "2030-01-01T00:00:00Z"},
        )
        cid3 = issued3["credential_id"]
        st, bound = _http(
            "POST", f"{BASE}/v1/credentials/{cid3}/present",
            {"disclose": ["/v"], "challenge": "hb",
             "expires_in": 300, "holder_binding": True},
        )
        assert st == 201, (st, bound)
        assert deact(erin, {"reason": "erin 关停"})[0] == 200
        st, r = _http(
            "POST",
            f"{BASE}/v1/presentations/{bound['presentation_id']}/verify",
            {"presentation": bound, "challenge": "hb"},
        )
        check("绑定演示 issuer 停用优先返回停用原因",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "签发DID已停用：erin 关停")

        # ---------------------------------------------------------- #
        # 7. 历史文档/公钥状态/凭证查询保持可读
        # ---------------------------------------------------------- #
        st, r = _http("GET", f"{BASE}/v1/dids/{alice}")
        check("GET DID 仍可读", st == 200 and r["did"] == alice)
        st, r = _http("GET", f"{BASE}/v1/dids/{alice}/document")
        check("GET DID 文档仍可读且含历史公钥",
              st == 200 and r["current_key_version"] >= 1
              and len(r["verification_methods"]) >= 1
              and "document_proof" in r)
        st, r = _http(
            "GET", f"{BASE}/v1/dids/{alice}/keys/1/status")
        check("GET 公钥版本状态仍可读 active",
              st == 200 and r["status"] == "active")
        st, r = _http("GET", f"{BASE}/v1/credentials/{cid}")
        check("GET 既有凭证仍可读", st == 200 and r["credential_id"] == cid)
        st, r = _http("GET", f"{BASE}/v1/credentials/{cid}/status")
        check("GET 凭证状态仍可读（revoked 保持）",
              st == 200 and r["status"] == "revoked")
        st, r = _http(
            "GET",
            f"{BASE}/v1/dids/{alice}/keys/revocations?limit=50&after=0")
        check("GET 密钥吊销历史仍可读", st == 200 and r["events"] == [])

        # 密钥版本吊销仍可独立操作（历史版本），停用不改变密钥模型可读性
        # —— nina 活动，轮换后吊销 v1 应保持原协议
        nina = register("nina-key")
        st, r = _http(
            "POST", f"{BASE}/v1/dids/{nina}/keys/rotate",
            {"key_handle": "nina-v2"})
        check("活动 DID 轮换不受影响 200", st == 200)
        st, r = _http(
            "POST", f"{BASE}/v1/dids/{nina}/keys/1/revoke", {})
        check("活动 DID 旧密钥吊销不受影响 200", st == 200)
        # 停用 DID 的旧密钥吊销仍按原密钥协议可读/可操作：
        # alice 当前版本未轮换，吊销当前版本仍 409（停用不改变该判定路径）
        st, r = _http(
            "POST", f"{BASE}/v1/dids/{alice}/keys/1/revoke", {})
        check("停用 DID 吊销当前密钥版本仍 409（密钥协议不变）", st == 409)

        # ---------------------------------------------------------- #
        # 8. 跨租户信任接口不受本地 DID 停用影响（兼容性抽查）
        # ---------------------------------------------------------- #
        st, r = _http(
            "GET", f"{BASE}/v1/audit?limit=1&after=0", headers=OT)
        check("他租户审计独立（看不到 default 停用事件）",
              st == 200 and all(
                  e["action"] != "did.deactivated" for e in r["events"]))

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # -------------------------------------------------------------- #
    # 9. 直接存储层：停用优先于有效期；落盘失败回滚
    # -------------------------------------------------------------- #
    from vcbackend.store import VCStore  # noqa: E402

    # 停用优先于有效期：构造一张“停用前已过期”的凭证
    p1 = tempfile.mktemp(suffix=".json")
    s1 = VCStore(p1)
    iss = s1.create_did("t", "example", "iss-exp")
    sub = s1.create_did("t", "example", "sub-exp")
    cred = s1.create_credential(
        "t", iss.did, sub.did, {"x": 1},
        expires_at="2030-01-01T00:00:00Z",
    )
    s1.deactivate_did("t", iss.did, reason="过期优先测试")
    # 手工把凭证 expires_at 改成过去时间（模拟停用前已到期的旧凭证）
    row = s1._bucket_locked("t")["credentials"][cred.credential_id]  # noqa: SLF001
    row["body"]["expires_at"] = "2000-01-01T00:00:00Z"
    ok, why = s1.verify_credential(
        "t", cred.credential_id,
        row["body"], cred.signature,
    )
    # 签名覆盖 expires_at，改动后签名失效——因此改为重新签名后再判定
    from vcbackend import crypto  # noqa: E402
    priv = s1._private_key_for_version_locked(  # noqa: SLF001
        s1._bucket_locked("t"), iss.did, 1)  # noqa: SLF001
    sig2 = crypto.sign(row["body"], priv)
    ok, why = s1.verify_credential("t", cred.credential_id, row["body"], sig2)
    check("停用优先于凭证有效期",
          not ok and why == "签发DID已停用：过期优先测试")

    # 落盘失败：状态回滚、审计不记
    p2 = tempfile.mktemp(suffix=".json")
    s2 = VCStore(p2)
    d = s2.create_did("t", "example", "rollback-did")

    def _boom():
        raise OSError("模拟落盘失败")

    s2._save_locked = _boom  # type: ignore[assignment]
    raised = False
    try:
        s2.deactivate_did("t", d.did, reason="回滚原因")
    except OSError:
        raised = True
    check("落盘失败时 deactivate_did 抛错", raised)
    check("落盘失败不记 did.deactivated 审计",
          all(e.action != "did.deactivated"
              for e in s2.list_audit("t", 0, 200)[0]))
    rec = s2._bucket_locked("t")["dids"][d.did]  # noqa: SLF001
    check("落盘失败停用状态回滚（仍 active）",
          rec.get("status") != "deactivated"
          and "deactivate_reason" not in rec)

    # -------------------------------------------------------------- #
    # 10. 重启持久化：状态、首次原因与时间稳定
    # -------------------------------------------------------------- #
    proc2 = start_server()
    try:
        st, r = _http("GET", f"{BASE}/v1/dids/{bob}/status")
        check("重启后停用状态与首次值稳定",
              st == 200 and r["status"] == "deactivated"
              and r["reason"] == "业务终止" and r["updated_at"] == first_ts)
        # 幂等停用仍返回首次值且再记一次审计
        st, r = _http(
            "POST", f"{BASE}/v1/dids/{bob}/deactivate", {"reason": "重启后"})
        check("重启后幂等停用返回首次值",
              st == 200 and r["reason"] == "业务终止"
              and r["updated_at"] == first_ts)
        st, got = _http("GET", f"{BASE}/v1/credentials/{cid}")
        body, sig = got["body"], got["signature"]
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cid}/verify",
            {"body": body, "signature": sig})
        check("重启后验签停用结论稳定",
              r == {"valid": False, "reason": "签发DID已停用：机构关停"})
    finally:
        proc2.terminate()
        proc2.wait(timeout=10)

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
