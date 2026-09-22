#!/usr/bin/env python3
"""DID 生命周期停用（POST /v1/dids/{did}/deactivate、
GET /v1/dids/{did}/status）端到端测试。

覆盖：
- 请求体仅允许空体、{} 或恰含可选 reason；reason 裁剪后非空字符串，
  缺省“DID 主动停用”，非法请求 400；未知或跨租户 DID 404；
- 首次停用 200 返回恰含 did/status:"deactivated"/reason/updated_at
  （UTC 秒精度 Z）；重复请求忽略新 reason（含非法值）幂等返回首次结果；
- GET 状态：活动 DID status:"active" 且 reason/updated_at 为 null，
  停用后返回首次值；未知/跨租户 404；
- 停用 DID 不能轮换密钥、作为 issuer 签发凭证、为其凭证生成演示或谓词
  证明，均返回 409 且不写记录/审计；
- 凭证/演示/谓词证明验签在锚定与签名成功后检查 issuer DID：停用返回
  HTTP 200 valid:false 与“签发DID已停用：<reason>”，优先于有效期与
  凭证吊销，签名/锚定失败仍按原分类协议；失败不消费；
- 历史 DID 文档、公钥状态与既有凭证查询保持可读；
- 首次及幂等停用均记 did.deactivated（resource_type=did、
  resource_id=did），失败不记；
- 状态与审计原子持久化，重启结论稳定；X-Tenant-ID 隔离。

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
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PORT = 8991
STORE = tempfile.mktemp(suffix=".json")
BASE = f"http://127.0.0.1:{PORT}"

Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
DEACTIVATE_FIELDS = {"did", "status", "reason", "updated_at"}
STATUS_FIELDS = {"did", "status", "reason", "updated_at"}


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
    from vcbackend.store import VCStore

    # 1. 落盘失败回滚：停用不生效、审计不记录
    path = tempfile.mktemp(suffix=".json")
    store = VCStore(path)
    d = store.create_did("ddt", "example", "rollback-did")

    def _boom():
        raise OSError("模拟落盘失败")

    store._save_locked = _boom  # type: ignore[assignment]
    raised = False
    try:
        store.deactivate_did("ddt", d.did, reason="x")
    except OSError:
        raised = True
    check("落盘失败时 deactivate_did 抛错", raised)
    events = store.list_audit("ddt", 0, 200)[0]
    check("落盘失败不记 did.deactivated 审计",
          all(e.action != "did.deactivated" for e in events))
    rec = store._bucket_locked("ddt")["dids"][d.did]  # noqa: SLF001
    check("落盘失败停用标记回滚（DID 仍活动）",
          rec.get("deactivation") is None)

    # 2. 停用优先于凭证有效期（直连构造已到期凭证）
    import copy
    from vcbackend import crypto
    from vcbackend.crypto import sign  # noqa: F401

    path2 = tempfile.mktemp(suffix=".json")
    s2 = VCStore(path2)
    iss = s2.create_did("ddt", "example", "exp-issuer")
    sub = s2.create_did("ddt", "example", "exp-subject")
    cred = s2.create_credential(
        "ddt", iss.did, sub.did, {"x": 1},
        expires_at="2030-01-01T00:00:00Z",
    )
    s2.deactivate_did("ddt", iss.did, reason="到期优先测试")
    bucket = s2._bucket_locked("ddt")  # noqa: SLF001
    body = copy.deepcopy(cred.body)
    body["expires_at"] = "2000-01-01T00:00:00Z"
    priv = bucket["dids"][iss.did]["private_key_pem"]
    signature = crypto.sign(body, priv)
    valid, reason = s2.verify_credential(
        "ddt", cred.credential_id, body, signature
    )
    check("停用优先于凭证有效期",
          (not valid) and reason == "签发DID已停用：到期优先测试")


def main():
    if os.path.exists(STORE):
        os.unlink(STORE)
    proc = start_server()
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def deactivate(did, payload=None, headers=None, raw=None):
        url = (f"{BASE}/v1/dids/"
               f"{urllib.parse.quote(did, safe='')}/deactivate")
        return _http("POST", url, payload=payload, headers=headers, raw=raw)

    def status(did, headers=None):
        url = (f"{BASE}/v1/dids/"
               f"{urllib.parse.quote(did, safe='')}/status")
        return _http("GET", url, headers=headers)

    def issue(issuer, subject, claims, headers=None):
        return _http("POST", f"{BASE}/v1/credentials",
                     {"issuer_did": issuer, "subject_did": subject,
                      "claims": claims}, headers=headers)

    def verify_cred(cid, body, signature, headers=None):
        return _http("POST", f"{BASE}/v1/credentials/{cid}/verify",
                     {"body": body, "signature": signature}, headers=headers)

    def present(cid, disclose, challenge, headers=None):
        return _http("POST", f"{BASE}/v1/credentials/{cid}/present",
                     {"disclose": disclose, "challenge": challenge},
                     headers=headers)

    def verify_vp(vp_id, vp, challenge, headers=None):
        return _http("POST",
                     f"{BASE}/v1/presentations/{vp_id}/verify",
                     {"presentation": vp, "challenge": challenge},
                     headers=headers)

    def prove(cid, predicates, challenge, headers=None):
        return _http("POST", f"{BASE}/v1/credentials/{cid}/prove",
                     {"predicates": predicates, "challenge": challenge},
                     headers=headers)

    def verify_proof(pid, pfo, challenge, headers=None):
        return _http("POST", f"{BASE}/v1/proofs/{pid}/verify",
                     {"proof": pfo, "challenge": challenge}, headers=headers)

    def audit(headers=None):
        st, r = _http("GET", f"{BASE}/v1/audit?limit=200", headers=headers)
        assert st == 200, (st, r)
        return r["events"]

    try:
        T1 = {"X-Tenant-ID": "dd-a"}
        T2 = {"X-Tenant-ID": "dd-b"}

        # ---- 注册两个租户的 DID ----
        st, alice = _http("POST", f"{BASE}/v1/dids",
                          {"method": "example", "public_key": "dd-alice"},
                          headers=T1)
        assert st == 201, (st, alice)
        alice_did = alice["did"]
        st, bob = _http("POST", f"{BASE}/v1/dids",
                        {"method": "example", "public_key": "dd-bob"},
                        headers=T1)
        assert st == 201, (st, bob)
        bob_did = bob["did"]
        st, cross = _http("POST", f"{BASE}/v1/dids",
                          {"method": "example", "public_key": "dd-cross"},
                          headers=T2)
        assert st == 201, (st, cross)
        cross_did = cross["did"]

        # ---- 1. GET 活动状态 ----
        st, r = status(alice_did, headers=T1)
        check("活动 DID 状态 200", st == 200)
        check("活动状态响应字段恰含四项", set(r) == STATUS_FIELDS)
        check("活动 status=active", r.get("status") == "active")
        check("活动 reason 为 null", r.get("reason") is None)
        check("活动 updated_at 为 null", r.get("updated_at") is None)
        check("活动状态回显 did", r.get("did") == alice_did)

        # ---- 2. 首次停用：空体默认原因 ----
        st, r = deactivate(alice_did, raw=b"", headers=T1)
        check("空体首次停用 200", st == 200)
        check("停用响应字段恰含四项", set(r) == DEACTIVATE_FIELDS)
        check("停用 status=deactivated", r.get("status") == "deactivated")
        check("默认 reason", r.get("reason") == "DID 主动停用")
        check("停用 updated_at 为 UTC 秒精度 Z",
              bool(Z_RE.match(r.get("updated_at", ""))))
        check("停用回显 did", r.get("did") == alice_did)
        first_reason = r["reason"]
        first_updated = r["updated_at"]

        # ---- 3. 幂等：{} / 新 reason / 非法 reason 均返回首次结果 ----
        st, r = deactivate(alice_did, payload={}, headers=T1)
        check("{} 幂等停用 200", st == 200)
        check("{} 幂等保持首次 reason/updated_at",
              r.get("reason") == first_reason
              and r.get("updated_at") == first_updated)
        st, r = deactivate(alice_did,
                           payload={"reason": "  另一个原因  "},
                           headers=T1)
        check("新 reason 幂等 200 且忽略",
              st == 200 and r.get("reason") == first_reason
              and r.get("updated_at") == first_updated)
        st, r = deactivate(alice_did, payload={"reason": "   "},
                           headers=T1)
        check("已停用时空白 reason 也被忽略 200",
              st == 200 and r.get("reason") == first_reason)
        st, r = deactivate(alice_did, payload={"reason": 123},
                           headers=T1)
        check("已停用时非法类型 reason 也被忽略 200",
              st == 200 and r.get("reason") == first_reason)

        # ---- 4. GET 停用后状态 ----
        st, r = status(alice_did, headers=T1)
        check("停用后 GET 200", st == 200)
        check("停用后 GET 返回首次 reason/updated_at",
              r.get("status") == "deactivated"
              and r.get("reason") == first_reason
              and r.get("updated_at") == first_updated)

        # ---- 5. 首次停用请求体校验（用未停用的 bob）----
        st, r = deactivate(bob_did, raw=b"{", headers=T1)
        check("非法 JSON 400", st == 400 and bool(r.get("error")))
        st, r = deactivate(bob_did, payload=[], headers=T1)
        check("非对象请求体 400", st == 400)
        st, r = deactivate(bob_did, payload={"reason": "   "}, headers=T1)
        check("首次空白 reason 400", st == 400)
        st, r = deactivate(bob_did, payload={"reason": None}, headers=T1)
        check("首次 null reason 400", st == 400)
        st, r = deactivate(bob_did, payload={"reason": 7}, headers=T1)
        check("首次非字符串 reason 400", st == 400)
        st, r = deactivate(bob_did, payload={"reason": "x", "y": 1},
                           headers=T1)
        check("多余字段 400", st == 400)
        st, r = deactivate(bob_did, payload={"other": 1}, headers=T1)
        check("非空但不含 reason 400", st == 400)
        # 校验失败不改变状态
        st, r = status(bob_did, headers=T1)
        check("非法请求不改变 DID 状态（仍 active）",
              st == 200 and r.get("status") == "active")

        # 首次停用携带裁剪后非空 reason
        st, r = deactivate(bob_did,
                           payload={"reason": "  机构违规解散  "},
                           headers=T1)
        check("自定义 reason 首次停用 200", st == 200)
        check("保存并返回裁剪后的 reason",
              r.get("reason") == "机构违规解散")

        # ---- 6. 未知 / 跨租户 404（不可探测）----
        st, _ = deactivate("did:example:00112233445566778899aabbccddeeff",
                           payload={}, headers=T1)
        check("未知 DID 停用 404", st == 404)
        st, _ = status("did:example:00112233445566778899aabbccddeeff",
                       headers=T1)
        check("未知 DID 状态 404", st == 404)
        st, _ = deactivate(alice_did, payload={}, headers=T2)
        check("跨租户停用 404", st == 404)
        st, _ = status(alice_did, headers=T2)
        check("跨租户状态 404", st == 404)

        # 显式空租户头 400
        st, _ = deactivate(alice_did, payload={},
                           headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID 停用 400", st == 400)
        st, _ = status(alice_did, headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID 状态 400", st == 400)

        # ---- 7. 停用后写操作一律 409 且不写记录 ----
        st, r = _http("POST",
                      f"{BASE}/v1/dids/{alice_did}/keys/rotate",
                      {"key_handle": "dd-alice-v2"}, headers=T1)
        check("停用后轮换密钥 409", st == 409 and bool(r.get("error")))

        st, r = issue(alice_did, bob_did, {"role": "admin"}, headers=T1)
        check("停用 DID 作为 issuer 签发 409",
              st == 409 and bool(r.get("error")))

        # 先用 alice 在停用前签发一张凭证（重启后场景需要，这里补发：
        # alice 已停用，无法签发；改用 bob 在停用前签发——bob 此刻已停用。
        # 因此凭证/演示/证明在停用前已准备，见下方 carol。）

        # ---- 8. 验签拦截与优先级（carol：活动时签发再停用）----
        st, carol = _http("POST", f"{BASE}/v1/dids",
                          {"method": "example", "public_key": "dd-carol"},
                          headers=T1)
        assert st == 201, (st, carol)
        carol_did = carol["did"]
        st, dave = _http("POST", f"{BASE}/v1/dids",
                         {"method": "example", "public_key": "dd-dave"},
                         headers=T1)
        assert st == 201, (st, dave)
        dave_did = dave["did"]

        st, issued = issue(carol_did, dave_did,
                           {"role": "admin", "age": 30}, headers=T1)
        assert st == 201, (st, issued)
        cid = issued["credential_id"]
        st, full = _http("GET", f"{BASE}/v1/credentials/{cid}", headers=T1)
        assert st == 200, (st, full)
        cbody, csig = full["body"], full["signature"]

        st, vp = present(cid, ["/role"], "vp-ch", headers=T1)
        assert st == 201, (st, vp)
        st, vpb = _http("POST", f"{BASE}/v1/credentials/{cid}/present",
                        {"disclose": [], "challenge": "vpb-ch",
                         "holder_binding": True}, headers=T1)
        assert st == 201, (st, vpb)
        st, zp = prove(cid,
                       [{"path": "/age", "op": "gte", "value": 18}],
                       "zp-ch", headers=T1)
        assert st == 201, (st, zp)

        # 停用 carol（issuer）
        st, _ = deactivate(carol_did,
                           payload={"reason": "签发机构注销"}, headers=T1)
        assert st == 200

        # 凭证验签：200/valid:false/停用原因
        st, r = verify_cred(cid, cbody, csig, headers=T1)
        check("停用后凭证验签 HTTP 200", st == 200)
        check("停用后凭证验签 valid:false", r.get("valid") is False)
        check("停用原因精确文案",
              r.get("reason") == "签发DID已停用：签发机构注销")

        # 演示验签
        st, r = verify_vp(vp["presentation_id"], vp, "vp-ch", headers=T1)
        check("停用后演示验签 200/valid:false",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "签发DID已停用：签发机构注销")
        st, r = verify_vp(vpb["presentation_id"], vpb, "vpb-ch",
                          headers=T1)
        check("停用后绑定演示验签同样拦截（未到 holder 阶段）",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "签发DID已停用：签发机构注销")

        # 谓词证明验签
        st, r = verify_proof(zp["proof_id"], zp, "zp-ch", headers=T1)
        check("停用后谓词证明验签 200/valid:false",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "签发DID已停用：签发机构注销")

        # 失败不消费：重复验证仍是停用原因而非“已消费”
        st, r = verify_vp(vp["presentation_id"], vp, "vp-ch", headers=T1)
        check("停用演示验证失败不消费（重复仍为停用原因）",
              r.get("reason") == "签发DID已停用：签发机构注销")
        st, r = verify_proof(zp["proof_id"], zp, "zp-ch", headers=T1)
        check("停用证明验证失败不消费（重复仍为停用原因）",
              r.get("reason") == "签发DID已停用：签发机构注销")

        # 为其凭证生成演示/谓词证明 409
        st, r = present(cid, ["/role"], "vp-after", headers=T1)
        check("停用后生成演示 409", st == 409 and bool(r.get("error")))
        st, r = prove(cid, [{"path": "/age", "op": "exists"}],
                      "zp-after", headers=T1)
        check("停用后生成谓词证明 409", st == 409 and bool(r.get("error")))

        # 优先级：签名篡改仍返回签名类原因
        st, r = verify_cred(cid, cbody, csig[:-2] + "AA", headers=T1)
        check("签名篡改优先返回签名原因（而非停用）",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名"))

        # 优先级：停用优先于凭证吊销
        st, _ = _http("POST",
                      f"{BASE}/v1/credentials/{cid}/revoke",
                      {"reason": "凭证造假"}, headers=T1)
        assert st == 200
        st, r = verify_cred(cid, cbody, csig, headers=T1)
        check("停用优先于凭证吊销",
              r.get("reason") == "签发DID已停用：签发机构注销")

        # ---- 9. 历史 DID 文档、公钥状态、既有凭证仍可读 ----
        st, r = _http("GET",
                      f"{BASE}/v1/dids/{carol_did}/document", headers=T1)
        check("停用 DID 文档仍可读 200",
              st == 200 and "verification_methods" in r
              and "document_proof" in r)
        st, r = _http("GET",
                      f"{BASE}/v1/dids/{carol_did}/keys/1/status",
                      headers=T1)
        check("停用 DID 公钥版本状态仍可读（active）",
              st == 200 and r.get("status") == "active")
        st, r = _http("GET", f"{BASE}/v1/credentials/{cid}", headers=T1)
        check("既有凭证记录仍可读", st == 200 and r.get("credential_id") == cid)
        st, r = _http("GET", f"{BASE}/v1/dids/{carol_did}", headers=T1)
        check("停用 DID 注册信息仍可读", st == 200 and r.get("did") == carol_did)

        # ---- 10. 审计：首次与幂等均记 did.deactivated，失败不记 ----
        events = audit(headers=T1)
        deact_events = [e for e in events if e["action"] == "did.deactivated"]
        # alice: 首次 + {} + 新reason + 空白 + 非法类型 = 5
        # bob: 自定义首次 = 1；carol: 首次 = 1  → 共 7
        check("首次及幂等停用均记 did.deactivated",
              len(deact_events) == 7)
        check("did.deactivated 资源类型/标识正确",
              all(e["resource_type"] == "did" for e in deact_events)
              and {e["resource_id"] for e in deact_events}
              == {alice_did, bob_did, carol_did})
        check("did.deactivated 事件字段完整",
              all(set(e) == {"seq", "timestamp", "tenant_id", "action",
                             "resource_type", "resource_id"}
                  and isinstance(e["seq"], int)
                  and isinstance(e["timestamp"], int)
                  for e in deact_events))
        # 失败路径（400/404/409）不产生对应 did.deactivated：
        # 未知 DID 与跨租户 DID 均无事件；bob 非法尝试只产生 1 条成功事件。
        bob_events = [e for e in deact_events if e["resource_id"] == bob_did]
        check("失败请求不记 did.deactivated（bob 仅 1 条）",
              len(bob_events) == 1)
        # 停用后签发/轮换/生成 409 不记对应业务审计
        check("停用后轮换 409 不记 key.rotated",
              not any(e["action"] == "key.rotated"
                      and e["resource_id"] == alice_did for e in events))

        # ---- 11. 租户隔离：T2 看不到 T1 的停用审计 ----
        events_t2 = audit(headers=T2)
        check("停用审计按租户隔离",
              all(e["tenant_id"] == "dd-b" for e in events_t2)
              and not any(e["action"] == "did.deactivated" for e in events_t2))

        # ---- 12. 重启持久化 ----
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server()

        st, r = status(carol_did, headers=T1)
        check("重启后停用状态与首次原因稳定",
              st == 200 and r.get("status") == "deactivated"
              and r.get("reason") == "签发机构注销")
        st, r = status(alice_did, headers=T1)
        check("重启后 alice 首次停用时间稳定",
              st == 200 and r.get("updated_at") == first_updated
              and r.get("reason") == first_reason)
        st, r = deactivate(carol_did,
                           payload={"reason": "重启后改原因"}, headers=T1)
        check("重启后幂等停用忽略新原因",
              st == 200 and r.get("reason") == "签发机构注销")
        st, r = verify_cred(cid, cbody, csig, headers=T1)
        check("重启后验签停用结论一致",
              r.get("reason") == "签发DID已停用：签发机构注销")
        st, r = _http("POST",
                      f"{BASE}/v1/dids/{carol_did}/keys/rotate",
                      {"key_handle": "dd-carol-v2"}, headers=T1)
        check("重启后停用 DID 仍不能轮换 409", st == 409)
        st, r = status(dave_did, headers=T1)
        check("未受影响的 DID 重启后仍 active",
              st == 200 and r.get("status") == "active")

    finally:
        run_direct_store_checks(failures, check)
        proc.terminate()
        proc.wait(timeout=10)

    if failures:
        print(f"\n{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        sys.exit(1)
    print("\nDID 生命周期停用测试全部通过 ✔")


if __name__ == "__main__":
    main()
