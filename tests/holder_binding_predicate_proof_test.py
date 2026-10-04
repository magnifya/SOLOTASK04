#!/usr/bin/env python3
"""谓词证明可选持有者绑定（holder binding）端到端测试。

覆盖：
- prove 未绑定（缺省 / holder_binding=false）响应保持九字段，verify
  行为与旧流程一致；
- holder_binding 非布尔 400、未知凭证 404；
- holder_binding=true 201 恰返十二字段，holder_did 为凭证 subject、
  holder_key_version 为持有者当前版本，holder_proof 可外部用持有者公钥
  验真（覆盖去掉 proof、holder_proof 的完整证明对象 + tenant_id）；
  issuer proof 覆盖范围不变（不含 holder_*）；
- 绑定证明 verify 成功仅一次并消费；持有者字段缺失/类型错误/与存储或
  凭证主体不符、holder_proof 格式错误/签名不匹配、未绑定记录附加绑定
  字段、绑定证明删掉持有者字段，均 200 valid:false 且 reason 恰为
  “持有者绑定校验失败”，不消费；
- 较早的既有失败优先（结构锚定/跨租户不存在），持有者校验位于签发者
  校验之后、凭证有效期及状态判定之前（签发密钥吊销优先于持有者；
  证明过期、凭证已吊销仍返回各自既有原因）；
- 持有者停用 / 所用版本吊销在验证与消费提交时按同一原因拒绝；
- 持有者密钥轮换后旧证明用历史公钥验证、新证明用新版本；重启后绑定
  记录与消费标记保留；
- prove-batch 允许混合两种证明，等长同序，任一项失败整批不写入；
- 外部信任证明接口仍按九字段协议，拒绝绑定证明；
- 直连 store：subject 未注册生成 400、持有者当前私钥不可用 400、
  holder_did 与凭证主体不符/历史公钥不可用 valid:false 不消费、
  批量落盘失败整批回滚、消费落盘失败不消费。

直接运行：python3 tests/holder_binding_predicate_proof_test.py
"""

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vcbackend import crypto  # noqa: E402

PORT = 8933
STORE = tempfile.mktemp(suffix=".json")
BASE = f"http://127.0.0.1:{PORT}"

UNBOUND_KEYS = {
    "proof_id", "credential_id", "issuer_did",
    "issuer_key_version", "predicates", "results",
    "challenge", "expires_at", "proof",
}
BOUND_KEYS = UNBOUND_KEYS | {
    "holder_did", "holder_key_version", "holder_proof",
}
BIND_REASON = "持有者绑定校验失败"
PRED = [{"path": "/age", "op": "gte", "value": 18}]


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


def _holder_payload(pf, tenant_id):
    payload = {k: v for k, v in pf.items()
               if k not in ("proof", "holder_proof")}
    payload["tenant_id"] = tenant_id
    return payload


def _issuer_payload(pf, tenant_id):
    payload = {k: v for k, v in pf.items()
               if k in UNBOUND_KEYS and k != "proof"}
    payload["tenant_id"] = tenant_id
    return payload


def run_direct_store_checks(check):
    """直连 VCStore 的防御路径（HTTP 无法构造的状态）。"""
    from vcbackend.store import VCStore, ValidationError

    direct_path = tempfile.mktemp(suffix=".json")
    try:
        store = VCStore(direct_path)
        issuer_rec = store.create_did("t1", "example", "zp-dir-issuer")
        subject_rec = store.create_did("t1", "example", "zp-dir-subject")
        cred = store.create_credential(
            "t1", issuer_rec.did, subject_rec.did, {"age": 30}
        )
        bucket = store._tenants["t1"]  # noqa: SLF001 测试直查内部状态

        # subject_did 未注册时绑定生成必须 400
        saved_subject = bucket["dids"].pop(subject_rec.did)
        try:
            raised = False
            try:
                store.create_proof(
                    "t1", cred.credential_id, PRED,
                    challenge="c", holder_binding=True,
                )
            except ValidationError:
                raised = True
            check("直连: subject 未注册时绑定生成抛 ValidationError", raised)
        finally:
            bucket["dids"][subject_rec.did] = saved_subject

        # 持有者当前私钥不可用 -> 400
        srec = bucket["dids"][subject_rec.did]
        entry_v1 = next(e for e in srec["key_history"] if e["version"] == 1)
        saved_priv = entry_v1.pop("private_key_pem")
        try:
            raised = False
            try:
                store.create_proof(
                    "t1", cred.credential_id, PRED,
                    challenge="c", holder_binding=True,
                )
            except ValidationError:
                raised = True
            check("直连: 持有者当前私钥不可用 -> ValidationError", raised)
        finally:
            entry_v1["private_key_pem"] = saved_priv

        # 正常绑定生成
        rec = store.create_proof(
            "t1", cred.credential_id, PRED,
            challenge="c", holder_binding=True,
        )
        row = bucket["proofs"][rec.proof_id]

        def request_view():
            return {k: v for k, v in row.items() if k != "tenant_id"}

        # holder_did 与凭证 subject_did 不一致 -> 绑定失败 不消费
        other_rec = store.create_did("t1", "example", "zp-dir-other")
        original = row["holder_did"]
        row["holder_did"] = other_rec.did
        valid, reason = store.verify_proof(
            "t1", rec.proof_id, request_view(), "c"
        )
        check("直连: holder_did 与 subject_did 不一致 -> 绑定失败",
              not valid and reason == BIND_REASON)
        row["holder_did"] = original

        # 持有者历史公钥不可用 -> 绑定失败 不消费
        saved_pub = entry_v1.pop("public_key")
        valid, reason = store.verify_proof(
            "t1", rec.proof_id, request_view(), "c"
        )
        check("直连: 持有者历史公钥不可用 -> 绑定失败",
              not valid and reason == BIND_REASON)
        entry_v1["public_key"] = saved_pub

        # 公钥恢复后此前失败均未消费，首次验证成功
        valid, _ = store.verify_proof(
            "t1", rec.proof_id, request_view(), "c"
        )
        check("直连: 公钥恢复后绑定证明 valid:true（失败不消费）", valid)

        # 批量生成落盘失败整批回滚
        cred2 = store.create_credential(
            "t1", issuer_rec.did, subject_rec.did, {"age": 40}
        )
        before = len(bucket["proofs"])

        def _boom():
            raise OSError("模拟落盘失败")

        store._save_locked = _boom  # type: ignore[assignment]
        raised = False
        try:
            store.create_proofs_batch(
                "t1", cred2.credential_id,
                [{"predicates": PRED, "holder_binding": True},
                 {"predicates": PRED, "holder_binding": False}],
            )
        except OSError:
            raised = True
        del store._save_locked
        check("直连: 批量落盘失败向上抛出", raised)
        # 回滚会替换整个租户字典，重新获取桶引用后核对记录数
        bucket = store._tenants["t1"]  # noqa: SLF001
        check("直连: 批量落盘失败整批回滚不留记录",
              len(bucket["proofs"]) == before)

        # 消费落盘失败：200 失败协议、不消费
        rec2 = store.create_proof(
            "t1", cred2.credential_id, PRED,
            challenge="c2", holder_binding=True,
        )
        row2 = bucket["proofs"][rec2.proof_id]
        view2 = {k: v for k, v in row2.items() if k != "tenant_id"}
        store._save_locked = _boom  # type: ignore[assignment]
        valid, reason = store.verify_proof(
            "t1", rec2.proof_id, view2, "c2"
        )
        del store._save_locked
        # 回滚替换桶引用后重新获取行核对未消费
        row2_after = store._tenants["t1"]["proofs"][rec2.proof_id]  # noqa: SLF001
        check("直连: 消费落盘失败 valid:false 且不消费",
              not valid and not row2_after.get("consumed") and bool(reason))
        valid, _ = store.verify_proof(
            "t1", rec2.proof_id, view2, "c2"
        )
        check("直连: 恢复后绑定证明消费 valid:true", valid)
    finally:
        if os.path.exists(direct_path):
            os.unlink(direct_path)


def main():
    proc = start_server()
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    try:
        # ---------------- 准备 ---------------- #
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "zphb-issuer"})
        assert st == 201, r
        issuer = r["did"]
        issuer_pem = r["public_key"]
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "zphb-subject"})
        assert st == 201, r
        subject = r["did"]
        subject_pem_v1 = r["public_key"]
        st, r = _http("POST", f"{BASE}/v1/credentials",
                      {"issuer_did": issuer, "subject_did": subject,
                       "claims": {"age": 30, "role": "admin"}})
        assert st == 201, r
        cred = r["credential_id"]

        def prove(body, cred_id=None):
            return _http(
                "POST",
                f"{BASE}/v1/credentials/{cred_id or cred}/prove",
                body,
            )

        def verify(pid, pf, challenge, headers=None):
            return _http("POST", f"{BASE}/v1/proofs/{pid}/verify",
                         {"proof": pf, "challenge": challenge},
                         headers=headers)

        # ---------------- 未绑定兼容 ---------------- #
        st, r = prove({"predicates": PRED, "challenge": "plain"})
        check("未绑定（缺省）201 且九字段",
              st == 201 and set(r) == UNBOUND_KEYS)
        st, vr = verify(r["proof_id"], r, "plain")
        check("未绑定 verify valid:true", st == 200 and vr == {"valid": True})

        st, r = prove({"predicates": PRED, "challenge": "plain-f",
                       "holder_binding": False})
        check("显式 false 201 且九字段",
              st == 201 and set(r) == UNBOUND_KEYS)
        st, vr = verify(r["proof_id"], r, "plain-f")
        check("显式 false verify valid:true",
              st == 200 and vr == {"valid": True})

        # 未绑定证明附加持有者字段 -> 绑定失败
        st, unbound = prove({"predicates": PRED, "challenge": "plain-add"})
        assert st == 201
        fake_bound = dict(unbound, holder_did=subject,
                          holder_key_version=1, holder_proof="AAAA")
        st, vr = verify(unbound["proof_id"], fake_bound, "plain-add")
        check("未绑定记录附加绑定字段 -> valid:false 绑定失败",
              st == 200 and vr.get("valid") is False
              and vr.get("reason") == BIND_REASON)
        st, vr = verify(unbound["proof_id"], unbound, "plain-add")
        check("未绑定原证明仍可消费（失败不消费）",
              st == 200 and vr == {"valid": True})

        # ---------------- 入参校验 ---------------- #
        for name, value in [("字符串", "true"), ("数字", 1),
                            ("null", None), ("列表", []), ("对象", {})]:
            st, r = prove({"predicates": PRED, "holder_binding": value})
            check(f"holder_binding 非布尔 400: {name}",
                  st == 400 and bool(r.get("error")))
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/vc_{'0'*32}/prove",
            {"predicates": PRED, "holder_binding": True},
        )
        check("绑定 + 未知凭证 -> 404", st == 404)

        # ---------------- 绑定生成与外部验真 ---------------- #
        st, pf = prove({"predicates": PRED, "challenge": "bind-1",
                        "holder_binding": True})
        check("绑定 prove -> 201 且恰十二字段",
              st == 201 and set(pf) == BOUND_KEYS)
        check("holder_did 为 subject", pf.get("holder_did") == subject)
        check("holder_key_version 当前为 1",
              pf.get("holder_key_version") == 1)
        check("不回传 claims", "claims" not in pf)
        try:
            crypto.verify(_holder_payload(pf, "default"),
                          pf["holder_proof"], subject_pem_v1)
            check("holder_proof 外部以持有者公钥验真", True)
        except Exception:  # noqa: BLE001
            check("holder_proof 外部以持有者公钥验真", False)
        try:
            crypto.verify(_holder_payload(pf, "other"),
                          pf["holder_proof"], subject_pem_v1)
            check("holder_proof 篡改 tenant_id 验签失败", False)
        except crypto.InvalidSignature:
            check("holder_proof 篡改 tenant_id 验签失败", True)
        raw = base64.urlsafe_b64decode(pf["holder_proof"] + "==")
        check("holder_proof 为 64 字节裸 R||S 无填充 base64url",
              len(raw) == 64 and "=" not in pf["holder_proof"])
        try:
            crypto.verify(_issuer_payload(pf, "default"),
                          pf["proof"], issuer_pem)
            check("issuer proof 按旧覆盖对象验真", True)
        except Exception:  # noqa: BLE001
            check("issuer proof 按旧覆盖对象验真", False)
        try:
            crypto.verify(
                {k: v for k, v in pf.items() if k != "proof"},
                pf["proof"], issuer_pem,
            )
            check("issuer proof 不含 holder_*（含则应失败）", False)
        except crypto.InvalidSignature:
            check("issuer proof 不含 holder_*（含则应失败）", True)

        # ---------------- 成功消费 ---------------- #
        st, vr = verify(pf["proof_id"], pf, "bind-1")
        check("绑定 verify 成功恰返 valid",
              st == 200 and vr == {"valid": True})
        st, vr = verify(pf["proof_id"], pf, "bind-1")
        check("绑定证明重复 verify -> 已消费",
              st == 200 and vr.get("valid") is False
              and "已消费" in vr.get("reason", ""))

        # ---------------- 篡改电池 ---------------- #
        st, fresh = prove({"predicates": PRED, "challenge": "bind-tamper",
                           "holder_binding": True})
        assert st == 201
        fid = fresh["proof_id"]

        def expect_bind_fail(name, bad):
            st, r = verify(fid, bad, "bind-tamper")
            check(name, st == 200 and r.get("valid") is False
                  and r.get("reason") == BIND_REASON)

        expect_bind_fail("缺 holder_did",
                         {k: v for k, v in fresh.items() if k != "holder_did"})
        expect_bind_fail("缺 holder_key_version",
                         {k: v for k, v in fresh.items()
                          if k != "holder_key_version"})
        expect_bind_fail("缺 holder_proof",
                         {k: v for k, v in fresh.items()
                          if k != "holder_proof"})
        # 多余字段属字段集合锚定失败（既有分类原因，非空即可），且不消费
        st, r = verify(fid, dict(fresh, extra=1), "bind-tamper")
        check("多余字段 -> valid:false 非空原因",
              st == 200 and r.get("valid") is False
              and isinstance(r.get("reason"), str) and bool(r["reason"]))
        expect_bind_fail("篡改 holder_did",
                         dict(fresh, holder_did="did:example:" + "0" * 32))
        expect_bind_fail("篡改 holder_key_version",
                         dict(fresh, holder_key_version=2))
        expect_bind_fail("holder_proof 格式错误",
                         dict(fresh, holder_proof="AAAA"))
        rand_sig = base64.urlsafe_b64encode(
            os.urandom(64)).rstrip(b"=").decode()
        expect_bind_fail("holder_proof 随机签名",
                         dict(fresh, holder_proof=rand_sig))
        # holder 字段类型错误
        expect_bind_fail("holder_did 类型错误",
                         dict(fresh, holder_did=123))
        expect_bind_fail("holder_key_version 类型错误",
                         dict(fresh, holder_key_version="1"))
        expect_bind_fail("holder_proof 类型错误",
                         dict(fresh, holder_proof=123))
        # 非持有者类既有失败保持各自原因（较早的既有失败优先）
        st, r = verify(fid, dict(fresh, challenge="other"), "bind-tamper")
        check("篡改 challenge -> 既有锚定原因（非绑定原因）",
              st == 200 and r.get("valid") is False
              and r.get("reason") != BIND_REASON and bool(r.get("reason")))
        st, r = verify(fid, fresh, "wrong-challenge")
        check("请求 challenge 错误 -> 既有锚定原因",
              st == 200 and r.get("valid") is False
              and r.get("reason") != BIND_REASON)
        # 全部失败不消费
        st, r = verify(fid, fresh, "bind-tamper")
        check("篡改尝试均不消费，原证明 valid:true",
              st == 200 and r == {"valid": True})

        # ---------------- 跨租户 ---------------- #
        st, fresh = prove({"predicates": PRED, "challenge": "bind-x",
                           "holder_binding": True})
        assert st == 201
        xid = fresh["proof_id"]
        st, r = verify(xid, fresh, "bind-x",
                       headers={"X-Tenant-ID": "other"})
        check("跨租户 -> 不存在（优先于绑定校验）",
              st == 200 and r.get("valid") is False
              and "不存在" in r.get("reason", ""))
        st, r = verify(xid, fresh, "bind-x")
        check("本租户验证 valid:true（跨租户失败不消费）",
              st == 200 and r == {"valid": True})

        # ---------------- prove-batch 混合与回滚 ---------------- #
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cred}/prove-batch",
            {"items": [
                {"predicates": PRED, "challenge": "b1"},
                {"predicates": PRED, "challenge": "b2",
                 "holder_binding": True},
                {"predicates": PRED, "challenge": "b3",
                 "holder_binding": False},
            ]},
        )
        check("混合批次 201 等长同序",
              st == 201 and len(r.get("proofs", [])) == 3)
        if st == 201:
            p0, p1, p2 = r["proofs"]
            check("批次项 1/3 未绑定九字段",
                  set(p0) == UNBOUND_KEYS and set(p2) == UNBOUND_KEYS)
            check("批次项 2 绑定十二字段", set(p1) == BOUND_KEYS)
            check("批次绑定项 holder_did 正确",
                  p1.get("holder_did") == subject)
            st2, vr = verify(p1["proof_id"], p1, "b2")
            check("批次绑定项 verify valid:true",
                  st2 == 200 and vr == {"valid": True})
        # 项内 holder_binding 非布尔 -> 400 整批不写入（以审计计数佐证）
        st, audit_before = _http("GET", f"{BASE}/v1/audit?limit=200")
        created_before = sum(
            1 for e in audit_before["events"]
            if e["action"] == "proof.created")
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cred}/prove-batch",
            {"items": [
                {"predicates": PRED, "challenge": "ok"},
                {"predicates": PRED, "holder_binding": "yes"},
            ]},
        )
        check("批次项 holder_binding 非布尔 -> 400",
              st == 400 and bool(r.get("error")))
        # 任一项 predicates 非法 -> 400 整批不写入
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cred}/prove-batch",
            {"items": [
                {"predicates": PRED, "challenge": "ok2",
                 "holder_binding": True},
                {"predicates": [], "holder_binding": True},
            ]},
        )
        check("批次任一项 predicates 非法 -> 400 整批不写入",
              st == 400 and bool(r.get("error")))
        st, audit_after = _http("GET", f"{BASE}/v1/audit?limit=200")
        created_after = sum(
            1 for e in audit_after["events"]
            if e["action"] == "proof.created")
        check("两个失败批次均不写 proof.created 审计",
              created_after == created_before)

        # ---------------- 证明过期与凭证吊销优先级 ---------------- #
        st, fresh = prove({"predicates": PRED, "expires_in": 1,
                           "holder_binding": True})
        assert st == 201
        time.sleep(2)
        st, r = verify(fresh["proof_id"], fresh, fresh["challenge"])
        check("绑定证明过期 -> 证明已过期（持有者校验之后）",
              st == 200 and r.get("valid") is False
              and "已过期" in r.get("reason", ""))

        st, r = _http("POST", f"{BASE}/v1/credentials",
                      {"issuer_did": issuer, "subject_did": subject,
                       "claims": {"age": 9}})
        assert st == 201, r
        cred_rev = r["credential_id"]
        st, fresh = _http(
            "POST", f"{BASE}/v1/credentials/{cred_rev}/prove",
            {"predicates": [{"path": "/age", "op": "exists"}],
             "challenge": "rev", "holder_binding": True},
        )
        assert st == 201, fresh
        st, _ = _http("POST", f"{BASE}/v1/credentials/{cred_rev}/revoke",
                      {"reason": "谓词绑定测试吊销"})
        assert st == 200
        st, r = verify(fresh["proof_id"], fresh, "rev")
        check("凭证吊销后绑定证明 -> 凭证已吊销（持有者校验之后）",
              st == 200 and r.get("valid") is False
              and "凭证已吊销" in r.get("reason", ""))

        # ---------------- 签发密钥吊销优先于持有者 ---------------- #
        # 用主凭证先生成一张绑定证明，再轮换并吊销签发者 v1
        st, issuer_old = prove({"predicates": PRED, "challenge": "ikr",
                                "holder_binding": True})
        assert st == 201, issuer_old
        st, r = _http("POST", f"{BASE}/v1/dids/{issuer}/keys/rotate",
                      {"key_handle": "zphb-issuer-v2"})
        assert st == 200, r
        st, _ = _http(
            "POST", f"{BASE}/v1/dids/{issuer}/keys/1/revoke",
            {"reason": "签发旧钥吊销"},
        )
        assert st == 200
        st, r = verify(issuer_old["proof_id"], issuer_old, "ikr")
        check("签发密钥吊销优先于持有者校验",
              st == 200 and r.get("valid") is False
              and "签发密钥已吊销" in r.get("reason", ""))

        # ---------------- 持有者轮换：历史公钥 ---------------- #
        # 签发者已轮换到 v2：新凭证用 v2 签发
        st, r = _http("POST", f"{BASE}/v1/credentials",
                      {"issuer_did": issuer, "subject_did": subject,
                       "claims": {"age": 31}})
        assert st == 201, r
        cred2 = r["credential_id"]
        st, before = _http(
            "POST", f"{BASE}/v1/credentials/{cred2}/prove",
            {"predicates": PRED, "challenge": "pre-rotate",
             "holder_binding": True},
        )
        assert st == 201, before
        check("轮换前绑定证明 holder_key_version=1",
              before["holder_key_version"] == 1)
        # 预留一张不消费的 v1 绑定证明，供吊销 v1 后验证
        st, v1_keep = _http(
            "POST", f"{BASE}/v1/credentials/{cred2}/prove",
            {"predicates": PRED, "challenge": "v1-keep",
             "holder_binding": True},
        )
        assert st == 201, v1_keep
        st, r = _http("POST", f"{BASE}/v1/dids/{subject}/keys/rotate",
                      {"key_handle": "zphb-subject-v2"})
        assert st == 200, r
        subject_pem_v2 = r["public_key"]
        check("持有者轮换到 v2", r.get("key_version") == 2)
        # 旧证明以 v1 历史公钥仍可验证（消费 before）
        st, rr = verify(before["proof_id"], before, "pre-rotate")
        check("轮换后旧绑定证明历史公钥 valid:true",
              st == 200 and rr == {"valid": True})
        try:
            crypto.verify(_holder_payload(before, "default"),
                          before["holder_proof"], subject_pem_v1)
            check("旧 holder_proof 外部以 v1 验真", True)
        except Exception:  # noqa: BLE001
            check("旧 holder_proof 外部以 v1 验真", False)
        # 预留的 v1 证明在轮换后仍密码学有效（外部验真，不消费）
        try:
            crypto.verify(_holder_payload(v1_keep, "default"),
                          v1_keep["holder_proof"], subject_pem_v1)
            check("预留 v1 holder_proof 轮换后外部仍可验真", True)
        except Exception:  # noqa: BLE001
            check("预留 v1 holder_proof 轮换后外部仍可验真", False)
        # 新证明用 v2
        st, after = _http(
            "POST", f"{BASE}/v1/credentials/{cred2}/prove",
            {"predicates": PRED, "challenge": "post-rotate",
             "holder_binding": True},
        )
        assert st == 201, after
        check("轮换后新绑定证明 holder_key_version=2",
              after["holder_key_version"] == 2)
        try:
            crypto.verify(_holder_payload(after, "default"),
                          after["holder_proof"], subject_pem_v2)
            check("新 holder_proof 外部以 v2 验真", True)
        except Exception:  # noqa: BLE001
            check("新 holder_proof 外部以 v2 验真", False)
        st, rr = verify(after["proof_id"], after, "post-rotate")
        check("轮换后新绑定证明 valid:true",
              st == 200 and rr == {"valid": True})

        # 持有者旧版本吊销：未消费的 v1 绑定证明 -> 绑定失败、不消费
        st, _ = _http(
            "POST", f"{BASE}/v1/dids/{subject}/keys/1/revoke",
            {"reason": "持有者旧钥吊销"},
        )
        assert st == 200
        st, r = verify(v1_keep["proof_id"], v1_keep, "v1-keep")
        check("持有者所用版本吊销 -> 绑定失败 不消费",
              st == 200 and r.get("valid") is False
              and r.get("reason") == BIND_REASON)
        st, r = verify(v1_keep["proof_id"], v1_keep, "v1-keep")
        check("吊销后重复验证仍绑定失败（未消费）",
              st == 200 and r.get("valid") is False
              and r.get("reason") == BIND_REASON)
        # 未绑定证明不受持有者密钥吊销影响
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cred2}/prove",
            {"predicates": PRED, "challenge": "unbound-ok"},
        )
        assert st == 201, r
        st, rr = verify(r["proof_id"], r, "unbound-ok")
        check("持有者旧钥吊销不影响未绑定证明",
              st == 200 and rr == {"valid": True})

        # ---------------- 重启持久化 ---------------- #
        st, keep = _http(
            "POST", f"{BASE}/v1/credentials/{cred2}/prove",
            {"predicates": PRED, "challenge": "restart-bind",
             "holder_binding": True},
        )
        assert st == 201, keep
        keep_id = keep["proof_id"]
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server()
        st, r = verify(keep_id, keep, "restart-bind")
        check("重启后绑定证明双签名验证 valid:true",
              st == 200 and r == {"valid": True})
        st, r = verify(keep_id, keep, "restart-bind")
        check("重启后消费标记保留（已消费）",
              st == 200 and r.get("valid") is False
              and "已消费" in r.get("reason", ""))

        # ---------------- 并发仅一次 ---------------- #
        st, race = _http(
            "POST", f"{BASE}/v1/credentials/{cred2}/prove",
            {"predicates": PRED, "challenge": "race",
             "holder_binding": True},
        )
        assert st == 201, race
        race_id = race["proof_id"]

        def one_verify(_):
            return verify(race_id, race, "race")

        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(one_verify, range(8)))
        valids = [r for st, r in outcomes
                  if st == 200 and r.get("valid") is True]
        consumed = [r for st, r in outcomes
                    if st == 200 and r.get("valid") is False
                    and "已消费" in r.get("reason", "")]
        check("绑定证明并发验证仅一次 valid:true",
              len(valids) == 1 and len(consumed) == 7)

        # ---------------- 持有者停用：生成 409 / 验证绑定失败 -------- #
        st, deact_proof = _http(
            "POST", f"{BASE}/v1/credentials/{cred2}/prove",
            {"predicates": PRED, "challenge": "deact",
             "holder_binding": True},
        )
        assert st == 201, deact_proof
        # 停用前未绑定证明仍可正常生成
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cred2}/prove",
            {"predicates": PRED, "challenge": "deact-unbound"},
        )
        check("持有者停用时未绑定证明仍可生成", st == 201)
        st, _ = _http("POST", f"{BASE}/v1/dids/{subject}/deactivate",
                      {"reason": "持有者离开"})
        assert st == 200
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cred2}/prove",
            {"predicates": PRED, "holder_binding": True},
        )
        check("持有者已停用 -> 绑定生成 409 且不留证明", st == 409)
        st, r = verify(deact_proof["proof_id"], deact_proof, "deact")
        check("持有者停用后绑定验证 -> 绑定失败 不消费",
              st == 200 and r.get("valid") is False
              and r.get("reason") == BIND_REASON)
        st, r = verify(deact_proof["proof_id"], deact_proof, "deact")
        check("持有者停用后重复验证仍失败（未消费）",
              st == 200 and r.get("valid") is False
              and r.get("reason") == BIND_REASON)

        # ---------------- 外部信任证明接口拒收绑定证明 -------------- #
        st, r = _http("POST", f"{BASE}/v1/trust/proofs/verify",
                      {"proof": keep, "challenge": "restart-bind",
                       "source_tenant_id": "default"})
        check("外部信任证明接口拒绝绑定证明（多余字段）",
              st == 200 and r.get("valid") is False
              and "多余字段" in r.get("reason", ""))

        # ---------------- 直连 store 防御路径 ---------------- #
        run_direct_store_checks(check)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(STORE):
            os.unlink(STORE)

    print()
    if failures:
        print(f"共 {len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("谓词证明持有者绑定测试全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
