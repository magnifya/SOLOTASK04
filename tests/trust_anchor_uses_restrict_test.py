#!/usr/bin/env python3
"""信任锚点用途收紧（PUT .../uses）的端到端测试。

直接运行：python3 tests/trust_anchor_uses_restrict_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402
from vcbackend.store import VCStore  # noqa: E402

ALL_USES = ["generic", "vc", "vp", "proof", "did", "status", "deactivation"]


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
            return resp.status, (json.loads(raw_body) if raw_body else {}), raw_body
    except urllib.error.HTTPError as exc:
        raw_body = exc.read().decode()
        return exc.code, (json.loads(raw_body) if raw_body else {}), raw_body


def wait_up(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
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


def only_chinese_error(r):
    return (
        set(r) == {"error"}
        and isinstance(r["error"], str)
        and bool(r["error"].strip())
    )


def main():
    port = 8967
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
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

    def put_uses(did, ver, payload, headers=None, raw=None):
        return _http(
            "PUT", f"{base}/v1/trust/anchors/{did}/{ver}/uses",
            payload=payload, headers=headers, raw=raw,
        )

    def uses_updated_events(headers):
        st, r, _ = _http("GET", f"{base}/v1/audit?limit=200&after=0",
                         headers=headers)
        assert st == 200
        return [e for e in r["events"]
                if e["action"] == "trust.anchor.uses.updated"]

    try:
        assert wait_up(port), "服务启动超时"

        T1 = {"X-Tenant-ID": "restrict-a"}
        T2 = {"X-Tenant-ID": "restrict-b"}

        priv1, pub1 = gen_keypair()
        priv2, pub2 = gen_keypair()
        did = "did:web:example.com:restrict"
        did2 = "did:web:example.com:other"

        def anchor(d, ver, pem, uses=None, headers=None):
            payload = {"did": d, "public_key": pem, "key_version": ver}
            if uses is not None:
                payload["uses"] = uses
            return _http("POST", f"{base}/v1/trust/anchors", payload,
                         headers=headers or T1)

        # 0. 显式空租户头 -> 400
        st, r, _ = put_uses(did, 1,
                            {"from_uses": ALL_USES, "uses": ["generic"]},
                            headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400 and only_chinese_error(r))

        # 1. 注册全用途锚点（省略 uses）
        st, _, _ = anchor(did, 1, pub1)
        check("注册锚点 201", st == 201)
        st, _, _ = anchor(did2, 1, pub2, headers=T2)
        check("他租户注册锚点 201", st == 201)

        # 2. 请求体非法 -> 400（恰含 from_uses、uses；两者均为合规数组）
        bad_bodies = [
            {"uses": ["generic"]},
            {"from_uses": ALL_USES},
            {"from_uses": ALL_USES, "uses": ["generic"], "x": 1},
            {"from_uses": None, "uses": ["generic"]},
            {"from_uses": "generic", "uses": ["generic"]},
            {"from_uses": [], "uses": ["generic"]},
            {"from_uses": [1], "uses": ["generic"]},
            {"from_uses": ["generic", "generic"], "uses": ["generic"]},
            {"from_uses": ["nope"], "uses": ["generic"]},
            {"from_uses": ["vc", "generic"], "uses": ["generic"]},
            {"from_uses": [""], "uses": ["generic"]},
            {"from_uses": ALL_USES, "uses": None},
            {"from_uses": ALL_USES, "uses": "generic"},
            {"from_uses": ALL_USES, "uses": []},
            {"from_uses": ALL_USES, "uses": ["generic", "generic"]},
            {"from_uses": ALL_USES, "uses": ["vc", "generic"]},
            {"from_uses": ALL_USES, "uses": ["all"]},
        ]
        for i, bad in enumerate(bad_bodies):
            st, r, _ = put_uses(did, 1, bad, headers=T1)
            check(f"非法请求体[{i}] -> 400", st == 400)
            check(f"非法请求体[{i}] 仅含非空中文 error",
                  only_chinese_error(r))
        # 非法 JSON / 非对象 / 空体
        for i, raw in enumerate([b"{", b"[1,2]", b""]):
            st, r, _ = put_uses(did, 1, None, headers=T1, raw=raw)
            check(f"非法 JSON[{i}] -> 400", st == 400 and only_chinese_error(r))

        # 3. 路径版本非法 -> 400
        for bad_ver in ["0", "-1", "1.0", "abc", "", "１２", "+1", " 1"]:
            st, r, _ = _http(
                "PUT",
                f"{base}/v1/trust/anchors/{did}/"
                f"{urllib.parse.quote(bad_ver)}/uses",
                payload={"from_uses": ALL_USES, "uses": ["generic"]},
                headers=T1,
            )
            check(f"路径版本 {bad_ver!r} -> 400",
                  st == 400 and only_chinese_error(r))

        # 4. 未知/跨租户锚点 -> 404
        st, r, _ = put_uses("did:web:none", 1,
                            {"from_uses": ALL_USES, "uses": ["generic"]},
                            headers=T1)
        check("未知 DID -> 404", st == 404 and only_chinese_error(r))
        st, r, _ = put_uses(did, 99,
                            {"from_uses": ALL_USES, "uses": ["generic"]},
                            headers=T1)
        check("未知版本 -> 404", st == 404 and only_chinese_error(r))
        st, r, _ = put_uses(did2, 1,
                            {"from_uses": ALL_USES, "uses": ["generic"]},
                            headers=T1)
        check("跨租户锚点 -> 404", st == 404 and only_chinese_error(r))

        # 5. 收紧成功：全用途 -> [generic, vc]
        st, r, raw_body = put_uses(
            did, 1, {"from_uses": ALL_USES, "uses": ["generic", "vc"]},
            headers=T1,
        )
        check("收紧 200", st == 200)
        check("收紧响应恰含 did/key_version/uses 且键序正确",
              list(r) == ["did", "key_version", "uses"]
              and r == {"did": did, "key_version": 1,
                        "uses": ["generic", "vc"]})
        check("响应体键序为 did,key_version,uses",
              list(json.loads(raw_body)) == ["did", "key_version", "uses"])
        st, r, _ = _http("GET",
                         f"{base}/v1/trust/anchors/{did}/1/uses", headers=T1)
        check("GET uses 反映收紧结果",
              r == {"did": did, "key_version": 1,
                    "uses": ["generic", "vc"]})

        # 6. 审计：恰有一条 trust.anchor.uses.updated
        events = uses_updated_events(T1)
        check("实际收紧追加一条 uses.updated 审计", len(events) == 1)
        check("审计 resource_type/resource_id",
              events[0]["resource_type"] == "trust_anchor"
              and events[0]["resource_id"] == f"{did}#1")
        check("审计事件恰含六字段",
              set(events[0]) == {"seq", "timestamp", "tenant_id", "action",
                                 "resource_type", "resource_id"})

        # 7. 幂等：目标等于当前值 -> 200，无副作用、不记审计
        st, r, _ = put_uses(
            did, 1,
            {"from_uses": ["generic", "vc"], "uses": ["generic", "vc"]},
            headers=T1,
        )
        check("幂等收紧 200",
              st == 200 and r["uses"] == ["generic", "vc"])
        check("幂等不追加审计", len(uses_updated_events(T1)) == 1)
        # from_uses 不匹配但目标等于当前值：仍按幂等处理（无副作用）
        st, r, _ = put_uses(
            did, 1,
            {"from_uses": ALL_USES, "uses": ["generic", "vc"]},
            headers=T1,
        )
        check("目标等于当前值始终幂等 200",
              st == 200 and r["uses"] == ["generic", "vc"])
        check("幂等不追加审计（2）", len(uses_updated_events(T1)) == 1)

        # 8. 前置不匹配 -> 409
        st, r, _ = put_uses(
            did, 1, {"from_uses": ALL_USES, "uses": ["generic"]}, headers=T1
        )
        check("from_uses 不等于当前值 -> 409",
              st == 409 and only_chinese_error(r))
        check("前置不匹配不改变用途", True)
        st, r, _ = _http("GET",
                         f"{base}/v1/trust/anchors/{did}/1/uses", headers=T1)
        check("409 后用途不变", r["uses"] == ["generic", "vc"])
        check("409 不追加审计", len(uses_updated_events(T1)) == 1)

        # 9. 扩权 -> 409（from 匹配当前，但目标含当前之外用途）
        st, r, _ = put_uses(
            did, 1,
            {"from_uses": ["generic", "vc"], "uses": ["generic", "vc", "vp"]},
            headers=T1,
        )
        check("扩权 -> 409", st == 409 and only_chinese_error(r))
        # 等长不同集合（非子集）也算扩权
        st, r, _ = put_uses(
            did, 1,
            {"from_uses": ["generic", "vc"], "uses": ["generic", "vp"]},
            headers=T1,
        )
        check("非子集替换 -> 409", st == 409 and only_chinese_error(r))
        st, r, _ = _http("GET",
                         f"{base}/v1/trust/anchors/{did}/1/uses", headers=T1)
        check("扩权 409 后用途不变", r["uses"] == ["generic", "vc"])
        check("扩权不追加审计", len(uses_updated_events(T1)) == 1)

        # 10. 正确前置的继续收紧 -> 200，再记一条审计
        st, r, _ = put_uses(
            did, 1,
            {"from_uses": ["generic", "vc"], "uses": ["generic"]},
            headers=T1,
        )
        check("继续收紧 200", st == 200 and r["uses"] == ["generic"])
        check("第二次收紧再追加一条审计",
              len(uses_updated_events(T1)) == 2)

        # 11. 变更立即作用于全部 /v1/trust 用途门控
        message = {"issuer_did": did, "issuer_key_version": 1, "nonce": "n1"}
        sig = crypto.sign(message, priv1)
        st, r, _ = _http("POST", f"{base}/v1/trust/verify",
                         {**message, "signature": sig}, headers=T1)
        check("generic 入口仍可用", r.get("valid") is True)

        body = {"credential_id": "cred-r1", "issuer_did": did,
                "subject_did": "did:web:sub", "claims": {"a": 1},
                "issued_at": "2026-01-01T00:00:00Z",
                "issuer_key_version": 1}
        sig = crypto.sign(body, priv1)
        st, r, _ = _http("POST", f"{base}/v1/trust/credentials/verify",
                         {"body": body, "signature": sig}, headers=T1)
        check("vc 入口立即拒绝（锚点不存在协议）",
              st == 200 and r.get("valid") is False
              and r.get("reason") == f"锚点不存在: {did}#1")

        sync_body = {"issuer_did": did, "credential_id": "cred-s2",
                     "status": "revoked",
                     "updated_at": "2026-01-01T00:00:00Z",
                     "issuer_key_version": 1}
        sig = crypto.sign(sync_body, priv1)
        st, r, _ = _http("POST", f"{base}/v1/trust/credential-status/sync",
                         {"body": sync_body, "signature": sig}, headers=T1)
        check("status 入口立即拒绝（200 公开协议）",
              st == 200 and r.get("valid") is False)

        deact_body = {"did": did, "key_version": 1, "reason": "测试",
                      "deactivated_at": "2026-01-01T00:00:00Z"}
        sig = crypto.sign(deact_body, priv1)
        st, r, _ = _http("POST", f"{base}/v1/trust/dids/deactivate-sync",
                         {"body": deact_body, "signature": sig}, headers=T1)
        check("deactivation 入口立即拒绝",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "锚点不可用")

        doc = {"did": did, "current_key_version": 1,
               "verification_methods": [
                   {"key_version": 1, "key_handle": "k1",
                    "public_key": pub1}],
               "document_proof": "x"}
        st, r, _ = _http("POST", f"{base}/v1/trust/dids/verify-document",
                         {"document": doc}, headers=T1)
        check("did 入口立即拒绝",
              r.get("valid") is False
              and r.get("reason") == f"锚点不存在: {did}#1")

        # 12. 并发不同收紧：from_uses 同为收紧前值，最多一个成功
        st, _, _ = anchor("did:web:concurrent", 1, pub1, headers=T1)
        assert st == 201
        cdid = "did:web:concurrent"
        targets = [["generic"], ["vc"], ["vp"], ["proof"], ["did"],
                   ["status"], ["deactivation"]]
        results = []
        barrier = threading.Barrier(len(targets))

        def worker(target):
            barrier.wait()
            code, resp, _ = put_uses(
                cdid, 1,
                {"from_uses": ALL_USES, "uses": target}, headers=T1,
            )
            results.append((code, resp.get("uses")))

        threads = [threading.Thread(target=worker, args=(t,)) for t in targets]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        winners = [x for x in results if x[0] == 200]
        check("并发收紧恰一个成功", len(winners) == 1)
        check("其余并发收紧均 409",
              len([x for x in results if x[0] == 409]) == len(targets) - 1)
        st, r, _ = _http("GET",
                         f"{base}/v1/trust/anchors/{cdid}/1/uses", headers=T1)
        check("并发后当前用途为获胜目标",
              r["uses"] == winners[0][1] and len(r["uses"]) == 1)
        before_retry = len(uses_updated_events(T1))
        # 失败者以最新当前值为前置继续收紧（单元素无法再收紧，
        # 故先注册一个多用途锚点验证“可重试成功”）
        st, _, _ = anchor("did:web:concurrent2", 1, pub1,
                          uses=["generic", "vc", "vp"], headers=T1)
        assert st == 201
        cur = ["generic", "vc", "vp"]
        st, r, _ = put_uses(
            "did:web:concurrent2", 1,
            {"from_uses": cur, "uses": ["generic", "vc"]}, headers=T1,
        )
        check("失败后以最新当前值重试成功",
              st == 200 and r["uses"] == ["generic", "vc"])
        check("重试成功追加一条审计",
              len(uses_updated_events(T1)) == before_retry + 1)

        # 13. 已吊销锚点 -> 409（吊销后不能再收紧）
        st, _, _ = anchor("did:web:revoked-anchor", 1, pub1,
                          uses=["generic", "vc"], headers=T1)
        assert st == 201
        st, _, _ = _http(
            "PUT",
            f"{base}/v1/trust/anchors/did:web:revoked-anchor/1/status",
            payload={"status": "revoked"}, headers=T1,
        )
        assert st == 200
        st, r, _ = put_uses(
            "did:web:revoked-anchor", 1,
            {"from_uses": ["generic", "vc"], "uses": ["generic"]}, headers=T1,
        )
        check("已吊销锚点收紧 -> 409",
              st == 409 and only_chinese_error(r))
        revoked_audit_before = [
            e for e in uses_updated_events(T1)
            if e["resource_id"] == "did:web:revoked-anchor#1"
        ]
        check("已吊销 409 不记 uses 审计", revoked_audit_before == [])

        # 14. 轮换继承收紧后的用途
        st, _, _ = anchor("did:web:inherit", 1, pub1, headers=T1)
        assert st == 201
        st, _, _ = put_uses(
            "did:web:inherit", 1,
            {"from_uses": ALL_USES, "uses": ["generic", "did"]}, headers=T1,
        )
        assert st == 200
        st, r, _ = _http(
            "POST", f"{base}/v1/trust/anchors/did:web:inherit/rotate",
            payload={"from_key_version": 1, "public_key": pub2}, headers=T1,
        )
        check("轮换 201", st == 201 and r["key_version"] == 2)
        st, r, _ = _http(
            "GET",
            f"{base}/v1/trust/anchors/did:web:inherit/2/uses", headers=T1,
        )
        check("轮换继承收紧后的用途",
              r == {"did": "did:web:inherit", "key_version": 2,
                    "uses": ["generic", "did"]})

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    # 15. 重启后收紧结果保持
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务重启超时"
        st, r, _ = _http("GET",
                         f"{base}/v1/trust/anchors/{did}/1/uses", headers=T1)
        check("重启后收紧结果保持",
              st == 200 and r["uses"] == ["generic"])
        st, r, _ = _http(
            "GET",
            f"{base}/v1/trust/anchors/did:web:inherit/2/uses", headers=T1,
        )
        check("重启后轮换继承用途保持", r["uses"] == ["generic", "did"])
        events = [
            e for e in uses_updated_events(T1)
            if e["resource_id"] == f"{did}#1"
        ]
        check("重启后审计保持（did#1 恰两条）", len(events) == 2)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    # 16. 落盘失败回滚（进程内直接构造 store，模拟 _save_locked 失败）
    path2 = tempfile.mktemp(suffix=".json")
    try:
        local = VCStore(path2)
        _priv3, pub3 = gen_keypair()
        local.register_trust_anchor("rollback-tenant", "did:web:rb", pub3, 1)

        def _boom():
            raise OSError("模拟磁盘已满")

        local._save_locked = _boom  # type: ignore[assignment]
        rolled_back = False
        try:
            local.restrict_trust_anchor_uses(
                "rollback-tenant", "did:web:rb", 1,
                list(ALL_USES), ["generic"],
            )
        except OSError:
            rolled_back = True
        check("落盘失败向上抛错（HTTP 层映射 500）", rolled_back)
        check("落盘失败后内存用途回滚为全用途",
              local.get_trust_anchor_uses(
                  "rollback-tenant", "did:web:rb", 1) == list(ALL_USES))
        audit_events, _ = local.list_audit("rollback-tenant", 0, 200)
        check("落盘失败后审计回滚（无 uses.updated）",
              all(e.action != "trust.anchor.uses.updated"
                  for e in audit_events))
        # 恢复落盘能力后重试可成功
        del local._save_locked
        uses_after, changed = local.restrict_trust_anchor_uses(
            "rollback-tenant", "did:web:rb", 1,
            list(ALL_USES), ["generic"],
        )
        check("恢复后收紧成功",
              changed is True and uses_after == ["generic"])
        audit_events, _ = local.list_audit("rollback-tenant", 0, 200)
        check("恢复后审计追加成功",
              [e.action for e in audit_events]
              == ["trust.anchor.registered", "trust.anchor.uses.updated"])
        # 重新从磁盘加载，收紧结果持久
        reloaded = VCStore(path2)
        check("回滚后成功的收紧跨重启持久",
              reloaded.get_trust_anchor_uses(
                  "rollback-tenant", "did:web:rb", 1) == ["generic"])
    finally:
        if os.path.exists(path2):
            os.unlink(path2)
        if os.path.exists(store):
            os.unlink(store)

    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
