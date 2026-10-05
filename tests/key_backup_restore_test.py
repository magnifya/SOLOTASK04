#!/usr/bin/env python3
"""DID 私钥口令加密备份与恢复端到端测试。

覆盖：
- POST /v1/dids/{did}/keys/backup：请求体恰含 passphrase（8..256 个
  Unicode 码点非空字符串）；空体、非法 JSON、字段缺失/多余/类型错误
  一律 400 {"error":"请求非法"}；未知或跨租户 DID 404，停用 DID 409；
  成功 200 恰含 did、key_version、key_handle、kdf、kdf_iterations、
  salt、cipher、nonce、ciphertext（kdf=PBKDF2-HMAC-SHA256、迭代
  310000、cipher=AES-256-GCM，salt 16 字节、nonce 12 字节无填充
  base64url）；私钥不出现在响应/审计/查询；成功追加
  did.key.backup.exported 审计，失败无副作用；
- POST /v1/dids/{did}/keys/restore：请求体恰含 backup、passphrase、
  key_handle；结构错误 400 请求非法；绑定不符/口令错误/解密认证失败/
  内容篡改统一 400 {"error":"备份无效"}；未知或跨租户 DID 404，停用
  DID 409，句柄已被本租户任一版本使用 409 {"error":"key_handle 已被使用"}；
  成功以当前版本加一创建新版本，响应字段同 /keys/rotate；恢复、密钥
  历史、轮换证明、游标与 key.rotated 审计同一次原子落盘，失败整体
  回滚；旧版本签名、吊销状态与凭证验签结论不变；重启后状态稳定。

直接运行：python3 tests/key_backup_restore_test.py
"""

import base64
import copy
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

PORT = 8995
PASSPHRASE = "备份口令-correct horse"
PRIVATE_MARKER = "PRIVATE KEY-----"

BACKUP_FIELDS = {
    "did",
    "key_version",
    "key_handle",
    "kdf",
    "kdf_iterations",
    "salt",
    "cipher",
    "nonce",
    "ciphertext",
}
ROTATE_PAYLOAD_FIELDS = {"did", "public_key", "key_mode", "key_handle",
                         "key_version"}


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


def b64url_len(text, nbytes):
    """无填充 base64url 解码后恰为 nbytes 字节且重编码一致。"""
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except Exception:  # noqa: BLE001
        return False
    return (
        len(raw) == nbytes
        and "=" not in text
        and base64.urlsafe_b64encode(raw).rstrip(b"=").decode() == text
    )


def main():
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    store_path = tempfile.mktemp(suffix=".json")
    proc = start_server(PORT, store_path)
    base = f"http://127.0.0.1:{PORT}"
    TA = {"X-Tenant-ID": "bk-a"}
    TB = {"X-Tenant-ID": "bk-b"}

    def backup(did, body, headers=TA, raw=None):
        return _http("POST", f"{base}/v1/dids/{did}/keys/backup",
                     payload=body, headers=headers, raw=raw)

    def restore(did, body, headers=TA, raw=None):
        return _http("POST", f"{base}/v1/dids/{did}/keys/restore",
                     payload=body, headers=headers, raw=raw)

    def audit(headers=TA):
        return _http("GET", f"{base}/v1/audit?limit=200", headers=headers)

    try:
        # ---- 准备：A 租户 DID（轮换到 v2），B 租户 DID ----
        st, a = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "bk-h1"},
                      headers=TA)
        assert st == 201, a
        did_a = a["did"]
        st, rot = _http("POST", f"{base}/v1/dids/{did_a}/keys/rotate",
                        {"key_handle": "bk-h2"}, headers=TA)
        assert st == 200, rot
        st, b = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "bk-b1"},
                      headers=TB)
        assert st == 201, b
        did_b = b["did"]
        # A 租户内的持有者 DID（签发凭证用）
        st, h = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "bk-holder"},
                      headers=TA)
        assert st == 201, h
        did_holder = h["did"]

        # 恢复前用当前版本（v2）签发一张凭证，供事后验证旧结论不变。
        st, cred_old = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": did_a, "subject_did": did_holder,
            "claims": {"role": "tester"}}, headers=TA)
        assert st == 201, cred_old
        old_cid = cred_old["credential_id"]
        st, old_vc = _http("GET", f"{base}/v1/credentials/{old_cid}",
                           headers=TA)
        assert st == 200, old_vc
        old_verify = {"body": old_vc["body"],
                      "signature": old_vc["signature"]}

        # ---- 1. backup 成功：字段、固定值、随机性、无私钥 ----
        st, bk = backup(did_a, {"passphrase": PASSPHRASE})
        check("backup 成功 200 且恰含九字段",
              st == 200 and set(bk) == BACKUP_FIELDS)
        check("backup 绑定当前 DID/版本/句柄",
              bk["did"] == did_a and bk["key_version"] == 2
              and bk["key_handle"] == "bk-h2")
        check("kdf/迭代/cipher 固定值",
              bk["kdf"] == "PBKDF2-HMAC-SHA256"
              and bk["kdf_iterations"] == 310000
              and bk["cipher"] == "AES-256-GCM")
        check("salt 16 字节、nonce 12 字节无填充 base64url",
              b64url_len(bk["salt"], 16) and b64url_len(bk["nonce"], 12))
        check("ciphertext 为无填充 base64url 且非空",
              isinstance(bk["ciphertext"], str)
              and "=" not in bk["ciphertext"] and len(bk["ciphertext"]) > 20)
        check("backup 响应绝不含私钥",
              PRIVATE_MARKER not in json.dumps(bk))
        st, bk2 = backup(did_a, {"passphrase": PASSPHRASE})
        check("两次备份 salt/nonce/ciphertext 随机不同",
              st == 200 and bk2["salt"] != bk["salt"]
              and bk2["nonce"] != bk["nonce"]
              and bk2["ciphertext"] != bk["ciphertext"])

        # ---- 2. backup 审计：成功追加 did.key.backup.exported ----
        st, au = audit()
        acts = [e["action"] for e in au["events"]]
        check("成功备份追加 did.key.backup.exported 审计（两次）",
              acts.count("did.key.backup.exported") == 2)
        check("审计内容不含私钥",
              PRIVATE_MARKER not in json.dumps(au))

        # ---- 3. backup 请求非法：统一 400 {"error":"请求非法"} ----
        n_audit_before = len(au["events"])
        bad_cases = [
            ("空体", None, b""),
            ("非法 JSON", None, b"{not-json"),
            ("非对象 JSON", None, b"[1,2]"),
            ("空对象", {}, None),
            ("缺 passphrase 多字段", {"other": "x"}, None),
            ("多余字段", {"passphrase": PASSPHRASE, "extra": 1}, None),
            ("口令非字符串", {"passphrase": 12345678}, None),
            ("口令为 null", {"passphrase": None}, None),
            ("口令为数组", {"passphrase": ["x" * 8]}, None),
            ("口令过短 7", {"passphrase": "x" * 7}, None),
            ("口令超长 257", {"passphrase": "x" * 257}, None),
            ("口令空串", {"passphrase": ""}, None),
        ]
        bad_ok = True
        for name, body, raw in bad_cases:
            st, r = backup(did_a, body, raw=raw)
            if not (st == 400 and r == {"error": "请求非法"}):
                bad_ok = False
                print("   backup 未按 400 请求非法拒绝:", name, st, r)
        check("backup 空体/非法 JSON/缺多字段/类型错误均 400 请求非法",
              bad_ok)
        # 边界：8 与 256 个码点（含多字节字符）均合法
        st, r = backup(did_a, {"passphrase": "口令" * 4})
        check("口令 8 个 Unicode 码点（多字节）合法", st == 200)
        st, r = backup(did_a, {"passphrase": "密" * 256})
        check("口令 256 个码点合法", st == 200)
        st, r = backup(did_a, {"passphrase": "密" * 255 + "x"})
        check("口令 256 码点边界合法", st == 200)

        # ---- 4. backup 404 / 409 ----
        st, _ = backup("did:example:00000000000000000000000000000000",
                       {"passphrase": PASSPHRASE})
        check("backup 未知 DID -> 404", st == 404)
        st, _ = backup(did_a, {"passphrase": PASSPHRASE}, headers=TB)
        check("backup 跨租户 DID -> 404", st == 404)
        st, dd = _http("POST", f"{base}/v1/dids",
                       {"method": "example", "public_key": "bk-dead"},
                       headers=TA)
        dead_did = dd["did"]
        st, _ = _http("POST", f"{base}/v1/dids/{dead_did}/deactivate",
                      {}, headers=TA)
        st, r = backup(dead_did, {"passphrase": PASSPHRASE})
        check("backup 停用 DID -> 409", st == 409)
        # 失败无副作用：审计条数不变（仅成功的边界口令各加一条）
        st, au = audit()
        exported = [e for e in au["events"]
                    if e["action"] == "did.key.backup.exported"]
        check("backup 失败不追加审计（共 5 次成功导出）",
              len(exported) == 5)

        # ---- 5. restore 成功：响应同 rotate，版本+1 ----
        st, r = restore(did_a, {"backup": bk, "passphrase": PASSPHRASE,
                                "key_handle": "bk-h3"})
        check("restore 成功 200 且响应字段同 rotate",
              st == 200 and set(r) == ROTATE_PAYLOAD_FIELDS)
        check("restore 新版本=当前+1、句柄为新句柄",
              r["key_version"] == 3 and r["key_handle"] == "bk-h3"
              and r["did"] == did_a and r["key_mode"] == "server")
        check("restore 响应不含私钥",
              PRIVATE_MARKER not in json.dumps(r))
        # 恢复的公钥与备份源版本（v2）公钥一致
        st, doc = _http("GET", f"{base}/v1/dids/{did_a}/document",
                        headers=TA)
        pubs = {m["key_version"]: m["public_key"]
                for m in doc["verification_methods"]}
        check("恢复的新版本公钥与备份源版本（v2）一致",
              pubs[3] == pubs[2] and pubs[3] == r["public_key"])

        # ---- 6. restore 后历史/证明/游标/审计一致 ----
        st, kh = _http("GET", f"{base}/v1/dids/{did_a}/keys/history",
                       headers=TA)
        check("密钥历史追加 v3 key.rotated",
              st == 200
              and [e["action"] for e in kh["events"]]
              == ["did.created", "key.rotated", "key.rotated"]
              and kh["events"][-1]["key_version"] == 3
              and kh["events"][-1]["key_handle"] == "bk-h3")
        check("密钥历史不暴露私钥",
              PRIVATE_MARKER not in json.dumps(kh))
        st, rp = _http("GET", f"{base}/v1/dids/{did_a}/keys/rotations",
                       headers=TA)
        check("轮换证明追加 2->3 且哈希链接续",
              st == 200 and len(rp["events"]) == 2
              and rp["events"][1]["from_key_version"] == 2
              and rp["events"][1]["to_key_version"] == 3
              and rp["events"][1]["to_key_handle"] == "bk-h3"
              and rp["events"][1]["previous_proof_digest"]
              == rp["events"][0]["proof_digest"])
        st, vr = _http("POST", f"{base}/v1/dids/rotation-proofs/verify",
                       {"did": did_a, "rotations": rp["events"]},
                       headers=TA)
        check("含恢复版本的完整证明链可独立验真",
              st == 200 and vr == {"valid": True})
        st, au = audit()
        check("restore 记 key.rotated 审计",
              au["events"][-1]["action"] == "key.rotated")

        # ---- 7. 旧版本签名/吊销状态/凭证验签结论不变 ----
        st, rv = _http("POST", f"{base}/v1/dids/{did_a}/keys/1/revoke",
                       {"reason": "旧钥吊销"}, headers=TA)
        assert st == 200, rv
        st, rr = restore(did_a, {"backup": bk, "passphrase": PASSPHRASE,
                                 "key_handle": "bk-h4"})
        assert st == 200 and rr["key_version"] == 4, rr
        st, ks = _http("GET", f"{base}/v1/dids/{did_a}/keys/1/status",
                       headers=TA)
        check("恢复后旧版本吊销状态不变（v1 仍 revoked）",
              st == 200 and ks["status"] == "revoked")
        st, vf = _http("POST", f"{base}/v1/credentials/{old_cid}/verify",
                       old_verify, headers=TA)
        check("恢复前签发的凭证验签结论不变（仍 valid）",
              st == 200 and vf.get("valid") is True)
        # 新版本用于后续签发
        st, cred_new = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": did_a, "subject_did": did_holder,
            "claims": {"role": "restored"}}, headers=TA)
        check("恢复后新版本可签发凭证",
              st == 201 and cred_new.get("issuer_key_version") == 4)
        new_cid = cred_new["credential_id"]
        st, new_vc = _http("GET", f"{base}/v1/credentials/{new_cid}",
                           headers=TA)
        st, vf = _http("POST",
                       f"{base}/v1/credentials/{new_cid}/verify",
                       {"body": new_vc["body"],
                        "signature": new_vc["signature"]}, headers=TA)
        check("恢复后签发凭证验签通过", st == 200 and vf.get("valid") is True)

        # ---- 8. restore 结构错误：400 请求非法 ----
        struct_cases = [
            ("空体", None, b""),
            ("非法 JSON", None, b"{oops"),
            ("非对象", None, b"42"),
            ("空对象", {}, None),
            ("缺 backup", {"passphrase": PASSPHRASE,
                           "key_handle": "x1"}, None),
            ("缺 passphrase", {"backup": bk, "key_handle": "x1"}, None),
            ("缺 key_handle", {"backup": bk,
                               "passphrase": PASSPHRASE}, None),
            ("多余字段", {"backup": bk, "passphrase": PASSPHRASE,
                          "key_handle": "x1", "extra": 1}, None),
            ("口令过短", {"backup": bk, "passphrase": "x" * 7,
                          "key_handle": "x1"}, None),
            ("口令非字符串", {"backup": bk, "passphrase": 123456789,
                              "key_handle": "x1"}, None),
            ("句柄空串", {"backup": bk, "passphrase": PASSPHRASE,
                          "key_handle": ""}, None),
            ("句柄全空白", {"backup": bk, "passphrase": PASSPHRASE,
                            "key_handle": "   "}, None),
            ("句柄为 PEM", {"backup": bk, "passphrase": PASSPHRASE,
                            "key_handle": "-----BEGIN PUBLIC KEY-----x"},
             None),
            ("句柄非字符串", {"backup": bk, "passphrase": PASSPHRASE,
                              "key_handle": 7}, None),
            ("backup 非对象", {"backup": "x", "passphrase": PASSPHRASE,
                               "key_handle": "x1"}, None),
            ("backup 缺字段", {"backup": {"did": did_a},
                               "passphrase": PASSPHRASE,
                               "key_handle": "x1"}, None),
            ("backup 多字段",
             {"backup": dict(bk, extra=1), "passphrase": PASSPHRASE,
              "key_handle": "x1"}, None),
            ("backup 版本为字符串",
             {"backup": dict(bk, key_version="2"),
              "passphrase": PASSPHRASE, "key_handle": "x1"}, None),
            ("backup 迭代为布尔",
             {"backup": dict(bk, kdf_iterations=True),
              "passphrase": PASSPHRASE, "key_handle": "x1"}, None),
            ("backup salt 非字符串",
             {"backup": dict(bk, salt=16), "passphrase": PASSPHRASE,
              "key_handle": "x1"}, None),
        ]
        bad_ok = True
        for name, body, raw in struct_cases:
            st, r = restore(did_a, body, raw=raw)
            if not (st == 400 and r == {"error": "请求非法"}):
                bad_ok = False
                print("   restore 未按 400 请求非法拒绝:", name, st, r)
        check("restore 结构/类型错误均 400 请求非法", bad_ok)

        # ---- 9. restore 备份无效：400 {"error":"备份无效"} ----
        def expect_invalid(mutate, name, passphrase=PASSPHRASE, did=did_a,
                           handle="bk-x"):
            bad = copy.deepcopy(bk)
            mutate(bad)
            st, r = restore(did, {"backup": bad, "passphrase": passphrase,
                                  "key_handle": handle})
            ok = st == 400 and r == {"error": "备份无效"}
            check(name, ok)
            return ok

        expect_invalid(lambda x: None, "口令错误 -> 备份无效",
                       passphrase="错误的口令 123")
        expect_invalid(
            lambda x: x.update(ciphertext=x["ciphertext"][:-4] + "AAAA"),
            "密文被篡改 -> 备份无效")
        expect_invalid(
            lambda x: x.update(salt=x["salt"][:-2] + "AA"),
            "salt 被篡改 -> 备份无效")
        expect_invalid(
            lambda x: x.update(nonce=x["nonce"][:-2] + "AA"),
            "nonce 被篡改 -> 备份无效")
        expect_invalid(lambda x: x.update(key_version=1),
                       "版本绑定被篡改 -> 备份无效")
        expect_invalid(lambda x: x.update(key_handle="bk-h1"),
                       "句柄绑定被篡改 -> 备份无效")
        expect_invalid(lambda x: x.update(kdf="PBKDF2"),
                       "kdf 被篡改 -> 备份无效")
        expect_invalid(lambda x: x.update(kdf_iterations=1000),
                       "迭代次数被篡改 -> 备份无效")
        expect_invalid(lambda x: x.update(cipher="AES-128-GCM"),
                       "cipher 被篡改 -> 备份无效")
        expect_invalid(lambda x: x.update(salt="!!!"),
                       "salt 非 base64url -> 备份无效")
        expect_invalid(lambda x: x.update(salt="AAAA"),
                       "salt 长度不符 -> 备份无效")
        expect_invalid(lambda x: x.update(ciphertext=""),
                       "空密文 -> 备份无效")
        # 绑定 DID 不符：备份对象声称的 did 与路径 did 不同
        expect_invalid(lambda x: x.update(did=did_b),
                       "备份 did 与路径不符 -> 备份无效")
        # 跨租户绑定：把 A 租户备份的 did 改成 B 租户 DID 后在 B 下恢复
        st, r = restore(did_b, {
            "backup": dict(bk, did=did_b), "passphrase": PASSPHRASE,
            "key_handle": "bk-bx"}, headers=TB)
        check("跨租户备份绑定不符 -> 备份无效",
              st == 400 and r == {"error": "备份无效"})
        # 失败无副作用：版本/审计不变
        st, r = _http("GET", f"{base}/v1/dids/{did_a}", headers=TA)
        check("备份无效后当前版本仍为 4", r["key_version"] == 4)

        # ---- 10. restore 404 / 409 ----
        st, _ = restore("did:example:00000000000000000000000000000000",
                        {"backup": bk, "passphrase": PASSPHRASE,
                         "key_handle": "bk-x"})
        check("restore 未知 DID -> 404", st == 404)
        st, _ = restore(did_a, {"backup": bk, "passphrase": PASSPHRASE,
                                "key_handle": "bk-x"}, headers=TB)
        check("restore 跨租户 DID -> 404", st == 404)
        st, _ = restore(dead_did, {"backup": bk, "passphrase": PASSPHRASE,
                                   "key_handle": "bk-x"})
        check("restore 停用 DID -> 409", st == 409)
        st, r = restore(did_a, {"backup": bk, "passphrase": PASSPHRASE,
                                "key_handle": "bk-h2"})
        check("restore 句柄已被历史版本使用 -> 409 精确文案",
              st == 409 and r == {"error": "key_handle 已被使用"})
        st, r = restore(did_a, {"backup": bk, "passphrase": PASSPHRASE,
                                "key_handle": "bk-dead"})
        check("restore 句柄被本租户其他 DID 使用 -> 409",
              st == 409 and r == {"error": "key_handle 已被使用"})

        # ---- 11. 旧备份在后续轮换后仍可恢复（恢复的是备份时版本）----
        st, rr = restore(did_a, {"backup": bk, "passphrase": PASSPHRASE,
                                 "key_handle": "bk-h5"})
        check("旧备份再次恢复成功（v5，公钥仍同 v2）",
              st == 200 and rr["key_version"] == 5
              and rr["public_key"] == pubs[2])
        # 恢复出的新备份可再次往返
        st, bk5 = backup(did_a, {"passphrase": "第二轮口令 456"})
        assert st == 200 and bk5["key_version"] == 5, bk5
        st, rr = restore(did_a, {"backup": bk5, "passphrase": "第二轮口令 456",
                                 "key_handle": "bk-h6"})
        check("恢复后再备份再恢复往返成功（v6）",
              st == 200 and rr["key_version"] == 6
              and rr["public_key"] == pubs[2])

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 12. 跨重启：恢复产生的历史/证明/审计稳定 ----
    proc = start_server(PORT, store_path)
    try:
        st, kh = _http("GET", f"{base}/v1/dids/{did_a}/keys/history",
                       headers=TA)
        check("重启后密钥历史完整（6 个 active 版本 + v1 revoked）",
              st == 200
              and [e["key_version"] for e in kh["events"]
                   if e["action"] != "key.revoked"] == [1, 2, 3, 4, 5, 6]
              and any(e["action"] == "key.revoked"
                      and e["key_version"] == 1 for e in kh["events"]))
        st, rp = _http("GET", f"{base}/v1/dids/{did_a}/keys/rotations",
                       headers=TA)
        st, vr = _http("POST", f"{base}/v1/dids/rotation-proofs/verify",
                       {"did": did_a, "rotations": rp["events"]},
                       headers=TA)
        check("重启后含恢复版本的证明链仍可验真",
              st == 200 and vr == {"valid": True})
        st, au = audit()
        check("重启后 did.key.backup.exported 审计保留",
              any(e["action"] == "did.key.backup.exported"
                  for e in au["events"]))
        st, vf = _http("POST", f"{base}/v1/credentials/{old_cid}/verify",
                       old_verify, headers=TA)
        check("重启后旧凭证验签结论不变", st == 200 and vf.get("valid") is True)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 13. 直连 store：落盘失败时恢复整体回滚 ----
    from vcbackend.store import VCStore

    direct_path = tempfile.mktemp(suffix=".json")
    store = VCStore(direct_path)
    d = store.create_did("rb", "example", "rb-h1")
    store.rotate_key("rb", d.did, "rb-h2")
    bk_direct = store.export_key_backup("rb", d.did, "回滚口令 123")

    def _boom():
        raise OSError("模拟落盘失败")

    store._save_locked = _boom  # type: ignore[assignment]
    raised = False
    try:
        store.restore_key("rb", d.did, "rb-h3", bk_direct, "回滚口令 123")
    except OSError:
        raised = True
    check("恢复落盘失败抛错", raised)
    got = store.get_did("rb", d.did)
    check("回滚后当前版本仍为 2", got.key_version == 2)
    proofs, _ = store.list_key_rotation_proofs("rb", d.did, 0, 50)
    check("回滚后无新增轮换证明", len(proofs) == 1)
    events, _ = store.list_key_lifecycle("rb", d.did, 0, 50)
    check("回滚后生命周期仍 2 条", len(events) == 2)
    au = store.list_audit("rb", 0, 200)[0]
    check("回滚后无新增 key.rotated 审计",
          [e.action for e in au].count("key.rotated") == 1)
    del store._save_locked
    rec = store.restore_key("rb", d.did, "rb-h3", bk_direct, "回滚口令 123")
    check("恢复落盘后 restore 成功到 v3", rec.key_version == 3)
    proofs, _ = store.list_key_rotation_proofs("rb", d.did, 0, 50)
    check("恢复后证明链 1->2、2->3 接续",
          len(proofs) == 2
          and proofs[1].previous_proof_digest == proofs[0].proof_digest)

    # 直连：备份导出的审计落盘失败同样回滚
    store._save_locked = _boom  # type: ignore[assignment]
    raised = False
    try:
        store.export_key_backup("rb", d.did, "回滚口令 123")
    except OSError:
        raised = True
    check("备份导出落盘失败抛错", raised)
    au = store.list_audit("rb", 0, 200)[0]
    check("备份导出失败不残留审计（仍仅先前 1 条）",
          len([e for e in au
               if e.action == "did.key.backup.exported"]) == 1)
    del store._save_locked

    for path in (store_path, direct_path):
        if os.path.exists(path):
            os.remove(path)

    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("密钥备份与恢复测试全部通过 ✔")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
