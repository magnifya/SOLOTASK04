#!/usr/bin/env python3
"""DID 密钥口令加密备份与恢复端到端测试。

覆盖：
- POST /v1/dids/{did}/keys/backup：请求体恰含 passphrase（8..256 个
  Unicode 码点）；空体、非法 JSON、字段缺失/多余/类型错误统一
  400 {"error":"请求非法"}；未知或跨租户 DID 404；停用 DID 409；
  成功 200 恰含 did、key_version、key_handle、kdf、kdf_iterations、
  salt、cipher、nonce、ciphertext 九字段；kdf 固定 PBKDF2-HMAC-SHA256、
  迭代 310000，cipher 固定 AES-256-GCM，salt/nonce 为 16/12 字节随机
  值的无填充 base64url；密文可经口令与绑定 AAD（租户/DID/版本/句柄）
  解出当前版本私钥；响应、审计与查询绝不出现私钥；成功追加
  did.key.backup.exported 审计，失败无副作用；
- POST /v1/dids/{did}/keys/restore：请求体恰含 backup、passphrase、
  key_handle；结构错误 400 {"error":"请求非法"}；绑定不符、口令错误、
  解密/认证失败、内容被篡改统一 400 {"error":"备份无效"}；未知或跨
  租户 DID 404；停用 DID 409；句柄已被本租户任一版本使用
  409 {"error":"key_handle 已被使用"}；成功以当前版本加一创建新版本，
  响应字段与轮换相同，密钥历史、轮换证明、游标与 key.rotated 审计
  同一次原子落盘；新版本用于后续签发，旧版本签名与验签结论不变；
- 直连 store：落盘失败时恢复/备份整体回滚；
- 轮换、文档、历史等既有行为保持兼容。

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

from vcbackend import crypto  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # noqa: E402

PORT = 8994
BACKUP_FIELDS = {
    "did", "key_version", "key_handle", "kdf", "kdf_iterations",
    "salt", "cipher", "nonce", "ciphertext",
}
DID_PAYLOAD_FIELDS = {"did", "public_key", "key_mode", "key_handle",
                      "key_version"}
PRIVATE_MARKER = "PRIVATE KEY-----"
PASSPHRASE = "备份口令-backup-1"


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


def _b64url_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decrypt_backup(backup, passphrase, tenant):
    """按公开参数手工解密备份：返回私钥 PEM 字符串。"""
    salt = _b64url_decode(backup["salt"])
    nonce = _b64url_decode(backup["nonce"])
    ciphertext = _b64url_decode(backup["ciphertext"])
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=310000
    ).derive(passphrase.encode("utf-8"))
    aad = crypto.canonicalize({
        "tenant": tenant,
        "did": backup["did"],
        "key_version": backup["key_version"],
        "key_handle": backup["key_handle"],
    })
    return AESGCM(key).decrypt(nonce, ciphertext, aad).decode("utf-8")


def main():
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    store_path = tempfile.mktemp(suffix=".json")
    proc = start_server(PORT, store_path)
    base = f"http://127.0.0.1:{PORT}"
    TA = {"X-Tenant-ID": "kb-a"}
    TB = {"X-Tenant-ID": "kb-b"}

    def backup(did, payload=Ellipsis, headers=None, raw=None):
        body = {"passphrase": PASSPHRASE} if payload is Ellipsis else payload
        return _http("POST", f"{base}/v1/dids/{did}/keys/backup",
                     payload=body, headers=headers or TA, raw=raw)

    def restore(did, payload, headers=None):
        return _http("POST", f"{base}/v1/dids/{did}/keys/restore",
                     payload=payload, headers=headers or TA)

    def audit(headers):
        return _http("GET", f"{base}/v1/audit?limit=200", headers=headers)

    try:
        # ---- 准备：A 租户两个 DID、B 租户一个 DID ----
        st, a = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "bk-h1"},
                      headers=TA)
        assert st == 201, a
        did_a, pub_a = a["did"], a["public_key"]
        st, a2 = _http("POST", f"{base}/v1/dids",
                       {"method": "example", "public_key": "bk-other"},
                       headers=TA)
        assert st == 201, a2
        did_a2 = a2["did"]
        st, b = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "bk-b1"},
                      headers=TB)
        assert st == 201, b
        did_b = b["did"]

        # 恢复前签发一张 v1 凭证，供恢复后验证旧签名结论不变
        st, cred = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": did_a, "subject_did": did_a2,
            "claims": {"role": "admin"}}, headers=TA)
        assert st == 201, cred
        cid_v1 = cred["credential_id"]
        check("恢复前签发凭证 issuer_key_version=1",
              cred["issuer_key_version"] == 1)

        # ---- 1. 备份成功：字段、固定参数、随机性与无私钥 ----
        st, au_before = audit(TA)
        n_audit = len(au_before["events"])
        st, bk = backup(did_a)
        check("备份成功 200 且恰含九字段",
              st == 200 and set(bk) == BACKUP_FIELDS)
        check("备份绑定当前 DID/版本/句柄",
              bk["did"] == did_a and bk["key_version"] == 1
              and bk["key_handle"] == "bk-h1")
        check("kdf/迭代/cipher 固定",
              bk["kdf"] == "PBKDF2-HMAC-SHA256"
              and bk["kdf_iterations"] == 310000
              and bk["cipher"] == "AES-256-GCM")
        salt_raw, nonce_raw = (_b64url_decode(bk["salt"]),
                               _b64url_decode(bk["nonce"]))
        check("salt 16 字节、nonce 12 字节且为无填充 base64url",
              len(salt_raw) == 16 and len(nonce_raw) == 12
              and _b64url(salt_raw) == bk["salt"]
              and _b64url(nonce_raw) == bk["nonce"]
              and "=" not in bk["salt"] + bk["nonce"])
        ct_raw = _b64url_decode(bk["ciphertext"])
        check("密文为规范 base64url 且含认证标签（>16 字节）",
              len(ct_raw) > 16 and _b64url(ct_raw) == bk["ciphertext"])
        check("备份响应不含私钥",
              PRIVATE_MARKER not in json.dumps(bk, ensure_ascii=False))
        st, bk2 = backup(did_a)
        check("再次备份 salt/nonce/ciphertext 随机不同",
              st == 200 and bk2["salt"] != bk["salt"]
              and bk2["nonce"] != bk["nonce"]
              and bk2["ciphertext"] != bk["ciphertext"])

        # 手工解密：口令 + 绑定 AAD 可解出当前版本私钥，公钥与 DID 一致
        try:
            pem = decrypt_backup(bk, PASSPHRASE, "kb-a")
            derived_pub = crypto.public_key_pem_from_private(pem).strip()
            check("备份可解出私钥且公钥与 DID 当前版本一致",
                  derived_pub == pub_a.strip())
        except Exception:  # noqa: BLE001
            check("备份可解出私钥且公钥与 DID 当前版本一致", False)
        # 错口令手工解密必须失败（认证标签）
        try:
            decrypt_backup(bk, "错误口令-wrong-1", "kb-a")
            check("错误口令手工解密失败", False)
        except Exception:  # noqa: BLE001
            check("错误口令手工解密失败", True)

        # 成功追加 did.key.backup.exported 审计（两次备份两条）
        st, au = audit(TA)
        exported = [e for e in au["events"]
                    if e["action"] == "did.key.backup.exported"]
        check("成功备份追加 did.key.backup.exported 审计",
              len(au["events"]) == n_audit + 2
              and len(exported) == 2
              and all(e["resource_type"] == "did"
                      and e["resource_id"] == did_a for e in exported))
        check("审计与查询输出不含私钥",
              PRIVATE_MARKER not in json.dumps(au, ensure_ascii=False))

        # ---- 2. 备份请求结构错误：统一 400 {"error":"请求非法"} ----
        bad_backups = [
            ("空体", None, b""),
            ("非法 JSON", None, b"{not-json"),
            ("非对象 JSON", None, b"[1]"),
            ("空对象", {}, None),
            ("多余字段", {"passphrase": PASSPHRASE, "x": 1}, None),
            ("口令为整数", {"passphrase": 12345678}, None),
            ("口令为布尔", {"passphrase": True}, None),
            ("口令为 null", {"passphrase": None}, None),
            ("口令为数组", {"passphrase": ["x"]}, None),
            ("口令 7 码点", {"passphrase": "1234567"}, None),
            ("口令 257 码点", {"passphrase": "x" * 257}, None),
            ("口令空串", {"passphrase": ""}, None),
        ]
        ok = True
        for name, payload, raw in bad_backups:
            st, r = backup(did_a, payload=payload, raw=raw)
            if not (st == 400 and r == {"error": "请求非法"}):
                ok = False
                print("   备份未按 400 请求非法拒绝:", name, st, r)
        check("空体/非法 JSON/缺/多字段/类型错误/长度越界均 400 请求非法",
              ok)
        # 边界：8 与 256 码点（含多字节字符按码点计）均可
        st, r = backup(did_a, payload={"passphrase": "口令abcdef"})
        check("8 码点口令（含多字节字符）可备份", st == 200)
        st, r = backup(did_a, payload={"passphrase": "密" * 256})
        check("256 码点口令可备份", st == 200)
        st, au = audit(TA)
        check("结构失败的备份无副作用（审计仅新增成功的 2 条）",
              len([e for e in au["events"]
                   if e["action"] == "did.key.backup.exported"]) == 4)

        # ---- 3. 备份 404/409 ----
        st, _ = backup("did:example:00000000000000000000000000000000")
        check("备份未知 DID -> 404", st == 404)
        st, _ = backup(did_a, headers=TB)
        check("备份跨租户 DID -> 404", st == 404)
        st, d = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "bk-dead"},
                      headers=TA)
        assert st == 201
        did_dead = d["did"]
        st, _ = _http("POST", f"{base}/v1/dids/{did_dead}/deactivate",
                      {}, headers=TA)
        assert st == 200
        st, _ = backup(did_dead)
        check("备份已停用 DID -> 409", st == 409)

        # ---- 4. 恢复成功：版本加一、响应同轮换、历史/证明/审计原子 ----
        st, r = restore(did_a, {"backup": bk, "passphrase": PASSPHRASE,
                                "key_handle": "bk-h2"})
        check("恢复成功 200 且响应字段与轮换相同",
              st == 200 and set(r) == DID_PAYLOAD_FIELDS)
        check("恢复后版本加一、句柄更新、公钥为备份公钥",
              r["key_version"] == 2 and r["key_handle"] == "bk-h2"
              and r["public_key"].strip() == pub_a.strip()
              and r["key_mode"] == "server"
              and PRIVATE_MARKER not in json.dumps(r, ensure_ascii=False))
        st, doc = _http("GET", f"{base}/v1/dids/{did_a}/document",
                        headers=TA)
        check("DID 文档当前版本为 2 且含两个版本公钥",
              st == 200 and doc["current_key_version"] == 2
              and [m["key_version"] for m in doc["verification_methods"]]
              == [1, 2])
        st, kh = _http("GET", f"{base}/v1/dids/{did_a}/keys/history",
                       headers=TA)
        check("密钥历史新增 v2 key.rotated 事件",
              st == 200
              and [e["action"] for e in kh["events"]]
              == ["did.created", "key.rotated"]
              and kh["events"][1]["key_version"] == 2
              and kh["events"][1]["key_handle"] == "bk-h2")
        st, rots = _http("GET", f"{base}/v1/dids/{did_a}/keys/rotations",
                         headers=TA)
        check("恢复产出 1->2 轮换证明且句柄对应",
              st == 200 and len(rots["events"]) == 1
              and rots["events"][0]["from_key_version"] == 1
              and rots["events"][0]["to_key_version"] == 2
              and rots["events"][0]["from_key_handle"] == "bk-h1"
              and rots["events"][0]["to_key_handle"] == "bk-h2")
        st, rv = _http("POST", f"{base}/v1/dids/rotation-proofs/verify",
                       {"did": did_a, "rotations": rots["events"]},
                       headers=TA)
        check("恢复产出的轮换证明可独立验真",
              st == 200 and rv == {"valid": True})
        st, au = audit(TA)
        check("恢复记 key.rotated 审计",
              any(e["action"] == "key.rotated" and e["resource_id"] == did_a
                  for e in au["events"]))

        # 新版本用于后续签发；旧版本签名与验签结论不变
        st, cred2 = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": did_a, "subject_did": did_a2,
            "claims": {"role": "ops"}}, headers=TA)
        check("恢复后签发使用新版本（issuer_key_version=2）",
              st == 201 and cred2["issuer_key_version"] == 2)
        st, v1 = _http("POST", f"{base}/v1/credentials/{cid_v1}/verify",
                       {"body": _http("GET", f"{base}/v1/credentials/{cid_v1}",
                                      headers=TA)[1]["body"],
                        "signature": cred["signature"]}, headers=TA)
        check("恢复前签发的凭证验签结论不变（仍 valid）",
              st == 200 and v1.get("valid") is True)
        st, v2 = _http(
            "POST", f"{base}/v1/credentials/{cred2['credential_id']}/verify",
            {"body": _http(
                "GET", f"{base}/v1/credentials/{cred2['credential_id']}",
                headers=TA)[1]["body"],
             "signature": cred2["signature"]}, headers=TA)
        check("恢复后签发的凭证验签通过", st == 200 and v2.get("valid") is True)

        # 恢复后仍可正常轮换，证明哈希链接续
        st, rot = _http("POST", f"{base}/v1/dids/{did_a}/keys/rotate",
                        {"key_handle": "bk-h3"}, headers=TA)
        check("恢复后再轮换到 v3 成功", st == 200 and rot["key_version"] == 3)
        st, rots = _http("GET", f"{base}/v1/dids/{did_a}/keys/rotations",
                         headers=TA)
        st, rv = _http("POST", f"{base}/v1/dids/rotation-proofs/verify",
                       {"did": did_a, "rotations": rots["events"]},
                       headers=TA)
        check("恢复+轮换后的完整证明链可验真",
              st == 200 and len(rots["events"]) == 2
              and rv == {"valid": True})
        # 用 v1 的备份再恢复一次：旧备份仍可恢复（版本继续加一）
        st, r = restore(did_a, {"backup": bk, "passphrase": PASSPHRASE,
                                "key_handle": "bk-h4"})
        check("旧备份可再次恢复（版本加一到 4，公钥回到备份公钥）",
              st == 200 and r["key_version"] == 4
              and r["public_key"].strip() == pub_a.strip())

        # ---- 5. 恢复请求结构错误：统一 400 {"error":"请求非法"} ----
        good = {"backup": bk, "passphrase": PASSPHRASE,
                "key_handle": "bk-x1"}
        bad_restores = [
            ("缺 backup", {"passphrase": PASSPHRASE, "key_handle": "bk-x1"}),
            ("缺 passphrase", {"backup": bk, "key_handle": "bk-x1"}),
            ("缺 key_handle", {"backup": bk, "passphrase": PASSPHRASE}),
            ("多余字段", dict(good, x=1)),
            ("口令过短", dict(good, passphrase="1234567")),
            ("口令类型错误", dict(good, passphrase=12345678)),
            ("句柄空串", dict(good, key_handle="")),
            ("句柄全空白", dict(good, key_handle="   ")),
            ("句柄为 PEM", dict(good,
                                key_handle="-----BEGIN PUBLIC KEY-----x")),
            ("句柄非字符串", dict(good, key_handle=7)),
            ("backup 非对象", dict(good, backup="x")),
            ("backup 缺字段", dict(good, backup={
                k: v for k, v in bk.items() if k != "salt"})),
            ("backup 多字段", dict(good, backup=dict(bk, x=1))),
            ("backup.key_version 类型错", dict(
                good, backup=dict(bk, key_version="1"))),
            ("backup.key_version 为布尔", dict(
                good, backup=dict(bk, key_version=True))),
            ("backup.kdf_iterations 类型错", dict(
                good, backup=dict(bk, kdf_iterations="310000"))),
            ("backup.salt 类型错", dict(good, backup=dict(bk, salt=1))),
            ("backup.ciphertext 类型错", dict(
                good, backup=dict(bk, ciphertext=None))),
        ]
        ok = True
        for name, payload in bad_restores:
            st, r = restore(did_a2, payload)
            if not (st == 400 and r == {"error": "请求非法"}):
                ok = False
                print("   恢复未按 400 请求非法拒绝:", name, st, r)
        check("恢复结构错误（缺/多字段、类型、口令、句柄）均 400 请求非法",
              ok)

        # ---- 6. 恢复内容失败：统一 400 {"error":"备份无效"} ----
        st, bk_a2 = backup(did_a2)
        assert st == 200
        tampered_ct = copy.deepcopy(bk_a2)
        ch = tampered_ct["ciphertext"]
        tampered_ct["ciphertext"] = (
            ch[:10] + ("A" if ch[10] != "A" else "B") + ch[11:])
        tampered_salt = dict(bk_a2, salt=_b64url(b"\x00" * 16))
        bad_contents = [
            ("口令错误", dict(good, passphrase="错误口令-wrong-2")),
            ("密文被篡改", dict(good, backup=tampered_ct)),
            ("salt 被替换", dict(good, backup=tampered_salt)),
            ("kdf 不符", dict(good, backup=dict(bk_a2, kdf="PBKDF2"))),
            ("迭代次数不符", dict(good,
                                  backup=dict(bk_a2, kdf_iterations=1))),
            ("cipher 不符", dict(good, backup=dict(bk_a2, cipher="AES-GCM"))),
            ("salt 长度不符", dict(good, backup=dict(
                bk_a2, salt=_b64url(b"\x00" * 8)))),
            ("nonce 长度不符", dict(good, backup=dict(
                bk_a2, nonce=_b64url(b"\x00" * 16)))),
            ("salt 非规范 base64url", dict(good, backup=dict(
                bk_a2, salt="!!!"))),
            ("版本非法", dict(good, backup=dict(bk_a2, key_version=0))),
            ("他 DID 的备份", dict(good, backup=bk)),
        ]
        ok = True
        for name, payload in bad_contents:
            st, r = restore(did_a2, payload)
            if not (st == 400 and r == {"error": "备份无效"}):
                ok = False
                print("   恢复未按 400 备份无效拒绝:", name, st, r)
        check("口令错误/篡改/参数或绑定不符均 400 备份无效", ok)
        # 跨租户绑定：A 租户备份恢复到 B 租户 DID
        st, r = restore(did_b, {"backup": bk, "passphrase": PASSPHRASE,
                                "key_handle": "bk-bx"}, headers=TB)
        check("跨租户备份绑定不符 -> 400 备份无效",
              st == 400 and r == {"error": "备份无效"})
        # 失败无副作用：did_a2 仍为 v1 且无 key.rotated
        st, doc = _http("GET", f"{base}/v1/dids/{did_a2}/document",
                        headers=TA)
        check("恢复失败后 DID 版本不变（仍 v1）",
              st == 200 and doc["current_key_version"] == 1)
        st, au = audit(TA)
        check("恢复失败不记 key.rotated（did_a2）",
              all(not (e["action"] == "key.rotated"
                       and e["resource_id"] == did_a2)
                  for e in au["events"]))

        # ---- 7. 恢复 404/409 ----
        st, _ = restore("did:example:00000000000000000000000000000000",
                        dict(good))
        check("恢复未知 DID -> 404", st == 404)
        st, _ = restore(did_a, dict(good), headers=TB)
        check("恢复跨租户 DID -> 404", st == 404)
        st, r = restore(did_dead, {"backup": bk, "passphrase": PASSPHRASE,
                                   "key_handle": "bk-x2"})
        check("恢复已停用 DID -> 409", st == 409)
        st, r = restore(did_a2, {"backup": bk_a2,
                                 "passphrase": PASSPHRASE,
                                 "key_handle": "bk-h1"})
        check("句柄已被本租户其他 DID 使用 -> 409 key_handle 已被使用",
              st == 409 and r == {"error": "key_handle 已被使用"})
        st, r = restore(did_a2, {"backup": bk_a2,
                                 "passphrase": PASSPHRASE,
                                 "key_handle": "bk-other"})
        check("句柄与本 DID 当前版本相同 -> 409 key_handle 已被使用",
              st == 409 and r == {"error": "key_handle 已被使用"})
        # 他租户句柄不冲突：B 租户可用 A 的句柄名恢复
        st, bk_b = backup(did_b, headers=TB)
        assert st == 200
        st, r = restore(did_b, {"backup": bk_b, "passphrase": PASSPHRASE,
                                "key_handle": "bk-h1"}, headers=TB)
        check("他租户句柄空间独立：B 租户可用同名句柄恢复",
              st == 200 and r["key_version"] == 2
              and r["key_handle"] == "bk-h1")

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 8. 跨重启：状态稳定，备份仍可恢复 ----
    proc = start_server(PORT, store_path)
    try:
        st, doc = _http("GET", f"{base}/v1/dids/{did_a}/document",
                        headers=TA)
        check("重启后 DID 版本与历史稳定",
              st == 200 and doc["current_key_version"] == 4)
        st, r = _http("POST", f"{base}/v1/dids/{did_a2}/keys/restore",
                      {"backup": bk_a2, "passphrase": PASSPHRASE,
                       "key_handle": "bk-h9"}, headers=TA)
        check("重启后备份仍可恢复（did_a2 -> v2）",
              st == 200 and r["key_version"] == 2)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 9. 直连 store：落盘失败整体回滚 ----
    from vcbackend.store import VCStore

    direct_path = tempfile.mktemp(suffix=".json")
    store = VCStore(direct_path)
    d = store.create_did("rb", "example", "rb-h1")
    bk_direct = store.export_key_backup("rb", d.did, "口令-passphrase")
    check("直连备份恰含九字段", set(bk_direct) == BACKUP_FIELDS)
    au = store.list_audit("rb", 0, 200)[0]
    check("直连备份记 did.key.backup.exported",
          any(e.action == "did.key.backup.exported" for e in au))

    def _boom():
        raise OSError("模拟落盘失败")

    store._save_locked = _boom  # type: ignore[assignment]
    raised = False
    try:
        store.restore_key("rb", d.did, "rb-h2", bk_direct, "口令-passphrase")
    except OSError:
        raised = True
    check("恢复落盘失败抛错", raised)
    got = store.get_did("rb", d.did)
    check("回滚后当前版本仍为 1", got.key_version == 1)
    proofs, _ = store.list_key_rotation_proofs("rb", d.did, 0, 50)
    check("回滚后无轮换证明", proofs == [])
    events, _ = store.list_key_lifecycle("rb", d.did, 0, 50)
    check("回滚后生命周期仅 v1 一条",
          len(events) == 1 and events[0].action == "did.created")
    au = store.list_audit("rb", 0, 200)[0]
    check("回滚后不记 key.rotated",
          all(e.action != "key.rotated" for e in au))
    # 备份导出落盘失败同样回滚（不追加审计）
    n_audit = len(store.list_audit("rb", 0, 200)[0])
    raised = False
    try:
        store.export_key_backup("rb", d.did, "口令-passphrase")
    except OSError:
        raised = True
    au = store.list_audit("rb", 0, 200)[0]
    check("备份落盘失败抛错且不追加审计",
          raised and len(au) == n_audit)

    del store._save_locked
    rec = store.restore_key("rb", d.did, "rb-h2", bk_direct, "口令-passphrase")
    check("恢复落盘恢复后成功到 v2", rec.key_version == 2)
    proofs, _ = store.list_key_rotation_proofs("rb", d.did, 0, 50)
    check("直连恢复产出 1->2 证明",
          len(proofs) == 1 and proofs[0].from_key_version == 1
          and proofs[0].to_key_version == 2)
    # 直连：错误口令 -> ValidationError("备份无效")；句柄冲突 -> ConflictError
    from vcbackend.store import ConflictError, ValidationError
    try:
        store.restore_key("rb", d.did, "rb-h3", bk_direct, "错误口令-xxxx")
        check("直连错误口令抛 备份无效", False)
    except ValidationError as exc:
        check("直连错误口令抛 备份无效", str(exc) == "备份无效")
    try:
        store.restore_key("rb", d.did, "rb-h2", bk_direct, "口令-passphrase")
        check("直连句柄冲突抛 ConflictError", False)
    except ConflictError as exc:
        check("直连句柄冲突抛 ConflictError",
              str(exc) == "key_handle 已被使用")

    for path in (store_path, direct_path):
        if os.path.exists(path):
            os.remove(path)

    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("DID 密钥备份与恢复测试全部通过 ✔")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
