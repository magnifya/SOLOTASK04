#!/usr/bin/env python3
"""POST /v1/trust/dids/deactivate-sync-batch 批量外部 DID 停用通告与
停用通告严格签名格式的端到端测试。

直接运行：python3 tests/trust_did_deactivation_sync_batch_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 严格签名格式（单项与批量两端点）：signature 须匹配
  [A-Za-z0-9_-]{86}、解码 64 字节且无填充 base64url 重编码等于原文；
  带填充、非规范尾位、长度不符、字母表外字符均在锚点检查后返回
  “签名格式错误”且不写入；锚点不可用优先于签名格式；
- 批量请求级：空体、非法 JSON、非对象、字段缺失/多余、items 非数组/
  空/超 100 一律 HTTP 200，键序 results、reason，值 [] 与非空中文
  “请求…”；
- 请求级合法时 200 仅含等长同序 results，顺序处理不短路；失败项键序
  valid、http_status、reason（项结构/字段错 400“请求…”，锚点/格式/
  验签 200 单项固定原因，同 did 异通告 409“冲突…”）；成功项键序
  valid、http_status、did、key_version、reason、deactivated_at，
  首次 201、完全重放 200；
- 批内同 did 可见前项写入（201→200→409）；落盘失败项 500“存储失败”，
  仅回滚该项并继续，重启后未持久化；已落盘项重启保持；
- X-Tenant-ID 缺省 default、显式空 400、租户隔离。
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

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402


def _http(method, url, payload=None, headers=None, raw=None):
    if raw is not None:
        data = raw
    else:
        data = json.dumps(payload).encode() if payload is not None else b""
    req = urllib.request.Request(url, data=data, method=method)
    if data:
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


def _keypair():
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


SYNC_PATH = "/v1/trust/dids/deactivate-sync"
BATCH_PATH = "/v1/trust/dids/deactivate-sync-batch"
FAIL_KEYS = ["valid", "http_status", "reason"]
OK_KEYS = ["valid", "http_status", "did", "key_version", "reason",
           "deactivated_at"]

B64URL_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def _noncanonical(sig):
    """把合法签名的末字符换成高 4 位相同、低 2 位非零的字符：解码字节
    相同（验签可通过），但无填充重编码不等于原文。"""
    last = sig[-1]
    idx = B64URL_ALPHABET.index(last)
    replacement = B64URL_ALPHABET[idx | 0b01]
    if replacement == last:
        replacement = B64URL_ALPHABET[idx | 0b10]
    return sig[:-1] + replacement


def main():
    port = 8998
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

    def make_body(did, key_version=1, reason="机构业务终止",
                  deactivated_at="2026-09-20T10:00:00Z"):
        return {
            "did": did,
            "key_version": key_version,
            "reason": reason,
            "deactivated_at": deactivated_at,
        }

    try:
        assert wait_up(port), "服务启动超时"

        TA = {"X-Tenant-ID": "tenant-a"}
        TB = {"X-Tenant-ID": "tenant-b"}
        did = "did:web:batch.example"
        priv1, pub1 = _keypair()
        priv2, pub2 = _keypair()

        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1},
                      headers=TA)
        assert st == 201, r

        def sync(payload=None, raw=None, headers=TA):
            return _http("POST", f"{base}{SYNC_PATH}", payload=payload,
                         raw=raw, headers=headers)

        def batch(payload=None, raw=None, headers=TA):
            return _http("POST", f"{base}{BATCH_PATH}", payload=payload,
                         raw=raw, headers=headers)

        def signed(body, priv=priv1):
            return {"body": body, "signature": crypto.sign(body, priv)}

        # ---------------------------------------------------------- #
        # 0. 显式空 X-Tenant-ID -> 400（进入批处理前）
        # ---------------------------------------------------------- #
        st, r = batch({"items": [signed(make_body(did))]},
                      headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400 仅 error",
              st == 400 and set(r) == {"error"} and r["error"])

        # ---------------------------------------------------------- #
        # 1. 请求级非法 -> 200 键序 results,reason；值 []、“请求…”
        # ---------------------------------------------------------- #
        def expect_bad_request(name, payload=None, raw=None):
            st, r = batch(payload=payload, raw=raw)
            check(f"请求级 200: {name}",
                  st == 200 and list(r.keys()) == ["results", "reason"]
                  and r["results"] == []
                  and isinstance(r["reason"], str)
                  and r["reason"].startswith("请求"))

        expect_bad_request("空体", raw=b"")
        expect_bad_request("非法 JSON", raw=b"{oops")
        expect_bad_request("非对象（数组）", raw=b"[1]")
        expect_bad_request("非对象（null）", raw=b"null")
        expect_bad_request("缺 items", payload={})
        expect_bad_request("多余字段", payload={"items": [], "x": 1})
        expect_bad_request("items 非数组", payload={"items": {}})
        expect_bad_request("items 空数组", payload={"items": []})
        expect_bad_request(
            "items 101 项超上限",
            payload={"items": [signed(make_body(did))] * 101})

        # ---------------------------------------------------------- #
        # 2. 严格签名格式（单项端点）：锚点检查后“签名格式错误”，不写入
        # ---------------------------------------------------------- #
        ghost_body = make_body("did:web:ghost-strict.example")
        st, r = sync({"body": ghost_body, "signature": "%%%bad%%%"})
        check("锚点不可用优先于签名格式",
              st == 200 and r == {"valid": False, "reason": "锚点不可用"})

        did_fmt = "did:web:fmt.example"
        priv_f, pub_f = _keypair()
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did_fmt, "public_key": pub_f,
                       "key_version": 1}, headers=TA)
        assert st == 201
        body_f = make_body(did_fmt)
        good_sig = crypto.sign(body_f, priv_f)
        assert len(good_sig) == 86

        bad_sigs = [
            ("带填充 ==", good_sig + "=="),
            ("带填充 =", good_sig + "="),
            ("非规范尾位", _noncanonical(good_sig)),
            ("长度 85", good_sig[:-1]),
            ("长度 87", good_sig + "A"),
            ("字母表外字符", good_sig[:-1] + "+"),
            ("标准 base64 斜杠", good_sig[:-1] + "/"),
        ]
        for name, sig in bad_sigs:
            st, r = sync({"body": body_f, "signature": sig})
            check(f"单项严格格式 200 签名格式错误: {name}",
                  st == 200 and r == {"valid": False, "reason": "签名格式错误"})
        # 非规范尾位解码字节相同、本可通过验签，确认是被格式规则拦截
        st, r = sync({"body": body_f, "signature": good_sig})
        check("合法签名首次接受 201",
              st == 201 and r["valid"] is True and r["did"] == did_fmt)

        # ---------------------------------------------------------- #
        # 3. 混合批：201/400/200锚点/200格式/200验签/409/200重放，不短路
        # ---------------------------------------------------------- #
        did_m = "did:web:mixed.example"
        priv_m, pub_m = _keypair()
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did_m, "public_key": pub_m, "key_version": 1},
                      headers=TA)
        assert st == 201
        body_m = make_body(did_m)
        item_ok = {"body": body_m, "signature": crypto.sign(body_m, priv_m)}
        item_bad_field = {"body": make_body(did_m, key_version=0),
                          "signature": "x"}
        item_not_object = [1, 2, 3]
        item_no_anchor = signed(make_body("did:web:no-anchor.example"))
        item_bad_sig = {"body": make_body(did_m), "signature": "%%%bad%%%"}
        item_wrong_key = {"body": make_body(did_m, reason="验签失败项"),
                          "signature": crypto.sign(
                              make_body(did_m, reason="验签失败项"), priv2)}
        item_conflict = {"body": make_body(did_m, reason="另一条原因"),
                         "signature": crypto.sign(
                             make_body(did_m, reason="另一条原因"), priv_m)}
        item_replay = {"body": body_m,
                       "signature": crypto.sign(body_m, priv_m)}

        items = [item_ok, item_bad_field, item_not_object, item_no_anchor,
                 item_bad_sig, item_wrong_key, item_conflict, item_replay]
        st, r = batch({"items": items})
        check("混合批 200 仅含 results 且等长同序",
              st == 200 and list(r.keys()) == ["results"]
              and len(r["results"]) == len(items))
        if len(r.get("results", [])) == len(items):
            res = r["results"]

            def fail_at(idx, http_status, prefix):
                row = res[idx]
                return (list(row.keys()) == FAIL_KEYS
                        and row["valid"] is False
                        and row["http_status"] == http_status
                        and isinstance(row["reason"], str)
                        and row["reason"].startswith(prefix))

            check("results[0] 首次 201 键序正确",
                  list(res[0].keys()) == OK_KEYS
                  and res[0]["valid"] is True
                  and res[0]["http_status"] == 201
                  and res[0]["did"] == did_m
                  and res[0]["key_version"] == 1
                  and res[0]["reason"] == "机构业务终止"
                  and res[0]["deactivated_at"] == "2026-09-20T10:00:00Z")
            check("results[1] 字段错误 400 请求…",
                  fail_at(1, 400, "请求"))
            check("results[2] 项非对象 400 请求…",
                  fail_at(2, 400, "请求"))
            check("results[3] 锚点不可用 200",
                  fail_at(3, 200, "锚点不可用")
                  and res[3]["reason"] == "锚点不可用")
            check("results[4] 签名格式错误 200",
                  fail_at(4, 200, "签名格式错误")
                  and res[4]["reason"] == "签名格式错误")
            check("results[5] 签名校验失败 200",
                  fail_at(5, 200, "签名校验失败")
                  and res[5]["reason"] == "签名校验失败")
            check("results[6] 同 did 异通告 409 冲突…",
                  fail_at(6, 409, "冲突"))
            check("results[7] 批内重放 200 返回首次记录",
                  list(res[7].keys()) == OK_KEYS
                  and res[7]["valid"] is True
                  and res[7]["http_status"] == 200
                  and res[7]["reason"] == "机构业务终止")

        # 失败项不写入：无锚点 did 之后仍可首次登记（此处仅验证混合批
        # 未短路且 did_m 记录为首次内容）
        st, r = sync({"body": body_m,
                      "signature": crypto.sign(body_m, priv_m)})
        check("混合批后单项重放仍 200 首次记录",
              st == 200 and r["valid"] is True
              and r["reason"] == "机构业务终止")

        # ---------------------------------------------------------- #
        # 4. 批内同 did 顺序效应：201 -> 重放 200 -> 异通告 409
        # ---------------------------------------------------------- #
        did_s = "did:web:seq.example"
        priv_s, pub_s = _keypair()
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did_s, "public_key": pub_s, "key_version": 1},
                      headers=TA)
        assert st == 201
        seq_items = [
            {"body": make_body(did_s),
             "signature": crypto.sign(make_body(did_s), priv_s)},
            {"body": make_body(did_s),
             "signature": crypto.sign(make_body(did_s), priv_s)},
            {"body": make_body(did_s, reason="异通告"),
             "signature": crypto.sign(make_body(did_s, reason="异通告"),
                                      priv_s)},
        ]
        st, r = batch({"items": seq_items})
        check("顺序批 201/200/409",
              st == 200 and len(r["results"]) == 3
              and [x["http_status"] for x in r["results"]] == [201, 200, 409]
              and [x["valid"] for x in r["results"]] == [True, True, False])

        # ---------------------------------------------------------- #
        # 5. 100 项上限合法（含 1 个坏项不短路）
        # ---------------------------------------------------------- #
        ok_items = []
        for i in range(99):
            d = f"did:web:cap-{i}.example"
            priv_c, pub_c = _keypair()
            st, _ = _http("POST", f"{base}/v1/trust/anchors",
                          {"did": d, "public_key": pub_c, "key_version": 1},
                          headers=TA)
            assert st == 201
            ok_items.append({"body": make_body(d),
                             "signature": crypto.sign(make_body(d), priv_c)})
        ok_items.append({"body": [], "signature": "x"})  # 第 100 项坏
        st, r = batch({"items": ok_items})
        check("100 项批合法且等长", st == 200 and len(r["results"]) == 100)
        check("100 项批：前 99 成功、末项 400，失败不短路",
              all(x["valid"] for x in r["results"][:99])
              and not r["results"][99]["valid"]
              and r["results"][99]["http_status"] == 400)

        # ---------------------------------------------------------- #
        # 6. 落盘失败：500 存储失败、仅回滚该项、继续处理、重启不保持
        # ---------------------------------------------------------- #
        did_p = "did:web:persist.example"
        priv_p, pub_p = _keypair()
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did_p, "public_key": pub_p, "key_version": 1},
                      headers=TA)
        assert st == 201
        body_p = make_body(did_p)
        st, r = sync({"body": body_p,
                      "signature": crypto.sign(body_p, priv_p)})
        assert st == 201, r  # 落盘窗口前已持久化

        did_q = "did:web:persist-q.example"
        priv_q, pub_q = _keypair()
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did_q, "public_key": pub_q, "key_version": 1},
                      headers=TA)
        assert st == 201

        # 让落盘失败：删除状态文件并在原路径建目录（os.replace 失败）
        assert os.path.isfile(store)
        os.remove(store)
        os.mkdir(store)
        try:
            fail_items = [
                {"body": make_body(did_q, key_version=0),  # 400
                 "signature": "x"},
                {"body": make_body(did_q),                 # 500 存储失败
                 "signature": crypto.sign(make_body(did_q), priv_q)},
                {"body": body_p,                           # 重放 200（无需写）
                 "signature": crypto.sign(body_p, priv_p)},
            ]
            st, r = batch({"items": fail_items})
            check("落盘失败批 200 等长不短路",
                  st == 200 and len(r["results"]) == 3)
            if len(r.get("results", [])) == 3:
                res = r["results"]
                check("落盘窗口：字段错 400",
                      res[0]["http_status"] == 400
                      and res[0]["reason"].startswith("请求"))
                check("落盘失败项 500 存储失败",
                      list(res[1].keys()) == FAIL_KEYS
                      and res[1]["valid"] is False
                      and res[1]["http_status"] == 500
                      and res[1]["reason"] == "存储失败")
                check("落盘失败不短路：后续重放项仍 200",
                      res[2]["valid"] is True
                      and res[2]["http_status"] == 200)
        finally:
            os.rmdir(store)

        # 仅回滚该项：did_q 未写入，落盘恢复后仍首次 201
        st, r = sync({"body": make_body(did_q),
                      "signature": crypto.sign(make_body(did_q), priv_q)})
        check("落盘失败项已回滚：恢复后首次 201",
              st == 201 and r["valid"] is True)

        # ---------------------------------------------------------- #
        # 7. 租户：缺省 default、隔离
        # ---------------------------------------------------------- #
        did_d = "did:web:default-batch.example"
        priv_d, pub_d = _keypair()
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did_d, "public_key": pub_d, "key_version": 1})
        assert st == 201
        st, r = batch({"items": [{"body": make_body(did_d),
                                  "signature": crypto.sign(make_body(did_d),
                                                           priv_d)}]},
                      headers={})
        check("缺省 default 租户批量首次 201",
              st == 200 and r["results"][0]["http_status"] == 201)
        st, r = batch({"items": [{"body": make_body(did_d),
                                  "signature": crypto.sign(make_body(did_d),
                                                           priv_d)}]},
                      headers=TB)
        check("跨租户锚点不可探测 -> 200 锚点不可用",
              st == 200 and r["results"][0]["http_status"] == 200
              and r["results"][0]["reason"] == "锚点不可用")

        # ---------------------------------------------------------- #
        # 8. 重启：已落盘项保持；落盘失败项未持久化
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(port), "服务重启超时"

        st, r = batch({"items": [
            {"body": body_p, "signature": crypto.sign(body_p, priv_p)},
            {"body": body_m, "signature": crypto.sign(body_m, priv_m)},
        ]})
        check("重启后已落盘项重放 200",
              st == 200
              and [x["http_status"] for x in r["results"]] == [200, 200]
              and all(x["valid"] for x in r["results"]))
        check("重启后记录内容稳定",
              r["results"][0]["reason"] == "机构业务终止"
              and r["results"][0]["deactivated_at"]
              == "2026-09-20T10:00:00Z")

    finally:
        proc.terminate()
        proc.wait(timeout=10)
        if os.path.isdir(store):
            os.rmdir(store)
        elif os.path.exists(store):
            os.remove(store)

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
