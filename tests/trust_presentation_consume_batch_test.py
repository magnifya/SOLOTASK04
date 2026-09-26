#!/usr/bin/env python3
"""批量验真并一次性消费 POST /v1/trust/presentations/consume-batch 的
端到端测试。

直接运行：python3 tests/trust_presentation_consume_batch_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import hashlib
import json
import os
import re
import shutil
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

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402

UTC_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
ISSUER_DID = "did:web:issuer.pcb.example"
HOLDER_DID = "did:web:holder.pcb.example"
SOURCE_TENANT = "source-tenant-pcb"


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


def start_server(port, store):
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up(port), "服务启动超时"
    return proc


def make_presentation(presentation_id, challenge="chal-1",
                      expires_at="2099-01-01T00:00:00Z",
                      credential_id="vc_pcb_0001",
                      issuer_did=ISSUER_DID, version=1):
    return {
        "presentation_id": presentation_id,
        "credential_id": credential_id,
        "issuer_did": issuer_did,
        "issuer_key_version": version,
        "disclose": ["/role", "/addr/city"],
        "claims": {"role": "admin", "addr": {"city": "北京"}},
        "challenge": challenge,
        "expires_at": expires_at,
    }


def sign_presentation(p, priv):
    """未绑定：proof 覆盖去掉 proof 后的全部字段。"""
    message = {k: v for k, v in p.items() if k != "proof"}
    p = dict(p)
    p["proof"] = crypto.sign(message, priv)
    return p


def make_bound(presentation_id, challenge="chal-1",
               expires_at="2099-01-01T00:00:00Z"):
    p = make_presentation(presentation_id=presentation_id,
                          challenge=challenge, expires_at=expires_at,
                          credential_id="vc_pcb_0002")
    p["holder_did"] = HOLDER_DID
    p["holder_key_version"] = 1
    return p


def sign_bound(p, issuer_priv, holder_priv, tenant_id=SOURCE_TENANT):
    """issuer proof 覆盖去掉 proof/holder_* 的八字段；holder proof 覆盖
    去掉 proof/holder_proof 的对象并加入 tenant_id。"""
    p = dict(p)
    unsigned = {
        k: v for k, v in p.items()
        if k != "proof" and not k.startswith("holder_")
    }
    p["proof"] = crypto.sign(unsigned, issuer_priv)
    holder_msg = dict(unsigned)
    holder_msg["holder_did"] = p["holder_did"]
    holder_msg["holder_key_version"] = p["holder_key_version"]
    holder_msg["tenant_id"] = tenant_id
    p["holder_proof"] = crypto.sign(holder_msg, holder_priv)
    return p


def vid(tag):
    return "vp_pcb_" + tag


def main():
    port = 8992
    store = tempfile.mktemp(suffix=".json")
    proc = start_server(port, store)
    base = f"http://127.0.0.1:{port}"
    path = "/v1/trust/presentations/consume-batch"
    single_path = "/v1/trust/presentations/consume"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def consume_batch(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{path}", payload,
                     headers=headers, raw=raw)

    def consume_single(payload, headers=None):
        return _http("POST", f"{base}{single_path}", payload,
                     headers=headers)

    def consumed_audits(headers):
        st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=headers)
        assert st == 200
        return [e for e in r["events"]
                if e["action"] == "trust.presentation.consumed"]

    try:
        T1 = {"X-Tenant-ID": "pcb-a"}
        T2 = {"X-Tenant-ID": "pcb-b"}

        iss_priv, iss_pub = gen_keypair()
        hold_priv, hold_pub = gen_keypair()

        # 显式空租户头 -> 400（进入验真/消费前判定）
        good_pres = sign_presentation(make_presentation(vid("g0001")), iss_priv)
        good_req = {"presentation": good_pres, "challenge": "chal-1"}
        st, r = consume_batch({"items": [good_req]},
                              headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400 仅 {error}",
              st == 400 and r == {"error": "X-Tenant-ID 不能为空"})

        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": ISSUER_DID, "public_key": iss_pub,
                       "key_version": 1}, headers=T1)
        check("注册签发者锚点 -> 201", st == 201)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": HOLDER_DID, "public_key": hold_pub,
                       "key_version": 1}, headers=T1)
        check("注册持有者锚点 -> 201", st == 201)

        # 1. 请求级非法 -> 200 按键序恰返 {"results":[],"reason":"请求非法"}
        def expect_request_invalid(name, payload=None, raw=None, headers=T1):
            st, r = consume_batch(payload=payload, raw=raw, headers=headers)
            check(name,
                  st == 200 and list(r.keys()) == ["results", "reason"]
                  and r == {"results": [], "reason": "请求非法"})

        expect_request_invalid("空请求体 -> 200 请求非法", raw=b"")
        expect_request_invalid("非法 JSON -> 200 请求非法", raw=b"not-json")
        expect_request_invalid("非 UTF-8 -> 200 请求非法", raw=b"\xff\xfe")
        expect_request_invalid("非对象（数组） -> 200 请求非法", raw=b"[1,2]")
        expect_request_invalid("缺 items -> 200 请求非法", payload={})
        expect_request_invalid("多余字段 -> 200 请求非法",
                               payload={"items": [good_req], "x": 1})
        expect_request_invalid("items 非数组 -> 200 请求非法",
                               payload={"items": "x"})
        expect_request_invalid("items 空数组 -> 200 请求非法",
                               payload={"items": []})
        over_items = [
            {"presentation": sign_presentation(
                make_presentation(vid(f"o{i:03d}")), iss_priv),
             "challenge": "chal-1"}
            for i in range(101)
        ]
        expect_request_invalid("items 超限（101）-> 200 请求非法",
                               payload={"items": over_items})

        # 2. 项结构非法 -> 请求项非法，不短路；末项合法首次消费成功
        good_first_batch = sign_presentation(
            make_presentation(vid("s0001")), iss_priv)
        good_first_req = {"presentation": good_first_batch,
                          "challenge": "chal-1"}
        want_cid_first = hashlib.sha256(
            crypto.canonicalize(good_first_req)).hexdigest()
        st, r = consume_batch({"items": [
            "not-object",
            [1, 2],
            42,
            {"presentation": good_first_batch},            # 缺 challenge
            {"presentation": good_first_batch,             # 多余字段
             "challenge": "chal-1", "x": 1},
            {"presentation": "x", "challenge": "chal-1"},  # presentation 非对象
            {"presentation": good_first_batch,             # challenge 空
             "challenge": ""},
            {"presentation": good_first_batch,             # challenge 非字符串
             "challenge": 1},
            # 未绑定项出现 source_tenant_id 但为空串
            {"presentation": good_first_batch,
             "challenge": "chal-1", "source_tenant_id": ""},
            {"presentation": good_first_batch,             # source 非字符串
             "challenge": "chal-1", "source_tenant_id": 9},
            good_first_req,
        ]}, headers=T1)
        check("混合结构批次 -> 200 且 results 等长同序",
              st == 200 and list(r.keys()) == ["results"]
              and len(r["results"]) == 11)
        results = r["results"]
        check("前十种非法项均为 请求项非法",
              all(item == {"valid": False, "reason": "请求项非法"}
                  for item in results[:10]))
        check("末项合法首次消费成功且键序正确",
              results[10] == {
                  "valid": True,
                  "consumption_id": want_cid_first,
                  "consumed_at": results[10]["consumed_at"],
              }
              and list(results[10].keys())
              == ["valid", "consumption_id", "consumed_at"]
              and HEX64_RE.fullmatch(results[10]["consumption_id"]) is not None
              and UTC_Z_RE.fullmatch(results[10]["consumed_at"]) is not None)
        check("结构错批次仅末项记一条审计",
              len(consumed_audits(T1)) == 1
              and consumed_audits(T1)[0]["resource_id"] == want_cid_first)

        # 3. 验真失败沿用单条 reason，逐项不短路，不记审计
        unknown = sign_presentation(
            make_presentation(vid("s0002"),
                              issuer_did="did:web:nobody.example"), iss_priv)
        bad_sig_pres = dict(good_first_batch, proof="!!!bad!!!",
                            presentation_id=vid("s0003"))
        expired = sign_presentation(
            make_presentation(vid("s0004"),
                              expires_at="2020-01-01T00:00:00Z"), iss_priv)
        wrong_hold = sign_bound(make_bound(vid("s0005")), iss_priv,
                                gen_keypair()[0])
        audits_before = len(consumed_audits(T1))
        st, r = consume_batch({"items": [
            {"presentation": good_first_batch, "challenge": "chal-2"},
            {"presentation": unknown, "challenge": "chal-1"},
            {"presentation": bad_sig_pres, "challenge": "chal-1"},
            {"presentation": expired, "challenge": "chal-1"},
            {"presentation": wrong_hold, "challenge": "chal-1",
             "source_tenant_id": SOURCE_TENANT},
        ]}, headers=T1)
        check("验真失败批次 -> 200 等长", st == 200 and len(r["results"]) == 5)
        reasons = [item["reason"] for item in r["results"]]
        check("验真失败原因与顺序沿用单条且键序为 valid,reason",
              all(list(item.keys()) == ["valid", "reason"]
                  and item["valid"] is False for item in r["results"])
              and reasons[0].startswith("挑战")
              and reasons[1].startswith("锚点")
              and reasons[2].startswith("签名格式错误")
              and reasons[3] == "演示已过期"
              and reasons[4].startswith("签名校验失败: holder_proof"))
        check("验真失败不记审计",
              len(consumed_audits(T1)) == audits_before)

        # 3b. 历史键篡改项验真失败 -> 返回验真原因而非已消费（验真先于判重）
        tampered = dict(good_first_batch, proof="!!!bad!!!")
        tampered_req = {"presentation": tampered, "challenge": "chal-1"}
        st, r = consume_batch({"items": [tampered_req]}, headers=T1)
        check("历史键的篡改项验真失败 -> 签名格式错误（非已消费）",
              st == 200 and len(r["results"]) == 1
              and r["results"][0]["reason"].startswith("签名格式错误"))

        # 4. 批内同键判重：首项成功、后项（含异内容）已消费；异键成功
        dup_pres = sign_presentation(make_presentation(vid("d0001")), iss_priv)
        dup_req = {"presentation": dup_pres, "challenge": "chal-1"}
        dup_other = sign_presentation(
            make_presentation(vid("d0001"), challenge="chal-9"), iss_priv)
        dup_other_req = {"presentation": dup_other, "challenge": "chal-9"}
        fresh_req = {"presentation": sign_presentation(
            make_presentation(vid("d0002")), iss_priv),
            "challenge": "chal-1"}
        bound_req = {"presentation": sign_bound(
            make_bound(vid("d0003")), iss_priv, hold_priv),
            "challenge": "chal-1", "source_tenant_id": SOURCE_TENANT}
        st, r = consume_batch(
            {"items": [dup_req, dup_other_req, fresh_req, bound_req]},
            headers=T1)
        check("批内：成功/异内容重放/异键成功/绑定成功",
              st == 200 and len(r["results"]) == 4
              and list(r["results"][0].keys())
              == ["valid", "consumption_id", "consumed_at"]
              and r["results"][0]["valid"] is True
              and r["results"][0]["consumption_id"]
              == hashlib.sha256(crypto.canonicalize(dup_req)).hexdigest()
              and r["results"][1]
              == {"valid": False, "reason": "外部演示已消费"}
              and r["results"][2]["valid"] is True
              and r["results"][3]["valid"] is True
              and list(r["results"][3].keys())
              == ["valid", "consumption_id", "consumed_at"]
              and r["results"][3]["consumption_id"]
              == hashlib.sha256(crypto.canonicalize(bound_req)).hexdigest())
        check("批内三项新消费记三条审计（累计 4 条）",
              len(consumed_audits(T1)) == 4)

        # 5. 与单条 consume 互判重
        st, r = consume_batch({"items": [dup_req]}, headers=T1)
        check("历史重放（整批重放）-> 外部演示已消费",
              st == 200
              and r["results"]
              == [{"valid": False, "reason": "外部演示已消费"}])
        single_pres = sign_presentation(make_presentation(vid("x0001")),
                                        iss_priv)
        single_req = {"presentation": single_pres, "challenge": "chal-1"}
        st, r = consume_single(single_req, headers=T1)
        check("单条先消费 -> 200 valid:true", st == 200 and r.get("valid"))
        st, r = consume_batch({"items": [single_req]}, headers=T1)
        check("单条消费后批量同键 -> 外部演示已消费",
              st == 200
              and r["results"]
              == [{"valid": False, "reason": "外部演示已消费"}])
        batch_pres = sign_presentation(make_presentation(vid("x0002")),
                                       iss_priv)
        batch_req = {"presentation": batch_pres, "challenge": "chal-1"}
        st, r = consume_batch({"items": [batch_req]}, headers=T1)
        check("批量先消费 -> 成功", st == 200
              and r["results"][0].get("valid") is True)
        st, r = consume_single(batch_req, headers=T1)
        check("批量消费后单条同键 -> 外部演示已消费",
              st == 200 and r
              == {"valid": False, "reason": "外部演示已消费"})
        check("互判重阶段新增两条首次消费审计（累计 6 条）",
              len(consumed_audits(T1)) == 6)

        # 6. 租户隔离 + 缺省 default
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": ISSUER_DID, "public_key": iss_pub,
                       "key_version": 1}, headers=T2)
        check("T2 注册签发者锚点 -> 201", st == 201)
        iso_pres = sign_presentation(make_presentation(vid("i0001")), iss_priv)
        iso_req = {"presentation": iso_pres, "challenge": "chal-1"}
        st, r = consume_batch({"items": [iso_req]}, headers=T1)
        check("租户 A 同键首次消费成功",
              st == 200 and r["results"][0].get("valid") is True)
        st, r = consume_batch({"items": [iso_req]}, headers=T2)
        check("租户 B 同键互不影响首次消费成功",
              st == 200 and r["results"][0].get("valid") is True)
        st, r = consume_batch({"items": [iso_req]}, headers=T2)
        check("租户 B 重放 -> 外部演示已消费",
              st == 200
              and r["results"]
              == [{"valid": False, "reason": "外部演示已消费"}])
        st, r = consume_batch({"items": [iso_req]})
        check("缺省租户头按 default 隔离 -> 锚点不存在类原因",
              st == 200 and r["results"][0].get("valid") is False
              and r["results"][0].get("reason", "").startswith("锚点不存在"))
        check("消费审计按租户隔离",
              len(consumed_audits(T1)) == 7 and len(consumed_audits(T2)) == 1)

        # 7. 并发：批量与单条同键仅一次成功
        conc_pres = sign_presentation(make_presentation(vid("c0001")), iss_priv)
        conc_req = {"presentation": conc_pres, "challenge": "chal-1"}
        outcomes = []

        def worker_batch():
            outcomes.append(consume_batch({"items": [conc_req]}, headers=T1))

        def worker_single():
            outcomes.append(consume_single(conc_req, headers=T1))

        threads = [threading.Thread(target=worker_batch) for _ in range(4)]
        threads += [threading.Thread(target=worker_single) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        n_ok = 0
        n_replay = 0
        for st, r in outcomes:
            item = r["results"][0] if "results" in r else r
            if st == 200 and item.get("valid") is True:
                n_ok += 1
            elif item == {"valid": False, "reason": "外部演示已消费"}:
                n_replay += 1
        check("并发同键（批量+单条）仅一次成功，其余均为已消费",
              n_ok == 1 and n_replay == 7)
        check("并发首次消费仅一条审计",
              len([e for e in consumed_audits(T1)
                   if e["resource_id"]
                   == hashlib.sha256(
                       crypto.canonicalize(conc_req)).hexdigest()]) == 1)

        # 8. 落盘失败：500 仅 {"error":"存储失败"}，全回滚可重试
        fail_req1 = {"presentation": sign_presentation(
            make_presentation(vid("f0001")), iss_priv),
            "challenge": "chal-1"}
        fail_req2 = {"presentation": sign_bound(
            make_bound(vid("f0002")), iss_priv, hold_priv),
            "challenge": "chal-1", "source_tenant_id": SOURCE_TENANT}
        audits_before = len(consumed_audits(T1))
        os.unlink(store)
        os.mkdir(store)
        try:
            st, r = consume_batch({"items": [fail_req1, fail_req2]},
                                  headers=T1)
            check("落盘失败 -> 500 仅 {error:存储失败}",
                  st == 500 and r == {"error": "存储失败"})
        finally:
            os.rmdir(store)
        check("落盘失败不记审计", len(consumed_audits(T1)) == audits_before)
        st, r = consume_batch({"items": [fail_req1, fail_req2]}, headers=T1)
        check("落盘失败回滚后同批两键均可重试成功",
              st == 200
              and all(item.get("valid") is True for item in r["results"]))
        check("重试成功后补记两条审计",
              len(consumed_audits(T1)) == audits_before + 2)

        # 9. 重启仍判重（含两租户与绑定形态）
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server(port, store)
        st, r = consume_batch(
            {"items": [good_first_req, dup_req, bound_req, iso_req,
                       fail_req1, fail_req2]},
            headers=T1)
        check("重启后历史键整批判重 -> 全部外部演示已消费",
              st == 200 and len(r["results"]) == 6
              and all(item == {"valid": False, "reason": "外部演示已消费"}
                      for item in r["results"]))
        st, r = consume_batch({"items": [iso_req]}, headers=T2)
        check("重启后他租户同键重放 -> 外部演示已消费",
              st == 200
              and r["results"]
              == [{"valid": False, "reason": "外部演示已消费"}])
        st, r = consume_single(bound_req, headers=T1)
        check("重启后单条与批量互判重 -> 外部演示已消费",
              st == 200 and r
              == {"valid": False, "reason": "外部演示已消费"})
        check("重启后重放不新增审计",
              len(consumed_audits(T1)) == audits_before + 2
              and len(consumed_audits(T2)) == 1)

    finally:
        proc.terminate()
        proc.wait(timeout=10)
        if os.path.isdir(store):
            shutil.rmtree(store)
        elif os.path.exists(store):
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
    raise SystemExit(main())
