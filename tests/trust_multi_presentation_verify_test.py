#!/usr/bin/env python3
"""跨系统多凭证组合展示验真端到端测试。

覆盖 POST /v1/trust/presentations/verify 与 verify-batch 对
/v1/presentations/multi 返回对象（未绑定与持有者绑定）的直接验真：
固定原因（请求非法/组合展示非法/挑战不匹配/锚点不可用/签名格式错误/
签名校验失败/演示已过期）、零披露与数组投影、双锚点双签名覆盖、
绑定 source_tenant_id/项序防篡改、批量单凭证与组合混用、外部 DID
停用通告（先签发者后持有者）、只读可重复验真、租户隔离。

直接运行：python3 tests/trust_multi_presentation_verify_test.py
"""

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

VERIFY_PATH = "/v1/trust/presentations/verify"
BATCH_PATH = "/v1/trust/presentations/verify-batch"
CONSUME_PATH = "/v1/trust/presentations/consume"
DEACTIVATE_SYNC_PATH = "/v1/trust/dids/deactivate-sync"


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


def _item_unsigned(presentation_id, item, challenge, expires_at):
    return {
        "presentation_id": presentation_id,
        "credential_id": item["credential_id"],
        "issuer_did": item["issuer_did"],
        "issuer_key_version": item["issuer_key_version"],
        "disclose": list(item["disclose"]),
        "claims": copy.deepcopy(item["claims"]),
        "challenge": challenge,
        "expires_at": expires_at,
    }


def sign_item(presentation_id, item, challenge, expires_at, priv_pem):
    item["proof"] = crypto.sign(
        _item_unsigned(presentation_id, item, challenge, expires_at),
        priv_pem,
    )


def sign_all_items(combo, priv_by_issuer):
    for item in combo["items"]:
        sign_item(
            combo["presentation_id"], item, combo["challenge"],
            combo["expires_at"], priv_by_issuer[item["issuer_did"]],
        )


def holder_payload(combo, source_tenant_id):
    return {
        "presentation_id": combo["presentation_id"],
        "items": [
            _item_unsigned(
                combo["presentation_id"], item,
                combo["challenge"], combo["expires_at"],
            )
            for item in combo["items"]
        ],
        "challenge": combo["challenge"],
        "expires_at": combo["expires_at"],
        "holder_did": combo["holder_did"],
        "holder_key_version": combo["holder_key_version"],
        "tenant_id": source_tenant_id,
    }


def sign_holder(combo, source_tenant_id, priv_pem):
    combo["holder_proof"] = crypto.sign(
        holder_payload(combo, source_tenant_id), priv_pem
    )


def main():
    port = 8988
    store_path = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store_path)
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

    def verify(payload, headers=None):
        return _http("POST", f"{base}{VERIFY_PATH}", payload, headers=headers)

    def expect_reason(name, payload, reason, headers=None):
        st, r = verify(payload, headers=headers)
        check(
            name,
            st == 200 and r == {"valid": False, "reason": reason},
        )

    try:
        assert wait_up(port), "服务启动超时"
        SRC = {"X-Tenant-ID": "src"}
        DST = {"X-Tenant-ID": "dst"}

        # ---------- 来源租户：真实走组合生成接口 ----------
        st, iss1 = _http("POST", f"{base}/v1/dids",
                         {"method": "example", "public_key": "iss1"},
                         headers=SRC)
        st, iss2 = _http("POST", f"{base}/v1/dids",
                         {"method": "example", "public_key": "iss2"},
                         headers=SRC)
        st, holder = _http("POST", f"{base}/v1/dids",
                           {"method": "example", "public_key": "hold"},
                           headers=SRC)
        d1, d2, dh = iss1["did"], iss2["did"], holder["did"]
        st, vc1 = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": d1, "subject_did": dh,
            "claims": {"name": "alice", "level": 3,
                       "addr": {"city": "X", "zip": "1"},
                       "tags": ["a", "b"]},
        }, headers=SRC)
        st, vc2 = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": d2, "subject_did": dh,
            "claims": {"role": "admin", "scores": [90, 80], "ok": True},
        }, headers=SRC)
        id1, id2 = vc1["credential_id"], vc2["credential_id"]

        st, unbound = _http("POST", f"{base}/v1/presentations/multi", {
            "items": [
                {"credential_id": id1,
                 "disclose": ["/name", "/addr/city", "/tags"]},
                {"credential_id": id2, "disclose": ["/role", "/scores"]},
            ],
        }, headers=SRC)
        check("来源租户生成未绑定组合 201", st == 201)
        check("未绑定组合公开键集合",
              set(unbound) == {"presentation_id", "items", "challenge",
                               "expires_at"})
        st, bound = _http("POST", f"{base}/v1/presentations/multi", {
            "items": [
                {"credential_id": id1, "disclose": []},
                {"credential_id": id2, "disclose": ["/ok"]},
            ],
            "holder_binding": True,
        }, headers=SRC)
        check("来源租户生成绑定组合 201（含零披露项）", st == 201)
        check("绑定组合公开键集合",
              set(bound) == {"presentation_id", "items", "challenge",
                             "expires_at", "holder_did",
                             "holder_key_version", "holder_proof"}
              and bound["holder_did"] == dh)
        st, zero = _http("POST", f"{base}/v1/presentations/multi", {
            "items": [{"credential_id": id1, "disclose": []},
                      {"credential_id": id2, "disclose": []}],
        }, headers=SRC)
        check("零披露组合 201", st == 201)

        # ---------- 验证租户：只登记信任锚点 ----------
        for did_info in (iss1, iss2, holder):
            st, _ = _http("POST", f"{base}/v1/trust/anchors", {
                "did": did_info["did"],
                "public_key": did_info["public_key"],
                "key_version": did_info["key_version"],
            }, headers=DST)
            check(f"登记锚点 {did_info['key_handle']} -> 201", st == 201)
        # 无 vp 用途的锚点
        st, no_vp_did = _http("POST", f"{base}/v1/dids",
                              {"method": "example", "public_key": "no-vp"},
                              headers=SRC)
        st, _ = _http("POST", f"{base}/v1/trust/anchors", {
            "did": no_vp_did["did"], "public_key": no_vp_did["public_key"],
            "key_version": 1, "uses": ["generic", "vc"],
        }, headers=DST)
        check("无 vp 用途锚点 -> 201", st == 201)

        # ---------- 成功路径 ----------
        st, r = verify(
            {"presentation": unbound, "challenge": unbound["challenge"]},
            headers=DST)
        check("未绑定组合验真成功，恰为 valid:true",
              st == 200 and r == {"valid": True})
        st, r = verify({
            "presentation": bound, "challenge": bound["challenge"],
            "source_tenant_id": "src",
        }, headers=DST)
        check("绑定组合验真成功，恰为 valid:true",
              st == 200 and r == {"valid": True})
        st, r = verify(
            {"presentation": zero, "challenge": zero["challenge"]},
            headers=DST)
        check("零披露组合验真成功（无需隐藏 claims）",
              st == 200 and r == {"valid": True})
        check("零披露投影均为空对象",
              all(item["claims"] == {} for item in zero["items"]))
        check("数组叶子整体投影",
              unbound["items"][0]["claims"]["tags"] == ["a", "b"]
              and unbound["items"][1]["claims"]["scores"] == [90, 80])

        # 只读：有效期内重复验真仍成功
        st, r = verify({
            "presentation": bound, "challenge": bound["challenge"],
            "source_tenant_id": "src",
        }, headers=DST)
        check("绑定组合重复验真仍成功（不消费）",
              st == 200 and r == {"valid": True})

        # 显式空租户头仍 400
        st, r = verify(
            {"presentation": unbound, "challenge": unbound["challenge"]},
            headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400)

        # ---------- 请求非法 ----------
        good_req = {"presentation": unbound,
                    "challenge": unbound["challenge"]}
        def expect_request_prefix(name, payload, headers=DST, raw=None):
            if raw is not None:
                st2, r2 = _http(
                    "POST", f"{base}{VERIFY_PATH}", raw=raw,
                    headers={**headers, "Content-Type": "application/json"})
            else:
                st2, r2 = verify(payload, headers=headers)
            check(
                name,
                st2 == 200 and r2.get("valid") is False
                and isinstance(r2.get("reason"), str)
                and r2["reason"].startswith("请求"),
            )
        for label, payload in [
        ]:
            expect_request_prefix(f"{label} -> 请求类原因", payload)
        # 无法辨识演示形态（缺/非对象 presentation、非对象请求体）时沿用
        # 单凭证路径的请求类原因；组合形态可辨识后的请求错误固定
        # “请求非法”。
        expect_request_prefix("缺 challenge -> 请求类原因",
                              {"presentation": unbound})
        expect_request_prefix("缺 presentation -> 请求类原因",
                              {"challenge": unbound["challenge"]})
        expect_request_prefix("多余字段 -> 请求类原因",
                              {**good_req, "extra": 1})
        expect_request_prefix("presentation 非对象 -> 请求类原因",
                              {"presentation": [], "challenge": "c"})
        expect_request_prefix("请求体非对象 -> 请求类原因",
                              None, raw=b"[1,2]")
        expect_reason("challenge 空串 -> 请求非法",
                      {"presentation": unbound, "challenge": ""},
                      "请求非法", headers=DST)
        expect_reason("challenge 非字符串 -> 请求非法",
                      {"presentation": unbound, "challenge": 123},
                      "请求非法", headers=DST)
        # 未绑定组合携带 source_tenant_id -> 组合展示非法（绑定关系不一致）
        expect_reason(
            "未绑定组合携带 source_tenant_id -> 组合展示非法",
            {"presentation": unbound, "challenge": unbound["challenge"],
             "source_tenant_id": "src"},
            "组合展示非法", headers=DST)
        # 绑定组合缺 source_tenant_id -> 组合展示非法
        expect_reason(
            "绑定组合缺 source_tenant_id -> 组合展示非法",
            {"presentation": bound, "challenge": bound["challenge"]},
            "组合展示非法", headers=DST)
        expect_reason(
            "source_tenant_id 空串 -> 请求非法",
            {"presentation": bound, "challenge": bound["challenge"],
             "source_tenant_id": ""},
            "请求非法", headers=DST)
        expect_reason(
            "source_tenant_id 非字符串 -> 请求非法",
            {"presentation": bound, "challenge": bound["challenge"],
             "source_tenant_id": 5},
            "请求非法", headers=DST)

        # ---------- 组合展示非法（结构） ----------
        def tampered(base_combo, mutate):
            p = copy.deepcopy(base_combo)
            mutate(p)
            return p

        def combo_reason(name, combo, reason, bound=False, source="src"):
            payload = {"presentation": combo, "challenge": combo["challenge"]}
            if bound:
                payload["source_tenant_id"] = source
            expect_reason(name, payload, reason, headers=DST)

        u = unbound
        combo_reason("顶层缺 presentation_id",
                     tampered(u, lambda p: p.pop("presentation_id")),
                     "组合展示非法")
        combo_reason("顶层多余字段",
                     tampered(u, lambda p: p.__setitem__("bogus", 1)),
                     "组合展示非法")
        combo_reason("presentation_id 空串",
                     tampered(u, lambda p: p.__setitem__(
                         "presentation_id", "")),
                     "组合展示非法")
        # 组合自身 challenge 类型非法（请求 challenge 仍合法）：
        # 组合结构先于挑战比较。
        st, r = verify({
            "presentation": tampered(
                u, lambda p: p.__setitem__("challenge", 9)),
            "challenge": u["challenge"],
        }, headers=DST)
        check("组合 challenge 非字符串 -> 组合展示非法",
              st == 200 and r == {"valid": False,
                                  "reason": "组合展示非法"})
        combo_reason("items 为空数组",
                     tampered(u, lambda p: p.__setitem__("items", [])),
                     "组合展示非法")
        combo_reason("items 超 100",
                     tampered(u, lambda p: p.__setitem__(
                         "items", p["items"] * 101)),
                     "组合展示非法")
        combo_reason("items 非数组",
                     tampered(u, lambda p: p.__setitem__("items", {})),
                     "组合展示非法")
        item0 = u["items"][0]
        combo_reason("项缺 proof",
                     tampered(u, lambda p: p["items"][0].pop("proof")),
                     "组合展示非法")
        combo_reason("项多余字段",
                     tampered(u, lambda p: p["items"][0].__setitem__(
                         "x", 1)),
                     "组合展示非法")
        combo_reason("credential_id 空串",
                     tampered(u, lambda p: p["items"][0].__setitem__(
                         "credential_id", "")),
                     "组合展示非法")
        combo_reason("credential_id 非字符串",
                     tampered(u, lambda p: p["items"][0].__setitem__(
                         "credential_id", 7)),
                     "组合展示非法")
        combo_reason("issuer_did 空串",
                     tampered(u, lambda p: p["items"][0].__setitem__(
                         "issuer_did", "")),
                     "组合展示非法")
        for bad, label in [(True, "布尔"), (0, "零"), (-2, "负数"),
                           (1.0, "浮点"), ("1", "字符串")]:
            combo_reason(
                f"issuer_key_version 非法（{label}）",
                tampered(u, lambda p, v=bad: p["items"][0].__setitem__(
                    "issuer_key_version", v)),
                "组合展示非法")
        combo_reason("disclose 非数组",
                     tampered(u, lambda p: p["items"][0].__setitem__(
                         "disclose", "/name")),
                     "组合展示非法")
        combo_reason("disclose 含非字符串",
                     tampered(u, lambda p: p["items"][0].__setitem__(
                         "disclose", [1])),
                     "组合展示非法")
        combo_reason("claims 非对象",
                     tampered(u, lambda p: p["items"][0].__setitem__(
                         "claims", [])),
                     "组合展示非法")
        combo_reason("proof 空串",
                     tampered(u, lambda p: p["items"][0].__setitem__(
                         "proof", "")),
                     "组合展示非法")
        combo_reason("credential_id 批内重复",
                     tampered(u, lambda p: p["items"].__setitem__(
                         1, copy.deepcopy(p["items"][0]))),
                     "组合展示非法")
        combo_reason("expires_at 空串",
                     tampered(u, lambda p: p.__setitem__("expires_at", "")),
                     "组合展示非法")

        # 持有者字段必须整体出现或省略
        for field in ("holder_did", "holder_key_version", "holder_proof"):
            combo_reason(
                f"未绑定组合仅出现 {field} -> 组合展示非法",
                tampered(u, lambda p, f=field: p.__setitem__(f, "x")),
                "组合展示非法")
            combo_reason(
                f"绑定组合缺 {field} -> 组合展示非法",
                tampered(bound, lambda p, f=field: p.pop(f)),
                "组合展示非法", bound=True)
        combo_reason("未知 holder_ 前缀字段",
                     tampered(u, lambda p: p.__setitem__(
                         "holder_unknown", "x")),
                     "组合展示非法")
        combo_reason("holder_did 空串",
                     tampered(bound, lambda p: p.__setitem__(
                         "holder_did", "")),
                     "组合展示非法", bound=True)
        combo_reason("holder_key_version 布尔",
                     tampered(bound, lambda p: p.__setitem__(
                         "holder_key_version", True)),
                     "组合展示非法", bound=True)
        combo_reason("holder_proof 非字符串",
                     tampered(bound, lambda p: p.__setitem__(
                         "holder_proof", 1)),
                     "组合展示非法", bound=True)

        # ---------- 挑战不匹配 ----------
        st, r = verify({"presentation": unbound, "challenge": "other-c"},
                       headers=DST)
        check("请求挑战与组合挑战不一致 -> 挑战不匹配",
              st == 200 and r == {"valid": False, "reason": "挑战不匹配"})
        # 组合内挑战被改但请求同步给新值（项证明随之失配 -> 签名校验失败；
        # 仅请求/组合不一致时才是挑战不匹配）
        st, r = verify(
            {"presentation": tampered(
                unbound, lambda p: p.__setitem__("challenge", "c2")),
             "challenge": "c2"},
            headers=DST)
        check("组合统一挑战被改动 -> 签名校验失败",
              st == 200 and r.get("reason") == "签名校验失败")

        # ---------- 锚点不可用 ----------
        # 未知签发者（只改 DID，重签无意义：锚点先于验签）
        st, r = verify({
            "presentation": tampered(
                unbound, lambda p: p["items"][0].__setitem__(
                    "issuer_did", "did:example:nobody")),
            "challenge": unbound["challenge"],
        }, headers=DST)
        check("签发者锚点缺失 -> 锚点不可用",
              st == 200 and r == {"valid": False, "reason": "锚点不可用"})
        # 第二项签发者未知（按项序，第一项通过后才到第二项）
        st, r = verify({
            "presentation": tampered(
                unbound, lambda p: p["items"][1].__setitem__(
                    "issuer_did", "did:example:nobody")),
            "challenge": unbound["challenge"],
        }, headers=DST)
        check("第二项签发者锚点缺失 -> 锚点不可用",
              st == 200 and r.get("reason") == "锚点不可用")
        # 版本不存在
        st, r = verify({
            "presentation": tampered(
                unbound, lambda p: p["items"][0].__setitem__(
                    "issuer_key_version", 9)),
            "challenge": unbound["challenge"],
        }, headers=DST)
        check("签发者锚点版本缺失 -> 锚点不可用",
              r.get("reason") == "锚点不可用")
        # 无 vp 用途：构造一张以 no-vp DID 签发的组合（手工重签第一项）
        no_vp_combo = copy.deepcopy(unbound)
        no_vp_combo["presentation_id"] = "mvp_" + "b" * 32
        no_vp_combo["items"][0]["issuer_did"] = no_vp_did["did"]
        # 该锚点为公钥 PEM；来源服务内私钥无法取到，故只验锚点分类：
        # proof 保持原值，锚点检查先于签名，应判锚点不可用
        st, r = verify({
            "presentation": no_vp_combo,
            "challenge": unbound["challenge"],
        }, headers=DST)
        check("缺少 vp 用途 -> 锚点不可用",
              r.get("reason") == "锚点不可用")
        # 吊销锚点
        st, _ = _http(
            "PUT", f"{base}/v1/trust/anchors/{d2}/1/status",
            {"status": "revoked"}, headers=DST)
        check("吊销锚点 v1 -> 200", st == 200)
        st, r = verify({
            "presentation": unbound, "challenge": unbound["challenge"]},
            headers=DST)
        check("签发者锚点已吊销 -> 锚点不可用",
              r.get("reason") == "锚点不可用")
        st, _ = _http(
            "PUT", f"{base}/v1/trust/anchors/{d2}/1/status",
            {"status": "active"}, headers=DST)
        # 持有者锚点缺失（绑定）
        st, r = verify({
            "presentation": tampered(
                bound, lambda p: p.__setitem__(
                    "holder_did", "did:example:no-holder")),
            "challenge": bound["challenge"], "source_tenant_id": "src",
        }, headers=DST)
        check("持有者锚点缺失 -> 锚点不可用",
              r.get("reason") == "锚点不可用")

        # ---------- 签名格式/验签（手工组合，私钥本地可控） ----------
        ext_issuer_priv = crypto.generate_private_key_pem()
        ext_issuer_pub = crypto.public_key_pem_from_private(ext_issuer_priv)
        ext_holder_priv = crypto.generate_private_key_pem()
        ext_holder_pub = crypto.public_key_pem_from_private(ext_holder_priv)
        ext_iss_did = "did:web:ext-issuer"
        ext_hold_did = "did:web:ext-holder"
        for did_value, pub in ((ext_iss_did, ext_issuer_pub),
                               (ext_hold_did, ext_holder_pub)):
            st, _ = _http("POST", f"{base}/v1/trust/anchors", {
                "did": did_value, "public_key": pub, "key_version": 1,
            }, headers=DST)
            assert st == 201

        def make_combo(bound=False, expires_at="2099-01-01T00:00:00Z",
                       challenge="chal-m"):
            combo = {
                "presentation_id": "mvp_" + "c" * 32,
                "items": [
                    {"credential_id": "vc_ext_1", "issuer_did": ext_iss_did,
                     "issuer_key_version": 1,
                     "disclose": ["/name"], "claims": {"name": "bob"},
                     "proof": ""},
                    {"credential_id": "vc_ext_2", "issuer_did": ext_iss_did,
                     "issuer_key_version": 1,
                     "disclose": [], "claims": {}, "proof": ""},
                ],
                "challenge": challenge,
                "expires_at": expires_at,
            }
            sign_all_items(combo, {ext_iss_did: ext_issuer_priv})
            if bound:
                combo["holder_did"] = ext_hold_did
                combo["holder_key_version"] = 1
                combo["holder_proof"] = ""
                sign_holder(combo, "src", ext_holder_priv)
            return combo

        mc = make_combo()
        st, r = verify({"presentation": mc, "challenge": "chal-m"},
                       headers=DST)
        check("手工未绑定组合验真成功", r == {"valid": True})
        mcb = make_combo(bound=True)
        st, r = verify({"presentation": mcb, "challenge": "chal-m",
                        "source_tenant_id": "src"}, headers=DST)
        check("手工绑定组合验真成功", r == {"valid": True})

        # proof 编码格式错误（锚点存在，格式先于密码学验签）
        bad_fmt = tampered(mc, lambda p: p["items"][0].__setitem__(
            "proof", "%%%not-base64url"))
        expect_reason("项 proof 编码非法 -> 签名格式错误",
                      {"presentation": bad_fmt, "challenge": "chal-m"},
                      "签名格式错误", headers=DST)
        bad_fmt2 = tampered(mc, lambda p: p["items"][0].__setitem__(
            "proof", "AAAA"))
        expect_reason("项 proof 长度非法 -> 签名格式错误",
                      {"presentation": bad_fmt2, "challenge": "chal-m"},
                      "签名格式错误", headers=DST)
        expect_reason(
            "holder_proof 编码非法 -> 签名格式错误",
            {"presentation": tampered(
                mcb, lambda p: p.__setitem__("holder_proof", "@@@")),
             "challenge": "chal-m", "source_tenant_id": "src"},
            "签名格式错误", headers=DST)

        # 合法编码但验签失败（内容被改动）
        forged = "A" * 86
        expect_reason(
            "项 proof 被替换 -> 签名校验失败",
            {"presentation": tampered(
                mc, lambda p: p["items"][0].__setitem__("proof", forged)),
             "challenge": "chal-m"},
            "签名校验失败", headers=DST)
        expect_reason(
            "组合标识被改动 -> 签名校验失败",
            {"presentation": tampered(
                mc, lambda p: p.__setitem__(
                    "presentation_id", "mvp_" + "d" * 32)),
             "challenge": "chal-m"},
            "签名校验失败", headers=DST)
        expect_reason(
            "期限被改动 -> 签名校验失败",
            {"presentation": tampered(
                mc, lambda p: p.__setitem__(
                    "expires_at", "2098-01-01T00:00:00Z")),
             "challenge": "chal-m"},
            "签名校验失败", headers=DST)
        expect_reason(
            "披露内容被改动 -> 签名校验失败",
            {"presentation": tampered(
                mc, lambda p: p["items"][0]["claims"].__setitem__(
                    "name", "mallory")),
             "challenge": "chal-m"},
            "签名校验失败", headers=DST)
        expect_reason(
            "disclose 被改动 -> 签名校验失败",
            {"presentation": tampered(
                mc, lambda p: p["items"][0].__setitem__(
                    "disclose", ["/name", "/role"])),
             "challenge": "chal-m"},
            "签名校验失败", headers=DST)
        expect_reason(
            "credential_id 被改动 -> 签名校验失败",
            {"presentation": tampered(
                mc, lambda p: p["items"][0].__setitem__(
                    "credential_id", "vc_other")),
             "challenge": "chal-m"},
            "签名校验失败", headers=DST)
        expect_reason(
            "holder_proof 被替换 -> 签名校验失败",
            {"presentation": tampered(
                mcb, lambda p: p.__setitem__("holder_proof", forged)),
             "challenge": "chal-m", "source_tenant_id": "src"},
            "签名校验失败", headers=DST)
        expect_reason(
            "绑定组合更换 source_tenant_id -> 签名校验失败",
            {"presentation": mcb, "challenge": "chal-m",
             "source_tenant_id": "other-src"},
            "签名校验失败", headers=DST)
        reordered = copy.deepcopy(mcb)
        reordered["items"] = list(reversed(reordered["items"]))
        expect_reason(
            "绑定组合调整项序 -> 签名校验失败",
            {"presentation": reordered, "challenge": "chal-m",
             "source_tenant_id": "src"},
            "签名校验失败", headers=DST)
        # 未绑定组合调整项序：项证明自带 presentation_id/挑战/期限，
        # 项序不在任何签名覆盖内，仍可验真
        reordered_u = copy.deepcopy(mc)
        reordered_u["items"] = list(reversed(reordered_u["items"]))
        st, r = verify(
            {"presentation": reordered_u, "challenge": "chal-m"},
            headers=DST)
        check("未绑定组合调整项序仍验真成功（与本地行为一致）",
              r == {"valid": True})

        # ---------- 期限 ----------
        past = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 1))
        now = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time()))
        for label, expires in (("过去时刻", past), ("当前时刻（达到即过期）", now)):
            combo_exp = make_combo(expires_at=expires)
            expect_reason(
                f"{label} -> 演示已过期",
                {"presentation": combo_exp, "challenge": "chal-m"},
                "演示已过期", headers=DST)
        bad_shape = make_combo(expires_at="2099-01-01 00:00:00")
        expect_reason(
            "expires_at 非 UTC 秒精度 Z -> 组合展示非法",
            {"presentation": bad_shape, "challenge": "chal-m"},
            "组合展示非法", headers=DST)

        # ---------- 外部 DID 停用通告（先签发者，再持有者） ----------
        def deactivate(did_value, reason, priv_pem,
                       deactivated_at="2026-09-20T10:00:00Z"):
            body = {"did": did_value, "key_version": 1, "reason": reason,
                    "deactivated_at": deactivated_at}
            return _http("POST", f"{base}{DEACTIVATE_SYNC_PATH}",
                         {"body": body,
                          "signature": crypto.sign(body, priv_pem)},
                         headers=DST)

        st, r = deactivate(ext_iss_did, "签发机构业务终止", ext_issuer_priv)
        check("登记签发者停用通告 -> 201", st == 201)
        st, r = verify({"presentation": mc, "challenge": "chal-m"},
                       headers=DST)
        check("签发者停用通告命中（组合项序先查签发者）",
              st == 200 and r == {
                  "valid": False,
                  "reason": "外部签发DID已停用：签发机构业务终止"})
        st, r = verify({"presentation": mcb, "challenge": "chal-m",
                        "source_tenant_id": "src"}, headers=DST)
        check("签发者通告先于持有者通告",
              r.get("reason") == "外部签发DID已停用：签发机构业务终止")

        # 仅他租户有通告不影响：在 src 租户为 ext_iss_did 登记通告
        st, r = deactivate(ext_iss_did, "他租户通告", ext_issuer_priv)
        check("他租户再登记 -> 按既有协议处理（非 201 即已有记录）",
              st in (200, 201, 409))

        # 持有者停用：另取一套未停用的签发者
        iss2_priv = crypto.generate_private_key_pem()
        iss2_pub = crypto.public_key_pem_from_private(iss2_priv)
        clean_iss = "did:web:clean-issuer"
        st, _ = _http("POST", f"{base}/v1/trust/anchors", {
            "did": clean_iss, "public_key": iss2_pub, "key_version": 1,
        }, headers=DST)
        assert st == 201
        combo_h = {
            "presentation_id": "mvp_" + "e" * 32,
            "items": [{
                "credential_id": "vc_ext_3", "issuer_did": clean_iss,
                "issuer_key_version": 1, "disclose": [], "claims": {},
                "proof": ""}],
            "challenge": "chal-h", "expires_at": "2099-01-01T00:00:00Z",
            "holder_did": ext_hold_did, "holder_key_version": 1,
            "holder_proof": "",
        }
        sign_all_items(combo_h, {clean_iss: iss2_priv})
        sign_holder(combo_h, "src", ext_holder_priv)
        st, r = verify({"presentation": combo_h, "challenge": "chal-h",
                        "source_tenant_id": "src"}, headers=DST)
        check("持有者通告登记前绑定组合成功", r == {"valid": True})
        st, r = deactivate(ext_hold_did, "持有者证件失效", ext_holder_priv)
        check("登记持有者停用通告 -> 201", st == 201)
        st, r = verify({"presentation": combo_h, "challenge": "chal-h",
                        "source_tenant_id": "src"}, headers=DST)
        check("持有者停用通告命中",
              st == 200 and r == {
                  "valid": False,
                  "reason": "外部持有者DID已停用：持有者证件失效"})

        # ---------- 批量：单凭证与组合混用、等长同序、不短路 ----------
        single = {
            "presentation_id": "vp_" + "a" * 32,
            "credential_id": "vc_single_1",
            "issuer_did": clean_iss, "issuer_key_version": 1,
            "disclose": ["/k"], "claims": {"k": "v"},
            "challenge": "chal-s", "expires_at": "2099-01-01T00:00:00Z",
        }
        single["proof"] = crypto.sign(
            {k: v for k, v in single.items()}, iss2_priv)
        fresh_combo = make_combo(bound=True, challenge="chal-f")
        # make_combo 的签发者 ext_iss_did 已停用，故批量中该项应失败；
        # 另以 clean_iss 构造一个有效组合
        clean_combo = copy.deepcopy(combo_h)
        clean_combo["challenge"] = "chal-cc"
        sign_all_items(clean_combo, {clean_iss: iss2_priv})
        sign_holder(clean_combo, "src", ext_holder_priv)
        # holder 已停用 -> 该组合应失败于持有者通告
        st, rr = _http("POST", f"{base}{BATCH_PATH}", {
            "presentations": [
                {"presentation": single, "challenge": "chal-s"},
                {"presentation": fresh_combo, "challenge": "chal-f",
                 "source_tenant_id": "src"},
                {"presentation": clean_combo, "challenge": "chal-cc",
                 "source_tenant_id": "src"},
                {"presentation": unbound, "challenge": "wrong"},
                "not-an-object",
            ],
        }, headers=DST)
        check("批量 200 且 results 等长同序",
              st == 200 and isinstance(rr.get("results"), list)
              and len(rr["results"]) == 5 and set(rr) == {"results"})
        if st == 200 and len(rr.get("results", [])) == 5:
            results = rr["results"]
            check("批[0] 单凭证成功", results[0] == {"valid": True})
            check("批[1] 组合签发者停用（不短路）",
                  results[1] == {
                      "valid": False,
                      "reason": "外部签发DID已停用：签发机构业务终止"})
            check("批[2] 组合持有者停用（签发者先通过）",
                  results[2] == {
                      "valid": False,
                      "reason": "外部持有者DID已停用：持有者证件失效"})
            check("批[3] 组合挑战不匹配",
                  results[3] == {"valid": False,
                                 "reason": "挑战不匹配"})
            check("批[4] 非对象项原因非空",
                  results[4].get("valid") is False
                  and bool(results[4].get("reason")))

        # 外层错误保留原协议
        for label, payload in [
            ("空对象", {}),
            ("presentations 空数组", {"presentations": []}),
            ("presentations 超 100",
             {"presentations": [1] * 101}),
            ("presentations 非数组", {"presentations": {}}),
            ("多余外层字段", {"presentations": [], "x": 1}),
        ]:
            st, rr = _http("POST", f"{base}{BATCH_PATH}", payload,
                           headers=DST)
            check(f"批量外层 {label} -> results 空 + reason",
                  st == 200 and rr.get("results") == []
                  and isinstance(rr.get("reason"), str)
                  and bool(rr["reason"])
                  and set(rr) == {"results", "reason"})

        # ---------- 其他入口不接受组合（既有行为保留） ----------
        st, rr = _http("POST", f"{base}{CONSUME_PATH}", {
            "presentation": unbound, "challenge": unbound["challenge"],
        }, headers=DST)
        check("consume 不接受组合形态（单凭证结构校验失败）",
              st == 200 and rr.get("valid") is False
              and bool(rr.get("reason")))

        # ---------- 租户隔离与 default ----------
        st, rr = verify(
            {"presentation": unbound, "challenge": unbound["challenge"]},
            headers={"X-Tenant-ID": "other-tenant"})
        check("无锚点租户验真 -> 锚点不可用",
              st == 200 and rr.get("valid") is False
              and rr.get("reason") == "锚点不可用")

        # 验真不写审计：验真前后 src/dst 审计事件数不变
        def audit_count(tenant_header):
            st, rr = _http("GET", f"{base}/v1/audit?limit=500",
                           headers=tenant_header)
            return len(rr.get("events", [])) if st == 200 else -1

        before_dst = audit_count(DST)
        verify({"presentation": unbound, "challenge": "wrong-c"},
               headers=DST)
        verify({"presentation": unbound,
                "challenge": unbound["challenge"]}, headers=DST)
        after_dst = audit_count(DST)
        check("验真（成功与失败）均不写审计", before_dst == after_dst)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    print(f"\n{'=' * 40}\n{len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
