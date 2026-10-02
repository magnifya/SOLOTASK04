#!/usr/bin/env python3
"""跨系统多凭证组合展示验真端到端测试。

覆盖 POST /v1/trust/presentations/verify 与其 verify-batch 入口对
POST /v1/presentations/multi 返回对象的直接验真：验证租户仅登记信任
锚点，无需登记来源 DID/凭证/展示。

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


_DELETE = object()


def main():
    port = 8963
    store_path = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store_path)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    path = "/v1/trust/presentations/verify"
    bpath = "/v1/trust/presentations/verify-batch"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def verify(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{path}", payload,
                     headers=headers, raw=raw)

    def expect_false(name, reason, payload, headers=None):
        st, r = verify(payload, headers)
        check(
            name,
            st == 200
            and r == {"valid": False, "reason": reason},
        )

    try:
        assert wait_up(port), "服务启动超时"
        SRC = {"X-Tenant-ID": "multi-src"}
        VER = {"X-Tenant-ID": "multi-ver"}
        VER2 = {"X-Tenant-ID": "multi-ver2"}
        VER3 = {"X-Tenant-ID": "multi-ver3"}
        NOANCHOR = {"X-Tenant-ID": "multi-noanchor"}

        # 来源租户：两个签发者 + 同一持有者
        _, issuer1 = _http("POST", f"{base}/v1/dids",
                           {"method": "example", "public_key": "i1-key"},
                           headers=SRC)
        _, issuer2 = _http("POST", f"{base}/v1/dids",
                           {"method": "example", "public_key": "i2-key"},
                           headers=SRC)
        _, holder = _http("POST", f"{base}/v1/dids",
                          {"method": "example", "public_key": "h-key"},
                          headers=SRC)
        d1, d2, dh = issuer1["did"], issuer2["did"], holder["did"]
        _, vc1 = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": d1, "subject_did": dh,
            "claims": {"name": "alice", "age": 30,
                       "addr": {"city": "X", "zip": "1"},
                       "tags": ["a", None, "b"]},
        }, headers=SRC)
        _, vc2 = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": d2, "subject_did": dh,
            "claims": {"level": 5, "tags": ["x", "y"]},
        }, headers=SRC)
        id1, id2 = vc1["credential_id"], vc2["credential_id"]

        # 验证租户只登记信任锚点（DID 文档公钥 PEM），不登记任何
        # DID/凭证/展示。
        for did in (d1, d2, dh):
            _, doc = _http("GET", f"{base}/v1/dids/{did}", headers=SRC)
            st, _ = _http("POST", f"{base}/v1/trust/anchors", {
                "did": did, "public_key": doc["public_key"],
                "key_version": 1,
            }, headers=VER)
            check(f"验证租户登记锚点 {did[-6:]}", st == 201)
            _http("POST", f"{base}/v1/trust/anchors", {
                "did": did, "public_key": doc["public_key"],
                "key_version": 1,
            }, headers=VER2)
            _http("POST", f"{base}/v1/trust/anchors", {
                "did": did, "public_key": doc["public_key"],
                "key_version": 1, "uses": ["vc"],
            }, headers=VER3)

        # ---------- 未绑定组合：零披露/嵌套/数组空位投影 ----------
        st, mvp = _http("POST", f"{base}/v1/presentations/multi", {
            "items": [
                {"credential_id": id1,
                 "disclose": ["/name", "/addr/city", "/tags"]},
                {"credential_id": id2, "disclose": []},
            ],
            "challenge": "chal-multi",
        }, headers=SRC)
        check("组合创建 201", st == 201)
        check("零披露 claims 为空对象",
              mvp["items"][1]["claims"] == {})
        check("嵌套与数组空位投影",
              mvp["items"][0]["claims"] == {
                  "name": "alice",
                  "addr": {"city": "X"},
                  "tags": ["a", None, "b"],
              })
        check("组合公开键集合",
              set(mvp) == {"presentation_id", "items", "challenge",
                           "expires_at"})
        check("项公开键集合",
              all(set(item) == {
                  "credential_id", "issuer_did", "issuer_key_version",
                  "disclose", "claims", "proof"} for item in mvp["items"]))

        st, r = verify({"presentation": mvp, "challenge": "chal-multi"},
                       headers=VER)
        check("未绑定组合验真成功且响应恰为 valid:true",
              st == 200 and r == {"valid": True})
        st, r = verify({"presentation": mvp, "challenge": "chal-multi"},
                       headers=VER)
        check("有效期内可重复验真", r == {"valid": True})

        # 显式空租户头 400（在验签前判定）
        st, _ = verify({"presentation": mvp, "challenge": "chal-multi"},
                       headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", st == 400)

        # ---------- 请求结构 ----------
        st, r = verify(None, headers=VER)
        check("空请求体沿用请求类原因",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("请求"))
        st, r = verify(raw=b"not-json", headers=VER)
        check("非法 JSON 走解析错误协议",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("请求"))
        st, r = verify(["x"], headers=VER)
        check("JSON 数组沿用请求类原因",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("请求"))
        expect_false("缺 challenge -> 请求非法", "请求非法",
                     {"presentation": mvp}, VER)
        expect_false("多余字段 -> 请求非法", "请求非法",
                     {"presentation": mvp, "challenge": "chal-multi",
                      "extra": 1}, VER)
        expect_false("challenge 非字符串 -> 请求非法", "请求非法",
                     {"presentation": mvp, "challenge": 1}, VER)
        st, r = verify({"presentation": [], "challenge": "c"},
                       headers=VER)
        check("presentation 非对象沿用请求类原因",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("请求"))
        expect_false("未绑定组合携带 source_tenant_id -> 请求非法",
                     "请求非法",
                     {"presentation": mvp, "challenge": "chal-multi",
                      "source_tenant_id": "multi-src"}, VER)
        expect_false("source_tenant_id 空串 -> 请求非法", "请求非法",
                     {"presentation": mvp, "challenge": "chal-multi",
                      "source_tenant_id": ""}, VER)

        # ---------- 组合结构 ----------
        def mvp_with(**changes):
            obj = copy.deepcopy(mvp)
            for key, value in changes.items():
                if value is _DELETE:
                    obj.pop(key, None)
                else:
                    obj[key] = value
            return obj

        for field in ("presentation_id", "challenge", "expires_at"):
            expect_false(f"组合缺字段 {field} -> 组合展示非法",
                         "组合展示非法",
                         {"presentation": mvp_with(**{field: _DELETE}),
                          "challenge": "chal-multi"}, VER)
        # 删除 items 后不再是组合对象（组合识别仅对含 items 的对象生效），
        # 由单凭证规则给出非空失败原因。
        st, r = verify(
            {"presentation": mvp_with(items=_DELETE),
             "challenge": "chal-multi"}, headers=VER)
        check("组合缺 items 给出非空失败原因",
              st == 200 and r.get("valid") is False
              and bool(r.get("reason")))
        expect_false("组合含多余字段 -> 组合展示非法", "组合展示非法",
                     {"presentation": mvp_with(unexpected=1),
                      "challenge": "chal-multi"}, VER)
        bad = mvp_with(items=[])
        expect_false("items 为空 -> 组合展示非法", "组合展示非法",
                     {"presentation": bad, "challenge": "chal-multi"}, VER)
        bad = mvp_with(items=[mvp["items"][0]] * 101)
        expect_false("items 超过 100 -> 组合展示非法", "组合展示非法",
                     {"presentation": bad, "challenge": "chal-multi"}, VER)
        dup = mvp_with(items=mvp["items"] + [mvp["items"][0]])
        expect_false("credential_id 重复 -> 组合展示非法", "组合展示非法",
                     {"presentation": dup, "challenge": "chal-multi"}, VER)
        # 项缺漏/额外字段
        item_bad = copy.deepcopy(mvp)
        del item_bad["items"][0]["claims"]
        expect_false("项缺 claims -> 组合展示非法", "组合展示非法",
                     {"presentation": item_bad, "challenge": "chal-multi"},
                     VER)
        item_bad = copy.deepcopy(mvp)
        item_bad["items"][0]["nope"] = 1
        expect_false("项含额外字段 -> 组合展示非法", "组合展示非法",
                     {"presentation": item_bad, "challenge": "chal-multi"},
                     VER)
        for bad_version, label in [
            (True, "布尔"), (0, "零"), (-2, "负数"), (1.5, "小数"),
        ]:
            item_bad = copy.deepcopy(mvp)
            item_bad["items"][0]["issuer_key_version"] = bad_version
            expect_false(f"版本非法（{label}）-> 组合展示非法",
                         "组合展示非法",
                         {"presentation": item_bad,
                          "challenge": "chal-multi"}, VER)
        item_bad = copy.deepcopy(mvp)
        item_bad["items"][0]["disclose"] = "/name"
        expect_false("disclose 非数组 -> 组合展示非法", "组合展示非法",
                     {"presentation": item_bad, "challenge": "chal-multi"},
                     VER)
        item_bad = copy.deepcopy(mvp)
        item_bad["items"][0]["disclose"] = ["/name", 1]
        expect_false("disclose 含非字符串 -> 组合展示非法",
                     "组合展示非法",
                     {"presentation": item_bad, "challenge": "chal-multi"},
                     VER)
        item_bad = copy.deepcopy(mvp)
        item_bad["items"][0]["claims"] = []
        expect_false("claims 非对象 -> 组合展示非法", "组合展示非法",
                     {"presentation": item_bad, "challenge": "chal-multi"},
                     VER)
        item_bad = copy.deepcopy(mvp)
        item_bad["items"][0]["proof"] = ""
        expect_false("proof 空串 -> 组合展示非法", "组合展示非法",
                     {"presentation": item_bad, "challenge": "chal-multi"},
                     VER)
        # 持有者字段须整体出现或省略
        half = mvp_with(holder_did=dh)
        expect_false("仅出现 holder_did -> 组合展示非法",
                     "组合展示非法",
                     {"presentation": half, "challenge": "chal-multi"}, VER)
        # 持有者三字段出现但请求缺 source_tenant_id -> 请求非法（形态
        # 一致性先于组合结构校验）。
        half_req_pres = mvp_with(holder_did=dh, holder_key_version=1,
                                 holder_proof="x")
        expect_false("绑定组合缺 source -> 请求非法",
                     "请求非法",
                     {"presentation": half_req_pres,
                      "challenge": "chal-multi"}, VER)
        # 请求形态一致但组合多出未知持有者键 -> 组合展示非法。
        half = mvp_with(holder_did=dh, holder_key_version=1,
                        holder_proof="x", holder_extra=1)
        expect_false("持有者字段外加多余键 -> 组合展示非法",
                     "组合展示非法",
                     {"presentation": half, "challenge": "chal-multi",
                      "source_tenant_id": "multi-src"}, VER)
        # ---------- 挑战 ----------
        expect_false("请求挑战与组合挑战不一致 -> 挑战不匹配",
                     "挑战不匹配",
                     {"presentation": mvp, "challenge": "other"}, VER)
        bad = mvp_with(challenge="inside-changed")
        expect_false("请求挑战跟改组合内 challenge -> 签名校验失败",
                     "签名校验失败",
                     {"presentation": bad, "challenge": "inside-changed"},
                     VER2)
        expect_false("请求挑战未跟改 -> 挑战不匹配",
                     "挑战不匹配",
                     {"presentation": bad, "challenge": "chal-multi"},
                     VER2)

        # ---------- 锚点 ----------
        st, r = verify({"presentation": mvp, "challenge": "chal-multi"},
                       headers=NOANCHOR)
        check("无锚点租户 -> 锚点不可用",
              r == {"valid": False, "reason": "锚点不可用"})
        # 无 vp 用途的锚点不可用（VER3 的锚点仅注册 vc 用途）
        st, r = verify({"presentation": mvp, "challenge": "chal-multi"},
                       headers=VER3)
        check("锚点缺 vp 用途 -> 锚点不可用",
              r == {"valid": False, "reason": "锚点不可用"})
        # 在 VER 吊销 d2（组合第二项签发者），VER2 保持活跃用于后续
        # 全部密码学与期限测试。
        st, _ = _http(
            "PUT",
            f"{base}/v1/trust/anchors/{d2}/1/status",
            {"status": "revoked"}, headers=VER)
        check("吊销签发锚点 200", st == 200)
        st, r = verify({"presentation": mvp, "challenge": "chal-multi"},
                       headers=VER)
        check("锚点吊销 -> 锚点不可用（按项序第二个签发者）",
              r == {"valid": False, "reason": "锚点不可用"})

        # ---------- 签名格式与验签（逐项签发证明） ----------
        # 格式错误优先于验签失败
        bad = copy.deepcopy(mvp)
        bad["items"][0]["proof"] = "@@@not-b64url@@@"
        st, r = verify({"presentation": bad, "challenge": "chal-multi"},
                       headers=VER2)
        check("proof 编码非法 -> 签名格式错误",
              r == {"valid": False, "reason": "签名格式错误"})
        # 合法编码、错误签名 -> 签名校验失败
        bad = copy.deepcopy(mvp)
        bad["items"][0]["proof"] = "A" * 86
        st, r = verify({"presentation": bad, "challenge": "chal-multi"},
                       headers=VER2)
        check("proof 内容被改 -> 签名校验失败",
              r == {"valid": False, "reason": "签名校验失败"})
        # 组合标识被改动 -> 验签失败
        bad = mvp_with(presentation_id="mvp_" + "f" * 32)
        st, r = verify({"presentation": bad, "challenge": "chal-multi"},
                       headers=VER2)
        check("改组合标识 -> 签名校验失败",
              r == {"valid": False, "reason": "签名校验失败"})
        # 期限被改动 -> 验签失败（先于期限判定）
        bad = mvp_with(expires_at="2099-01-01T00:00:00Z")
        st, r = verify({"presentation": bad, "challenge": "chal-multi"},
                       headers=VER2)
        check("改期限 -> 签名校验失败",
              r == {"valid": False, "reason": "签名校验失败"})
        # 披露内容被改动（disclose / claims）-> 验签失败
        bad = copy.deepcopy(mvp)
        bad["items"][0]["disclose"] = ["/name"]
        st, r = verify({"presentation": bad, "challenge": "chal-multi"},
                       headers=VER2)
        check("改 disclose -> 签名校验失败",
              r["reason"] == "签名校验失败")
        bad = copy.deepcopy(mvp)
        bad["items"][0]["claims"]["name"] = "mallory"
        st, r = verify({"presentation": bad, "challenge": "chal-multi"},
                       headers=VER2)
        check("改 claims -> 签名校验失败",
              r["reason"] == "签名校验失败")
        bad = copy.deepcopy(mvp)
        bad["items"][0]["credential_id"] = "vc_other"
        st, r = verify({"presentation": bad, "challenge": "chal-multi"},
                       headers=VER2)
        check("改 credential_id -> 签名校验失败",
              r["reason"] == "签名校验失败")

        # ---------- 期限 ----------
        st, expired = _http("POST", f"{base}/v1/presentations/multi", {
            "items": [{"credential_id": id1, "disclose": ["/name"]}],
            "challenge": "exp", "expires_in": 1,
        }, headers=SRC)
        check("一秒期组合创建", st == 201)
        time.sleep(1.1)
        st, r = verify({"presentation": expired, "challenge": "exp"},
                       headers=VER2)
        check("当前时间达到期限 -> 演示已过期",
              r == {"valid": False, "reason": "演示已过期"})
        # ---------- 持有者绑定组合 ----------
        st, bound = _http("POST", f"{base}/v1/presentations/multi", {
            "items": [
                {"credential_id": id1, "disclose": ["/name", "/age"]},
                {"credential_id": id2, "disclose": ["/level"]}],
            "challenge": "chal-bound", "holder_binding": True,
        }, headers=SRC)
        check("绑定组合创建 201", st == 201)
        check("绑定组合公开键集合",
              set(bound) == {"presentation_id", "items", "challenge",
                             "expires_at", "holder_did",
                             "holder_key_version", "holder_proof"}
              and bound["holder_did"] == dh)
        st, r = verify({"presentation": bound, "challenge": "chal-bound",
                        "source_tenant_id": "multi-src"}, headers=VER2)
        check("绑定组合验真成功", r == {"valid": True})
        # 缺 source_tenant_id -> 请求非法
        expect_false("绑定组合缺 source_tenant_id -> 请求非法",
                     "请求非法",
                     {"presentation": bound, "challenge": "chal-bound"},
                     VER2)
        # 更换 source_tenant_id -> holder 验签失败
        st, r = verify({"presentation": bound, "challenge": "chal-bound",
                        "source_tenant_id": "other-source"}, headers=VER2)
        check("更换 source_tenant_id -> 签名校验失败",
              r == {"valid": False, "reason": "签名校验失败"})
        # 调整项序 -> holder 验签失败（逐项签发证明仍各自有效）
        reordered = copy.deepcopy(bound)
        reordered["items"] = list(reversed(reordered["items"]))
        st, r = verify({"presentation": reordered,
                        "challenge": "chal-bound",
                        "source_tenant_id": "multi-src"}, headers=VER2)
        check("调整项序 -> 签名校验失败",
              r == {"valid": False, "reason": "签名校验失败"})
        # holder_proof 编码非法 -> 签名格式错误
        bad = copy.deepcopy(bound)
        bad["holder_proof"] = "@@bad@@"
        st, r = verify({"presentation": bad, "challenge": "chal-bound",
                        "source_tenant_id": "multi-src"}, headers=VER2)
        check("holder_proof 编码非法 -> 签名格式错误",
              r == {"valid": False, "reason": "签名格式错误"})
        # holder_proof 被改 -> 签名校验失败
        bad = copy.deepcopy(bound)
        bad["holder_proof"] = "B" * 86
        st, r = verify({"presentation": bad, "challenge": "chal-bound",
                        "source_tenant_id": "multi-src"}, headers=VER2)
        check("holder_proof 被改 -> 签名校验失败",
              r == {"valid": False, "reason": "签名校验失败"})
        # 持有者锚点缺失
        st, r = verify({"presentation": bound, "challenge": "chal-bound",
                        "source_tenant_id": "multi-src"}, headers=NOANCHOR)
        check("持有者锚点缺失 -> 锚点不可用",
              r == {"valid": False, "reason": "锚点不可用"})
        # 持有者版本非法 -> 组合展示非法
        bad = copy.deepcopy(bound)
        bad["holder_key_version"] = True
        st, r = verify({"presentation": bad, "challenge": "chal-bound",
                        "source_tenant_id": "multi-src"}, headers=VER2)
        check("holder_key_version 布尔 -> 组合展示非法",
              r.get("reason") == "组合展示非法")

        # ---------- 外部 DID 停用通告：先签发者（按项序）再持有者 ----------
        from cryptography.hazmat.primitives import serialization  # noqa: E402
        from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
        stop_priv = ec.generate_private_key(ec.SECP256R1())
        stop_priv_pem = stop_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        stop_pub_pem = stop_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        stop_did = "did:web:stop-multi.example"
        st, _ = _http("POST", f"{base}/v1/trust/anchors", {
            "did": stop_did, "public_key": stop_pub_pem,
            "key_version": 1,
        }, headers=VER2)
        check("停用通告 DID 锚点注册", st == 201)
        notice_body = {
            "did": stop_did, "key_version": 1,
            "reason": "来源系统通告停用",
            "deactivated_at": "2026-01-02T03:04:05Z",
        }
        st, nr = _http("POST",
                       f"{base}/v1/trust/dids/deactivate-sync", {
                           "body": notice_body,
                           "signature": crypto.sign(
                               notice_body, stop_priv_pem),
                       }, headers=VER2)
        check("停用通告登记", st in (200, 201) and nr.get("valid") is True)
        # 构造一个由 stop_did 签发、可通过全部密码学校验的未绑定组合
        unsigned = {
            "presentation_id": "mvp_" + "9" * 32,
            "credential_id": "vc_external_stop",
            "issuer_did": stop_did,
            "issuer_key_version": 1,
            "disclose": ["/role"],
            "claims": {"role": "viewer"},
            "challenge": "chal-stop",
            "expires_at": "2099-01-01T00:00:00Z",
        }
        stop_item = {
            "credential_id": unsigned["credential_id"],
            "issuer_did": stop_did,
            "issuer_key_version": 1,
            "disclose": ["/role"],
            "claims": {"role": "viewer"},
            "proof": crypto.sign(unsigned, stop_priv_pem),
        }
        stop_mvp = {
            "presentation_id": unsigned["presentation_id"],
            "items": [stop_item],
            "challenge": "chal-stop",
            "expires_at": "2099-01-01T00:00:00Z",
        }
        st, r = verify({"presentation": stop_mvp,
                        "challenge": "chal-stop"}, headers=VER2)
        check("签发者停用通告原因",
              st == 200 and r == {
                  "valid": False,
                  "reason": "外部签发DID已停用：来源系统通告停用"})
        # 他租户通告不影响
        st, r = verify({"presentation": stop_mvp,
                        "challenge": "chal-stop"}, headers=NOANCHOR)
        check("无锚点时先于通告判锚点不可用",
              r == {"valid": False, "reason": "锚点不可用"})
        # 非法期限字符串在结构/期限阶段先于停用通告被拒：构造密码学上
        # 可通过签名（签名不覆盖 expires_at 的格式合法性之外的结构外，
        # 这里直接用 stop 锚点的独立未绑定组合，其 expires_at 非法但
        # 证明对该串签名，验签通过后进入期限判定）。
        bad_exp_unsigned = dict(unsigned)
        bad_exp_unsigned["expires_at"] = "not-a-time"
        bad_exp_item = dict(stop_item)
        bad_exp_item["proof"] = crypto.sign(bad_exp_unsigned, stop_priv_pem)
        bad_exp_mvp = {
            "presentation_id": unsigned["presentation_id"],
            "items": [bad_exp_item],
            "challenge": "chal-stop",
            "expires_at": "not-a-time",
        }
        st, r = verify({"presentation": bad_exp_mvp,
                        "challenge": "chal-stop"}, headers=VER2)
        check("非法 expires_at 格式 -> 组合展示非法",
              r.get("valid") is False
              and r.get("reason") == "组合展示非法")


        # 持有者停用通告：绑定组合先按项序过签发者，再命中持有者
        hstop_priv = ec.generate_private_key(ec.SECP256R1())
        hstop_priv_pem = hstop_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        hstop_pub_pem = hstop_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        hstop_did = "did:web:holder-stop.example"
        _http("POST", f"{base}/v1/trust/anchors", {
            "did": hstop_did, "public_key": hstop_pub_pem,
            "key_version": 1,
        }, headers=VER2)
        # 手工构造持有者绑定组合：签发者沿用 d1/d2 锚点公钥（取自来源
        # 系统真实组合项），持有者换成 hstop_did 并重签 holder_proof。
        hbound = copy.deepcopy(bound)
        holder_unsigned_items = [
            {
                "presentation_id": hbound["presentation_id"],
                "credential_id": item["credential_id"],
                "issuer_did": item["issuer_did"],
                "issuer_key_version": item["issuer_key_version"],
                "disclose": item["disclose"],
                "claims": item["claims"],
                "challenge": hbound["challenge"],
                "expires_at": hbound["expires_at"],
            }
            for item in hbound["items"]
        ]
        holder_payload = {
            "presentation_id": hbound["presentation_id"],
            "items": holder_unsigned_items,
            "challenge": hbound["challenge"],
            "expires_at": hbound["expires_at"],
            "holder_did": hstop_did,
            "holder_key_version": 1,
            "tenant_id": "multi-src",
        }
        hbound["holder_did"] = hstop_did
        hbound["holder_key_version"] = 1
        hbound["holder_proof"] = crypto.sign(holder_payload, hstop_priv_pem)
        st, r = verify({"presentation": hbound,
                        "challenge": "chal-bound",
                        "source_tenant_id": "multi-src"}, headers=VER2)
        check("持有者停用通告前可验真", r == {"valid": True})
        hnotice = {
            "did": hstop_did, "key_version": 1,
            "reason": "持有者停用",
            "deactivated_at": "2026-01-03T03:04:05Z",
        }
        _http("POST", f"{base}/v1/trust/dids/deactivate-sync", {
            "body": hnotice,
            "signature": crypto.sign(hnotice, hstop_priv_pem),
        }, headers=VER2)
        st, r = verify({"presentation": hbound,
                        "challenge": "chal-bound",
                        "source_tenant_id": "multi-src"}, headers=VER2)
        check("持有者停用通告原因",
              st == 200 and r == {
                  "valid": False,
                  "reason": "外部持有者DID已停用：持有者停用"})

        # ---------- 批量：单凭证与组合混用，不短路，等长同序 ----------
        st, single = _http(
            "POST", f"{base}/v1/credentials/{id1}/present",
            {"disclose": ["/name"], "challenge": "chal-single"},
            headers=SRC)
        check("单凭证演示创建", st == 201)
        batch_payload = {"presentations": [
            {"presentation": single, "challenge": "chal-single"},
            {"presentation": mvp, "challenge": "chal-multi"},
            {"presentation": bound, "challenge": "chal-bound",
             "source_tenant_id": "multi-src"},
            {"presentation": mvp, "challenge": "wrong"},
            {"presentation": mvp_with(items=[]),
             "challenge": "chal-multi"},
            "not-an-object",
        ]}
        st, rb = _http("POST", f"{base}{bpath}", batch_payload,
                       headers=VER2)
        check("批量 200 且等长同序", st == 200 and len(rb["results"]) == 6)
        check("批量[0] 单凭证成功",
              rb["results"][0] == {"valid": True})
        check("批量[1] 组合成功",
              rb["results"][1] == {"valid": True})
        check("批量[2] 绑定组合成功",
              rb["results"][2] == {"valid": True})
        check("批量[3] 挑战不匹配",
              rb["results"][3] == {"valid": False,
                                   "reason": "挑战不匹配"})
        check("批量[4] 组合展示非法",
              rb["results"][4] == {"valid": False,
                                   "reason": "组合展示非法"})
        check("批量[5] 非对象项请求非法",
              isinstance(rb["results"][5].get("reason"), str)
              and rb["results"][5]["reason"])
        # 外层错误保留原协议
        st, rb = _http("POST", f"{base}{bpath}",
                       {"presentations": []}, headers=VER2)
        check("批量空数组外层原因",
              st == 200 and rb.get("results") == [] and rb.get("reason"))
        st, rb = _http("POST", f"{base}{bpath}", {"items": []},
                       headers=VER2)
        check("批量错误字段外层原因",
              st == 200 and rb.get("results") == [] and rb.get("reason"))

        # ---------- 只读：跨系统验真不消费来源租户本地组合 ----------
        st, fresh = _http("POST", f"{base}/v1/presentations/multi", {
            "items": [{"credential_id": id1, "disclose": ["/name"]}],
            "challenge": "chal-readonly",
        }, headers=SRC)
        fpid = fresh["presentation_id"]
        for _ in range(2):
            verify({"presentation": fresh,
                    "challenge": "chal-readonly"}, headers=VER2)
        st, r = _http(
            "POST", f"{base}/v1/presentations/{fpid}/verify",
            {"presentation": fresh, "challenge": "chal-readonly"},
            headers=SRC)
        check("来源租户首次本地验真仍成功（跨系统验真不消费）",
              r == {"valid": True})

        # 验证租户审计中不出现 presentation 相关动作
        st, audit = _http("GET", f"{base}/v1/audit?limit=200", headers=VER2)
        actions = [e.get("action", "") for e in audit.get("events", [])]
        check("验证租户无 presentation 审计",
              all("presentation" not in a for a in actions))

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    print(f"\n{'=' * 40}\n{len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
