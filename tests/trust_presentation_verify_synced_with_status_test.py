#!/usr/bin/env python3
"""POST /v1/trust/presentations/verify-synced-with-status
同一同步快照验真持有者绑定演示并合并状态测试。

直接运行：python3 tests/trust_presentation_verify_synced_with_status_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

本端点扩展为同时接受未绑定与持有者绑定两种请求：
- 未绑定请求恰含 signer_did/at/presentation/challenge 四键，演示恰为
  九字段、出现 holder_* 即非法，协议与 verify-synced 完全一致；
- 绑定请求在原四键外恰加非空字符串 source_tenant_id，演示恰为绑定
  十二字段；字段类型、挑战、期限及请求级 400/404/409 沿用契约；
  两类锚点均取该来源 cursor<=at 的各 DID/版本末事件，须 active 且
  uses 含 vp；不可用原因依次恰为“同步锚点不可用”
  “同步持有者锚点不可用”；issuer proof 覆盖去掉 proof 及 holder_*
  的八字段；holder_proof 覆盖去掉 proof、holder_proof 的对象并加入
  tenant_id=source_tenant_id；均为 ES256 的 64 字节裸 R||S 无填充
  base64url；顺序为演示、挑战、签发锚点/格式/验签、持有者锚点/格式/
  验签、期限，持有者格式/验签失败原因恰为“持有者签名格式错误”
  “持有者签名校验失败”；验真通过后按原子读取的本租户状态查
  (issuer_did, credential_id)，四种状态结论沿用 with-status 协议。
覆盖请求级 400/404/409、逐项 200 原因、成功仅 {"valid":true}、
失败键序 valid、reason、状态合并、纯只读、重启一致与租户隔离。
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
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vcbackend import crypto  # noqa: E402

VERIFY_PATH = "/v1/trust/presentations/verify-synced-with-status"
SYNC_PATH = "/v1/trust/anchor-changes/sync"
STATUS_SYNC_PATH = "/v1/trust/credential-status/sync"
ALL_USES = ["generic", "vc", "vp", "proof", "did", "status", "deactivation"]
CHALLENGE = "chal-bound-synced-status"
SOURCE_TENANT = "source-tenant-1"

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


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
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


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
    priv = crypto.generate_private_key_pem()
    return priv, crypto.public_key_pem_from_private(priv)


def utc_z(delta):
    return (datetime.now(timezone.utc) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_event(cursor, did, key_version=1, action="registered",
               status="active", uses=None, pub="pem"):
    return {
        "cursor": cursor,
        "action": action,
        "did": did,
        "key_version": key_version,
        "public_key": pub,
        "status": status,
        "uses": list(uses if uses is not None else ALL_USES),
    }


def build_changes(events, after, did, signer_priv):
    signed = {
        "events": events,
        "next_after": events[-1]["cursor"] if events else after,
        "signer_did": did,
        "signer_key_version": 1,
    }
    signed["signature"] = crypto.sign(signed, signer_priv)
    return {"changes": signed, "after": after}


def make_presentation(cred_id, issuer_did, bound=False, holder_did=None,
                      holder_key_version=1, **overrides):
    pres = {
        "presentation_id": "vp-ext-bound-1",
        "credential_id": cred_id,
        "issuer_did": issuer_did,
        "issuer_key_version": 1,
        "disclose": ["/role"],
        "claims": {"role": "admin"},
        "challenge": CHALLENGE,
        "expires_at": "2999-01-01T00:00:00Z",
    }
    if bound:
        pres["holder_did"] = holder_did
        pres["holder_key_version"] = holder_key_version
    pres.update(overrides)
    return pres


def sign_presentation(pres, issuer_priv, holder_priv=None,
                      tenant_id=SOURCE_TENANT):
    """issuer proof 覆盖去掉 proof 及 holder_* 的八字段；绑定形态另以
    holder_priv 对去掉 proof/holder_proof 的对象加 tenant_id 签
    holder_proof。"""
    pres = dict(pres)
    message = {
        k: v
        for k, v in pres.items()
        if k != "proof" and not k.startswith("holder_")
    }
    pres["proof"] = crypto.sign(message, issuer_priv)
    if holder_priv is not None:
        holder_message = dict(message)
        holder_message["holder_did"] = pres["holder_did"]
        holder_message["holder_key_version"] = pres["holder_key_version"]
        holder_message["tenant_id"] = tenant_id
        pres["holder_proof"] = crypto.sign(holder_message, holder_priv)
    return pres


def flip_signature(signature):
        raw = base64.urlsafe_b64decode(signature + "==")
        flipped = bytes([raw[0] ^ 0x01]) + raw[1:]
        return base64.urlsafe_b64encode(flipped).decode().rstrip("=")


# 密钥在进程内仅生成一次：重启后用同一公钥重放注册（同 PEM 幂等），
# 私钥也用于重放锚点变更页与凭证状态同步签名。
_SIGNER_PRIV, SIGNER_PUB = gen_keypair()
_ISSUER_PRIV, ISSUER_PUB = gen_keypair()
_HOLDER_PRIV, HOLDER_PUB = gen_keypair()
_OTHER_PRIV, OTHER_PUB = gen_keypair()


def run_case(restart, store_path, base):
    TA = {"X-Tenant-ID": "tenant-a"}
    TB = {"X-Tenant-ID": "tenant-b"}
    TC = {"X-Tenant-ID": "tenant-c"}

    signer_did = "did:web:remote-signer"
    signer_priv, signer_pub = _SIGNER_PRIV, SIGNER_PUB
    issuer_did = "did:web:issuer"
    issuer_priv, issuer_pub = _ISSUER_PRIV, ISSUER_PUB
    holder_did = "did:web:holder"
    holder_priv, holder_pub = _HOLDER_PRIV, HOLDER_PUB
    other_priv, other_pub = _OTHER_PRIV, OTHER_PUB

    def verify(payload=None, headers=None, raw=None):
        return _http("POST", base + VERIFY_PATH, payload,
                     headers=headers if headers is not None else TA, raw=raw)

    def body_of(resp):
        try:
            return json.loads(resp.decode() or "{}")
        except ValueError:
            return None

    def expect_error_only(name, st, resp, status):
        body = body_of(resp)
        check(
            name,
            st == status
            and isinstance(body, dict)
            and set(body) == {"error"}
            and isinstance(body["error"], str)
            and body["error"].strip() != "",
        )

    def expect_400(name, payload=None, headers=None, raw=None):
        st, resp = verify(payload=payload, headers=headers or TA, raw=raw)
        expect_error_only(name, st, resp, 400)

    def expect_reason(name, payload, reason, headers=None):
        st, resp = verify(payload=payload, headers=headers or TA)
        body = body_of(resp)
        check(
            name,
            st == 200
            and isinstance(body, dict)
            and list(body.keys()) == ["valid", "reason"]
            and body["valid"] is False
            and body["reason"] == reason,
        )

    def bound_request(pres, at=3, challenge=CHALLENGE,
                      source=SOURCE_TENANT, signer=signer_did):
        payload = {
            "signer_did": signer,
            "at": at,
            "presentation": pres,
            "challenge": challenge,
        }
        if source is not None:
            payload["source_tenant_id"] = source
        return payload

    def sync_status(cred_id, status, reason=None, headers=TA):
        sb = {
            "issuer_did": issuer_did,
            "credential_id": cred_id,
            "status": status,
            "updated_at": utc_z(timedelta(days=-1)),
            "issuer_key_version": 1,
        }
        if reason is not None:
            sb["reason"] = reason
        return _http(
            "POST", base + STATUS_SYNC_PATH,
            {"body": sb, "signature": crypto.sign(sb, issuer_priv)},
            headers=headers,
        )

    tag = "（重启后）" if restart else ""

    # 首启完成锚点注册、锚点变更页同步与凭证状态同步；这些写入均跨
    # 重启持久化（ECDSA 签名字节随机，无法逐字节重放同步页，故重启
    # 轮不重复写入，直接复用状态文件）。
    if not restart:
        # 签名方与签发者锚点（status sync 验签用本地锚点），两租户均
        # 登记。
        for headers in (TA, TB):
            st, raw = _http(
                "POST", f"{base}/v1/trust/anchors",
                {"did": signer_did, "public_key": signer_pub,
                 "key_version": 1},
                headers,
            )
            assert st in (200, 201), raw
            st, raw = _http(
                "POST", f"{base}/v1/trust/anchors",
                {"did": issuer_did, "public_key": issuer_pub,
                 "key_version": 1},
                headers,
            )
            assert st in (200, 201), raw

        # 同步锚点变更页：c1 issuer#1 注册（active 全用途）；c2
        # holder#1 注册（active 全用途）；c3 无 vp 锚点注册。
        # tenant-a、tenant-b 检查点均为 3。
        page = build_changes(
            [
                make_event(1, issuer_did, pub=issuer_pub),
                make_event(2, holder_did, pub=holder_pub),
                make_event(3, "did:web:novp", 1,
                           uses=["generic", "vc"], pub=other_pub),
            ],
            0, signer_did, signer_priv,
        )
        for headers in (TA, TB):
            st, _ = _http("POST", base + SYNC_PATH, page, headers=headers)
            assert st == 201

        # tenant-a 同步四种凭证状态；tenant-b 全部不同步（隔离验证）。
        assert sync_status("vc-active", "active")[0] == 201
        assert sync_status("vc-rev", "revoked",
                           reason="持证人违规")[0] == 201
        assert sync_status("vc-rev-nr", "revoked")[0] == 201
        assert sync_status("vc-unk", "unknown")[0] == 201

    good_bound = sign_presentation(
        make_presentation("vc-active", issuer_did, bound=True,
                          holder_did=holder_did),
        issuer_priv, holder_priv,
    )
    good_unbound = sign_presentation(
        make_presentation("vc-active", issuer_did), issuer_priv
    )

    # -------------------------------------------------------------- #
    # 1. 请求级 400：四键协议不变，绑定恰加非空 source_tenant_id
    # -------------------------------------------------------------- #
    expect_400("非法 JSON 400" + tag, raw=b"{not json")
    expect_400("非对象 400" + tag, raw=b"[1,2]")
    expect_400("空体 400" + tag, raw=b"")
    expect_400("缺 signer_did 400" + tag,
               payload={"at": 3, "presentation": {}, "challenge": CHALLENGE,
                        "source_tenant_id": SOURCE_TENANT})
    expect_400("缺 challenge 400" + tag,
               payload={"signer_did": signer_did, "at": 3,
                        "presentation": {}, "source_tenant_id": SOURCE_TENANT})
    expect_400("多余键 400" + tag,
               payload=dict(bound_request(good_bound), extra=1))
    expect_400("signer_did 非串 400" + tag,
               payload=bound_request(good_bound, signer=123))
    expect_400("at 负数 400" + tag,
               payload=bound_request(good_bound, at=-1))
    expect_400("at 布尔 400" + tag,
               payload=bound_request(good_bound, at=True))
    expect_400("presentation 非对象 400" + tag,
               payload={"signer_did": signer_did, "at": 3,
                        "presentation": [], "challenge": CHALLENGE,
                        "source_tenant_id": SOURCE_TENANT})
    expect_400("challenge 空串 400" + tag,
               payload=bound_request(good_bound, challenge=""))
    expect_400("source_tenant_id 空串 400" + tag,
               payload=bound_request(good_bound, source=""))
    expect_400("source_tenant_id 非字符串 400" + tag,
               payload=bound_request(good_bound, source=123))
    expect_400("显式空租户头 400" + tag,
               payload=bound_request(good_bound),
               headers={"X-Tenant-ID": ""})

    # -------------------------------------------------------------- #
    # 2. 404/409 先于演示校验
    # -------------------------------------------------------------- #
    st, resp = verify(bound_request(good_bound, signer="did:web:nope"))
    expect_error_only("未同步来源 404" + tag, st, resp, 404)
    st, resp = verify(bound_request(good_bound),
                      headers=TC)
    expect_error_only("跨租户来源 404" + tag, st, resp, 404)
    st, resp = verify(bound_request(good_bound, at=4))
    expect_error_only("at 超检查点 409" + tag, st, resp, 409)

    # -------------------------------------------------------------- #
    # 3. 成功与未绑定回归
    # -------------------------------------------------------------- #
    st, resp = verify(bound_request(good_bound))
    check("绑定成功仅 {valid:true}" + tag,
          st == 200 and body_of(resp) == {"valid": True})
    st, resp = verify(bound_request(good_unbound, source=None))
    check("未绑定成功仅 {valid:true}" + tag,
          st == 200 and body_of(resp) == {"valid": True})

    # 未绑定请求提交十二字段演示：holder_* 即非法，不因请求无
    # source_tenant_id 而容忍。
    st, resp = verify(bound_request(good_bound, source=None))
    body = body_of(resp)
    check("未绑定 holder_* 原因含持有者绑定字段" + tag,
          st == 200 and body["valid"] is False
          and "持有者绑定字段" in body["reason"])

    # -------------------------------------------------------------- #
    # 4. 绑定演示十二字段与类型
    # -------------------------------------------------------------- #
    bad = dict(good_bound)
    del bad["holder_proof"]
    st, resp = verify(bound_request(bad))
    body = body_of(resp)
    check("缺 holder_proof" + tag,
          st == 200 and list(body) == ["valid", "reason"]
          and body["valid"] is False and "holder_proof" in body["reason"])
    bad = dict(good_bound)
    bad["holder_extra"] = 1
    st, resp = verify(bound_request(bad))
    body = body_of(resp)
    check("绑定演示多余字段" + tag,
          st == 200 and body["valid"] is False and "多余" in body["reason"])
    bad = sign_presentation(
        make_presentation("vc-active", issuer_did, bound=True,
                          holder_did=holder_did, holder_key_version=0),
        issuer_priv, holder_priv,
    )
    st, resp = verify(bound_request(bad))
    check("holder_key_version 原因" + tag,
          "holder_key_version" in body_of(resp)["reason"])
    bad = sign_presentation(
        make_presentation("vc-active", issuer_did, bound=True,
                          holder_did=""),
        issuer_priv, holder_priv,
    )
    st, resp = verify(bound_request(bad))
    check("holder_did 空串" + tag,
          st == 200 and body_of(resp)["valid"] is False
          and "holder_did" in body_of(resp)["reason"])
    bad = dict(good_bound)
    bad["holder_proof"] = 123
    st, resp = verify(bound_request(bad))
    check("holder_proof 非字符串" + tag,
          st == 200 and body_of(resp)["valid"] is False
          and "holder_proof" in body_of(resp)["reason"])

    # 挑战：请求 challenge 须等于演示 challenge（位于锚点之前）。
    st, resp = verify(bound_request(good_bound, challenge="other"))
    check("挑战原因文案" + tag, "挑战" in body_of(resp)["reason"])

    # -------------------------------------------------------------- #
    # 5. 签发锚点 / 格式 / 验签
    # -------------------------------------------------------------- #
    expect_reason("签发锚点缺失（at=0）" + tag,
                  bound_request(good_bound, at=0),
                  "同步锚点不可用")
    # holder 锚点在 at=1 尚不存在，但顺序上先判签发锚点：at=1 时
    # issuer 已存在，因此应落到持有者锚点不可用（见下节）。
    bad = dict(good_bound)
    bad["proof"] = "not-base64url-signature!"
    expect_reason("签发签名格式错误" + tag,
                  bound_request(bad), "签名格式错误")
    bad = dict(good_bound)
    bad["proof"] = flip_signature(good_bound["proof"])
    expect_reason("签发签名校验失败" + tag,
                  bound_request(bad), "签名校验失败")

    # -------------------------------------------------------------- #
    # 6. 持有者锚点 / 格式 / 验签（先于期限、后于签发验签）
    # -------------------------------------------------------------- #
    expect_reason("持有者锚点未到游标（at=1）" + tag,
                  bound_request(good_bound, at=1),
                  "同步持有者锚点不可用")
    bad = sign_presentation(
        make_presentation("vc-active", issuer_did, bound=True,
                          holder_did=holder_did, holder_key_version=9),
        issuer_priv, holder_priv,
    )
    expect_reason("持有者锚点版本缺失" + tag,
                  bound_request(bad), "同步持有者锚点不可用")
    bad = sign_presentation(
        make_presentation("vc-active", issuer_did, bound=True,
                          holder_did="did:web:novp"),
        issuer_priv, holder_priv,
    )
    expect_reason("持有者锚点无 vp 用途" + tag,
                  bound_request(bad), "同步持有者锚点不可用")
    bad = dict(good_bound)
    bad["holder_proof"] = "not-base64url-signature!"
    expect_reason("持有者签名格式错误" + tag,
                  bound_request(bad), "持有者签名格式错误")
    # 他人私钥签名 -> 与持有者锚点公钥不匹配。
    bad = sign_presentation(
        make_presentation("vc-active", issuer_did, bound=True,
                          holder_did=holder_did),
        issuer_priv, other_priv,
    )
    expect_reason("持有者签名校验失败（错误私钥）" + tag,
                  bound_request(bad), "持有者签名校验失败")
    # tenant_id 与 source_tenant_id 不一致。
    bad = sign_presentation(
        make_presentation("vc-active", issuer_did, bound=True,
                          holder_did=holder_did),
        issuer_priv, holder_priv, tenant_id="other-tenant",
    )
    expect_reason("tenant_id 不匹配" + tag,
                  bound_request(bad), "持有者签名校验失败")

    # -------------------------------------------------------------- #
    # 7. 期限最后
    # -------------------------------------------------------------- #
    expired = sign_presentation(
        make_presentation("vc-active", issuer_did, bound=True,
                          holder_did=holder_did,
                          expires_at="2000-01-01T00:00:00Z"),
        issuer_priv, holder_priv,
    )
    expect_reason("演示已过期" + tag,
                  bound_request(expired), "演示已过期")

    # -------------------------------------------------------------- #
    # 8. 状态合并（原子读取的本租户快照）
    # -------------------------------------------------------------- #
    revoked = sign_presentation(
        make_presentation("vc-rev", issuer_did, bound=True,
                          holder_did=holder_did),
        issuer_priv, holder_priv,
    )
    expect_reason("revoked 带原因" + tag,
                  bound_request(revoked), "外部凭证已吊销：持证人违规")
    revoked_nr = sign_presentation(
        make_presentation("vc-rev-nr", issuer_did, bound=True,
                          holder_did=holder_did),
        issuer_priv, holder_priv,
    )
    expect_reason("revoked 空原因用未知原因" + tag,
                  bound_request(revoked_nr), "外部凭证已吊销：未知原因")
    unknown = sign_presentation(
        make_presentation("vc-unk", issuer_did, bound=True,
                          holder_did=holder_did),
        issuer_priv, holder_priv,
    )
    expect_reason("unknown 状态" + tag,
                  bound_request(unknown), "外部凭证状态未知")
    unsynced = sign_presentation(
        make_presentation("vc-missing", issuer_did, bound=True,
                          holder_did=holder_did),
        issuer_priv, holder_priv,
    )
    expect_reason("未同步状态" + tag,
                  bound_request(unsynced), "外部凭证状态未同步")
    # 未绑定形态同样合并状态。
    expect_reason("未绑定 revoked 合并" + tag,
                  bound_request(
                      sign_presentation(
                          make_presentation("vc-rev", issuer_did),
                          issuer_priv),
                      source=None),
                  "外部凭证已吊销：持证人违规")

    # -------------------------------------------------------------- #
    # 9. 租户隔离与只读
    # -------------------------------------------------------------- #
    # tenant-b 有同一锚点快照但无状态：验签通过、状态未同步。
    st, resp = verify(bound_request(good_bound), headers=TB)
    check("他租户无状态" + tag,
          st == 200 and body_of(resp)
          == {"valid": False, "reason": "外部凭证状态未同步"})

    # 只读：同步视图不被推进或改变。
    st, state_raw = _http(
        "GET",
        f"{base}/v1/trust/anchor-changes/synced-state"
        f"?signer_did={signer_did}&at=3",
        headers=TA,
    )
    assert st == 200
    state = body_of(state_raw)
    check("同步视图仍含三条末事件" + tag,
          state is not None and len(state.get("anchors", [])) == 3)


def main():
    port = 9233
    store_path = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store_path)

    def start():
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(port), "服务启动超时"
        return proc

    proc = start()
    base = f"http://127.0.0.1:{port}"
    try:
        run_case(False, store_path, base)
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    # 重启后结论一致（只读协议，同步页与状态均跨重启持久化）。
    proc = start()
    try:
        run_case(True, store_path, base)
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    if failures:
        print(f"\n{len(failures)} 项失败")
        sys.exit(1)
    print("\n全部通过")


if __name__ == "__main__":
    main()
