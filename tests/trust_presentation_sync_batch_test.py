#!/usr/bin/env python3
"""POST /v1/trust/presentation-sync-batch 批量跨系统外部演示消费历史
同步端到端测试。

直接运行：python3 tests/trust_presentation_sync_batch_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

数据来源与 trust_presentation_sync_test.py 相同：来源租户先经
/v1/trust/presentations/consume 产生真实外部演示消费历史，再由 export
（NDJSON）与 manifest（签名清单）导出；目标租户登记同 did/公钥（含 vp
用途）的信任锚点后通过 presentation-sync-batch 批量同步。

注意：外部演示消费历史的 cursor 取首次消费审计的 seq，为稀疏严格递增
空间（非 1..n 稠密），故本测试不硬编码游标，全部从 export 实际行读取。

覆盖：
- 请求级非法（空体/非法 JSON/非对象/键集错/items 非数组/空/超过 50
  项）均 HTTP200 且恰返 {"results":[],"reason":"请求非法"}；
- 项结构/类型错误（非对象、缺漏/多余键、manifest 非对象、ndjson 非
  字符串）收敛为 {valid:false,http_status:400,reason:"请求项非法"}；
- 逐项沿用单条 presentation-sync 规则：清单验真/NDJSON 内容失败为
  http_status 200 固定 reason；游标冲突 409“同步游标冲突”；
- 批次按序不短路、等长同序 results；失败项键序 valid,http_status,
  reason；成功项键序 valid,http_status,signer_did,snapshot,
  next_after,count；首次检查点 201，否则 200；
- 同签名方后项可见前项（同批连续两页依次推进）；
- 与单条 presentation-sync 并发同页仅一次 201，不跳页、不重复推进；
- 同步不写审计；consume / consume-batch 命中批量同步索引 ->
  “外部演示已消费”；
- 租户隔离；显式空租户头 400；跨重启检查点稳定。
"""

import concurrent.futures
import copy
import hashlib
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

SYNC_PATH = "/v1/trust/presentation-sync"
BATCH_PATH = "/v1/trust/presentation-sync-batch"
EXPORT_PATH = "/v1/trust/presentations/consumptions/export"
MANIFEST_PATH = "/v1/trust/presentations/consumptions/manifest"
CONSUME_PATH = "/v1/trust/presentations/consume"
CONSUME_BATCH_PATH = "/v1/trust/presentations/consume-batch"
ANCHORS_PATH = "/v1/trust/anchors"
OK_KEYS = ["valid", "http_status", "signer_did", "snapshot",
           "next_after", "count"]
FAIL_KEYS = ["valid", "http_status", "reason"]

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


def _http(method, url, payload=None, headers=None, raw_body=None):
    if raw_body is not None:
        data = raw_body
    else:
        data = (
            json.dumps(payload).encode("utf-8")
            if payload is not None
            else None
        )
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


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


ISSUER_DID = "did:web:pres-batch-issuer.example"


def make_presentation(priv, index, presentation_id=None,
                      issuer_did=None, challenge=None):
    """构造并签发一个合法的未绑定外部演示（九字段）。"""
    p = {
        "presentation_id": presentation_id or f"vp_sync_batch_{index:03d}",
        "credential_id": f"vc_sync_batch_{index:03d}",
        "issuer_did": issuer_did or ISSUER_DID,
        "issuer_key_version": 1,
        "disclose": ["/role"],
        "claims": {"role": "admin", "seq": index},
        "challenge": challenge or f"chal-batch-{index}",
        "expires_at": "2099-01-01T00:00:00Z",
    }
    p["proof"] = crypto.sign(dict(p), priv)
    return p, p["challenge"]


def main():
    port = 9071
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

    def post(path, payload=None, headers=None, raw_body=None):
        return _http("POST", base + path, payload=payload,
                     headers=headers, raw_body=raw_body)

    def get(path, headers=None):
        return _http("GET", base + path, headers=headers)

    try:
        SRC = {"X-Tenant-ID": "src-tenant"}
        DST = {"X-Tenant-ID": "dst-tenant"}
        OTHER = {"X-Tenant-ID": "other-tenant"}

        issuer_priv, issuer_pub = _keypair()

        st, _, _ = post(ANCHORS_PATH,
                        {"did": ISSUER_DID, "public_key": issuer_pub,
                         "key_version": 1}, SRC)
        assert st == 201, st
        st, _, raw = post("/v1/dids",
                          {"method": "web",
                           "public_key": "presentation-sync-batch-signer"},
                          SRC)
        assert st == 201, (st, raw)
        did_rec = json.loads(raw)
        signer_did = did_rec["did"]
        signer_pub = did_rec["public_key"]

        def read_signer_private():
            with open(store_path, "r", encoding="utf-8") as fh:
                state = json.load(fh)
            return state["tenants"]["src-tenant"]["dids"][signer_did][
                "key_history"][0]["private_key_pem"]

        signer_priv = read_signer_private()

        for tenant in (SRC, DST):
            st, _, _ = post(ANCHORS_PATH,
                            {"did": signer_did, "public_key": signer_pub,
                             "key_version": 1}, tenant)
            assert st in (200, 201), st
        st, _, _ = post(ANCHORS_PATH,
                        {"did": ISSUER_DID, "public_key": issuer_pub,
                         "key_version": 1}, DST)
        assert st in (200, 201), st

        consumed = []

        def consume_one(index):
            presentation, challenge = make_presentation(issuer_priv, index)
            st, _, raw = post(CONSUME_PATH,
                              {"presentation": presentation,
                               "challenge": challenge}, SRC)
            assert st == 200 and json.loads(raw)["valid"] is True, raw
            consumed.append((presentation, challenge))

        for i in range(1, 6):  # 来源侧 5 条消费历史
            consume_one(i)

        def export_page(after, limit, snapshot, headers=SRC):
            st, hd, raw = get(
                f"{EXPORT_PATH}?after={after}&limit={limit}"
                f"&snapshot={snapshot}", headers=headers)
            assert st == 200, (st, raw)
            return raw.decode("utf-8"), int(hd["X-Snapshot-Cursor"])

        def manifest_page(after, limit, snapshot, headers=SRC):
            st, _, raw = get(
                f"{MANIFEST_PATH}?after={after}&limit={limit}"
                f"&snapshot={snapshot}&signer_did={signer_did}",
                headers=headers)
            assert st == 200, (st, raw)
            return json.loads(raw)

        def item(after, limit, snapshot):
            nd, _ = export_page(after, limit, snapshot)
            return {"manifest": manifest_page(after, limit, snapshot),
                    "ndjson": nd}

        def sync_batch(items, headers=DST):
            return post(BATCH_PATH, {"items": items}, headers=headers)

        def resign(manifest_obj, ndjson_text):
            m = copy.deepcopy(manifest_obj)
            m["count"] = ndjson_text.count("\n")
            m["digest"] = hashlib.sha256(
                ndjson_text.encode("utf-8")).hexdigest()
            m["signature"] = crypto.sign(
                {k: m[k] for k in (
                    "snapshot", "filters", "count", "alg", "digest",
                    "signer_did", "key_version")}, signer_priv)
            return m

        def current_snapshot():
            _, hd, _ = get(f"{EXPORT_PATH}?after=0&limit=1", headers=SRC)
            return int(hd["X-Snapshot-Cursor"])

        # 来源游标为审计 seq（稀疏），全部从实际导出行读取：c1..c5。
        s5 = current_snapshot()
        full_nd, full_snap = export_page(0, 1000, s5)
        assert full_snap == s5
        all_rows = [json.loads(line) for line in full_nd.strip().split("\n")]
        assert len(all_rows) == 5
        c1, c2, c3, c4, c5 = (row["cursor"] for row in all_rows)
        assert c1 < c2 < c3 < c4 < c5 == s5

        # ---------------------------------------------------------- #
        # 1. 请求级非法：一律 200 恰返 {"results":[],"reason":"请求非法"}
        # ---------------------------------------------------------- #
        def expect_bad_request(name, **kwargs):
            st, _, raw = post(BATCH_PATH, headers=DST, **kwargs)
            r = json.loads(raw.decode() or "{}")
            check(name, st == 200 and list(r.keys()) == ["results", "reason"]
                  and r == {"results": [], "reason": "请求非法"})

        expect_bad_request("空体", raw_body=b"")
        expect_bad_request("非法 JSON", raw_body=b"not-json")
        expect_bad_request("非对象", raw_body=b"[1,2]")
        expect_bad_request("标量", raw_body=b"5")
        expect_bad_request("缺 items", payload={"x": []})
        expect_bad_request("多余键",
                           payload={"items": [{"manifest": {},
                                               "ndjson": ""}], "x": 1})
        expect_bad_request("items 非数组", payload={"items": {}})
        expect_bad_request("items 空数组", payload={"items": []})
        expect_bad_request(
            "items 超 50 项",
            payload={"items": [{"manifest": {}, "ndjson": ""}] * 51})
        # 恰 50 项不属请求级非法（逐项失败而非整体拒绝）
        st, _, raw = sync_batch([{"manifest": {}, "ndjson": ""}] * 50)
        r = json.loads(raw)
        check("恰 50 项受理", st == 200 and list(r.keys()) == ["results"]
              and len(r["results"]) == 50 and "reason" not in r)

        st, _, _ = post(BATCH_PATH, payload={"items": []},
                        headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", st == 400)

        # ---------------------------------------------------------- #
        # 2. 项结构/类型错误：400 “请求项非法”，不短路
        # ---------------------------------------------------------- #
        nd1, _ = export_page(0, 2, s5)
        m1 = manifest_page(0, 2, s5)
        good1 = {"manifest": m1, "ndjson": nd1}

        bad_items = [
            "not-an-object",
            {"ndjson": ""},                        # 缺 manifest
            {"manifest": {}},                      # 缺 ndjson
            {"manifest": {}, "ndjson": "", "x": 1},  # 多余键
            {"manifest": "x", "ndjson": ""},       # manifest 非对象
            {"manifest": {}, "ndjson": 5},         # ndjson 非字符串
        ]
        st, _, raw = sync_batch(bad_items + [good1])
        r = json.loads(raw)
        check("项错误批 HTTP200 且仅含 results",
              st == 200 and list(r.keys()) == ["results"])
        check("项错误批等长同序", len(r["results"]) == len(bad_items) + 1)
        check("项结构错误 400 请求项非法",
              all(list(row.keys()) == FAIL_KEYS
                  and row == {"valid": False, "http_status": 400,
                              "reason": "请求项非法"}
                  for row in r["results"][:-1]))
        tail = r["results"][-1]
        check("项错误不短路（末项首次 201）",
              list(tail.keys()) == OK_KEYS
              and tail == {"valid": True, "http_status": 201,
                           "signer_did": signer_did, "snapshot": s5,
                           "next_after": c2, "count": 2})

        # 同页重放 -> 200
        st, _, raw = sync_batch([good1])
        r = json.loads(raw)["results"][0]
        check("批量同页重放 200",
              r["valid"] is True and r["http_status"] == 200
              and r["next_after"] == c2 and r["snapshot"] == s5
              and r["count"] == 2)

        # ---------------------------------------------------------- #
        # 3. 清单验真失败：http_status 200 固定 reason
        # ---------------------------------------------------------- #
        bad = copy.deepcopy(m1)
        bad.pop("alg")
        bad_sig = copy.deepcopy(m1)
        bad_sig["signature"] = "A" * 86
        st, _, raw = sync_batch([
            {"manifest": bad, "ndjson": nd1},
            {"manifest": bad_sig, "ndjson": nd1},
            {"manifest": m1, "ndjson": nd1 + '{"cursor":9}\n'},
        ])
        res = json.loads(raw)["results"]
        check("清单非法 200", res[0] == {"valid": False, "http_status": 200,
                                         "reason": "清单非法"})
        check("签名校验失败 200", res[1] == {"valid": False,
                                             "http_status": 200,
                                             "reason": "签名校验失败"})
        check("导出内容不匹配 200", res[2] == {"valid": False,
                                               "http_status": 200,
                                               "reason": "导出内容不匹配"})
        check("验真失败项键序",
              all(list(row.keys()) == FAIL_KEYS for row in res))
        # 他租户无 signer 锚点 -> 锚点不可用
        st, _, raw = sync_batch([good1], headers=OTHER)
        check("锚点不可用（他租户）200",
              json.loads(raw)["results"][0]
              == {"valid": False, "http_status": 200,
                  "reason": "锚点不可用"})

        # ---------------------------------------------------------- #
        # 4. NDJSON 非法与游标冲突：200/409，互不短路
        # ---------------------------------------------------------- #
        first_rows = [json.loads(line) for line in nd1.strip().split("\n")]
        row = first_rows[0]
        # 行键序错误（重签清单保证验真通过）
        reordered = json.dumps(
            {"consumption_id": row["consumption_id"],
             "cursor": row["cursor"],
             "issuer_did": row["issuer_did"],
             "presentation_id": row["presentation_id"],
             "consumed_at": row["consumed_at"]},
            separators=(",", ":"), ensure_ascii=False) + "\n"
        illegal_item = {"manifest": resign(m1, reordered),
                        "ndjson": reordered}
        # 旧快照倒退（snapshot=c1）
        nd_old, _ = export_page(0, 1, c1)
        old_item = {"manifest": manifest_page(0, 1, c1),
                    "ndjson": nd_old}
        # 跳页：snapshot=s5 after=c4 缺 c3,c4
        nd_skip, _ = export_page(c4, 1, s5)
        skip_item = {"manifest": manifest_page(c4, 1, s5),
                     "ndjson": nd_skip}
        # 合法续页 snapshot=s5 after=c2（c3,c4,c5）
        nd3, _ = export_page(c2, 3, s5)
        m3 = manifest_page(c2, 3, s5)
        r3, r4, r5 = (json.loads(line) for line in nd3.strip().split("\n"))
        assert [r3["cursor"], r4["cursor"], r5["cursor"]] == [c3, c4, c5]
        cont_item = {"manifest": m3, "ndjson": nd3}

        # 与历史重复 (issuer_did,presentation_id)：cp 仍为 (s5,c2)，续页
        # 窗口内复用首页行的键 -> 200 “导出内容非法”，检查点不推进。
        hist_dup_rows = [
            dict(r3, issuer_did=first_rows[0]["issuer_did"],
                 presentation_id=first_rows[0]["presentation_id"],
                 consumption_id="e" * 64), r4, r5]
        hist_dup_nd = "".join(
            json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n"
            for r in hist_dup_rows)
        st, _, raw = sync_batch([
            {"manifest": resign(m3, hist_dup_nd), "ndjson": hist_dup_nd}])
        check("与历史重复键 200",
              json.loads(raw)["results"][0]
              == {"valid": False, "http_status": 200,
                  "reason": "导出内容非法"})

        st, _, raw = sync_batch([
            illegal_item,
            old_item,
            skip_item,
            cont_item,
        ])
        res = json.loads(raw)["results"]
        check("NDJSON 非法 200",
              res[0] == {"valid": False, "http_status": 200,
                         "reason": "导出内容非法"})
        check("旧快照倒退 409",
              res[1] == {"valid": False, "http_status": 409,
                         "reason": "同步游标冲突"})
        check("跳页 409",
              res[2] == {"valid": False, "http_status": 409,
                         "reason": "同步游标冲突"})
        check("失败后合法续页仍推进",
              res[3] == {"valid": True, "http_status": 200,
                         "signer_did": signer_did, "snapshot": s5,
                         "next_after": c5, "count": 3})
        check("失败项键序", all(list(row.keys()) == FAIL_KEYS
                                for row in res[:3]))
        check("成功项键序", list(res[3].keys()) == OK_KEYS)

        # ---------------------------------------------------------- #
        # 5. 同签名方后项可见前项：同批连续两页依次推进
        # ---------------------------------------------------------- #
        for i in range(6, 9):  # 再来 3 条 -> 新快照 s8
            consume_one(i)
        s8 = current_snapshot()
        new_full, _ = export_page(0, 1000, s8)
        new_rows = [json.loads(line)
                    for line in new_full.strip().split("\n")]
        c6, c7, c8 = (r["cursor"] for r in new_rows[5:8])
        assert c5 < c6 < c7 < c8 == s8
        st, _, raw = sync_batch([
            item(c5, 2, s8),   # c6,c7
            item(c7, 1, s8),  # c8（依赖前项已推进到 c7）
        ])
        res = json.loads(raw)["results"]
        check("同批连续页依次推进",
              res[0]["http_status"] == 200 and res[0]["next_after"] == c7
              and res[0]["count"] == 2
              and res[1] == {"valid": True, "http_status": 200,
                             "signer_did": signer_did, "snapshot": s8,
                             "next_after": c8, "count": 1})

        # 追平后空页 200、不推进
        st, _, raw = sync_batch([
            {"manifest": manifest_page(c8, 1000, s8), "ndjson": ""}])
        r = json.loads(raw)["results"][0]
        check("追平后空页 200",
              r == {"valid": True, "http_status": 200,
                    "signer_did": signer_did, "snapshot": s8,
                    "next_after": c8, "count": 0})

        # ---------------------------------------------------------- #
        # 6. 同步不写审计；consume / consume-batch 命中批量同步索引
        # ---------------------------------------------------------- #
        st, _, raw = get("/v1/audit?limit=200", headers=DST)
        actions = [e["action"] for e in json.loads(raw)["events"]]
        check("批量同步不写审计",
              all("presentation" not in a for a in actions
                  if a != "trust.presentation.consumed")
              and actions.count("trust.presentation.consumed") == 0)

        presentation1, challenge1 = consumed[0]
        consume_req = {
            "presentation": presentation1,
            "challenge": challenge1,
        }
        st, _, raw = post(CONSUME_PATH, consume_req, headers=DST)
        check("consume 命中批量同步索引",
              st == 200 and json.loads(raw)
              == {"valid": False, "reason": "外部演示已消费"})
        st, _, raw = post(CONSUME_BATCH_PATH, {"items": [consume_req]},
                          headers=DST)
        check("consume-batch 命中批量同步索引",
              st == 200 and json.loads(raw)["results"][0]
              == {"valid": False, "reason": "外部演示已消费"})
        # 命中后仍不写审计
        st, _, raw = get("/v1/audit?limit=200", headers=DST)
        actions2 = [e["action"] for e in json.loads(raw)["events"]]
        check("命中同步索引不写审计",
              actions2.count("trust.presentation.consumed") == 0)

        # ---------------------------------------------------------- #
        # 7. 租户隔离：他租户首次同步同内容仍 201
        # ---------------------------------------------------------- #
        st, _, _ = post(ANCHORS_PATH,
                        {"did": signer_did, "public_key": signer_pub,
                         "key_version": 1}, OTHER)
        assert st == 201, st
        st, _, raw = sync_batch([item(0, 2, s5)], headers=OTHER)
        r = json.loads(raw)["results"][0]
        check("他租户首次同步独立 201",
              r["http_status"] == 201 and r["count"] == 2)

        # ---------------------------------------------------------- #
        # 8. 与单条并发同页：合计仅一次 201
        # ---------------------------------------------------------- #
        conc_priv, conc_pub = _keypair()
        conc_signer = "did:web:conc-pres-batch-signer.example"
        st, _, _ = post(ANCHORS_PATH,
                        {"did": conc_signer, "public_key": conc_pub,
                         "key_version": 1}, DST)
        assert st == 201, st
        conc_nd = (
            json.dumps(
                {"cursor": 1, "consumption_id": "c" * 64,
                 "issuer_did": "did:web:conc-pres-batch-issuer.example",
                 "presentation_id": "vp_conc_batch_1",
                 "consumed_at": "2099-01-01T00:00:00Z"},
                separators=(",", ":"), ensure_ascii=False) + "\n"
        )
        conc_manifest = {
            "snapshot": 1,
            "filters": {"after": 0, "limit": 1000},
            "count": 1,
            "alg": "SHA-256",
            "digest": hashlib.sha256(conc_nd.encode("utf-8")).hexdigest(),
            "signer_did": conc_signer,
            "key_version": 1,
        }
        conc_manifest["signature"] = crypto.sign(
            {k: conc_manifest[k] for k in (
                "snapshot", "filters", "count", "alg", "digest",
                "signer_did", "key_version")}, conc_priv)
        conc_item = {"manifest": conc_manifest, "ndjson": conc_nd}

        def call_single(_):
            st, _, _ = post(SYNC_PATH, conc_item, headers=DST)
            return st

        def call_batch(_):
            st, _, raw = sync_batch([conc_item])
            assert st == 200
            return json.loads(raw)["results"][0]["http_status"]

        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            codes = list(pool.map(call_single, range(8)))
            codes += list(pool.map(call_batch, range(8)))
        check("并发同页仅一次 201，其余 200",
              codes.count(201) == 1 and codes.count(200) == 15)

        # ---------------------------------------------------------- #
        # 9. 跨重启：检查点保留，重放 200、旧快照 409、consume 仍命中
        # ---------------------------------------------------------- #
        replay_item = item(c7, 1, s8)
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, _, raw = sync_batch([replay_item])
        check("重启后当前快照页重放 200",
              json.loads(raw)["results"][0]["http_status"] == 200)
        st, _, raw = sync_batch([old_item])
        check("重启后旧快照仍 409",
              json.loads(raw)["results"][0]
              == {"valid": False, "http_status": 409,
                  "reason": "同步游标冲突"})
        st, _, raw = post(CONSUME_PATH,
                          {"presentation": presentation1,
                           "challenge": challenge1}, DST)
        check("重启后 consume 仍命中",
              json.loads(raw)
              == {"valid": False, "reason": "外部演示已消费"})

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store_path):
            os.remove(store_path)

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
