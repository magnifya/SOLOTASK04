#!/usr/bin/env python3
"""信任锚点四条写事务的落盘失败回滚测试（直连 VCStore）。

覆盖 register_trust_anchor / rotate_trust_anchor / revoke_trust_anchor /
update_trust_anchor_uses 在持久化抛 OSError 时：

- 原样向上抛 OSError；
- 锚点、生命周期/用途历史、可签名变更事件、三类租户游标
  （trust_anchor_history / trust_anchor_uses_history /
  trust_anchor_change）及全局审计/序号全部回到调用前状态；
- 新租户注册失败不残留空租户桶、空 DID 映射或空版本；
- 磁盘文件字节不变（os.replace 未发生），重新创建 VCStore(path)
  得到同一快照，不加载半写状态；
- 移除故障后重试：每条历史/变更事件与审计只新增一次，三类游标自
  原值连续递增，再次重启状态稳定；
- 返回形态不变：register/rotate 为 (TrustAnchorRecord, bool)，
  revoke 为 TrustAnchorRecord，update_uses 为 list[str]。

直接运行：python3 tests/trust_anchor_write_rollback_test.py
仅用标准库 + cryptography。
"""

import copy
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend.models import TrustAnchorRecord  # noqa: E402
from vcbackend.store import (  # noqa: E402
    TRUST_ANCHOR_USES,
    VCStore,
)

TENANT = "rollback-ta"
OTHER_TENANT = "rollback-tb"
DID = "did:web:rollback-issuer"
NEW_DID = "did:web:rollback-new"
FULL_USES = list(TRUST_ANCHOR_USES)
SUB_USES = ["vc", "vp"]

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


def gen_pub():
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def expect_oserror(name, fn):
    try:
        fn()
    except OSError as exc:
        check(f"{name}：原样抛 OSError", isinstance(exc, OSError))
        return
    check(f"{name}：原样抛 OSError", False)


def capture(store):
    """参与事务的全部可变状态的深拷贝快照。"""
    return {
        "tenants": copy.deepcopy(store._tenants),  # noqa: SLF001
        "audit": copy.deepcopy(store._audit),  # noqa: SLF001
        "audit_seq": store._audit_seq,  # noqa: SLF001
        "anchor_cursors": copy.deepcopy(  # noqa: SLF001
            store._trust_anchor_history_cursors
        ),
        "uses_cursors": copy.deepcopy(  # noqa: SLF001
            store._trust_anchor_uses_history_cursors
        ),
        "change_cursors": copy.deepcopy(  # noqa: SLF001
            store._trust_anchor_change_cursors
        ),
    }


def install_boom(store):
    def _boom():
        raise OSError("模拟落盘失败: 磁盘已满")

    store._save_locked = _boom  # type: ignore[assignment]


def audit_actions(store, tenant_id):
    events, _ = store.list_audit(tenant_id, 0, 1000)
    return [e.action for e in events]


def history_cursors(store, tenant_id, did):
    events, _ = store.list_trust_anchor_history(tenant_id, did, 0, 1000)
    return [e.cursor for e in events]


def uses_history_cursors(store, tenant_id, did, version):
    events, _ = store.list_trust_anchor_uses_history(
        tenant_id, did, version, 0, 1000
    )
    return [e.cursor for e in events]


def change_cursors(store, tenant_id):
    events, _ = store.list_trust_anchor_changes(tenant_id, 0, 1000)
    return [e.cursor for e in events]


def main():
    path = tempfile.mktemp(suffix=".json")
    store = VCStore(path)
    pub1 = gen_pub()
    pub2 = gen_pub()

    # 基线：已有租户 DID#1（省略 uses -> 全用途），落盘成功。
    rec, created = store.register_trust_anchor(TENANT, DID, pub1, 1)
    check("基线注册返回 (TrustAnchorRecord, True)",
          isinstance(rec, TrustAnchorRecord) and created is True
          and rec.did == DID and rec.key_version == 1
          and rec.status == "active" and rec.updated_at is None)

    baseline = capture(store)
    disk0 = Path(path).read_bytes()

    def unchanged(name):
        check(f"{name}：内存状态回到调用前", capture(store) == baseline)
        check(f"{name}：磁盘文件字节不变（无半写）",
              Path(path).read_bytes() == disk0)

    # -------------------------------------------------------------- #
    # 1. register：新租户失败 -> 不残留空租户/DID/版本
    # -------------------------------------------------------------- #
    install_boom(store)
    expect_oserror(
        "新租户注册",
        lambda: store.register_trust_anchor(OTHER_TENANT, NEW_DID, pub2, 1),
    )
    check("新租户注册失败不残留空租户", OTHER_TENANT not in store._tenants)  # noqa: SLF001
    unchanged("新租户注册")

    # 同一调用失败后再建 VCStore(path)：不得出现半写租户
    reopened = VCStore(path)
    check("新租户失败后重开不加载半写租户",
          OTHER_TENANT not in reopened._tenants  # noqa: SLF001
          and capture(reopened) == baseline)

    # -------------------------------------------------------------- #
    # 2. register：既有租户新 DID 失败 -> 不残留空 DID 映射
    # -------------------------------------------------------------- #
    expect_oserror(
        "既有租户新 DID 注册",
        lambda: store.register_trust_anchor(TENANT, NEW_DID, pub2, 1),
    )
    anchors = store._tenants[TENANT]["trust_anchors"]  # noqa: SLF001
    check("新 DID 注册失败不残留空 DID 映射/版本", NEW_DID not in anchors)
    unchanged("既有租户新 DID 注册")

    # -------------------------------------------------------------- #
    # 3. register：幂等重试落盘失败 -> 审计回滚、不新增任何历史
    # -------------------------------------------------------------- #
    expect_oserror(
        "幂等重试注册",
        lambda: store.register_trust_anchor(TENANT, DID, pub1, 1),
    )
    unchanged("幂等重试注册")

    # -------------------------------------------------------------- #
    # 4. rotate：落盘失败 -> 无 v2、无历史/用途/变更事件、游标不前进
    # -------------------------------------------------------------- #
    result_box = {}

    def rotate():
        result_box["r"] = store.rotate_trust_anchor(
            TENANT, DID, 1, pub2
        )

    expect_oserror("轮换", rotate)
    check("轮换失败不落 v2",
          "2" not in store._tenants[TENANT]["trust_anchors"][DID])  # noqa: SLF001
    unchanged("轮换")

    # -------------------------------------------------------------- #
    # 5. 首次吊销：落盘失败 -> 仍 active、无 revoked 事件/审计
    # -------------------------------------------------------------- #
    expect_oserror(
        "首次吊销",
        lambda: store.revoke_trust_anchor(TENANT, DID, 1),
    )
    row = store._tenants[TENANT]["trust_anchors"][DID]["1"]  # noqa: SLF001
    check("首次吊销失败后锚点仍 active 且 updated_at 为 None",
          row.get("status") == "active" and row.get("updated_at") is None)
    unchanged("首次吊销")

    # -------------------------------------------------------------- #
    # 6. 用途实改：落盘失败 -> uses 不变、无 updated 事件
    # -------------------------------------------------------------- #
    ret_box = {}

    def update_uses():
        ret_box["r"] = store.update_trust_anchor_uses(
            TENANT, DID, 1, FULL_USES, SUB_USES
        )

    expect_oserror("用途实改", update_uses)
    check("用途实改失败后仍为全用途",
          store.get_trust_anchor_uses(TENANT, DID, 1) == FULL_USES)
    unchanged("用途实改")

    # -------------------------------------------------------------- #
    # 7. 全部失败后重开：同一快照
    # -------------------------------------------------------------- #
    reopened2 = VCStore(path)
    check("四条路径失败后重开得到同一快照",
          capture(reopened2) == baseline)

    # -------------------------------------------------------------- #
    # 8. 移除故障后重试：成功、事件/审计仅一次、游标连续
    # -------------------------------------------------------------- #
    del store._save_locked  # type: ignore[attr-defined]

    base_anchor_cur = baseline["anchor_cursors"].get(TENANT, 0)
    base_uses_cur = baseline["uses_cursors"].get(TENANT, 0)
    base_change_cur = baseline["change_cursors"].get(TENANT, 0)

    rec_tb, created_tb = store.register_trust_anchor(
        OTHER_TENANT, NEW_DID, pub2, 1
    )
    check("重试：新租户注册成功返回 (R, True)",
          isinstance(rec_tb, TrustAnchorRecord) and created_tb is True)

    rec_v2, created_v2 = store.rotate_trust_anchor(TENANT, DID, 1, pub2)
    check("重试：轮换返回 (R, True) 且为 v2 active",
          isinstance(rec_v2, TrustAnchorRecord) and created_v2 is True
          and rec_v2.key_version == 2 and rec_v2.status == "active")

    uses_now = store.update_trust_anchor_uses(
        TENANT, DID, 1, FULL_USES, SUB_USES
    )
    check("重试：用途实改返回 list[str] 且生效为子集",
          uses_now == SUB_USES and isinstance(uses_now, list))

    rec_rev = store.revoke_trust_anchor(TENANT, DID, 1)
    check("重试：首次吊销返回 TrustAnchorRecord(revoked)",
          isinstance(rec_rev, TrustAnchorRecord)
          and rec_rev.status == "revoked"
          and isinstance(rec_rev.updated_at, str))

    # 幂等重复吊销不新增历史/变更（公开行为不变的附带校验）
    rec_rev2 = store.revoke_trust_anchor(TENANT, DID, 1)
    check("重复吊销保持首次 updated_at",
          rec_rev2.updated_at == rec_rev.updated_at)

    # 生命周期历史：基线 1(registered) + 轮换 + 首次吊销 = 3，
    # 游标自原值连续；失败尝试与幂等吊销均不追加。
    hc = history_cursors(store, TENANT, DID)
    check("生命周期事件仅 3 条且游标连续",
          hc == [base_anchor_cur, base_anchor_cur + 1, base_anchor_cur + 2])

    # 用途历史游标为租户内跨 DID 共享：重试序为 rotate 先、用途实改后，
    # 故 DID#1 registered=base、updated=base+2；DID#2 rotated=base+1。
    uc_v1 = uses_history_cursors(store, TENANT, DID, 1)
    uc_v2 = uses_history_cursors(store, TENANT, DID, 2)
    check("DID#1 用途事件 registered+updated，游标连续",
          uc_v1 == [base_uses_cur, base_uses_cur + 2])
    check("DID#2 用途事件 rotated 接续游标", uc_v2 == [base_uses_cur + 1])

    # 变更事件：基线 registered(1) + 新租户注册 + 轮换 + 用途 + 吊销 = 5，
    # 全部自原游标连续。
    cc = change_cursors(store, TENANT)
    check("变更事件游标自原值连续递增",
          cc == [base_change_cur + i for i in range(0, 4)])
    check("新租户变更游标从 1 起",
          change_cursors(store, OTHER_TENANT) == [1])

    # 审计：基线 registered 1 条；之后 rotated/uses.updated/revoked 各 1，
    # 失败尝试与重复吊销中仅重复吊销本身合法记 1 条审计。
    actions = audit_actions(store, TENANT)
    check("审计只新增一次（失败不记）",
          actions == [
              "trust.anchor.registered",
              "trust.anchor.rotated",
              "trust.anchor.uses.updated",
              "trust.anchor.revoked",
              "trust.anchor.revoked",
          ], )
    check("全局审计序号连续无空洞",
          [e["seq"] for e in store._audit] == list(range(1, len(store._audit) + 1)))  # noqa: SLF001

    # -------------------------------------------------------------- #
    # 9. 成功后重开：状态稳定、游标不变
    # -------------------------------------------------------------- #
    success_state = capture(store)
    reopened3 = VCStore(path)
    check("成功重试后重开状态稳定", capture(reopened3) == success_state)
    check("重开后游标读取一致",
          history_cursors(reopened3, TENANT, DID)
          == history_cursors(store, TENANT, DID)
          and change_cursors(reopened3, TENANT)
          == change_cursors(store, TENANT))

    # 重开后的实例上再做一次写，确认序号/游标在持久值上继续，不复用
    rec_v3, created_v3 = reopened3.rotate_trust_anchor(TENANT, DID, 2, gen_pub())
    check("重开后轮换 v3 成功且游标接续",
          created_v3 is True and rec_v3.key_version == 3
          and history_cursors(reopened3, TENANT, DID)[-1]
          == base_anchor_cur + 3)
    check("重开后再次重开稳定",
          capture(VCStore(path)) == capture(reopened3))

    if os.path.exists(path):
        os.remove(path)

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
