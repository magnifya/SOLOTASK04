#!/usr/bin/env python3
"""信任锚点写事务（落盘失败回滚）的直连 store 测试。

覆盖 register/rotate/revoke/update_uses 四条写路径：_save_locked
抛 OSError 时须原样抛出，且锚点、生命周期/用途历史、变更事件、
三类租户游标、全局审计与序号全部回到调用前状态；新租户注册失败
不得残留空租户、DID 或版本；磁盘不得留下半写状态（重新创建
VCStore(path) 得到同一快照）。移除故障后重试成功，事件与审计只
新增一次，游标从原值连续递增且重启稳定。

直接运行：python3 tests/trust_anchor_write_tx_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend.store import TRUST_ANCHOR_USES, VCStore  # noqa: E402

FULL_USES = list(TRUST_ANCHOR_USES)
NARROW_USES = ["generic", "vc"]


def gen_pub():
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def mem_state(store):
    """内存全量可变状态快照（可比较）。"""
    return store._snapshot_locked()  # noqa: SLF001


def disk_state(path):
    """从磁盘重新加载的全量状态快照（与另一次加载可比）。"""
    return VCStore(path)._snapshot_locked()  # noqa: SLF001


def _boom():
    raise OSError("模拟落盘失败")


def main():
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    path = tempfile.mktemp(suffix=".json")
    store = VCStore(path)
    did = "did:web:example.com:issuer"
    pub1, pub2, pub3 = gen_pub(), gen_pub(), gen_pub()

    def fail_call(fn, *args):
        """在 _save_locked 故障下调用 fn，返回是否原样抛出 OSError。"""
        store._save_locked = _boom  # type: ignore[assignment]
        try:
            fn(*args)
        except OSError as exc:
            return str(exc) == "模拟落盘失败"
        except Exception:  # noqa: BLE001
            return False
        finally:
            del store._save_locked  # type: ignore[attr-defined]
        return False

    try:
        # ---- 1. 新租户注册落盘失败：不残留空租户/DID/版本 ----
        disk0 = disk_state(path)
        mem0 = mem_state(store)
        check(
            "新租户注册落盘失败原样抛 OSError",
            fail_call(store.register_trust_anchor, "tx-a", did, pub1, 1),
        )
        check(
            "新租户注册失败不残留空租户/DID/版本",
            mem_state(store) == mem0 and store._tenants == {},  # noqa: SLF001
        )
        check("新租户注册失败磁盘无半写状态", disk_state(path) == disk0)

        # 移除故障后重试成功：事件与审计只新增一次
        rec, created = store.register_trust_anchor("tx-a", did, pub1, 1)
        check("注册重试成功返回 (R, True)", created and rec.key_version == 1)
        events, _ = store.list_trust_anchor_history("tx-a", did, 0, 50)
        changes, _ = store.list_trust_anchor_changes("tx-a", 0, 50)
        uses_events, _ = store.list_trust_anchor_uses_history(
            "tx-a", did, 1, 0, 50
        )
        audit = store.list_audit("tx-a", 0, 200)[0]
        check(
            "注册重试后历史/变更/用途/审计各恰一条且游标从 1 起",
            [e.cursor for e in events] == [1]
            and [e.cursor for e in changes] == [1]
            and [e.cursor for e in uses_events] == [1]
            and [e.seq for e in audit] == [1],
        )

        # ---- 2. 已有租户新 DID 注册落盘失败：不残留空 DID 条目 ----
        mem0 = mem_state(store)
        disk0 = disk_state(path)
        check(
            "已有租户新 DID 注册落盘失败原样抛 OSError",
            fail_call(
                store.register_trust_anchor, "tx-a", "did:web:other", pub2, 1
            ),
        )
        check(
            "已有租户新 DID 注册失败完全回滚（无空 DID 条目）",
            mem_state(store) == mem0
            and "did:web:other"
            not in store._tenants["tx-a"]["trust_anchors"],  # noqa: SLF001
        )
        check("已有租户新 DID 注册失败磁盘无半写状态", disk_state(path) == disk0)

        # ---- 3. 幂等注册重试落盘失败：审计与序号回滚 ----
        mem0 = mem_state(store)
        check(
            "幂等注册重试落盘失败原样抛 OSError",
            fail_call(store.register_trust_anchor, "tx-a", did, pub1, 1),
        )
        check("幂等注册失败回滚（审计/序号不动）", mem_state(store) == mem0)
        rec, created = store.register_trust_anchor("tx-a", did, pub1, 1)
        audit = store.list_audit("tx-a", 0, 200)[0]
        check(
            "幂等注册重试成功返回 (R, False) 且审计仅新增一条",
            not created and len(audit) == 2 and audit[-1].seq == 2,
        )

        # ---- 4. 轮换落盘失败：完全回滚 ----
        mem0 = mem_state(store)
        disk0 = disk_state(path)
        check(
            "轮换落盘失败原样抛 OSError",
            fail_call(store.rotate_trust_anchor, "tx-a", did, 1, pub2),
        )
        anchors = {a.key_version for a in store.list_trust_anchors("tx-a", did)}
        check(
            "轮换失败回滚：无 v2、状态与调用前一致",
            mem_state(store) == mem0 and anchors == {1},
        )
        check("轮换失败磁盘无半写状态", disk_state(path) == disk0)
        rec, created = store.rotate_trust_anchor("tx-a", did, 1, pub2)
        check("轮换重试成功返回 (R, True)", created and rec.key_version == 2)

        # 幂等轮换重试落盘失败：审计与序号回滚
        mem0 = mem_state(store)
        check(
            "幂等轮换重试落盘失败原样抛 OSError",
            fail_call(store.rotate_trust_anchor, "tx-a", did, 1, pub2),
        )
        check("幂等轮换失败回滚（审计/序号不动）", mem_state(store) == mem0)
        rec, created = store.rotate_trust_anchor("tx-a", did, 1, pub2)
        check("幂等轮换重试成功返回 (R, False)", not created)

        # ---- 5. 首次吊销落盘失败：完全回滚 ----
        mem0 = mem_state(store)
        disk0 = disk_state(path)
        check(
            "首次吊销落盘失败原样抛 OSError",
            fail_call(store.revoke_trust_anchor, "tx-a", did, 2),
        )
        rec = {a.key_version: a for a in store.list_trust_anchors("tx-a", did)}[2]
        check(
            "首次吊销失败回滚：v2 仍 active 且状态与调用前一致",
            mem_state(store) == mem0
            and rec.status == "active"
            and rec.updated_at is None,
        )
        check("首次吊销失败磁盘无半写状态", disk_state(path) == disk0)
        rec = store.revoke_trust_anchor("tx-a", did, 2)
        check("吊销重试成功返回 R(revoked)", rec.status == "revoked")

        # 重复吊销落盘失败：审计与序号回滚
        mem0 = mem_state(store)
        check(
            "重复吊销落盘失败原样抛 OSError",
            fail_call(store.revoke_trust_anchor, "tx-a", did, 2),
        )
        check("重复吊销失败回滚（审计/序号不动）", mem_state(store) == mem0)

        # ---- 6. 用途实改落盘失败：完全回滚 ----
        mem0 = mem_state(store)
        disk0 = disk_state(path)
        check(
            "用途实改落盘失败原样抛 OSError",
            fail_call(
                store.update_trust_anchor_uses,
                "tx-a", did, 1, FULL_USES, NARROW_USES,
            ),
        )
        check(
            "用途实改失败回滚：仍为全用途且状态与调用前一致",
            mem_state(store) == mem0
            and store.get_trust_anchor_uses("tx-a", did, 1) == FULL_USES,
        )
        check("用途实改失败磁盘无半写状态", disk_state(path) == disk0)
        effective = store.update_trust_anchor_uses(
            "tx-a", did, 1, FULL_USES, NARROW_USES
        )
        check(
            "用途实改重试成功返回 list[str]",
            effective == NARROW_USES
            and store.get_trust_anchor_uses("tx-a", did, 1) == NARROW_USES,
        )

        # ---- 7. 全部重试后：事件/审计只新增一次，游标连续且重启稳定 ----
        events, _ = store.list_trust_anchor_history("tx-a", did, 0, 50)
        changes, _ = store.list_trust_anchor_changes("tx-a", 0, 50)
        uses_v1, _ = store.list_trust_anchor_uses_history(
            "tx-a", did, 1, 0, 50
        )
        uses_v2, _ = store.list_trust_anchor_uses_history(
            "tx-a", did, 2, 0, 50
        )
        audit = store.list_audit("tx-a", 0, 200)[0]
        check(
            "生命周期历史每操作恰一条且游标连续",
            [e.action for e in events]
            == [
                "trust.anchor.registered",
                "trust.anchor.rotated",
                "trust.anchor.revoked",
            ]
            and [e.cursor for e in events] == [1, 2, 3],
        )
        check(
            "变更流每操作恰一条且游标连续",
            [e.action for e in changes]
            == ["registered", "rotated", "revoked", "uses.updated"]
            and [e.cursor for e in changes] == [1, 2, 3, 4],
        )
        check(
            "用途历史每操作恰一条且游标连续",
            [e.cursor for e in uses_v1] == [1, 3]
            and [e.action for e in uses_v1] == ["registered", "updated"]
            and [e.cursor for e in uses_v2] == [2],
        )
        check(
            "审计每操作恰一条且 seq 全局连续",
            [e.action for e in audit]
            == [
                "trust.anchor.registered",
                "trust.anchor.registered",
                "trust.anchor.rotated",
                "trust.anchor.rotated",
                "trust.anchor.revoked",
                "trust.anchor.uses.updated",
            ]
            and [e.seq for e in audit] == [1, 2, 3, 4, 5, 6],
        )

        # 重启（重新加载）后快照一致：内存态落盘内容 == 重新创建 VCStore
        reloaded = disk_state(path)
        check(
            "重启后锚点/历史/变更/游标/审计快照稳定",
            reloaded[1] == mem_state(store)[1]  # audit
            and reloaded[2] == mem_state(store)[2]  # audit_seq
            and reloaded[6] == mem_state(store)[6]  # 锚点历史游标
            and reloaded[7] == mem_state(store)[7]  # 用途历史游标
            and reloaded[11] == mem_state(store)[11]  # 变更流游标
            and reloaded[0]["tx-a"] == mem_state(store)[0]["tx-a"],
        )
        # 重启后续写游标从原值连续递增
        store2 = VCStore(path)
        rec, created = store2.register_trust_anchor("tx-a", did, pub3, 3)
        events2, _ = store2.list_trust_anchor_history("tx-a", did, 0, 50)
        check(
            "重启后续写游标连续递增",
            created and events2[-1].cursor == 4,
        )
    finally:
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
    sys.exit(main())
