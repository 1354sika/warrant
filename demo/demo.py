# -*- coding: utf-8 -*-
"""安全场景下「单源判定」vs「信使式双源判定」的对照原型（可复算，一条命令跑）。

⚠️ 诚实边界
- 这是**按 crates/warrant/src/rank.rs 语义的等价原型**（d_eff≥2 且含非甲轴），不是引擎本体。
- 事件是**合成数据**，不是真机抓的。目的是验证「结构性差异」，不是测检出率。
- 三个来源刻意模拟不同独立性：
    甲 auth.log    —— 攻击者拿到权限可改可删（最弱）
    乙 conn_table  —— 另一个进程读连接表，攻击者不一定知道要改
    丙 pcap        —— 离线抓包，改历史需要重写整段流量（最强）

📌 评分口径（2026-10-21 修正，务必读）
    两个判定器**输出词表不同**（裸判定器只会说「报警/无事」），
    因此必须先把它们各自映射到同一判定空间 {attack, clean}，再比真实情况；
    **不能**拿信使式的措辞（「认定：…」）去 string-startswith 评裸判定器 ——
    那样裸判定器无论对错都会被记成错（旧版本 0/4 的成因）。

用法：
    python demo.py           # 跑并打印对照表
    python demo.py --check   # 另加断言（裸 2/4、信使 4/4）；不达预期则非零退出
"""

import sys

try:  # Windows 控制台默认 GBK，会撞上「⇒/→」这类字符；先切 UTF-8
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:  # pragma: no cover - 老 Python / 已重定向
    pass

SCENARIOS = [
    {
        "name": "S1 真攻击",
        "truth": "真攻击",
        "auth_log": [f"Failed password for root from 45.9.1.7 port {40000+i}" for i in range(482)],
        "conn_table": [(f"45.9.1.7", 22) for _ in range(482)],
        "pcap": {"syn_from": {"45.9.1.7": 482}},
    },
    {
        "name": "S2 自己人打错密码",
        "truth": "非攻击",
        "auth_log": ["Failed password for admin from 192.168.1.20 port 50111"],
        "conn_table": [("192.168.1.20", 22)],
        "pcap": {"syn_from": {"192.168.1.20": 1}},
    },
    {
        "name": "S3 攻击者删了日志",
        "truth": "真攻击（日志被清）",
        "auth_log": [],
        "conn_table": [("45.9.1.7", 22) for _ in range(482)],
        "pcap": {"syn_from": {"45.9.1.7": 482}},
    },
    {
        "name": "S4 攻击者伪造日志（栽赃）",
        "truth": "非攻击（日志是伪造的）",
        "auth_log": [f"Failed password for root from 203.0.113.9 port {41000+i}" for i in range(500)],
        "conn_table": [],
        "pcap": {"syn_from": {}},
    },
]

FAIL_THRESHOLD = 10  # 裸判定器的阈值：单源失败次数 ≥10 就报警

# 统一判定空间
ATTACK = "attack"
CLEAN = "clean"


def naive_judge(s):
    """裸判定器：只看 auth.log（现实里 90% 的告警规则就是这样）。

    返回 (判定空间里的结论, 展示文本, 理由)。
    """
    fails = len(s["auth_log"])
    if fails >= FAIL_THRESHOLD:
        return ATTACK, "报警", "auth.log 失败次数 %d ≥ %d" % (fails, FAIL_THRESHOLD)
    return CLEAN, "无事", "auth.log 失败次数 %d < %d" % (fails, FAIL_THRESHOLD)


def witness_judge(s):
    """信使式判定：要求 ≥2 个独立来源（甲/乙/丙）都指向同一结论，且至少含一条非甲。"""
    log_fails = len(s["auth_log"])
    axes = {}
    if log_fails >= FAIL_THRESHOLD:
        axes["甲(auth.log)"] = "有攻击痕迹"
    conn = {}
    for ip, port in s["conn_table"]:
        conn[ip] = conn.get(ip, 0) + 1
    for ip, n in conn.items():
        if n >= FAIL_THRESHOLD:
            axes["乙(conn_table)"] = "同一 IP %d 条连接" % n
    for ip, n in s["pcap"]["syn_from"].items():
        if n >= FAIL_THRESHOLD:
            axes["丙(pcap)"] = "SYN %d 个" % n

    non_jia = [k for k in axes if not k.startswith("甲")]
    d_eff = len(axes)
    if d_eff >= 2 and non_jia:
        return ATTACK, "认定：攻击成立", "d_eff=%d（%s）" % (d_eff, "、".join(axes))
    if d_eff == 1 and non_jia:
        return CLEAN, "未认定：有线索（缺日志侧证据）", "d_eff=1（%s），缺甲轴" % list(axes)[0]
    if d_eff == 1:
        return CLEAN, "未认定：只有日志（可能是伪造）", "d_eff=1（甲），无独立来源佐证"
    return CLEAN, "未认定：无证据", "d_eff=0"


def truth_verdict(truth):
    """真实情况映射到同一判定空间。"""
    return ATTACK if truth.startswith("真攻击") else CLEAN


def main(check=False):
    print("=" * 96)
    print("%-24s %-16s %-24s %-6s %-24s %-6s" % ("场景", "真实情况", "裸判定器", "对错", "信使式判定", "对错"))
    print("=" * 96)
    rows = []
    for s in SCENARIOS:
        nv, ntext, nreason = naive_judge(s)
        wv, wtext, wreason = witness_judge(s)
        want = truth_verdict(s["truth"])
        n_ok, w_ok = nv == want, wv == want
        rows.append((s["name"], s["truth"], ntext, nreason, n_ok, wtext, wreason, w_ok))
        print("%-24s %-16s %-24s %-6s %-24s %-6s" % (
            s["name"], s["truth"], ntext, "OK" if n_ok else "X",
            wtext, "OK" if w_ok else "X"))

    print("\n" + "=" * 96)
    print("明细（判定空间：attack / clean）")
    print("=" * 96)
    for (name, truth, ntext, nreason, n_ok, wtext, wreason, w_ok) in rows:
        print("\n[%s]  真实=%s → 期望=%s" % (name, truth, truth_verdict(truth)))
        print("  裸判定器 : %s   → %s  [%s]" % (ntext, nreason, "对" if n_ok else "错"))
        print("  信使式   : %s   → %s  [%s]" % (wtext, wreason, "对" if w_ok else "错"))

    n_ok = sum(1 for r in rows if r[4])
    w_ok = sum(1 for r in rows if r[7])
    print("\n" + "=" * 96)
    print("汇总：裸判定器 %d/%d 正确 ；信使式 %d/%d 正确" % (n_ok, len(rows), w_ok, len(rows)))
    print("读法：裸判定器答对 S1/S2 是**应该的**——它在「单源就够」的场景并不差；")
    print("      差别只在 S3（日志被删）与 S4（日志被伪造）：单源在那里结构上无法自救。")
    print("=" * 96)

    if check:
        # 这两个数是本 demo 的回归基线；任何改动若让它们变化，必须在提交说明里解释。
        expected = (2, 4)
        got = (n_ok, w_ok)
        if got != expected:
            print("\nCHECK FAILED：期望 裸=%d/4、信使=%d/4，实得 裸=%d/4、信使=%d/4"
                  % (expected[0], expected[1], got[0], got[1]))
            return 1
        print("\nCHECK OK：裸 %d/4、信使 %d/4（与基线一致）" % (got[0], got[1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(check="--check" in sys.argv[1:]))
