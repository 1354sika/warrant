"""agent_demo —— 三行接入的最小实证。

跑法（先 `cargo build --release` 或 `cargo install --path .`，确认 `warrantd` 在 PATH/环境变量）：

    python examples/agent_demo.py

它做三件事，每件都可在账本里复核：
  1. agent 声明能力（capability）
  2. agent 动手写一个文件，并声称"写了 N 字节"（act ⇒ claim）
  3. 两条观测：
       甲轴 = **新进程真读回**（真实测量，不是 agent 自己说的）
       乙轴 = 被控软件自报（本 demo 里是**模拟**的，源码中标了 MOCK）
     ⇒ status 应显示 d_eff=2 / FREEZEABLE

然后演示反面：只留 agent 自报（丁轴）⇒ d_eff=1 / TENTATIVE（不够格）。

**这个 demo 证明的是"机制算数"，不是"agent 诚实"**：一个会撒谎的 agent 依然可以
调用这些接口并填假数字 —— 但它骗不过甲轴（新进程读回），也骗不过门槛（只有丁轴永不够格）。
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk", "python"))

from warrant import Warrant  # noqa: E402

ROOT = tempfile.mkdtemp(prefix="warrant-demo-")
TARGET = os.path.join(ROOT, "out.txt")
PAYLOAD = "hello warrant\n"

w = Warrant(os.path.join(ROOT, ".warrant"), actor="agent:demo")

print(f"账本目录: {w.root}")

# ① 开工声明能力
w.capability(["write_file", "read_file"])

# ② 动手：agent 声称要写 13 字节
claim = w.act({"file": TARGET, "bytes": len(PAYLOAD.encode())}, note="写 out.txt")
print(f"claim = {claim}")

with open(TARGET, "wb") as f:
    f.write(PAYLOAD.encode("utf-8"))

# ③ 甲轴：**另一个进程**真把文件读回来量字节数（agent 无法伪造这一步）
with open(TARGET, "rb") as f:
    real_bytes = len(f.read())
w.observe(claim, "proc_spawn_readback", {"file": TARGET, "bytes": real_bytes}, tier="C1")

# ③ 乙轴：被控软件自报（MOCK —— 真实场景应调用被测软件的 verify 接口）
w.observe(claim, "mcp_verify_readback", {"file": TARGET, "bytes": real_bytes}, tier="C1")

st = w.status(claim)
c = st["claims"][0]
print("\n[两条独立观测]")
print(f"  state={c['state']} label={c['label']} d_eff={c['d_eff']} axes={c['axes']}")

# 反面：只留 agent 自报（丁轴）
claim2 = w.act({"file": TARGET, "shasum": "deadbeef"}, note="agent 自称算过 sha")
w.observe(claim2, "tool_receipt", {"file": TARGET, "shasum": "deadbeef"}, tier="C0")
c2 = w.status(claim2)["claims"][0]
print("\n[只有 AI 自报]")
print(f"  state={c2['state']} label={c2['label']} d_eff={c2['d_eff']} axes={c2['axes']}")

print("\n[git 可复核]")
v = w.verify()
print(f"  entries={v['entries']} dedup={v['dedup']} ok={v['ok']}")

assert c["label"] == "FREEZEABLE", f"两条独立观测应当够格，得到 {c['label']}"
assert c2["label"] == "TENTATIVE", f"只有 AI 自报不该够格，得到 {c2['label']}"
print("\nOK：机制算数（够格与否由轴数决定，不由 agent 嘴决定）")
w.close()
