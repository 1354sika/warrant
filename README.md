# Warrant（信使 · 认定层）

> **别人优化「更聪明」，这里只解决一件事：一件事到底算不算「发生过」。**
> AI 说"我做了"不算；**同一件事被两个独立来源看到、且至少一个不是它自己**，才够格。

Warrant 是一个**可独立复算**的判定层，不依赖任何智能体、不绑定任何被控软件：

| 它给你 | 你要付出的 |
|---|---|
| 一份**链式账本**（每条带规范 id 与 prev，改一条就断链） | 把事件写进来 |
| 一套**证据轴与门槛**（甲/乙/丙/丁四轴，≥2 轴且至少一轴非 AI 才够格） | 说清每轴来自谁 |
| **人签冻结**（只有人的签名能把"够格"变成"事实"） | 一把密钥 |
| 一个**只读复算器**（第三人拿同一份账本自己算一遍） | 无 |

> **一句话：Warrant 不是给智能体加日志，是给它加「能不能说出口」的权力边界。**
> 它治的不是"AI 会犯错"，而是**出错时没人能当场知道、事后也复核不了**——
> 把**滞后**压到当轮，把**黑盒**压到只剩"轴的数量"。完整定位（含它治不了什么）：[`POSITIONING.md`](POSITIONING.md)。

## 30 秒：先自己算一遍

```bash
cargo test                       # 25 单测 + 17 一致性/链/签名测试
cargo run --example make_sample_ledger   # 生成一份自洽示例账本 ledger/entries.jsonl
cargo run --bin warrant-export -- --help 2>/dev/null || echo "见 src/bin/messenger_export.rs"
```

一致性档 **C1–C13** 的可执行定义 = `SPEC.md` 文本 + `vectors/*.json` 向量；测试逐字节对拍，
**夹具缺失即失败、不跳过**（跳过等于假通过）。

## 接一个 agent（三行）

```python
from warrant import Warrant
w = Warrant(".warrant")
claim = w.act({"file": "out.txt", "bytes": 13})                       # 动手，带预期
w.observe(claim, "proc_spawn_readback", {"file": "out.txt", "bytes": 13})  # 另一通道观测
print(w.label(claim))        # FREEZEABLE（两条独立来源）/ TENTATIVE（只有它自己说的）
```

`warrantd` 是那一层可执行程序：`capability` / `act` / `observe` 三原语 + `status` / `verify`，
**CLI 与 stdio 守护进程同一套实现**（不开端口）。详见 [`ADAPTER-SDK.md`](ADAPTER-SDK.md)，
可跑示例 [`examples/agent_demo.py`](examples/agent_demo.py)、Python SDK [`sdk/python/warrant`](sdk/python/warrant)。

## 规范（改判据之前先读）

| 文件 | 内容 |
|---|---|
| `SPEC.md` | v1.0，**已冻结**。规范序列化、事件 id、链位、签名输入、投影、门槛 |
| `PROTOCOL.md` | 「凭什么算够格」：轴的定义、d_eff、状态机；顶部有**落地状态表**（哪些条款已落地、哪些没） |
| `ADAPTER.md` | 宿主如何接入：适配器契约、能力声明、离线复算档 |

## 它**不**做什么（诚实边界）

- **不做内容判断**：它不读"日志里写了什么"，只数"有几个独立来源看到了"。内容可以骗人，轴的数量不容易。
- **不替你决定可信**：够格 ≠ 正确。它只回答"这件事被几个独立来源观测、是否有人签过"。
- **单源、自证、不可复算的场景它无能为力**——那种场景请用别的东西。
- `demo/` 里的 5 个场景是**人工构造**的，不是真实攻击数据；README 里已标明差距与复现方式。

## 目录

```
src/        canon(规范序列化/事件id) · ledger(信封/去重/链/验签) · rank(轴与门槛)
            projection(投影) · admission(准入) · graph(证据图) · merkle(批锚/包含证明)
            json(严格 JSON 解析器：不借库的宽松行为)
tests/      C1–C13 一致性 + 真实链破坏检测 + 签名/信任锚
vectors/    一致性向量（随仓发布，测试直接读）
ledger/     示例账本（由 examples/make_sample_ledger 生成，可复现）
demo/       5 个对照场景：裸判定器 vs 轴式判定
```

## 许可

- **代码**：`MIT OR Apache-2.0`（任选其一）。见 `LICENSE-MIT` / `LICENSE-APACHE`。
- **规范文本**（`SPEC.md` / `PROTOCOL.md` / `ADAPTER.md`）：**CC BY 4.0**（`LICENSE-DOCS.md`），转载需署名。
- **名称与商标**：「Warrant」「信使」及本项目 logo 不随上述许可授予；**请勿把你的分支称为官方实现**。
  想声明"通过一致性档 C1–C13"，请跑 `cargo test` 并附上向量版本号。

## 引用

见 `CITATION.cff`。若你在论文/审计报告里用到，请引用规范版本（`warrant/1`）而非某个提交号。
