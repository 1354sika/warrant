# 接入层：让任何 agent 三行接上

> `warrant` 内核只做三件事：**校验账本、数轴、卡出口**。它不认识"谁在干活"。
> 这一层（`warrantd` + `sdk/`）补的正是那个缺口：**动作与观测怎么落进账本**。

## 一 为什么需要一层

没有这一层，每种 agent 都要自己实现"怎么算 id、怎么接链、什么算一条观测"——
实现一次错一次，且**不同实现算出来的 d_eff 不可比**。有了这一层：

- **只有一处写侧**（`src/adapter.rs`），别人不可能"顺手"写坏链位；
- **通道固定**，编个新名字骗不到轴；
- **CLI / stdio 同一套实现**，Python、TS、shell、Go 的行为完全一致。

## 二 三原语

| 原语 | 做什么 | 写进账本的 `kind` | 产轴吗 |
|---|---|---|---|
| `capability` | 开工前声明"我能做什么" | `capability` | 否 |
| `act` | 动手，带**预期结果** `expect` | `claim`（`type=warrant://types/agent.action@1`） | 否（它是**被观测的对象**） |
| `observe` | 把"世界看到的结果"挂到 claim 上 | `observation`（`subject.id` = claim id） | **是**，由 `channel` 决定 |

### 通道 → 轴（写错即报错，不静默降级）

| channel | 轴 | 含义 | 谁能伪造 |
|---|---|---|---|
| `proc_spawn_readback` | 甲（系统日志） | 我方独立：**新进程**读回 / 离线复算 | 需要能改外部世界 |
| `mcp_verify_readback` | 乙（软件自报） | 被控软件自己的 verify 回读 | 被控软件本身 |
| `tool_receipt` | 丁（AI 自报） | 同会话工具回执 | **AI 自己**，所以永不计入够格 |
| —（签名） | 丙（人） | 人类 freeze 签名 | 需要私钥 |

**够格门槛**：`d_eff ≥ 2` 且至少一条非甲（即至少一条 乙/丙 轴）。
只有丁轴 ⇒ `TENTATIVE`，永远不够格 —— 这就是"自说自话不算数"的实现。

## 三 两种接法

### ① CLI（任何语言，`subprocess` 即可）

```bash
warrantd capability --root .warrant --actor agent:demo --caps write_file,read_file
# → {"ok":true,"id":"sha256:...","seq":0}

warrantd act --root .warrant --actor agent:demo --expect '{"file":"out.txt","bytes":13}'
# → {"ok":true,"id":"sha256:...","seq":1}

warrantd observe --root .warrant --actor engine:readback --subject sha256:... \
  --channel proc_spawn_readback --tier C1 --result '{"file":"out.txt","bytes":13}'
# → {"ok":true,"axis":"甲",...}

warrantd status --root .warrant
# → {"ok":true,"claims":[{"state":"CONSISTENT","label":"FREEZEABLE","d_eff":2,"axes":["甲","乙"]}],"facts":[]}

warrantd verify --root .warrant
# → {"ok":true,"chain_errors":[],"signature_errors":[]}
```

### ② stdio 守护进程（一次启动、多轮请求）

```bash
warrantd serve --root .warrant
```
每行一个 JSON 请求、每行一个 JSON 响应：

```json
{"op":"act","actor":"agent:demo","expect":{"file":"out.txt"},"note":"写文件"}
{"ok":true,"id":"sha256:...","seq":1}
```

**为什么不开端口**：stdio 不需要网络权限、不被防火墙拦、不抢端口，天然按会话隔离
（谁起的进程谁说话）。要跨进程共享，就让它们指向**同一个 `--root`**。

## 四 Python：三行接入

```python
from warrant import Warrant
w = Warrant(".warrant")
claim = w.act({"file": "out.txt", "bytes": 13}, note="写文件")
w.observe(claim, "proc_spawn_readback", {"file": "out.txt", "bytes": 13}, tier="C1")
print(w.label(claim))     # FREEZEABLE / TENTATIVE
```

完整可跑示例：`examples/agent_demo.py`（真写文件、真用另一进程读回、真跑判定）。

其他语言照 stdio 协议实现十行即可；**不要**自己实现 id/链位算法——那是规范的事。

## 五 诚实的边界

- **它不阻止 agent 撒谎**。会撒谎的 agent 一样能调 `observe` 并填假数字。
  它保证的是：**假数字骗不过甲轴**（新进程真读回），且**只有自报时永远不够格**。
- **它不读你的内容**。判定只数"有几个独立来源"，不判断"日志里写了什么"。
- **它不保证结论正确**，只保证"证据不够时没有权力说出口"。
- **没有做**（下一步）：签名/冻结的 CLI（现在要人签仍走宿主）、跨主机聚合、语言 SDK 只给了 Python。

## 六 落盘形状

```
.warrant/
├─ entries.jsonl   # append-only，一行一条；chain.seq / chain.prev 自洽
└─ entries.lock    # 写入期间的互斥锁（进程异常退出后可手工删除）
```

任何人拿到 `entries.jsonl` + 本仓代码，都能跑 `warrantd verify` 得到同样结论——
这就是"可独立复算"的含义。
