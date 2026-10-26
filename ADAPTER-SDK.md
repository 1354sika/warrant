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

## 七 签名与冻结（人的那一轴）

`FREEZEABLE` 只是"够格"，**够格不等于事实**。要成为事实，必须有人签：

```bash
# ① 生成一把人类钥（只一次；文件里有私钥，放账本目录外）
warrantd keygen --out ~/warrant-human.key.json
# → {"ok":true,"key_id":"ed25519:<hex>", ...}

# ② 人登记这把钥（信任锚）——**这一步必须由人执行**
warrantd trust --root .warrant --key-id ed25519:<hex> --note "我的离线钥"

# ③ 签
warrantd freeze --root .warrant --claim <claim id> --key ~/warrant-human.key.json \
  --signer user:me --reason "确认"
# → {"claims":[{"state":"WARRANTED", ...}]}

# 只出待签字节、私钥不出本机（交给硬件令牌/其他机器签）
warrantd freeze --root .warrant --claim <id> --signer user:me --print-payload
```

三道闸都在代码里（`tests/signing.rs` 钉住）：

1. **证据不足不许冻**：`d_eff < 2` 或只有 AI 轴 ⇒ 直接报错；
2. **未登记的钥不算数**：`verify` 会把它列进 `trust_errors`（自造一对钥骗不过信任锚）；
3. **改一个字节就断**：链或签名必然报错。

## 八 甲轴不可伪造：预置探针（probe）

`observe --result '<json>'` 的 result 由调用方给 —— 如果 agent 自己填，"甲轴"就还是它说了算。
`--exec "<cmd>"` 也不行：命令串是它递进来的，它完全可以递一个只输出 `{"bytes":13}` 的假脚本
（**已默认关闭**，仅 `WARRANT_ALLOW_EXEC=1` 时可人工调试）。

**正解 = 预置探针（闭集）**：agent 只能选探针名 + 参数，不能递代码。

```bash
warrantd observe --root .warrant --subject <claim id> \
  --channel proc_spawn_readback --tier C1 \
  --probe file.sha256 --arg path=/path/to/out.txt
# → {"ok":true,"axis":"甲",...}
```

| 探针 | 参数 | 返回 |
|---|---|---|
| `file.stat` | `path` | `{path, exists, bytes}` |
| `file.sha256` | `path` | `{path, bytes, sha256}` |
| `dir.count` | `path`[, `ext`] | `{path, ext, count}` |
| `json.field` | `path`, `key` | `{path, key, value}` |
| `cmd.exit` | `exe`[, `args`(用 `\x1f` 分隔)] | `{exe, exit_code}` —— **不返回 stdout** |

两条纪律写进代码（`tests/probe_proxy.rs` 钉住）：
1. **未知探针一律拒绝**（"编个名字"骗不到轴，也不能执行任意代码）；
2. **`cmd.exit` 不交 stdout** —— 否则它就成了"agent 的通用 shell + 读文件器"。

⚠️ **`expect` 必须与探针返回同域**：`compare` 要求 `expect` 的**每个键**都在 result 里且相等，
缺键算 `unknown`（不算支持证据）。所以要么让 claim 的 `expect` 用探针会回显的键
（如 `{"path": "...", "sha256": "..."}`），要么别指望那条观测能产轴。

## 九 MCP 代理（默认开启）

探针解决了"测不了假"，但**只要 agent 可以选择不调 warrantd**，滞后与黑盒就还在。
所以真正的形态是**插在中间**：

```bash
warrantd mcp-proxy --root .warrant --upstream "python my_mcp_server.py" \
  --probe file.sha256 --arg path=/path/to/artifact
```

```text
agent ──tools/call──▶ warrantd mcp-proxy ──▶ 上游 MCP server
                       │ ① act：expect = agent 自己递的 arguments（不替它编预期）
                       │ ② 转发、取回执（先还回执，记账失败不卡业务）
                       └ ③ observe：tool_receipt（丁） + probe 实测（甲）
```

**它绕不过去**：agent 只能通过代理说话，每次 `tools/call` 都会自动落两条记录。
`tests/probe_proxy.rs` 用内存上游钉住三件事：每次调用都有 claim、探针成功产甲轴、
**探针失败绝不产出甲轴**（不伪造）。

**限制（诚实）**：本实现按串行请求假设（发一个等一个）。MCP 允许并发/通知，并发时响应可能错配；
需要并发请一条请求起一个代理进程。

## 九 跨主机聚合

每台机器各自维护一份账本（各自链独立自洽），聚合时只读地把条目并起来数轴 ——
甲轴在这台、乙轴在那台，才凑得出 `d_eff=2`：

```bash
warrantd aggregate /mnt/a/.warrant /mnt/b/.warrant
# → {"ok":true,"roots":[{"root":"...","chain_errors":[]}],"claims":[{"d_eff":2,...}]}
```

**诚实的限制**：聚合视图**不做跨本链校验**（两本的 `seq` 会冲突）；每本的链只看自己的
`chain_errors`。跨主机信任最终仍要回到人（谁认定哪台机器是可信的）。

## 十 多语言

| 语言 | 位置 | 状态 |
|---|---|---|
| Python | `sdk/python/warrant` | ✅ 真机跑通（`examples/agent_demo.py`） |
| TypeScript | `sdk/ts/warrant.ts` | ✅ 零依赖（node 18+），协议与 Python 逐字节相同 |
| Go | `sdk/go/warrant.go` | ⚠️ **未编译验证**（开发机无 Go 工具链）；协议相同，约 120 行 |

任何语言照 stdio 协议自己写十行即可，但**不要**自己实现 id / 链位 / 签名输入 —— 那是规范的事。

## 十一 发布

```bash
cargo publish --dry-run          # 打包检查（已通过：45 文件 / 619 KiB）
cargo publish                    # 需要 CARGO_REGISTRY_TOKEN，且能连到 crates.io
```

本仓已满足 `cargo package` 要求；`repository` 字段待填真实地址后即可发布。
