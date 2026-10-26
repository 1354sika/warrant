//! Warrant 认定层 —— **ZeroPage 的运行时权威实现**（引擎 workspace 叶子 crate）。
//!
//! 规范就在本 crate 旁：`crates/warrant/SPEC.md`（v1.0，**已冻结** 2026-10-11）、`crates/warrant/PROTOCOL.md`（线性代数协议：
//! 「凭什么算够格」）与 `crates/warrant/ADAPTER.md`。
//! **改轴 / 判据 / 状态机之前先读它们**（`PROTOCOL.md` 顶部有**落地状态表**：哪些条款已落地、哪些还没）。原 `信使系统` 仓已降为**蓝本与对拍参照**
//! （其 `vectors/` 仍作测试夹具：只读，不进二进制）。
//! 本 crate 不认识任何具体被控软件；禁止 import 执行层任何 crate。
//! 目标：通过 SPEC §7 全部一致性档 C1–C13，与 vectors/ 逐字节对拍。
//!
//! W2 扩建：rank（秩内核：轴/d_eff/I3 快照）与 graph（证据图：扇出/无环幂零），
//! 仍为纯函数叶子模块，不依赖执行层。

//! Warrant 认定层 —— 可独立复算的「谁说的、凭什么信、够不够格」。
//!
//! 规范就在本 crate 旁边：`SPEC.md`（v1.0，**已冻结** 2026-10-11）、`PROTOCOL.md`（线性代数协议：
//! 「凭什么算够格」）与 `ADAPTER.md`（宿主如何接入）。
//! **改轴 / 判据 / 状态机之前先读它们**（`PROTOCOL.md` 顶部有**落地状态表**）。
//!
//! 本 crate 不认识任何具体被控软件、不依赖任何宿主运行时；它只做三件事：
//! ① 规范序列化与事件 id（`canon`）；② 账本信封 / 去重 / 链位 / 签名验证（`ledger`）；
//! ③ 轴与门槛的投影与定级（`rank` / `projection` / `admission` / `graph` / `merkle`）。
//!
//! 目标：通过 SPEC §7 全部一致性档 C1–C13，与 `vectors/` 逐字节对拍。
//!
//! `rank`（秩内核：轴 / d_eff / I3 快照）与 `graph`（证据图：扇出 / 无环幂零）为纯函数叶子模块。
pub mod admission;
pub mod canon;
pub mod graph;
pub mod json;
pub mod ledger;
// 批锚 + 包含证明（纯函数叶子模块：不依赖任何执行层，不改既有条目语义）。
pub mod merkle;
pub mod projection;
pub mod rank;