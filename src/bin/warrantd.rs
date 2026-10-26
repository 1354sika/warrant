//! `warrantd` —— 任何智能体都能接的那一层：三原语 CLI + stdio 守护进程。
//!
//! 两种接法（同一套实现，同一份账本）：
//!
//! ① **CLI**（shell / 任何语言 `subprocess` 都能用）：
//! ```text
//! warrantd act     --root .warrant --actor agent:demo --expect '{"file":"out.txt"}'
//! warrantd observe --root .warrant --subject sha256:... --channel proc_spawn_readback \
//!                  --tier C1 --result '{"file":"out.txt"}'
//! warrantd status  --root .warrant
//! warrantd verify  --root .warrant
//! ```
//!
//! ② **stdio 守护进程**（一次启动、多轮请求；Python/TS 的 SDK 走这条）：
//! ```text
//! warrantd serve --root .warrant
//! {"op":"act","actor":"agent:demo","expect":{"file":"out.txt"},"note":"写文件"}
//! {"ok":true,"id":"sha256:...","seq":0}
//! ```
//! 每行一个请求、每行一个响应；空行忽略；`{"op":"quit"}` 退出。
//!
//! 设计取舍：**不开端口**。stdio 不需要网络权限、不会被防火墙拦、不会和别的服务抢端口，
//! 也天然按会话隔离（谁起的进程谁说话）。

use std::collections::HashMap;
use std::io::{BufRead, Write};
use warrant::adapter::{Adapter, CHANNELS, TIERS};
use warrant::json::{self, Value};

fn usage() -> ! {
    println!(
        "warrantd —— 认定层接入（三原语 + 状态/复算）

用法：
  warrantd serve      --root <dir> [--root <dir> ...]        stdio JSONL 守护进程
  warrantd capability --root <dir> --actor <id> --caps a,b,c
  warrantd act        --root <dir> --actor <id> --expect '<json>' [--note '<text>']
  warrantd observe    --root <dir> --actor <id> --subject <claim id> \\
                      --channel <{:?}> --tier <{:?}> --result '<json>'
  warrantd status     --root <dir> [--claim <claim id>]
  warrantd verify     --root <dir>

约定：
  · 轴由 --channel 决定：proc_spawn_readback=甲 / mcp_verify_readback=乙 / tool_receipt=丁；其余通道不产轴。
  · 够格门槛：d_eff ≥ 2 且至少一条非甲（即至少一条 乙/丙 轴）。只有丁轴 ⇒ 永远不够格。
  · JSON 用严格档：仅整数、无浮点、无重复键（见 SPEC §3）。
",
        CHANNELS, TIERS
    );
    std::process::exit(2)
}

fn args_map(argv: &[String]) -> HashMap<String, String> {
    let mut m = HashMap::new();
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if let Some(k) = a.strip_prefix("--") {
            let v = argv.get(i + 1).cloned().unwrap_or_default();
            m.insert(k.to_string(), v);
            i += 2;
        } else {
            i += 1;
        }
    }
    m
}

fn parse_json_arg(m: &HashMap<String, String>, key: &str, required: bool) -> Result<Value, String> {
    match m.get(key) {
        Some(raw) => json::parse(raw).map_err(|e| format!("--{key} 不是合法 JSON（严格档）：{e}")),
        None if required => Err(format!("缺少 --{key}（严格 JSON，例如 '{{\"ok\":true}}'）")),
        None => Ok(Value::Object(vec![])),
    }
}

fn actor(m: &HashMap<String, String>) -> String {
    m.get("actor")
        .cloned()
        .unwrap_or_else(|| warrant::adapter::ACTOR_UNKNOWN.to_string())
}

fn root_of(m: &HashMap<String, String>) -> Result<Adapter, String> {
    let root = m
        .get("root")
        .cloned()
        .unwrap_or_else(|| ".warrant".to_string());
    Adapter::open(root).map_err(|e| e.to_string())
}

/// 单条请求 → 单条响应（CLI 与 serve 共用，保证两条接法行为一致）。
fn handle(adapter: &Adapter, op: &str, m: &HashMap<String, String>) -> Result<Value, String> {
    match op {
        "capability" => {
            let caps: Vec<&str> = m
                .get("caps")
                .map(|c| c.split(',').map(str::trim).filter(|x| !x.is_empty()).collect())
                .unwrap_or_default();
            let (id, seq) = adapter
                .capability(&actor(m), &caps)
                .map_err(|e| e.to_string())?;
            Ok(Value::Object(vec![
                ("ok".to_string(), Value::Bool(true)),
                ("id".to_string(), Value::Str(id)),
                ("seq".to_string(), Value::Int(seq)),
            ]))
        }
        "act" => {
            let expect = parse_json_arg(m, "expect", true)?;
            let note = m.get("note").cloned().unwrap_or_default();
            let (id, seq) = adapter
                .act(&actor(m), expect, &note)
                .map_err(|e| e.to_string())?;
            Ok(Value::Object(vec![
                ("ok".to_string(), Value::Bool(true)),
                ("id".to_string(), Value::Str(id)),
                ("seq".to_string(), Value::Int(seq)),
                ("axis".to_string(), Value::Null), // act 本身不产轴（它是被观测的对象）
            ]))
        }
        "observe" => {
            let subject = m.get("subject").cloned().unwrap_or_default();
            if subject.is_empty() {
                return Err("缺少 --subject（要观测的那条 claim id）".to_string());
            }
            let channel = m.get("channel").cloned().unwrap_or_default();
            let tier = m.get("tier").cloned().unwrap_or_else(|| "C1".to_string());
            let result = parse_json_arg(m, "result", true)?;
            let (id, seq) = adapter
                .observe(&actor(m), &subject, &channel, &tier, result)
                .map_err(|e| e.to_string())?;
            let axis = warrant::rank::axis_of_channel(&channel).map(|a| a.name());
            Ok(Value::Object(vec![
                ("ok".to_string(), Value::Bool(true)),
                ("id".to_string(), Value::Str(id)),
                ("seq".to_string(), Value::Int(seq)),
                (
                    "axis".to_string(),
                    axis.map(|a| Value::Str(a.to_string())).unwrap_or(Value::Null),
                ),
            ]))
        }
        "status" => adapter
            .status(m.get("claim").map(String::as_str))
            .map_err(|e| e.to_string()),
        "verify" => adapter.verify().map_err(|e| e.to_string()),
        other => Err(format!("未知 op {other:?}（可用：capability/act/observe/status/verify/quit）")),
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = argv.first().cloned() else { usage() };
    let m = args_map(&argv[1..]);

    if cmd == "serve" {
        let adapter = match root_of(&m) {
            Ok(a) => a,
            Err(e) => {
                println!("{e}");
                std::process::exit(2);
            }
        };
        let stdin = std::io::stdin();
        let mut out = std::io::stdout();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { break };
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            let v = match json::parse(t) {
                Ok(v) => v,
                Err(e) => {
                    let _ = writeln!(out, "{{\"ok\":false,\"error\":\"bad json: {e}\"}}");
                    let _ = out.flush();
                    continue;
                }
            };
            let op = v.get("op").and_then(|x| x.as_str()).unwrap_or("").to_string();
            if op == "quit" {
                break;
            }
            // 请求里的扁平字段 → 与 CLI 同形的参数表（两条接法共用 handle）
            let mut mm: HashMap<String, String> = HashMap::new();
            if let Value::Object(kv) = &v {
                for (k, val) in kv {
                    if k == "op" {
                        continue;
                    }
                    mm.insert(k.clone(), warrant::adapter::to_json(val));
                }
                // 字符串字段要还原成裸值（避免 handle 里再解析一层引号）
                for key in ["actor", "subject", "channel", "tier", "note", "claim", "caps"] {
                    if let Some(Value::Str(sv)) = v.get(key) {
                        mm.insert(key.to_string(), sv.clone());
                    }
                }
            }
            let resp = match handle(&adapter, &op, &mm) {
                Ok(v) => warrant::adapter::to_json(&v),
                Err(e) => format!(
                    "{{\"ok\":false,\"error\":{}}}",
                    warrant::adapter::to_json(&Value::Str(e))
                ),
            };
            let _ = writeln!(out, "{resp}");
            let _ = out.flush();
        }
        return;
    }

    let adapter = match root_of(&m) {
        Ok(a) => a,
        Err(e) => {
            println!("{{\"ok\":false,\"error\":{}}}", warrant::adapter::to_json(&Value::Str(e)));
            std::process::exit(2);
        }
    };
    match handle(&adapter, &cmd, &m) {
        Ok(v) => println!("{}", warrant::adapter::to_json(&v)),
        Err(e) => {
            println!(
                "{{\"ok\":false,\"error\":{}}}",
                warrant::adapter::to_json(&Value::Str(e))
            );
            std::process::exit(2);
        }
    }
}
