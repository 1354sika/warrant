//! MCP 代理（**默认开启**）：让"每次工具调用都记账"成为结构，而不是自觉。
//!
//! 为什么需要它：`warrantd act/observe` 再好，只要 agent 可以选择不调，滞后与黑盒就还在。
//! 真正把它压下去的唯一办法是**插在 agent 与被控软件之间**——agent 只能通过代理说话，
//! 代理在转发前后自动记账，它绕不过去。
//!
//! 形态：stdio 上的 JSON-RPC 桥。
//!
//! ```text
//! agent ──tools/call──▶ warrantd mcp-proxy ──▶ 上游 MCP server（被控软件）
//!                        │ ① act：记下"要用什么工具、什么参数"
//!                        │ ② 转发并拿回执
//!                        └ ③ observe：工具回执（丁轴）+ 预置探针实测（甲轴）
//! ```
//!
//! **限制（诚实）**：本实现按"串行请求"假设（客户端发一个等一个）。MCP 允许并发/通知，
//! 并发时响应可能错配；如需并发请用每条请求一个代理进程。

use crate::adapter::Adapter;
use crate::json::Value;
use crate::probe;
use std::io::{BufRead, Write};

/// 每次 `tools/call` 之后自动跑的预置探针（产生**甲轴**）。
#[derive(Debug, Clone)]
pub struct ProbeSpec {
    pub name: String,
    pub args: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub actor: String,
    pub probes: Vec<ProbeSpec>,
    /// 上游命令（经 `cmd /C` 执行；生产环境请给绝对路径）
    pub upstream: String,
}

/// 上游抽象：生产是子进程，测试是内存桩（这样记账逻辑可以无外部依赖地验证）。
pub trait Upstream {
    fn send(&mut self, line: &str) -> Result<(), String>;
    fn recv(&mut self) -> Option<String>;
}

/// 串行 stdio 代理：读 agent 的一行 → 处理 → 写回一行。
pub fn run_with(
    adapter: &Adapter,
    cfg: &ProxyConfig,
    mut input: impl BufRead,
    mut output: impl Write,
    upstream: &mut dyn Upstream,
) -> Result<(), String> {
    let mut line = String::new();
    loop {
        line.clear();
        let n = input.read_line(&mut line).map_err(|e| format!("读 agent 输入: {e}"))?;
        if n == 0 {
            return Ok(()); // agent 关掉了 stdin
        }
        let text = line.trim_end_matches(['\r', '\n']).to_string();
        if text.trim().is_empty() {
            continue;
        }
        let msg = match crate::json::parse(&text) {
            Ok(v) => v,
            Err(e) => {
                // 不认识的字节：原样转发，不让代理成为解析瓶颈
                upstream.send(&text)?;
                if let Some(resp) = upstream.recv() {
                    writeln!(output, "{resp}").map_err(|e| e.to_string())?;
                    output.flush().ok();
                }
                let _ = e;
                continue;
            }
        };

        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let is_tool_call = method == "tools/call" && id.is_some();

        // ① 动手前先记账：**`expect` 用 agent 自己递的 arguments**。
        // 这一点很关键：甲轴的意义是“独立测量能否证实 **AI 所声称的东西**”，
        // 所以代理**不能替 agent 编造期待值**（argument 为空时只能退化成工具名）。
        let claim = if is_tool_call {
            let tool = msg
                .get("params")
                .and_then(|p| p.get("name"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let args = msg.get("params").and_then(|p| p.get("arguments")).cloned();
            let note = format!(
                "mcp tools/call {tool} args={}",
                args.as_ref()
                    .map(crate::adapter::to_json)
                    .unwrap_or_else(|| "null".to_string())
            );
            let expect = match &args {
                Some(Value::Object(kv)) if !kv.is_empty() => args.clone().unwrap(),
                _ => Value::Object(vec![("tool".to_string(), Value::Str(tool.clone()))]),
            };
            adapter.act(&cfg.actor, expect, &note).map(|(id, _)| id).ok()
        } else {
            None
        };

        // ② 转发并取回执
        upstream.send(&text)?;
        let response = if id.is_some() {
            // 请求：等到同 id 的响应（跳过上游主动发的 notification）
            loop {
                match upstream.recv() {
                    Some(r) => {
                        let same_id = crate::json::parse(&r)
                            .ok()
                            .and_then(|v| v.get("id").cloned())
                            .map(|x| x == id.clone().unwrap_or(Value::Null))
                            .unwrap_or(false);
                        if same_id || r.trim().is_empty() {
                            break Some(r);
                        }
                        // 不是这次的响应：先转给 agent，别吞掉
                        writeln!(output, "{r}").map_err(|e| e.to_string())?;
                        output.flush().ok();
                    }
                    None => break None,
                }
            }
        } else {
            None // notification：不等待
        };

        // ③ 回执写回 agent（**先还回执**，记账失败不能卡住业务）
        if let Some(r) = response {
            writeln!(output, "{r}").map_err(|e| e.to_string())?;
            output.flush().ok();
        }

        // ④ 观测：丙/丁轴（工具回执）+ 甲轴（预置探针实测）
        if let Some(claim) = claim {
            let tool = msg
                .get("params")
                .and_then(|p| p.get("name"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            // 工具回执：带上 arguments 的键（否则与 `expect` 不同域 ⇒ 永远 unknown ⇒ 不产丁轴）
            let args_v = msg.get("params").and_then(|p| p.get("arguments")).cloned();
            let mut receipt = match &args_v {
                Some(Value::Object(kv)) => kv.clone(),
                _ => Vec::new(),
            };
            receipt.retain(|(k, _)| k != "tool");
            receipt.push(("tool".to_string(), Value::Str(tool.clone())));
            let _ = adapter.observe(&cfg.actor, &claim, "tool_receipt", "C0", Value::Object(receipt));
            for p in &cfg.probes {
                if let Ok(v) = probe::run(&p.name, &p.args) {
                    let _ = adapter.observe(&cfg.actor, &claim, "proc_spawn_readback", "C1", v);
                }
            }
        }
    }
}

/// 生产用：把上游当成子进程（`cmd /C <upstream>`）。
pub struct ProcessUpstream {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: std::io::BufReader<std::process::ChildStdout>,
}

impl ProcessUpstream {
    pub fn spawn(cmdline: &str) -> Result<Self, String> {
        use std::process::{Command, Stdio};
        let mut child = Command::new("cmd")
            .arg("/C")
            .arg(cmdline)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("启动上游 {cmdline:?}: {e}"))?;
        let stdin = child.stdin.take().ok_or("上游 stdin 不可用")?;
        let stdout = std::io::BufReader::new(child.stdout.take().ok_or("上游 stdout 不可用")?);
        Ok(ProcessUpstream { child, stdin, stdout })
    }
}

impl Upstream for ProcessUpstream {
    fn send(&mut self, line: &str) -> Result<(), String> {
        writeln!(self.stdin, "{line}").map_err(|e| format!("写上游: {e}"))?;
        self.stdin.flush().map_err(|e| format!("flush 上游: {e}"))
    }
    fn recv(&mut self) -> Option<String> {
        let mut s = String::new();
        match self.stdout.read_line(&mut s) {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(s.trim_end_matches(['\r', '\n']).to_string()),
        }
    }
}

impl Drop for ProcessUpstream {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}
