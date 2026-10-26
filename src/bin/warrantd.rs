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
  warrantd keygen     --out <file.key.json>                      生成 ed25519 密钥对（仅此一次）
  warrantd trust      --root <dir> --key-id <ed25519:hex> [--note '...']   登记人类公钥（信任锚）
  warrantd freeze     --root <dir> --claim <id> --key <file.key.json> --signer user:<id> \\
                      [--signed-at <RFC3339>] [--reason '...'] [--based-on <obs,obs2>] [--print-payload]
  warrantd aggregate  <rootA> <rootB> [... ]                     跨主机聚合（各自链独立校验 + 合并数轴）

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
            // 位置参数记进 `_pos`（aggregate 用：`warrantd aggregate A B C`）
            let e = m.entry("_pos".to_string()).or_insert_with(String::new);
            if !e.is_empty() {
                e.push(',');
            }
            e.push_str(a);
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
            // `--exec`：**采集权在 warrantd**——命令由本进程执行，agent 只能“请求跑”，
            // 不能“提供结果”。这是「甲轴不可伪造」的唯一实现方式：乙/丁轴的 result 由调用方给，
            // 而甲轴必须是本进程亲眼看到的。
            let result = if let Some(expr) = m.get("exec") {
                let out = std::process::Command::new("cmd")
                    .arg("/C")
                    .arg(expr)
                    .output()
                    .map_err(|e| format!("执行 --exec 失败：{e}"))?;
                let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
                match json::parse(&text) {
                    Ok(v @ Value::Object(_)) => v,
                    _ => Value::Object(vec![
                        (
                            "exit_code".to_string(),
                            Value::Int(out.status.code().unwrap_or(-1) as i64),
                        ),
                        ("stdout".to_string(), Value::Str(text.chars().take(2000).collect())),
                    ]),
                }
            } else {
                parse_json_arg(m, "result", true)?
            };
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
        "keygen" => {
            let out = m
                .get("out")
                .cloned()
                .unwrap_or_else(|| "warrant-human.key.json".to_string());
            let kp = warrant::signing::KeyPair::generate().map_err(|e| e.to_string())?;
            if std::path::Path::new(&out).exists() {
                return Err(format!("{out} 已存在：不覆盖密钥（先自己确认并手动删除）"));
            }
            std::fs::write(&out, warrant::adapter::to_json(&kp.to_json()))
                .map_err(|e| format!("写 {out}: {e}"))?;
            Ok(Value::Object(vec![
                ("ok".to_string(), Value::Bool(true)),
                ("key_id".to_string(), Value::Str(kp.key_id.clone())),
                ("public_hex".to_string(), Value::Str(kp.public_hex.clone())),
                ("path".to_string(), Value::Str(out)),
                (
                    "warn".to_string(),
                    Value::Str("该文件含私钥：放在账本目录外、不要入 git；下一步用 `warrantd trust` 登记它的公钥（信任锚）".to_string()),
                ),
            ]))
        }
        "trust" => {
            let kid = m.get("key-id").cloned().unwrap_or_default();
            if kid.is_empty() {
                return Err("缺少 --key-id（形如 ed25519:<hex 公钥>）".to_string());
            }
            let note = m.get("note").cloned().unwrap_or_default();
            let at = warrant::adapter::utc_iso(warrant::adapter::now_ms());
            warrant::signing::trust_key(adapter.root(), &kid, &note, &at)
                .map_err(|e| e.to_string())?;
            Ok(Value::Object(vec![
                ("ok".to_string(), Value::Bool(true)),
                ("key_id".to_string(), Value::Str(kid)),
                (
                    "warn".to_string(),
                    Value::Str("这一步必须由人执行：登记等于“我认可这把钥代表那个人”".to_string()),
                ),
            ]))
        }
        "freeze" => {
            let claim = m
                .get("claim")
                .cloned()
                .ok_or_else(|| "缺少 --claim（要冻结的那条 claim id）".to_string())?;
            let signer = m
                .get("signer")
                .cloned()
                .ok_or_else(|| "缺少 --signer（例如 user:sikaq）".to_string())?;
            let at = m
                .get("signed-at")
                .cloned()
                .unwrap_or_else(|| warrant::adapter::utc_iso(warrant::adapter::now_ms()));
            let reason = m.get("reason").cloned();
            let based_on: Option<Vec<String>> = m.get("based-on").map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|x| !x.is_empty())
                    .map(str::to_string)
                    .collect()
            });

            // 前置：证据够了才能冻（T1：d_eff ≥ 2；T2：至少一条非 AI 轴）
            let entries = adapter.entries().map_err(|e| e.to_string())?;
            let merged = warrant::ledger::dedup(&entries);
            let v = warrant::rank::judge(&merged, &claim)
                .ok_or_else(|| format!("账本里没有可判定的 claim {claim}"))?;
            if v.d_eff < 2 || !v.has_non_ai {
                return Err(format!(
                    "证据不足，不能冻结：d_eff={} has_non_ai={}（需要 d_eff ≥ 2 且至少一条非 AI 轴）",
                    v.d_eff, v.has_non_ai
                ));
            }

            if m.contains_key("print-payload") {
                let payload = warrant::canon::sig_payload_with(
                    &claim,
                    "freeze",
                    &signer,
                    &at,
                    reason.as_deref(),
                    based_on.as_deref(),
                );
                let bytes = warrant::canon::sig_bytes(&payload).map_err(|e| e.to_string())?;
                return Ok(Value::Object(vec![
                    ("ok".to_string(), Value::Bool(true)),
                    ("payload".to_string(), payload),
                    (
                        "payload_sig_input_hex".to_string(),
                        Value::Str(warrant::canon::hex(&bytes)),
                    ),
                    ("claim".to_string(), Value::Str(claim)),
                    ("d_eff".to_string(), Value::Int(v.d_eff as i64)),
                ]));
            }

            let key_path = m
                .get("key")
                .cloned()
                .ok_or_else(|| "缺少 --key（密钥文件）；或用 --print-payload 交给外部签".to_string())?;
            let text = std::fs::read_to_string(&key_path)
                .map_err(|e| format!("读密钥 {key_path}: {e}"))?;
            let kv = json::parse(&text).map_err(|e| format!("密钥文件不是合法 JSON: {e}"))?;
            let kp = warrant::signing::KeyPair::from_json(&kv).map_err(|e| e.to_string())?;

            // 信任锚：**必须先登记**，否则任何人自造一把钥都能“签”出一条人类签名
            let trusted = warrant::signing::trusted_keys(adapter.root());
            if !trusted.contains(&kp.key_id) {
                return Err(format!(
                    "这把钥没有登记为人类钥（{}）：请先 `warrantd trust --key-id {}`（由人执行）",
                    kp.key_id, kp.key_id
                ));
            }

            let sig = kp
                .sign_freeze(&claim, &signer, &at, reason.as_deref(), based_on.as_deref())
                .map_err(|e| e.to_string())?;
            let (id, seq) = adapter.add_signature(&claim, sig).map_err(|e| e.to_string())?;
            let mut out = match adapter.status(Some(&claim)).map_err(|e| e.to_string())? {
                v => v,
            };
            if let Value::Object(kv) = &mut out {
                kv.push(("frozen".to_string(), Value::Str(id)));
                kv.push(("seq".to_string(), Value::Int(seq)));
            }
            Ok(out)
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

    // 跨主机聚合：每台机器各自维护一份账本（各自链独立自洽），
    // 聚合时**只读**地把条目并起来数轴——这才有意义：甲轴在本机、乙轴在被控机。
    // 注意：合并后的 seq 会冲突（两本都从 0 开始），所以聚合视图**不做链校验**；
    // 每本的链由它自己的 verify 负责（下面逐本报 chain_errors）。
    if cmd == "aggregate" {
        let roots: Vec<String> = m
            .get("_pos")
            .map(|s| {
                s.split(',')
                    .filter(|x| !x.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        if roots.len() < 2 {
            println!(
                "{{\"ok\":false,\"error\":\"aggregate 至少需要两个位置参数：warrantd aggregate <rootA> <rootB>\"}}"
            );
            std::process::exit(2);
        }
        let mut parts: Vec<Value> = Vec::new();
        let mut all: Vec<warrant::ledger::Entry> = Vec::new();
        let mut chains_ok = true;
        for r in &roots {
            let adapter = match Adapter::open(r) {
                Ok(a) => a,
                Err(e) => {
                    println!(
                        "{{\"ok\":false,\"error\":{}}}",
                        warrant::adapter::to_json(&Value::Str(e.to_string()))
                    );
                    std::process::exit(2);
                }
            };
            let entries = match adapter.entries() {
                Ok(v) => v,
                Err(e) => {
                    println!(
                        "{{\"ok\":false,\"error\":{}}}",
                        warrant::adapter::to_json(&Value::Str(e.to_string()))
                    );
                    std::process::exit(2);
                }
            };
            let errs = warrant::ledger::verify_chain(&entries);
            if !errs.is_empty() {
                chains_ok = false;
            }
            parts.push(Value::Object(vec![
                ("root".to_string(), Value::Str(r.clone())),
                ("entries".to_string(), Value::Int(entries.len() as i64)),
                (
                    "chain_errors".to_string(),
                    Value::Array(errs.iter().map(|e| Value::Str(e.clone())).collect()),
                ),
            ]));
            all.extend(entries);
        }
        let merged = warrant::ledger::dedup(&all);
        let mut claims: Vec<Value> = Vec::new();
        for e in &merged {
            if e.body.get("kind").and_then(|x| x.as_str()) != Some("claim") {
                continue;
            }
            if let Some(v) = warrant::rank::judge(&merged, &e.id) {
                claims.push(Value::Object(vec![
                    ("id".to_string(), Value::Str(e.id.clone())),
                    ("label".to_string(), Value::Str(v.label.to_string())),
                    ("d_eff".to_string(), Value::Int(v.d_eff as i64)),
                    (
                        "axes".to_string(),
                        Value::Array(v.axes.iter().map(|a| Value::Str(a.name().to_string())).collect()),
                    ),
                    ("non_jia".to_string(), Value::Bool(v.non_jia)),
                    ("has_non_ai".to_string(), Value::Bool(v.has_non_ai)),
                ]));
            }
        }
        println!(
            "{}",
            warrant::adapter::to_json(&Value::Object(vec![
                ("ok".to_string(), Value::Bool(chains_ok)),
                ("roots".to_string(), Value::Array(parts)),
                ("merged_entries".to_string(), Value::Int(merged.len() as i64)),
                ("claims".to_string(), Value::Array(claims)),
                (
                    "note".to_string(),
                    Value::Str("聚合视图只数轴、不做跨本链校验（每本的链见 roots[].chain_errors）".to_string()),
                ),
            ]))
        );
        return;
    }

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
