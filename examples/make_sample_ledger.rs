//! make_sample_ledger — 生成一个**自洽可复算**的示例账本（`ledger/entries.jsonl`）。
//!
//! 为什么需要它：`c5_real_ledger_chain_verifies` 要在"真实账本"上证明链校验能力。
//! 开源仓库不能附带作者的私有账本，所以这份样本用本 crate 自己的 `canon::event_id`
//! 现场算出 id 与链位 —— 它是**可复现**的，任何人都能重跑并逐字节比对。
//!
//! 用法：
//!   cargo run --example make_sample_ledger            # 写 ledger/entries.jsonl
//!   cargo run --example make_sample_ledger -- out.jsonl
//!
//! 形状说明：
//! - 96 条去重条目（chain.seq 0..95，prev 指前一条 id，创世 prev 为 ""）；
//! - 每 10 条再追加一行"同 id + 多一条签名"的记录 ⇒ 演示 SPEC 2.7 的签名增长，
//!   总行数 106 > 去重 96；
//! - **签名是占位符**（不参与任何密码学校验），本文件只用于链位与去重路径。

use std::path::PathBuf;
use warrant::json::Value;
use warrant::{canon, ledger};

const ENTRIES: i64 = 96;
const GROWTH_EVERY: i64 = 10;

fn body_for(seq: i64, prev: &str) -> Value {
    Value::Object(vec![
        ("chain".to_string(), ledger::chain_body(seq, prev)),
        ("kind".to_string(), Value::Str("observation".to_string())),
        ("note".to_string(), Value::Str(format!("sample entry #{seq}"))),
        ("n".to_string(), Value::Int(seq)),
    ])
}

/// 一条占位签名：形状对齐 SPEC，`sig`/`key_id` 故意是不可验的假值。
fn placeholder_sig(idx: i64) -> Value {
    Value::Object(vec![
        ("alg".to_string(), Value::Str("ed25519".to_string())),
        ("key_id".to_string(), Value::Str(format!("sample-key-{idx}"))),
        ("over".to_string(), Value::Str(String::new())),
        ("role".to_string(), Value::Str("observation".to_string())),
        ("sig".to_string(), Value::Str("AA".repeat(64))),
        ("signed_at".to_string(), Value::Str("2026-01-01T00:00:00Z".to_string())),
        (
            "signer".to_string(),
            Value::Object(vec![
                ("id".to_string(), Value::Str("sample:generator".to_string())),
                ("kind".to_string(), Value::Str("process".to_string())),
            ]),
        ),
    ])
}

fn envelope(id: &str, body: &Value, sigs: &[Value]) -> String {
    let body_text = String::from_utf8(canon::canonical_body(body).expect("body 可规范化"))
        .expect("规范序列化必为 UTF-8");
    let mut sig_text = String::from("[");
    for (i, s) in sigs.iter().enumerate() {
        if i > 0 {
            sig_text.push(',');
        }
        let bytes = canon::canonical_bytes(s).expect("签名可规范化");
        sig_text.push_str(&String::from_utf8(bytes).expect("UTF-8"));
    }
    sig_text.push(']');
    format!(
        "{{\"spec\":\"{}\",\"id\":\"{}\",\"body\":{},\"signatures\":{}}}",
        ledger::SPEC,
        id,
        body_text,
        sig_text
    )
}

fn main() {
    let out: PathBuf = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ledger").join("entries.jsonl"));

    let mut lines: Vec<String> = Vec::new();
    let mut prev = String::new();
    let mut ids: Vec<String> = Vec::new();

    for seq in 0..ENTRIES {
        let body = body_for(seq, &prev);
        let id = canon::event_id(&body).expect("event_id 可计算");
        // 首行：无签名
        lines.push(envelope(&id, &body, &[]));
        // 签名增长：同 id 再来一行（带占位签名）
        if seq % GROWTH_EVERY == 0 {
            let mut sig = placeholder_sig(seq);
            if let Value::Object(kv) = &mut sig {
                for kv in kv.iter_mut() {
                    if kv.0 == "over" {
                        kv.1 = Value::Str(id.clone());
                    }
                }
            }
            lines.push(envelope(&id, &body, &[sig]));
        }
        prev = id.clone();
        ids.push(id);
    }

    if let Some(dir) = out.parent() {
        std::fs::create_dir_all(dir).expect("创建输出目录");
    }
    std::fs::write(&out, lines.join("\n") + "\n").expect("写账本");

    // 自检：生成的账本必须过得了本 crate 自己的链位校验
    let text = std::fs::read_to_string(&out).expect("回读");
    let entries = ledger::load_jsonl(&text).expect("解析");
    let errs = ledger::verify_chain(&entries);
    let d = ledger::dedup(&entries);
    println!(
        "wrote {} — lines={} dedup={} chain_errs={}",
        out.display(),
        entries.len(),
        d.len(),
        errs.len()
    );
    for e in errs.iter().take(5) {
        println!("  [chain] {e}");
    }
    if !errs.is_empty() {
        std::process::exit(2);
    }
}
