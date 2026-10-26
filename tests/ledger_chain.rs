//! 一致性档 C5（信使 SPEC.md 7 节）：账本链，篡改后必须在首个不一致处报错。
//!
//! 两路验证：
//! 甲、向量 vectors/ledger_cases.json（链位 + 链位哈希）
//! 乙、**信使仓里的真实账本** ledger/entries.jsonl —— 本实现要逐条算出
//! 与文件里完全相同的 id，并判定链位连续。合成向量远不如此有力。

use std::fs;
use std::path::PathBuf;
use warrant::{canon, json, ledger};

/// 夹具位置：默认本仓根（`vectors/`、`ledger/` 随仓发布）；`WARRANT_DIR` 可覆盖。
fn xinshi(parts: &[&str]) -> PathBuf {
    let base = std::env::var("WARRANT_DIR")
        .or_else(|_| std::env::var("WARRANT_XINSHI_DIR"))
        .unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_string());
    let mut p = PathBuf::from(base);
    for x in parts {
        p.push(x);
    }
    p
}

fn vectors(name: &str) -> serde_json::Value {
    let p = xinshi(&["vectors", name]);
    let t = fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {p:?}: {e}"));
    serde_json::from_str(&t).unwrap_or_else(|e| panic!("parse {p:?}: {e}"))
}

#[test]
fn c5_link_hash_matches_vectors() {
    let doc = vectors("ledger_cases.json");
    let recs = doc["records"].as_array().unwrap();
    assert_eq!(recs.len(), 3);
    for r in recs {
        let txt = serde_json::to_string(&r["chain"]).unwrap();
        let chain = json::parse(&txt).unwrap();
        let got = canon::link_hash(&chain).unwrap();
        assert_eq!(
            got,
            r["link"].as_str().unwrap(),
            "seq {} 的链位哈希不同",
            r["seq"]
        );
    }
}

#[test]
fn c5_vector_records_chain_positions_are_self_consistent() {
    let doc = vectors("ledger_cases.json");
    let recs = doc["records"].as_array().unwrap();
    let mut prev = String::new();
    for (i, r) in recs.iter().enumerate() {
        assert_eq!(r["chain"]["seq"].as_i64().unwrap(), i as i64, "seq 不连续");
        assert_eq!(
            r["chain"]["prev"].as_str().unwrap(),
            prev,
            "第 {i} 条 prev 指错"
        );
        prev = r["id"].as_str().unwrap().to_string();
    }
}

/// C5 的真实验证：在信使仓的真实账本上跑（609 行 / 437 去重条目的实测账）。
#[test]
fn c5_real_ledger_chain_verifies() {
    let p = xinshi(&["ledger", "entries.jsonl"]);
    let text = fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {p:?}: {e}"));
    let entries = ledger::load_jsonl(&text).expect("真实账本应当被本实现解析");
    let d = ledger::dedup(&entries);
    let errs = ledger::verify_chain(&entries);
    assert!(
        errs.is_empty(),
        "真实账本链校验失败（前 8 条）:\n{}",
        errs.iter().take(8).cloned().collect::<Vec<_>>().join("\n")
    );
    assert!(d.len() >= 80, "去重后条目数异常: {}", d.len());
    assert!(entries.len() > d.len(), "应当存在签名增长导致的重复行");
}

/// 篡改检测：改动一条 body 之后，链必须在**首个不一致处**报错。
/// 覆盖两种篡改方式，并证明本实现与向量 ledger_cases.json 的
/// `tamper.first_bad_index = 2` 语义一致。
#[test]
fn c5_tampering_is_caught_at_the_first_inconsistent_entry() {
    let p = xinshi(&["ledger", "entries.jsonl"]);
    let text = fs::read_to_string(&p).unwrap();
    let entries = ledger::load_jsonl(&text).unwrap();
    assert!(ledger::verify_chain(&entries).is_empty(), "干净账本不该报错");

    let d = ledger::dedup(&entries);
    let target_id = d[1].id.clone();

    // ---- 篡改甲：只改 body，不重算 id（偷懒的篡改者）----
    // 这一条自己就"id 与 body 不符"，篡改点落在 entry 1。
    let mut lazy = entries.clone();
    for e in lazy.iter_mut() {
        if e.id == target_id {
            if let warrant::json::Value::Object(o) = &mut e.body {
                o.push(("tampered".into(), warrant::json::Value::Str("yes".into())));
            }
        }
    }
    let errs = ledger::verify_chain(&lazy);
    assert!(!errs.is_empty(), "篡改后居然没报错");
    assert!(
        errs[0].starts_with("entry 1: id does not match body"),
        "首个不一致应当是 entry 1 的 id 失配，得到: {errs:?}"
    );

    // ---- 篡改乙：改 body 并重算 id（用心的篡改者）----
    // 这时 entry 1 自己已经自洽，但它**原来的 id** 被后继条目的 chain.prev 引用着，
    // 于是首个不一致落到 entry 2 —— 正是向量里的 first_bad_index = 2。
    let mut clever = entries.clone();
    let mut new_id = String::new();
    for e in clever.iter_mut() {
        if e.id == target_id {
            if let warrant::json::Value::Object(o) = &mut e.body {
                o.push(("tampered".into(), warrant::json::Value::Str("yes".into())));
            }
            new_id = canon::event_id(&e.body).unwrap();
            e.id = new_id.clone();
        }
    }
    assert_ne!(new_id, target_id, "改了 body 之后 id 应当变");
    let errs = ledger::verify_chain(&clever);
    assert!(
        errs[0].starts_with("entry 2: chain.prev="),
        "首个不一致应当是 entry 2 的链位（与向量的 first_bad_index=2 一致），得到: {errs:?}"
    );
}