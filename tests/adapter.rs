//! 适配层端到端：三原语 → 轴 → 门槛。
//!
//! 这些测试是「接入层真的算数」的证据：不是"能写文件"，而是
//! **只有丁轴时永远不够格、加了甲/乙才够格**——与 PROTOCOL 一致。

use warrant::adapter::Adapter;
use warrant::json::Value;

fn tmp(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("warrant-adapter-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn obj(pairs: &[(&str, &str)]) -> Value {
    Value::Object(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), Value::Str(v.to_string())))
            .collect(),
    )
}

/// 只有丁轴（AI 自报）⇒ d_eff=1 ⇒ TENTATIVE。这正是"自说自话不算数"。
#[test]
fn ding_only_is_never_enough() {
    let dir = tmp("ding");
    let a = Adapter::open(&dir).unwrap();
    let (claim, seq) = a.act("agent:demo", obj(&[("file", "out.txt")]), "写文件").unwrap();
    assert_eq!(seq, 0, "第一条 claim 的 chain.seq 应为 0");
    let (_, seq2) = a
        .observe("agent:demo", &claim, "tool_receipt", "C0", obj(&[("file", "out.txt")]))
        .unwrap();
    assert_eq!(seq2, 1);

    let st = a.status(Some(&claim)).unwrap();
    assert_eq!(st.get("ok").and_then(|v| v.as_bool()), Some(true));
    let claims = st.get("claims").and_then(|v| v.as_array()).unwrap();
    assert_eq!(claims.len(), 1);
    let c = &claims[0];
    assert_eq!(c.get("d_eff").and_then(|v| v.as_int()), Some(1));
    assert_eq!(c.get("label").and_then(|v| v.as_str()), Some("TENTATIVE"));
    // 注意语义：`non_jia` = “≠甲”（丁也不是甲 ⇒ true）；真正表达“只有 AI”的是 `has_non_ai`。
    // 够格门槛是 `d_eff ≥ 2 且 non_jia` —— 只有丁轴时 d_eff=1，所以仍然不够格。
    assert_eq!(c.get("has_non_ai").and_then(|v| v.as_bool()), Some(false));
}

/// 甲（系统日志，新进程读回）+ 乙（软件自报）⇒ d_eff=2 且含非甲 ⇒ FREEZEABLE。
#[test]
fn two_independent_axes_are_freezeable() {
    let dir = tmp("two");
    let a = Adapter::open(&dir).unwrap();
    let (claim, _) = a
        .act("agent:demo", obj(&[("file", "out.txt"), ("bytes", "12")]), "写文件")
        .unwrap();
    a.observe(
        "engine:readback",
        &claim,
        "proc_spawn_readback",
        "C1",
        obj(&[("file", "out.txt"), ("bytes", "12")]),
    )
    .unwrap();
    a.observe(
        "tool:filesystem",
        &claim,
        "mcp_verify_readback",
        "C1",
        obj(&[("file", "out.txt"), ("bytes", "12")]),
    )
    .unwrap();

    let st = a.status(Some(&claim)).unwrap();
    let claims = st.get("claims").and_then(|v| v.as_array()).unwrap();
    let c = &claims[0];
    assert_eq!(c.get("d_eff").and_then(|v| v.as_int()), Some(2));
    assert_eq!(c.get("label").and_then(|v| v.as_str()), Some("FREEZEABLE"));
    assert_eq!(c.get("non_jia").and_then(|v| v.as_bool()), Some(true));
    let axes: Vec<&str> = c
        .get("axes")
        .and_then(|v| v.as_array())
        .unwrap()
        .iter()
        .filter_map(|x| x.as_str())
        .collect();
    assert!(axes.len() >= 2, "两轴应当并存，得到 {axes:?}");
}

/// 观测结果与 expect 不一致 ⇒ CONTRADICTED（不是"够格"，是"被推翻"）。
#[test]
fn mismatch_is_contradicted() {
    let dir = tmp("mis");
    let a = Adapter::open(&dir).unwrap();
    let (claim, _) = a
        .act("agent:demo", obj(&[("bytes", "12")]), "以为写了 12 字节")
        .unwrap();
    a.observe(
        "engine:readback",
        &claim,
        "proc_spawn_readback",
        "C1",
        obj(&[("bytes", "0")]),
    )
    .unwrap();
    let st = a.status(Some(&claim)).unwrap();
    let c = &st.get("claims").and_then(|v| v.as_array()).unwrap()[0];
    assert_eq!(c.get("state").and_then(|v| v.as_str()), Some("CONTRADICTED"));
}

/// 未知通道必须被拒：编个名字骗不到一根轴。
#[test]
fn unknown_channel_is_rejected() {
    let dir = tmp("chan");
    let a = Adapter::open(&dir).unwrap();
    let (claim, _) = a.act("agent:demo", obj(&[("k", "v")]), "").unwrap();
    let e = a.observe("x", &claim, "my_own_channel", "C1", obj(&[("k", "v")]));
    assert!(e.is_err(), "未知通道应当被拒");
    // 被拒后账本不变（仍然只有那条 claim）
    assert_eq!(a.entries().unwrap().len(), 1);
}

/// 链位自洽：每条 seq 连续、prev 指向上一条 id，verify 零错。
#[test]
fn chain_is_self_consistent() {
    let dir = tmp("chain");
    let a = Adapter::open(&dir).unwrap();
    for i in 0..5 {
        let (claim, seq) = a
            .act("agent:demo", obj(&[("i", &i.to_string())]), "第 i 次")
            .unwrap();
        assert_eq!(seq, 2 * i, "每轮 act 前面已经有一条 act + 一条 observe");
        let (_, seq_obs) = a
            .observe("tool", &claim, "tool_receipt", "C0", obj(&[("i", &i.to_string())]))
            .unwrap();
        assert_eq!(seq_obs, 2 * i + 1);
    }
    let v = a.verify().unwrap();
    assert_eq!(v.get("ok").and_then(|x| x.as_bool()), Some(true));
    assert_eq!(v.get("dedup").and_then(|x| x.as_int()), Some(10));
    assert_eq!(
        v.get("chain_errors").and_then(|x| x.as_array()).map(|a| a.len()),
        Some(0)
    );
}

/// capability 也进账本（事后不能改口"我当时没这个能力"）。
#[test]
fn capability_is_recorded() {
    let dir = tmp("cap");
    let a = Adapter::open(&dir).unwrap();
    let (id, seq) = a.capability("agent:demo", &["read_file", "write_file"]).unwrap();
    assert!(!id.is_empty());
    assert_eq!(seq, 0);
    let entries = a.entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].body.get("kind").and_then(|x| x.as_str()),
        Some("capability")
    );
}
