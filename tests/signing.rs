//! 签名与冻结：人的那一轴真的能签、真的被验、真的产生 WARRANTED。
//!
//! 这组测试钉住三件事（缺一件，"人签"就是装饰）：
//! ① 未登记公钥的签名**必须被拒**（信任锚）；
//! ② 证据不足（d_eff<2 或只有 AI 轴）**不许冻**；
//! ③ 冻过之后状态从 CONSISTENT → **WARRANTED**，且 `verify` 链/签名零错。

use warrant::adapter::Adapter;
use warrant::json::Value;
use warrant::signing::{trust_key, trusted_keys, KeyPair};

fn tmp(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("warrant-sign-{}-{}", tag, std::process::id()));
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

/// 造一个"够格"的 claim：两条独立轴、结果与预期一致。
fn freezeable(a: &Adapter) -> String {
    let (claim, _) = a.act("agent:demo", obj(&[("file", "out.txt")]), "写文件").unwrap();
    a.observe("engine:rb", &claim, "proc_spawn_readback", "C1", obj(&[("file", "out.txt")]))
        .unwrap();
    a.observe("tool:fs", &claim, "mcp_verify_readback", "C1", obj(&[("file", "out.txt")]))
        .unwrap();
    claim
}

fn state_of(a: &Adapter, claim: &str) -> String {
    let st = a.status(Some(claim)).unwrap();
    let c = &st.get("claims").and_then(|v| v.as_array()).unwrap()[0];
    c.get("state").and_then(|v| v.as_str()).unwrap().to_string()
}

/// 全流程：生成钥 → 人登记（信任锚）→ 冻结 → WARRANTED。
#[test]
fn human_freeze_makes_it_a_fact() {
    let dir = tmp("flow");
    let a = Adapter::open(&dir).unwrap();
    let claim = freezeable(&a);

    let before = state_of(&a, &claim);
    assert_eq!(before, "CONSISTENT", "两条一致观测，还没人签");

    let kp = KeyPair::generate().unwrap();
    trust_key(&dir, &kp.key_id, "test 人的钥", "2026-10-26T00:00:00Z").unwrap();
    assert!(trusted_keys(&dir).contains(&kp.key_id));

    let sig = kp
        .sign_freeze(&claim, "user:test", "2026-10-26T00:00:00Z", Some("确认"), None)
        .unwrap();
    a.add_signature(&claim, sig).unwrap();

    assert_eq!(state_of(&a, &claim), "WARRANTED", "人签之后应当是事实");

    let v = a.verify().unwrap();
    assert_eq!(v.get("chain_errors").and_then(|x| x.as_array()).map(|a| a.len()), Some(0));
    assert_eq!(
        v.get("signature_errors").and_then(|x| x.as_array()).map(|a| a.len()),
        Some(0),
        "签名应当过密码学校验；实际: {}",
        warrant::adapter::to_json(&v)
    );
    assert_eq!(
        v.get("trust_errors").and_then(|x| x.as_array()).map(|a| a.len()),
        Some(0),
        "登记过的钥应当过信任锚"
    );
}

/// 信任锚缺口：**没登记**的钥签出来的东西必须被判失败。
/// （否则任何人自造一对钥就能伪造"人类认定"——这正是 SPEC §2.6 要堵的洞。）
#[test]
fn untrusted_key_is_reported() {
    let dir = tmp("untrusted");
    let a = Adapter::open(&dir).unwrap();
    let claim = freezeable(&a);

    let kp = KeyPair::generate().unwrap(); // 故意不 trust
    let sig = kp
        .sign_freeze(&claim, "user:faker", "2026-10-26T00:00:00Z", None, None)
        .unwrap();
    a.add_signature(&claim, sig).unwrap();

    let v = a.verify().unwrap();
    // 签名本身是"密码学正确"的（同一把钥自洽），但信任锚必须拒绝它
    assert_eq!(
        v.get("signature_errors").and_then(|x| x.as_array()).map(|a| a.len()),
        Some(0)
    );
    assert_eq!(
        v.get("trust_errors").and_then(|x| x.as_array()).map(|a| a.len()),
        Some(1),
        "未登记的钥必须被信任锚点名"
    );
}

/// 篡改：改一个字节，签名必须失效。
#[test]
fn tampered_body_breaks_signature() {
    let dir = tmp("tamper");
    let a = Adapter::open(&dir).unwrap();
    let claim = freezeable(&a);
    let kp = KeyPair::generate().unwrap();
    trust_key(&dir, &kp.key_id, "", "2026-10-26T00:00:00Z").unwrap();
    let sig = kp
        .sign_freeze(&claim, "user:test", "2026-10-26T00:00:00Z", None, None)
        .unwrap();
    a.add_signature(&claim, sig).unwrap();

    // 直接把账本里该 claim 的 expect 改掉（模拟"事后改账"）
    let p = a.ledger_path();
    let text = std::fs::read_to_string(&p).unwrap();
    let tampered = text.replace("\"file\":\"out.txt\"", "\"file\":\"other.txt\"");
    assert_ne!(text, tampered, "测试前提：确实改到了内容");
    std::fs::write(&p, tampered).unwrap();

    let v = a.verify().unwrap();
    let chain_errs = v.get("chain_errors").and_then(|x| x.as_array()).unwrap().len();
    let sig_errs = v.get("signature_errors").and_then(|x| x.as_array()).unwrap().len();
    assert!(chain_errs + sig_errs > 0, "改过字节必须被抓到（chain 或 sig）");
}

/// append-only：加签名不修改任何历史行，只在末尾多一行。
#[test]
fn signing_appends_it_never_rewrites() {
    let dir = tmp("append");
    let a = Adapter::open(&dir).unwrap();
    let claim = freezeable(&a);
    let before = std::fs::read_to_string(a.ledger_path()).unwrap();

    let kp = KeyPair::generate().unwrap();
    trust_key(&dir, &kp.key_id, "", "2026-10-26T00:00:00Z").unwrap();
    let sig = kp.sign_freeze(&claim, "user:test", "2026-10-26T00:00:00Z", None, None).unwrap();
    a.add_signature(&claim, sig).unwrap();

    let after = std::fs::read_to_string(a.ledger_path()).unwrap();
    assert!(
        after.starts_with(&before),
        "历史字节必须一字不改（append-only）；实际前缀已变"
    );
    assert_eq!(after.lines().count(), before.lines().count() + 1);
}
