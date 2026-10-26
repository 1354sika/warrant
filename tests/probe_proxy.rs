//! 两个隐患的钉子：
//! ① **甲轴不可伪造** —— 探针是闭集，agent 只能选名字+参数，不能递代码；
//! ② **默认开启** —— 走 MCP 代理时，每次 tools/call 都自动记账，agent 绕不过去。

use warrant::adapter::Adapter;
use warrant::json::Value;
use warrant::probe;
use warrant::proxy::{run_with, ProbeSpec, ProxyConfig, Upstream};

fn tmp(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("warrant-pp-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn arg(k: &str, v: &str) -> (String, String) {
    (k.to_string(), v.to_string())
}

// ---------------------------------------------------------------------------
// ① 探针：闭集 + 只读测量
// ---------------------------------------------------------------------------

#[test]
fn probe_is_a_closed_set() {
    let err = probe::run("shell.exec", &[arg("cmd", "echo hi")]).unwrap_err();
    assert!(err.contains("闭集"), "未知探针必须被拒，得到: {err}");
    // 名字表是编译期常量，agent 无法扩充
    assert_eq!(probe::NAMES.len(), 5);
}

#[test]
fn file_sha256_measures_for_real() {
    let dir = tmp("sha");
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("a.txt");
    std::fs::write(&f, b"hello warrant").unwrap();
    let v = probe::run("file.sha256", &[arg("path", f.to_str().unwrap())]).unwrap();
    assert_eq!(v.get("bytes").and_then(|x| x.as_int()), Some(13));
    let sha = v.get("sha256").and_then(|x| x.as_str()).unwrap();
    assert_eq!(sha.len(), 64, "sha256 应是 64 位十六进制");
    // 内容变了，测量值必须变（这正是"agent 说没改"骗不过的地方）
    std::fs::write(&f, b"hello warrant!").unwrap();
    let v2 = probe::run("file.sha256", &[arg("path", f.to_str().unwrap())]).unwrap();
    assert_ne!(v.get("sha256"), v2.get("sha256"));
}

#[test]
fn cmd_exit_does_not_leak_stdout() {
    let v = probe::run(
        "cmd.exit",
        &[arg("exe", "cmd"), arg("args", "/C\u{1f}exit\u{1f}3")],
    )
    .unwrap();
    assert_eq!(v.get("exit_code").and_then(|x| x.as_int()), Some(3));
    assert!(
        v.get("stdout").is_none(),
        "cmd.exit 不允许把 stdout 交出去（否则它就是个通用 shell）"
    );
}

// ---------------------------------------------------------------------------
// ② MCP 代理：每次 tools/call 自动记账
// ---------------------------------------------------------------------------

/// 内存上游：按序吐出预设响应（不依赖任何外部 MCP server）。
struct FakeUpstream {
    sent: Vec<String>,
    replies: std::collections::VecDeque<String>,
}

impl Upstream for FakeUpstream {
    fn send(&mut self, line: &str) -> Result<(), String> {
        self.sent.push(line.to_string());
        Ok(())
    }
    fn recv(&mut self) -> Option<String> {
        self.replies.pop_front()
    }
}

#[test]
fn proxy_records_every_tool_call() {
    let dir = tmp("proxy");
    let a = Adapter::open(&dir).unwrap();
    let cfg = ProxyConfig {
        actor: "agent:via-proxy".to_string(),
        probes: vec![ProbeSpec {
            name: "file.sha256".to_string(),
            args: vec![arg("path", "definitely-missing-file")], // 不存在 ⇒ 探针失败 ⇒ 不写甲轴
        }],
        upstream: "fake".to_string(),
    };
    let call = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"out.txt"}}}"#;
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
    let input = format!("{init}\n{call}\n");
    let mut out: Vec<u8> = Vec::new();
    let mut up = FakeUpstream {
        sent: Vec::new(),
        replies: std::collections::VecDeque::from(vec![
            r#"{"jsonrpc":"2.0","id":1,"result":{"capabilities":{}}}"#.to_string(),
            r#"{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"ok"}]}}"#.to_string(),
        ]),
    };

    run_with(&a, &cfg, input.as_bytes(), &mut out, &mut up).unwrap();

    // 回执必须原样回到 agent（记账失败不能卡业务）
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("\"id\":7"), "tools/call 的响应必须写回 agent");
    // 两次请求都转发了
    assert_eq!(up.sent.len(), 2);

    // 账本：1 条 claim（tools/call）+ 1 条观测（工具回执，丁轴）
    let st = a.status(None).unwrap();
    assert_eq!(st.get("entries").and_then(|x| x.as_int()), Some(2));
    let claims = st.get("claims").and_then(|x| x.as_array()).unwrap();
    assert_eq!(claims.len(), 1, "initialize 不该被记成 claim");
    let c = &claims[0];
    assert_eq!(c.get("label").and_then(|x| x.as_str()), Some("TENTATIVE"));
    assert_eq!(c.get("d_eff").and_then(|x| x.as_int()), Some(1), "只有丁轴 ⇒ 1");
    assert_eq!(
        c.get("has_non_ai").and_then(|x| x.as_bool()),
        Some(false),
        "丁轴不算非 AI 轴"
    );
}

/// 代理 + 可用探针 ⇒ 甲轴成立；再补一条乙轴就够格。
#[test]
fn proxy_with_working_probe_produces_metre_axis() {
    let dir = tmp("proxy2");
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("artifact.txt");
    std::fs::write(&target, b"hello warrant").unwrap();

    let a = Adapter::open(&dir).unwrap();
    let cfg = ProxyConfig {
        actor: "agent:via-proxy".to_string(),
        probes: vec![ProbeSpec {
            name: "file.sha256".to_string(),
            args: vec![arg("path", target.to_str().unwrap())],
        }],
        upstream: "fake".to_string(),
    };
    // agent 的 arguments 就是它的"声称" ⇒ 代理把它当作 expect；探针实测必须与之同域
    let args_json = warrant::adapter::to_json(&Value::Object(vec![(
        "path".to_string(),
        Value::Str(target.to_str().unwrap().to_string()),
    )]));
    let call = format!(
        r#"{{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{{"name":"write_file","arguments":{args_json}}}}}"#
    );
    let mut out: Vec<u8> = Vec::new();
    let mut up = FakeUpstream {
        sent: Vec::new(),
        replies: std::collections::VecDeque::from(vec![
            r#"{"jsonrpc":"2.0","id":9,"result":{"isError":false}}"#.to_string(),
        ]),
    };
    run_with(&a, &cfg, format!("{call}\n").as_bytes(), &mut out, &mut up).unwrap();

    let st = a.status(None).unwrap();
    eprintln!("DIAG {}", warrant::adapter::to_json(&st));
    let c = &st.get("claims").and_then(|x| x.as_array()).unwrap()[0];
    assert_eq!(
        c.get("d_eff").and_then(|x| x.as_int()),
        Some(2),
        "甲+丁 = 2 轴；实际 d_eff={:?} axes={:?} state={:?}",
        c.get("d_eff"),
        c.get("axes"),
        c.get("state")
    );
    assert_eq!(c.get("label").and_then(|x| x.as_str()), Some("FREEZEABLE"));
    let axes: Vec<&str> = c
        .get("axes")
        .and_then(|x| x.as_array())
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(axes.contains(&"甲"), "探针应当产出甲轴，得到 {axes:?}");
}

/// 探针失败时不能"假装有甲轴"：账本里只该有丁轴。
#[test]
fn failing_probe_never_fakes_an_axis() {
    let dir = tmp("proxy3");
    let a = Adapter::open(&dir).unwrap();
    let cfg = ProxyConfig {
        actor: "agent:via-proxy".to_string(),
        probes: vec![ProbeSpec {
            name: "file.sha256".to_string(),
            args: vec![arg("path", "no-such-file-anywhere")],
        }],
        upstream: "fake".to_string(),
    };
    let call = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"t","arguments":{}}}"#;
    let mut out: Vec<u8> = Vec::new();
    let mut up = FakeUpstream {
        sent: Vec::new(),
        replies: std::collections::VecDeque::from(vec![
            r#"{"jsonrpc":"2.0","id":3,"result":{}}"#.to_string(),
        ]),
    };
    run_with(&a, &cfg, format!("{call}\n").as_bytes(), &mut out, &mut up).unwrap();
    let st = a.status(None).unwrap();
    let c = &st.get("claims").and_then(|x| x.as_array()).unwrap()[0];
    assert_eq!(c.get("d_eff").and_then(|x| x.as_int()), Some(1), "探针失败 ⇒ 只剩丁轴");
    assert!(
        !c.get("axes").and_then(|x| x.as_array()).unwrap().iter().any(|v| v.as_str() == Some("甲")),
        "探针失败绝不能产出甲轴"
    );
    assert_eq!(Value::Bool(true).as_bool(), Some(true)); // 保持 Value 引入有用途
}
