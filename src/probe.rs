//! 预置探针（**甲轴的不可伪造性来源**）。
//!
//! 问题：`observe --exec "<cmd>"` 虽然由 warrantd 执行，但**命令串是 agent 递进来的** ——
//! 它完全可以递一个只输出 `{"bytes":13}` 的假脚本。那"甲轴"就又变成了它说了算。
//!
//! 解法：**探针是预置的**。agent 只能选探针名 + 参数，不能递代码。参数只用于指定"看哪个对象"
//! （路径 / 字段 / 命令），不能改变"怎么测量"。测量代码在编译期就固定在本模块里。
//!
//! 每个探针都返回**可直接与 claim 的 `expect` 逐键比对**的对象（含入参回显），
//! 所以调用方写 `expect` 时可以直接用探针回显的键名。

use crate::json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

/// 可用的探针名（**闭集**：不在这个列表里的一律拒绝）。
pub const NAMES: [&str; 5] = ["file.stat", "file.sha256", "dir.count", "json.field", "cmd.exit"];

fn s(x: impl Into<String>) -> Value {
    Value::Str(x.into())
}

fn obj(kv: Vec<(&str, Value)>) -> Value {
    Value::Object(kv.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn arg<'a>(args: &'a [(String, String)], key: &str) -> Option<&'a str> {
    args.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

fn need<'a>(args: &'a [(String, String)], key: &str) -> Result<&'a str, String> {
    arg(args, key).ok_or_else(|| format!("探针缺少参数 --arg {key}=..."))
}

/// 执行一个预置探针。**只认名字 + 参数，不接受代码**。
pub fn run(name: &str, args: &[(String, String)]) -> Result<Value, String> {
    match name {
        "file.stat" => {
            let p = need(args, "path")?;
            let path = Path::new(p);
            let bytes = std::fs::metadata(path).map(|m| m.len()).ok();
            Ok(obj(vec![
                ("path", s(p)),
                ("exists", Value::Bool(bytes.is_some())),
                ("bytes", bytes.map(|b| Value::Int(b as i64)).unwrap_or(Value::Null)),
            ]))
        }
        "file.sha256" => {
            let p = need(args, "path")?;
            let bytes = std::fs::read(p).map_err(|e| format!("读 {p}: {e}"))?;
            let mut h = Sha256::new();
            h.update(&bytes);
            let digest = h.finalize();
            Ok(obj(vec![
                ("path", s(p)),
                ("bytes", Value::Int(bytes.len() as i64)),
                ("sha256", s(crate::canon::hex(&digest))),
            ]))
        }
        "dir.count" => {
            let p = need(args, "path")?;
            let ext = arg(args, "ext");
            let mut n: i64 = 0;
            let rd = std::fs::read_dir(p).map_err(|e| format!("读目录 {p}: {e}"))?;
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                match ext {
                    Some(x) if !name.ends_with(x) => continue,
                    _ => n += 1,
                }
            }
            Ok(obj(vec![
                ("path", s(p)),
                ("ext", ext.map(s).unwrap_or(Value::Null)),
                ("count", Value::Int(n)),
            ]))
        }
        "json.field" => {
            let p = need(args, "path")?;
            let key = need(args, "key")?;
            let text = std::fs::read_to_string(p).map_err(|e| format!("读 {p}: {e}"))?;
            let v = crate::json::parse(&text).map_err(|e| format!("{p} 不是合法 JSON（严格档）: {e}"))?;
            let got = v
                .get(key)
                .cloned()
                .ok_or_else(|| format!("{p} 里没有字段 {key:?}"))?;
            Ok(obj(vec![("path", s(p)), ("key", s(key)), ("value", got)]))
        }
        // 只返回**退出码**，不返回 stdout —— 否则它就成了「agent 的通用 shell + 读文件器」。
        "cmd.exit" => {
            let exe = need(args, "exe")?;
            let mut c = std::process::Command::new(exe);
            if let Some(rest) = arg(args, "args") {
                for a in rest.split('\u{1f}').filter(|x| !x.is_empty()) {
                    c.arg(a);
                }
            }
            let out = c.output().map_err(|e| format!("执行 {exe}: {e}"))?;
            Ok(obj(vec![
                ("exe", s(exe)),
                ("exit_code", Value::Int(out.status.code().unwrap_or(-1) as i64)),
            ]))
        }
        other => Err(format!(
            "未知探针 {other:?}：探针是**闭集**，只能用 {NAMES:?}。\
             agent 不能自己写测量代码 —— 这是「甲轴不可伪造」的实现方式。"
        )),
    }
}
