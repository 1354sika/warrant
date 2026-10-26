//! 适配层（**写侧**）：`capability` / `act` / `observe` 三原语 + 状态查询。
//!
//! 为什么这个模块长在这里（而不放进 `ledger`）：`ledger` 是**只读校验器**——
//! 它证明"账本没被动过"，但从不写账本。写侧一旦混进去，"校验者"就同时是"写入者"，
//! 那份校验的可信度就下降了。所以写侧独立成一层：**唯一会 append 的代码**。
//!
//! 三原语的语义来自 `ADAPTER.md`：
//! - `capability`：声明"我能做什么"（对齐宿主能力表，防止事后解释）。
//! - `act`：动手 —— 写一条 `claim`，带上**预期结果** `expect`（这是之后要比对的东西）。
//! - `observe`：观测 —— 写一条 `observation`，挂到某个 claim 上，带 `channel` / `tier` / `result`。
//!   **轴由 `channel` 决定**：`proc_spawn_readback`=甲 / `mcp_verify_readback`=乙 / `tool_receipt`=丁；
//!   未知通道**不产轴**（编个名字骗不到一根轴）。
//!
//! 不变量：追加只写文件尾、不改既有行；`chain.seq` = 去重后的条目数，`chain.prev` = 上一条 id。

use crate::canon;
use crate::json::Value;
use crate::ledger::{self, Entry};
use crate::projection;
use crate::rank;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// agent 动作类 claim 的类型名（与规范里的 `warrant://types/...` 同形）。
pub const T_AGENT_ACTION: &str = "warrant://types/agent.action@1";
/// 未指定 actor 时的默认值（**故意显眼**：写进账本就是要让人看见"没署名"）。
pub const ACTOR_UNKNOWN: &str = "agent:unknown";

/// 已知通道（其余通道**不产轴**，见 `rank::axis_of_channel`）。
pub const CHANNELS: [&str; 3] = ["proc_spawn_readback", "mcp_verify_readback", "tool_receipt"];
/// 观测档位（C0 最弱：不得支撑冻结）。
pub const TIERS: [&str; 4] = ["C0", "C1", "C2", "C3"];

#[derive(Debug)]
pub struct AdapterError(pub String);

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for AdapterError {}

type R<T> = Result<T, AdapterError>;

fn err<T>(msg: impl Into<String>) -> R<T> {
    Err(AdapterError(msg.into()))
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// epoch ms → UTC ISO 8601（civil_from_days；不引第三方日期库）。
pub fn utc_iso(ms: u64) -> String {
    let secs = ms / 1000;
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (h, mi, s) = ((rem / 3600) as u32, ((rem % 3600) / 60) as u32, (rem % 60) as u32);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// 规范序列化（也是本模块所有 CLI/协议输出的 JSON 形式）。
pub fn to_json(v: &Value) -> String {
    canon::canonical_bytes(v)
        .map(|b| String::from_utf8(b).unwrap_or_default())
        .unwrap_or_else(|e| format!("{{\"ok\":false,\"error\":\"canon: {e}\"}}"))
}

fn s(x: &str) -> Value {
    Value::Str(x.to_string())
}

/// 账本写侧适配器：一个目录 = 一份账本（`entries.jsonl`）。
pub struct Adapter {
    root: PathBuf,
}

impl Adapter {
    /// 打开（必要时创建）一份账本。只创建目录与空文件，**不写任何条目**。
    pub fn open(root: impl Into<PathBuf>) -> R<Self> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|e| AdapterError(format!("create {}: {e}", root.display())))?;
        let path = root.join("entries.jsonl");
        if !path.exists() {
            fs::write(&path, b"").map_err(|e| AdapterError(format!("init {}: {e}", path.display())))?;
        }
        Ok(Adapter { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn ledger_path(&self) -> PathBuf {
        self.root.join("entries.jsonl")
    }

    /// 读全部条目（原始行，含签名增长造成的重复行）。
    pub fn entries(&self) -> R<Vec<Entry>> {
        let p = self.ledger_path();
        let text = fs::read_to_string(&p).unwrap_or_default();
        ledger::load_jsonl(&text).map_err(|e| AdapterError(format!("{}: {e}", p.display())))
    }

    /// 追加一条（**唯一写入口**）：自算 seq / prev / id，落盘后返回 `(id, seq)`。
    fn append(&self, body: Value) -> R<(String, i64)> {
        self.append_full(body, Vec::new())
    }

    /// 带签名的追加（签名增长：同一 id 再追加一行，`dedup` 会把签名合并进首条）。
    fn append_full(&self, mut body: Value, sigs: Vec<Value>) -> R<(String, i64)> {
        let _guard = Lock::acquire(&self.root)?;
        let entries = self.entries()?;
        let merged = ledger::dedup(&entries);
        let seq = merged.len() as i64;
        let prev = merged.last().map(|e| e.id.clone()).unwrap_or_default();

        // 链位写进 body（在算 id 之前 —— id 覆盖 chain，改链位即改 id）
        if let Value::Object(kv) = &mut body {
            kv.retain(|(k, _)| k != "chain");
            kv.push(("chain".to_string(), ledger::chain_body(seq, &prev)));
        } else {
            return err("body 必须是对象");
        }
        let id = canon::event_id(&body).map_err(|e| AdapterError(format!("event_id: {e}")))?;

        let line = format!(
            "{{\"spec\":\"{}\",\"id\":\"{}\",\"body\":{},\"signatures\":{}}}\n",
            ledger::SPEC,
            id,
            to_json(&body),
            sigs_json(&sigs)
        );
        let mut f = OpenOptions::new()
            .append(true)
            .open(self.ledger_path())
            .map_err(|e| AdapterError(format!("open for append: {e}")))?;
        f.write_all(line.as_bytes())
            .map_err(|e| AdapterError(format!("append: {e}")))?;
        f.flush().ok();
        Ok((id, seq))
    }

    /// ① 声明能力（开工前一次）。记进账本 ⇒ 事后不能改口"我当时没这个能力"。
    pub fn capability(&self, actor: &str, caps: &[&str]) -> R<(String, i64)> {
        let at = utc_iso(now_ms());
        self.append(Value::Object(vec![
            ("kind".to_string(), s("capability")),
            ("actor".to_string(), s(actor)),
            (
                "caps".to_string(),
                Value::Array(caps.iter().map(|c| s(c)).collect()),
            ),
            ("at".to_string(), s(&at)),
        ]))
    }

    /// ② 动手：写一条 claim，`expect` 是**之后要拿来比对**的预期结果。
    pub fn act(&self, actor: &str, expect: Value, note: &str) -> R<(String, i64)> {
        if !matches!(expect, Value::Object(_)) {
            return err("`expect` 必须是对象（例如 {\"file_written\":true}）——它要能和观测结果逐键比对");
        }
        let at = utc_iso(now_ms());
        self.append(Value::Object(vec![
            ("kind".to_string(), s("claim")),
            ("type".to_string(), s(T_AGENT_ACTION)),
            ("actor".to_string(), s(actor)),
            ("expect".to_string(), expect),
            ("note".to_string(), s(note)),
            ("at".to_string(), s(&at)),
        ]))
    }

    /// ③ 观测：把"世界看到的结果"挂到 claim 上。**轴由 channel 决定**。
    pub fn observe(
        &self,
        actor: &str,
        subject: &str,
        channel: &str,
        tier: &str,
        result: Value,
    ) -> R<(String, i64)> {
        if !CHANNELS.contains(&channel) {
            return err(format!(
                "未知 channel {channel:?}：不产轴（可选 {:?}）。编个名字骗不到轴，这是设计。",
                CHANNELS
            ));
        }
        if !TIERS.contains(&tier) {
            return err(format!("未知 tier {tier:?}（可选 {TIERS:?}）"));
        }
        if !matches!(result, Value::Object(_)) {
            return err("`result` 必须是对象");
        }
        let at = utc_iso(now_ms());
        self.append(Value::Object(vec![
            ("kind".to_string(), s("observation")),
            ("type".to_string(), s(projection::T_OBS)),
            ("actor".to_string(), s(actor)),
            ("subject".to_string(), Value::Object(vec![("id".to_string(), s(subject))])),
            (
                "observation".to_string(),
                Value::Object(vec![
                    ("channel".to_string(), s(channel)),
                    ("tier".to_string(), s(tier)),
                    ("result".to_string(), result),
                    ("at".to_string(), s(&at)),
                ]),
            ),
            ("at".to_string(), s(&at)),
        ]))
    }

    /// 看结论：每条 claim 的九档状态 + `d_eff` + 轴。
    ///
    /// `d_eff` 由 `rank::judge` 算（与内核同一实现，不在这层重新发明判据）。
    pub fn status(&self, claim: Option<&str>) -> R<Value> {
        let entries = self.entries()?;
        let merged = ledger::dedup(&entries);
        let projected = projection::project_opts(&merged, None, false);
        let mut claims: Vec<Value> = Vec::new();
        for (id, state) in &projected {
            if let Some(only) = claim {
                if only != id {
                    continue;
                }
            }
            let mut kv = vec![
                ("id".to_string(), s(id)),
                ("state".to_string(), s(state)),
            ];
            if let Some(v) = rank::judge(&merged, id) {
                kv.push(("label".to_string(), s(v.label)));
                kv.push(("d_eff".to_string(), Value::Int(v.d_eff as i64)));
                kv.push((
                    "axes".to_string(),
                    Value::Array(v.axes.iter().map(|a| s(a.name())).collect()),
                ));
                kv.push(("non_jia".to_string(), Value::Bool(v.non_jia)));
                kv.push(("has_non_ai".to_string(), Value::Bool(v.has_non_ai)));
                kv.push(("snapshot".to_string(), s(&v.snapshot_sha256)));
            }
            claims.push(Value::Object(kv));
        }
        let facts = projection::facts(&merged, None);
        Ok(Value::Object(vec![
            ("ok".to_string(), Value::Bool(true)),
            ("gated".to_string(), Value::Bool(false)), // 未施加授权门控（见 projection::project_opts）
            ("root".to_string(), s(&self.root.display().to_string())),
            ("entries".to_string(), Value::Int(entries.len() as i64)),
            ("dedup".to_string(), Value::Int(merged.len() as i64)),
            ("claims".to_string(), Value::Array(claims)),
            (
                "facts".to_string(),
                Value::Array(facts.iter().map(|f| s(f)).collect()),
            ),
        ]))
    }

    /// 给既有条目**追加一个签名**（签名增长）。账本仍 append-only：新行同 id、多一个签名，
    /// `ledger::dedup` 在读取时合并 ⇒ 不改任何历史字节。
    ///
    /// 关键细节（踩过）：新行必须**沿用原 body 与原 id**。因为 `id = event_id(body)` 而
    /// body 里包含 `chain`——若像普通追加那样重算 chain，id 就变了，签名会挂到一条“新条目”上，
    /// 原 claim 永远拿不到 freeze 签名（表现为“签了但状态还是 CONSISTENT”）。
    pub fn add_signature(&self, entry_id: &str, sig: Value) -> R<(String, i64)> {
        let _guard = Lock::acquire(&self.root)?;
        let entries = self.entries()?;
        let merged = ledger::dedup(&entries);
        let base = merged
            .iter()
            .find(|e| e.id == entry_id)
            .ok_or_else(|| AdapterError(format!("账本里没有 {entry_id}")))?;
        let mut sigs = base.signatures.clone();
        sigs.push(sig);
        let line = format!(
            "{{\"spec\":\"{}\",\"id\":\"{}\",\"body\":{},\"signatures\":{}}}\n",
            ledger::SPEC,
            entry_id,
            to_json(&base.body),
            sigs_json(&sigs)
        );
        let mut f = OpenOptions::new()
            .append(true)
            .open(self.ledger_path())
            .map_err(|e| AdapterError(format!("open for append: {e}")))?;
        f.write_all(line.as_bytes())
            .map_err(|e| AdapterError(format!("append: {e}")))?;
        f.flush().ok();
        Ok((entry_id.to_string(), merged.len() as i64))
    }

    /// 只读复算：链位 + 逐条密码学签名。**任何第三方拿到同一文件都能跑出同样结果**。
    pub fn verify(&self) -> R<Value> {
        let entries = self.entries()?;
        let merged = ledger::dedup(&entries);
        let chain_errs = ledger::verify_chain(&entries);
        let sig_errs = ledger::verify_signatures(&entries);
        // 信任锚：签名“密码学正确”不等于“这个人”；key_id 必须落在已登记的人类公钥集里。
        let trusted = crate::signing::trusted_keys(&self.root);
        let trust_errs = ledger::check_key_trust(&entries, &trusted);
        let ok = chain_errs.is_empty() && sig_errs.is_empty() && trust_errs.is_empty();
        Ok(Value::Object(vec![
            ("ok".to_string(), Value::Bool(ok)),
            ("root".to_string(), s(&self.root.display().to_string())),
            ("entries".to_string(), Value::Int(entries.len() as i64)),
            ("dedup".to_string(), Value::Int(merged.len() as i64)),
            (
                "chain_errors".to_string(),
                Value::Array(chain_errs.iter().map(|e| s(e)).collect()),
            ),
            (
                "signature_errors".to_string(),
                Value::Array(sig_errs.iter().map(|e| s(e)).collect()),
            ),
            (
                "trust_errors".to_string(),
                Value::Array(trust_errs.iter().map(|e| s(e)).collect()),
            ),
            ("trusted_keys".to_string(), Value::Int(trusted.len() as i64)),
        ]))
    }
}

/// 把一个签名数组序列化成信封里的 `signatures` 字段（紧凑、与 body 同口径）。
fn sigs_json(sigs: &[Value]) -> String {
    let mut arr = String::from("[");
    for (i, s) in sigs.iter().enumerate() {
        if i > 0 {
            arr.push(',');
        }
        arr.push_str(&to_json(s));
    }
    arr.push(']');
    arr
}

/// 极简互斥：同一目录多进程同时 append 会写坏链位 ⇒ 用 `create_new` 锁文件串行。
struct Lock {
    path: PathBuf,
}

impl Lock {
    fn acquire(root: &Path) -> R<Self> {
        let path = root.join("entries.lock");
        for _ in 0..200 {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(_) => return Ok(Lock { path }),
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
        err(format!("取锁超时（{}）；若确认无进程在用，删掉该文件再试", path.display()))
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
