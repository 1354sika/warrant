//! 签名与信任锚（**人的那一轴**）：密钥生成、待签字节、签名产生。
//!
//! 设计纪律（SPEC §2.6 / §10.2 P3）：**本库只验证，不托管私钥**。
//! 但"只验证"意味着没人能签 —— 那冻结永远是 0。所以这里补的是**离线签名工具**：
//! 私钥只在密钥文件里、只在 `freeze` 这一条命令里被读一次，用完即走；账本里只出现公钥。
//!
//! 关键：`verify_signatures` 会从 `key_id`（`ed25519:<hex 公钥>`）取出公钥验签，
//! 但**它证明不了"这把公钥就是某个人"** —— 那一步由 [`trusted_keys`]（信任锚）负责。
//! 两者必须同时通过，一个签名才算数。

use crate::canon;
use crate::json::Value;
use std::collections::HashSet;
use std::fmt;
use std::path::Path;

#[derive(Debug)]
pub struct SignError(pub String);

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for SignError {}

type R<T> = Result<T, SignError>;

fn err<T>(m: impl Into<String>) -> R<T> {
    Err(SignError(m.into()))
}

// ---------------------------------------------------------------------------
// base64url（无填充）——与 ledger 的解码口径一致
// ---------------------------------------------------------------------------

pub fn b64url_encode(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() * 4 + 2) / 3);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(T[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(T[(n & 63) as usize] as char);
        }
    }
    out
}

pub fn hex_encode(bytes: &[u8]) -> String {
    canon::hex(bytes)
}

// ---------------------------------------------------------------------------
// 密钥
// ---------------------------------------------------------------------------

/// 一把 ed25519 钥（文件形状：`{"alg","seed_hex","public_hex","key_id"}`）。
///
/// **`seed_hex` 是私钥**。本文件只在 `freeze` 时被读；不要把它放进账本目录、
/// 不要提交进 git（仓库的 `.gitignore` 已排除 `*.key.json`）。
pub struct KeyPair {
    pub key_id: String,
    pub public_hex: String,
    seed_hex: String,
}

impl KeyPair {
    /// 生成新钥（种子来自系统 CSPRNG）。
    pub fn generate() -> R<KeyPair> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| SignError(format!("CSPRNG 不可用：{e}")))?;
        Ok(Self::from_seed(&seed))
    }

    pub fn from_seed(seed: &[u8; 32]) -> KeyPair {
        let sk = ed25519_dalek::SigningKey::from_bytes(seed);
        let public_hex = hex_encode(sk.verifying_key().as_bytes());
        KeyPair {
            key_id: format!("ed25519:{public_hex}"),
            public_hex,
            seed_hex: hex_encode(seed),
        }
    }

    pub fn from_json(v: &Value) -> R<KeyPair> {
        let seed_hex = v
            .get("seed_hex")
            .and_then(|x| x.as_str())
            .ok_or_else(|| SignError("密钥文件缺 seed_hex".to_string()))?;
        let seed = hex_decode(seed_hex).ok_or_else(|| SignError("seed_hex 不是合法十六进制".to_string()))?;
        let arr: [u8; 32] = seed
            .try_into()
            .map_err(|_| SignError("seed 必须是 32 字节".to_string()))?;
        Ok(KeyPair::from_seed(&arr))
    }

    /// 密钥文件内容（**含私钥**，写入时请确保权限与位置）。
    pub fn to_json(&self) -> Value {
        Value::Object(vec![
            ("alg".to_string(), Value::Str("ed25519".to_string())),
            ("seed_hex".to_string(), Value::Str(self.seed_hex.clone())),
            ("public_hex".to_string(), Value::Str(self.public_hex.clone())),
            ("key_id".to_string(), Value::Str(self.key_id.clone())),
        ])
    }

    /// 签一条 freeze 声明，返回可直接放进 `signatures` 的对象。
    pub fn sign_freeze(
        &self,
        entry_id: &str,
        signer_id: &str,
        signed_at: &str,
        reason: Option<&str>,
        based_on: Option<&[String]>,
    ) -> R<Value> {
        let payload = canon::sig_payload_with(entry_id, "freeze", signer_id, signed_at, reason, based_on);
        let bytes = canon::sig_bytes(&payload).map_err(|e| SignError(format!("payload: {e}")))?;
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed_bytes(&self.seed_hex)?);
        use ed25519_dalek::Signer as _;
        let sig = sk.sign(&bytes);
        // SPEC §2.6：`reason` / `based_on` **必须挂到签名上**——它们已并入 payload，
        // 若不写进签名对象，验签方按"无 reason"重算 payload 就会对不上（实测踩过：
        // 表现为 "verification FAILED"，而密码学本身没错）。
        let mut kv = vec![
            ("alg".to_string(), Value::Str("ed25519".to_string())),
            ("key_id".to_string(), Value::Str(self.key_id.clone())),
            ("over".to_string(), Value::Str(entry_id.to_string())),
            ("role".to_string(), Value::Str("freeze".to_string())),
            ("signed_at".to_string(), Value::Str(signed_at.to_string())),
            ("sig".to_string(), Value::Str(b64url_encode(&sig.to_bytes()))),
            (
                "signer".to_string(),
                Value::Object(vec![
                    ("id".to_string(), Value::Str(signer_id.to_string())),
                    ("kind".to_string(), Value::Str("human".to_string())),
                ]),
            ),
        ];
        if let Some(r) = reason {
            if !r.is_empty() {
                kv.push(("reason".to_string(), Value::Str(r.to_string())));
            }
        }
        if let Some(b) = based_on {
            if !b.is_empty() {
                kv.push((
                    "based_on".to_string(),
                    Value::Array(b.iter().map(|x| Value::Str(x.clone())).collect()),
                ));
            }
        }
        Ok(Value::Object(kv))
    }
}

fn seed_bytes(hex: &str) -> R<[u8; 32]> {
    let b = hex_decode(hex).ok_or_else(|| SignError("seed 不是十六进制".to_string()))?;
    b.try_into().map_err(|_| SignError("seed 必须是 32 字节".to_string()))
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// 信任锚
// ---------------------------------------------------------------------------

/// 读 `<root>/trusted_keys.json` → 已登记的人类公钥集合。
///
/// 文件形状：`{"keys":[{"key_id":"ed25519:<hex>","note":"sikaq 的离线钥","added_at":"..."}]}`
pub fn trusted_keys(root: &Path) -> HashSet<String> {
    let p = root.join("trusted_keys.json");
    let Ok(text) = std::fs::read_to_string(&p) else {
        return HashSet::new();
    };
    let Ok(v) = crate::json::parse(&text) else {
        return HashSet::new();
    };
    let Some(arr) = v.get("keys").and_then(|x| x.as_array()) else {
        return HashSet::new();
    };
    arr.iter()
        .filter_map(|k| k.get("key_id").and_then(|x| x.as_str()).map(str::to_string))
        .collect()
}

/// 登记一把钥为"人"（人类认可它代表谁）。**必须由人执行**，不要让 agent 自己调。
pub fn trust_key(root: &Path, key_id: &str, note: &str, at: &str) -> R<()> {
    if !key_id.starts_with("ed25519:") && !key_id.starts_with("es256:") {
        return err("key_id 必须形如 ed25519:<hex 公钥> 或 es256:<hex 公钥>");
    }
    let p = root.join("trusted_keys.json");
    let mut keys: Vec<Value> = std::fs::read_to_string(&p)
        .ok()
        .and_then(|t| crate::json::parse(&t).ok())
        .and_then(|v| v.get("keys").and_then(|x| x.as_array()).map(|a| a.to_vec()))
        .unwrap_or_default();
    let already = keys
        .iter()
        .any(|k| k.get("key_id").and_then(|x| x.as_str()) == Some(key_id));
    if !already {
        keys.push(Value::Object(vec![
            ("key_id".to_string(), Value::Str(key_id.to_string())),
            ("note".to_string(), Value::Str(note.to_string())),
            ("added_at".to_string(), Value::Str(at.to_string())),
        ]));
    }
    let doc = Value::Object(vec![("keys".to_string(), Value::Array(keys))]);
    std::fs::create_dir_all(root).map_err(|e| SignError(format!("mkdir: {e}")))?;
    std::fs::write(&p, crate::adapter::to_json(&doc)).map_err(|e| SignError(format!("write: {e}")))?;
    Ok(())
}
