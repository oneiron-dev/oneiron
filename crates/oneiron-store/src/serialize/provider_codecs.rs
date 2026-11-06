//! Provider read formats share prepared rows and always null credential-bearing fields.
use crate::serialize::pack_format::PackFormat;
use serde_json::{Value, json};

pub fn contains_private_key(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim();
        line.starts_with("-----BEGIN ") && line.ends_with("PRIVATE KEY-----")
    })
}
