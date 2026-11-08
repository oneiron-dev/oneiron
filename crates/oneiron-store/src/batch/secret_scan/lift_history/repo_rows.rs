//! Repo-mutation oplog and proposal rows (FIX 2890). Their bytes stay as
//! they are, hash-bound as the other retained rows are; each is read as its
//! stored texts, and a hit gets the carrier-text mark a code document's or
//! a typed body's does (owner ruling C2), then a value-free proposal. A
//! reviewed proposal's file bytes are read among its texts, never rewritten.

use heed::{RoTxn, RwTxn};
use rmpv::Value;

use oneiron_base::error::Result;

/// The carrier texts of stored row `stored`: every string and byte string
/// its MessagePack holds, a file's bytes spelled as byte values among
/// them; the bytes as one text when they decode as nothing else.
pub fn texts_of(stored: &[u8]) -> Vec<String> {
    if stored.is_empty() {
        return Vec::new();
    }
    let mut cursor = std::io::Cursor::new(stored);
    if let Ok(value) = rmpv::decode::read_value(&mut cursor)
        && cursor.position() == stored.len() as u64
    {
        let mut texts = Vec::new();
        collect(&value, &mut texts);
        if !texts.is_empty() {
            return texts;
        }
        return Vec::new();
    }
    vec![String::from_utf8_lossy(stored).into_owned()]
}

/// Every string `value` holds, into `texts`: a byte array as the text its
/// bytes spell.
fn collect(value: &Value, texts: &mut Vec<String>) {
    match value {
        Value::String(text) => {
            let text = text
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| String::from_utf8_lossy(text.as_bytes()).into_owned());
            if !text.is_empty() {
                texts.push(text);
            }
        }
        Value::Binary(bytes) => {
            if !bytes.is_empty() {
                texts.push(String::from_utf8_lossy(bytes).into_owned());
            }
        }
        Value::Array(items) => {
            if !items.is_empty()
                && items
                    .iter()
                    .all(|item| item.as_u64().is_some_and(|byte| byte <= u64::from(u8::MAX)))
            {
                let bytes = items
                    .iter()
                    .map(|item| u8::try_from(item.as_u64().unwrap_or_default()).unwrap_or_default())
                    .collect::<Vec<_>>();
                texts.push(String::from_utf8_lossy(&bytes).into_owned());
            } else {
                for item in items {
                    collect(item, texts);
                }
            }
        }
        Value::Map(entries) => {
            for (key, value) in entries {
                collect(key, texts);
                collect(value, texts);
            }
        }
        _ => {}
    }
}
