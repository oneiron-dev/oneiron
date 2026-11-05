//! Per-window native held-stamp records retained in STAMPS. CONTENT uses
//! its separate carrier, which also retains admitted born-with text.

use crate::window_key::WindowKey;
use oneiron_base::error::{Error, Result};

const PARTS_ERR: &str = "staged import window parts";

/// Encodes ordered `(WindowKey, exact bytes)` parts as an `rmpv` array of
/// `[String key, Binary bytes]` 2-tuples. Order and ALL entries preserved.
pub fn encode_staged_window_parts(parts: &[(WindowKey, Vec<u8>)]) -> Result<Vec<u8>> {
    let items = parts
        .iter()
        .map(|(key, bytes)| {
            rmpv::Value::Array(vec![
                rmpv::Value::from(key.as_str()),
                rmpv::Value::Binary(bytes.clone()),
            ])
        })
        .collect::<Vec<_>>();
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &rmpv::Value::Array(items))
        .map_err(|_| Error::CorruptedIndex(PARTS_ERR))?;
    Ok(out)
}

/// Decodes [`encode_staged_window_parts`]. Fail-closed: non-array, empty
/// list, non-2-tuple, non-string/invalid key, non-binary, duplicate key, or
/// trailing bytes all read [`Error::CorruptedIndex`]. An empty UPDATE byte
/// vec is NOT rejected here; the owning native parser judges it.
pub fn decode_staged_window_parts(raw: &[u8]) -> Result<Vec<(WindowKey, Vec<u8>)>> {
    let err = || Error::CorruptedIndex(PARTS_ERR);
    let mut cursor = std::io::Cursor::new(raw);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| err())?;
    if cursor.position() != raw.len() as u64 {
        return Err(err());
    }
    let rmpv::Value::Array(items) = value else {
        return Err(err());
    };
    if items.is_empty() {
        return Err(err());
    }
    let mut seen = std::collections::HashSet::new();
    let mut parts = Vec::with_capacity(items.len());
    for item in items {
        let rmpv::Value::Array(pair) = item else {
            return Err(err());
        };
        let [key, bytes] = pair.as_slice() else {
            return Err(err());
        };
        let Some(key) = key.as_str().and_then(WindowKey::try_new) else {
            return Err(err());
        };
        let rmpv::Value::Binary(bytes) = bytes else {
            return Err(err());
        };
        if !seen.insert(key.as_str().to_owned()) {
            return Err(err());
        }
        parts.push((key, bytes.clone()));
    }
    Ok(parts)
}
