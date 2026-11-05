//! Identity-bearing facet classification and canonical PERSON body maps.

use oneiron_contracts::error::{Error, Result};
use rmpv::Value;
use std::collections::BTreeSet;

/// A FACET body naming `kind` `persona` or `relationship` carries identity,
/// which belongs on PERSON. Both write-admission refusals share this shape test.
pub fn is_identity_facet_body(data: &[u8]) -> bool {
    let Ok(rmpv::Value::Map(entries)) = rmpv::decode::read_value(&mut &data[..]) else {
        return false;
    };
    entries.iter().any(|(k, v)| {
        k.as_str() == Some("kind") && matches!(v.as_str(), Some("persona" | "relationship"))
    })
}

pub fn body_fields(data: &[u8]) -> Result<Vec<(Value, Value)>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let mut cursor = std::io::Cursor::new(data);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| invalid_companion("invalid persona record body"))?;
    if cursor.position() != data.len() as u64 {
        return Err(invalid_companion("trailing persona record bytes"));
    }
    let Value::Map(entries) = value else {
        return Err(invalid_companion("persona record body must be a map"));
    };
    let mut keys = BTreeSet::new();
    for (key, _) in &entries {
        if !keys.insert(
            key.as_str()
                .ok_or_else(|| invalid_companion("persona record key must be text"))?,
        ) {
            return Err(invalid_companion("duplicate persona record key"));
        }
    }
    Ok(entries)
}

pub fn invalid_companion(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}
