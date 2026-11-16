//! Moved from `crates/oneiron/src/claim/reaction_record.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use rmpv::Value;

pub const KEY_CONNECTOR: &str = "connector";

pub const KEY_ID: &str = "id";

pub const MAX_CONNECTOR_BYTES: usize = 256;

pub const MAX_EXTERNAL_ID_BYTES: usize = 1024;

pub fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

pub fn exact_map<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Result<Vec<(&'a str, &'a Value)>> {
    let Value::Map(entries) = value else {
        return Err(invalid("reaction value must be a map"));
    };
    let mut seen = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        let key = key
            .as_str()
            .filter(|key| required.contains(key) || optional.contains(key))
            .ok_or_else(|| invalid("reaction value key"))?;
        if seen.iter().any(|(prior, _)| *prior == key) {
            return Err(invalid("duplicate reaction value key"));
        }
        seen.push((key, value));
    }
    if required
        .iter()
        .any(|key| !seen.iter().any(|(seen, _)| seen == key))
    {
        return Err(invalid("missing reaction value key"));
    }
    Ok(seen)
}

pub fn find<'a>(entries: &[(&str, &'a Value)], key: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find(|(candidate, _)| *candidate == key)
        .map(|(_, value)| *value)
}

pub fn string<'a>(entries: &[(&str, &'a Value)], key: &str) -> Result<&'a str> {
    find(entries, key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("reaction value string"))
}
