//! Moved from `crates/oneiron/src/claim/reaction_record.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::msgpack;
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
    let checked = msgpack::Entries::of(value)
        .and_then(|map| map.exact_keys(required, optional))
        .map_err(|error| match error {
            msgpack::MsgpackError::NotMap => invalid("reaction value must be a map"),
            msgpack::MsgpackError::DuplicateKey(_) => invalid("duplicate reaction value key"),
            msgpack::MsgpackError::MissingKey(_) => invalid("missing reaction value key"),
            _ => invalid("reaction value key"),
        })?;
    Ok(checked
        .as_slice()
        .iter()
        .filter_map(|(key, value)| Some((key.as_str()?, value)))
        .collect())
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
