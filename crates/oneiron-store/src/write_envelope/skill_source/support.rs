//! Bounded hub value parsing helpers.
//! Entry: `exact_map`.
//! Defines its own items.

use rmpv::Value;

use oneiron_contracts::error::{ArtifactError, Error, Result};
use oneiron_contracts::msgpack::{self, Entries};

pub const MAX_HUB_TEXT_BYTES: usize = 4096;

pub fn exact_map<'a>(
    value: &'a Value,
    keys: &[&str],
    context: &'static str,
) -> Result<&'a [(Value, Value)]> {
    Entries::of(value)
        .and_then(|entries| entries.exact_keys(keys, &[]))
        .map(Entries::as_slice)
        .map_err(|_| Error::Artifact(ArtifactError::InvalidSkillBody(context)))
}

pub fn required_value<'a>(
    entries: &'a [(Value, Value)],
    key: &str,
    context: &'static str,
) -> Result<&'a Value> {
    Entries::new(entries)
        .require(key)
        .map_err(|_| Error::Artifact(ArtifactError::InvalidSkillBody(context)))
}

pub fn required_text(
    entries: &[(Value, Value)],
    key: &str,
    max_bytes: usize,
    context: &'static str,
) -> Result<String> {
    let text = required_value(entries, key, context)?
        .as_str()
        .ok_or(Error::Artifact(ArtifactError::InvalidSkillBody(context)))?;
    validate_text(text, max_bytes, context)?;
    Ok(text.to_owned())
}

pub fn validate_text(text: &str, max_bytes: usize, context: &'static str) -> Result<()> {
    if text.trim().is_empty() || text.len() > max_bytes {
        return Err(Error::Artifact(ArtifactError::InvalidSkillBody(context)));
    }
    Ok(())
}

/// The context named a write error, which writing into a Vec cannot raise; kept for the callers.
pub fn encode_value(value: &Value, _context: &'static str) -> Result<Vec<u8>> {
    Ok(msgpack::encode(value))
}

pub fn decode_value(bytes: &[u8], context: &'static str) -> Result<Value> {
    msgpack::decode(bytes).map_err(|_| Error::Artifact(ArtifactError::InvalidSkillBody(context)))
}

/// A key that appears twice reads as absent (PLAN-UC-08 PR 2 K-proof).
pub fn map_value<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    Entries::of(value).ok()?.get(key).ok().flatten()
}

pub fn map_text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    map_value(value, key)?.as_str()
}
