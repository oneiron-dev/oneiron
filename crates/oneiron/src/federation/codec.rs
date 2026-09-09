//! Shared MessagePack and entity-ref decoding helpers for the federation module.

use rmpv::Value;

use super::grant::invalid_grant;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};

pub(crate) fn optional_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
}

pub(crate) fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    optional_value(entries, key).ok_or_else(invalid_grant)
}

pub(crate) fn encode_msgpack_value(value: &Value, context: &'static str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).map_err(|_| Error::InvariantViolation(context))?;
    Ok(out)
}

pub(crate) fn decode_entity_ref(value: &Value) -> Result<EntityId> {
    let hex = value.as_str().ok_or_else(invalid_grant)?;
    EntityId::from_hex(hex).map_err(|_| invalid_grant())
}

/// [`decode_entity_ref`] restricted to the canonical lowercase hex spelling.
///
/// `EntityId::from_hex` is case-insensitive, so an uppercase spelling would
/// re-encode to different bytes than it arrived as. `delegated_by` is a fresh
/// key with no shipped bodies behind it, so it is pinned canonical from the
/// start and the grant body stays byte-stable across a decode/encode round.
pub(super) fn decode_canonical_entity_ref(value: &Value) -> Result<EntityId> {
    let hex = value.as_str().ok_or_else(invalid_grant)?;
    let id = EntityId::from_hex(hex).map_err(|_| invalid_grant())?;
    if id.to_hex() == hex {
        Ok(id)
    } else {
        Err(invalid_grant())
    }
}
