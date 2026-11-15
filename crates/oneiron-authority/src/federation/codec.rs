//! Shared MessagePack and entity-ref decoding helpers for the federation module.

use oneiron_contracts::msgpack;
use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};

/// The value under `key`, `None` when it is absent; a key stored twice is refused.
pub fn optional_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<Option<&'a Value>> {
    msgpack::Entries::new(entries)
        .get(key)
        .map_err(|_| invalid_grant())
}

pub fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    optional_value(entries, key)?.ok_or_else(invalid_grant)
}

pub fn encode_msgpack_value(value: &Value, _context: &'static str) -> Result<Vec<u8>> {
    Ok(msgpack::encode(value))
}

pub fn decode_entity_ref(value: &Value) -> Result<EntityId> {
    let hex = value.as_str().ok_or_else(invalid_grant)?;
    EntityId::from_hex(hex).map_err(|_| invalid_grant())
}

/// [`decode_entity_ref`] restricted to the canonical lowercase hex spelling.
///
/// `EntityId::from_hex` is case-insensitive, so an uppercase spelling would
/// re-encode to different bytes than it arrived as. `delegated_by` is a fresh
/// key with no shipped bodies behind it, so it is pinned canonical from the
/// start and the grant body stays byte-stable across a decode/encode round.
pub fn decode_canonical_entity_ref(value: &Value) -> Result<EntityId> {
    let hex = value.as_str().ok_or_else(invalid_grant)?;
    let id = EntityId::from_hex(hex).map_err(|_| invalid_grant())?;
    if id.to_hex() == hex {
        Ok(id)
    } else {
        Err(invalid_grant())
    }
}

/// The refusal every federation grant codec returns for a malformed body.
pub fn invalid_grant() -> Error {
    Error::Record(RecordError::InvalidFederationGrantBody(
        "body failed validation",
    ))
}
