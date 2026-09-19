//! Mandatory world and relationship tags on the claim wire ABI.

use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use rmpv::Value;

pub(super) fn encode_scope_tag(id: Option<EntityId>, default: &str) -> Value {
    id.map_or_else(
        || Value::from(default),
        |id| Value::Binary(id.as_bytes().to_vec()),
    )
}

pub(super) fn decode_scope_tag(value: &Value, default: &str) -> Result<Option<EntityId>> {
    if value.as_str() == Some(default) {
        return Ok(None);
    }
    let Value::Binary(bytes) = value else {
        return Err(Error::InvalidClaimBody(
            "scope must be an explicit default tag or binary id",
        ));
    };
    let bytes: [u8; ENTITY_ID_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidClaimBody("scope id must be 16 bytes"))?;
    EntityId::from_bytes(bytes)
        .map(Some)
        .map_err(|_| Error::InvalidClaimBody("scope id is reserved"))
}
