//! Shared campaign-enrollment storage primitives: schema version and hex/JSON row helpers.
//!
//! The typed `vault_meta` bindings for this family's five rows (program, step,
//! event, baseline, home-node designation) live next to the row type each one
//! stores, in `program.rs`, `detection.rs`, and `home_node.rs`.

use serde::Serialize;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// The ONE attempt kind this ticket introduces. No queue enum, no recurrence
/// primitive, no second kind for the outward leg.
pub const CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND: &str = "campaign.enrollment.macro";

/// Schema version shared by every campaign-local row this module persists.
pub const CAMPAIGN_ENROLLMENT_SCHEMA_VERSION: u32 = 1;

/// Generic JSON encode, used where the value crosses a non-`vault_meta` wire
/// (the attempt-queue payload in `runner.rs`); the five `vault_meta` rows
/// encode through their own typed `SideTable::put` instead.
pub(super) fn to_row<T: Serialize>(row: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(row).map_err(|_| invalid("campaign enrollment row encode failed"))
}

pub(super) fn from_row<T: serde::de::DeserializeOwned>(
    raw: &[u8],
    context: &'static str,
) -> Result<T> {
    serde_json::from_slice(raw).map_err(|_| Error::CorruptedIndex(context))
}

pub(super) fn pin_schema(schema_version: u32, context: &'static str) -> Result<()> {
    if schema_version == CAMPAIGN_ENROLLMENT_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(Error::CorruptedIndex(context))
    }
}

pub(super) fn id_from_hex(value: &str, context: &'static str) -> Result<EntityId> {
    EntityId::from_hex(value).map_err(|_| Error::CorruptedIndex(context))
}

pub(super) fn hash_from_hex(value: &str, context: &'static str) -> Result<[u8; 32]> {
    bytes_from_hex(value, context)?
        .try_into()
        .map_err(|_| Error::CorruptedIndex(context))
}

pub(super) fn bytes_from_hex(value: &str, context: &'static str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(Error::CorruptedIndex(context));
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(value.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = hex_nibble(pair[0]).ok_or(Error::CorruptedIndex(context))?;
        let lo = hex_nibble(pair[1]).ok_or(Error::CorruptedIndex(context))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

pub(super) fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}
