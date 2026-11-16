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

pub use crate::memory::campaign_records::program_definition::CAMPAIGN_ENROLLMENT_SCHEMA_VERSION;

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
    oneiron_hex::decode_vec(value).ok_or(Error::CorruptedIndex(context))
}

pub(super) fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}
