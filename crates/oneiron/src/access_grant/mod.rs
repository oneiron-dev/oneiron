//! AccessGrant control-plane record substrate.
//!
//! Access grants are engine-authored maintenance records that authorize a
//! principal for a narrowly scoped control-plane capability. Bodies are pinned
//! MessagePack maps and decode fail-closed: unknown keys, duplicate keys,
//! unsupported scope/capability/status strings, malformed entity references,
//! and inconsistent revocation state are rejected.

mod codec;
mod record;
mod vault_doors;

pub use self::codec::{
    ACCESS_GRANT_BODY_KEYS, ACCESS_GRANT_SCHEMA_VERSION, decode_access_grant_body,
    encode_access_grant_body,
};
pub(crate) use self::codec::{
    ACCESS_GRANT_FIELDS_FULL, ACCESS_GRANT_FIELDS_MINIMAL, ACCESS_GRANT_FIELDS_STANDARD,
    decode_entity_ref, invalid_grant, required_value, validate_access_grant_body_bytes,
    validate_keys,
};
pub use self::record::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus, CalendarAccessGrantRow,
};

#[cfg(test)]
mod tests;

// The flat access_grant.rs module used to provide these names to the sibling test
// module through `use super::*`: private codec keys/helpers, and crate/std
// imports the tests name bare. After the directory split the seam re-imports
// them so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::codec::{
    KEY_CAPABILITY, KEY_CREATED_AT, KEY_PRINCIPAL_REF, KEY_REVOKED_AT, KEY_SCHEMA_VERSION,
    KEY_SCOPE, KEY_STATUS, SCOPE_KEY_KIND, SCOPE_KEYS_CALENDAR, SCOPE_KEYS_COMPANION_PROFILE,
    SCOPE_KIND_CALENDAR, SCOPE_KIND_COMPANION_PROFILE, encode_scope,
};
#[cfg(test)]
use crate::booking::DisclosureRung;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use rmpv::Value;
#[cfg(test)]
use std::collections::BTreeSet;
#[cfg(test)]
use std::io::Cursor;
