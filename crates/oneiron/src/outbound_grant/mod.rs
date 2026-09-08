//! Standing outbound-grant records for OF-367 RS6.2/RS6.5.
//!
//! These are engine-authored, vault-resident grant claims minted from OF-336
//! consent escalators or bundle approvals. They intentionally have no expiry
//! field: policy-floor staleness and explicit revocation are the invalidation
//! paths.

mod codec;
mod consume;
mod grant;
mod index;
mod mint;
mod scope;

pub use self::codec::{
    OUTBOUND_GRANT_BODY_KEYS, OUTBOUND_GRANT_SCHEMA_VERSION, decode_standing_outbound_grant_body,
    encode_standing_outbound_grant_body,
};
pub use self::consume::CHANNEL_IDENTITY_GRANT_USAGE_PREFIX;
pub use self::grant::{StandingOutboundGrant, StandingOutboundGrantStatus};
pub use self::scope::{
    BookingPageInviteGrantMintIntent, ScopedMcpGrantMintIntent, StandingOutboundGrantScope,
};

pub(crate) use self::codec::{
    OUTBOUND_GRANT_FIELDS_FULL, OUTBOUND_GRANT_FIELDS_MINIMAL, OUTBOUND_GRANT_FIELDS_STANDARD,
    validate_standing_outbound_grant_body_bytes,
};
pub(crate) use self::index::{
    standing_outbound_grant_principal_index_entity_id, standing_outbound_grant_principal_index_key,
    standing_outbound_grant_principal_index_prefix,
};
pub(crate) use self::mint::standing_outbound_grant_in_txn;

#[cfg(test)]
mod tests;

// The flat outbound_grant.rs module used to provide these names to the sibling
// test module through `use super::*`: the private codec/scope helpers the
// tests name bare, its own private crate/std import header, and every
// outbound-grant-internal item the tests name bare. After the directory split
// the seam re-imports both so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::{codec::*, scope::*};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use crate::genui::GrantMintIntent;
#[cfg(test)]
use crate::outbound_consent::{DataClass, ScopedMcpGrantRef};
#[cfg(test)]
use rmpv::Value;
#[cfg(test)]
use std::io::Cursor;
