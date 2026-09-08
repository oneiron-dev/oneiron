//! ChannelIdentity record substrate (OF-347 CID-1).
//!
//! A ChannelIdentity is a vault-resident engine record plus a typed
//! `channel_identity.*` claim family. Provisioning verbs, provider adapters,
//! reputation scoring, and manifest contents are intentionally outside this
//! module; CID-1 pins the primitive shape and lifecycle invariants only.
//!
//! Two things live beside the record because they are properties OF the record
//! rather than of whichever adapter last touched it:
//!
//! - `address` — the channel key and the assignment address are VALUES,
//!   normalized once at construction, and [`AssignmentKey`] is the single
//!   canonical inhabitant every uniqueness road compares.
//! - `custody` — a `delegated_grant` row is a mailbox the product never
//!   minted. What makes such a row true is a live custody record that NAMES
//!   THIS MAILBOX, so the proof carries the mailbox and only the engine can
//!   mint one.

mod address;
mod binding;
mod codec;
mod custody;
mod keys;
mod lifecycle;
mod record;
mod shape;
mod transition;
mod vault_doors;

pub use address::{
    AssignmentAddress, AssignmentKey, ChannelKey, MailboxAddr, normalize_email_domain,
};
pub use custody::{
    DelegatedCustodyProof, DelegatedGrant, DelegatedGrantScope, delegated_custody_effector,
    delegated_custody_scopes, delegated_custody_subject_scope,
};

pub use self::binding::{ChannelIdentityBinding, ChannelIdentityFulfillment};
pub use self::codec::{
    decode_channel_identity_body, encode_channel_identity_body, is_channel_identity_claim_predicate,
};
pub use self::keys::{
    CHANNEL_IDENTITY_BODY_KEYS, CHANNEL_IDENTITY_CLAIM_PREDICATES,
    CHANNEL_IDENTITY_DELEGATED_BODY_KEYS, CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION,
    CHANNEL_IDENTITY_MIN_QUARANTINE_SECS, CHANNEL_IDENTITY_SCHEMA_VERSION, KEY_BINDING_FACET_REF,
    PREDICATE_CHANNEL_IDENTITY_ADDRESS_OR_HANDLE, PREDICATE_CHANNEL_IDENTITY_BINDING_FACET_REF,
    PREDICATE_CHANNEL_IDENTITY_BINDING_SCOPE, PREDICATE_CHANNEL_IDENTITY_BINDING_TARGET,
    PREDICATE_CHANNEL_IDENTITY_CHANNEL, PREDICATE_CHANNEL_IDENTITY_MANIFEST_REF,
    PREDICATE_CHANNEL_IDENTITY_PENDING_FULFILLMENT, PREDICATE_CHANNEL_IDENTITY_QUARANTINE_UNTIL,
    PREDICATE_CHANNEL_IDENTITY_REPUTATION_REF, PREDICATE_CHANNEL_IDENTITY_SHAPE,
    PREDICATE_CHANNEL_IDENTITY_STATE, PREDICATE_CHANNEL_IDENTITY_STATE_CHANGED_AT,
};
pub use self::lifecycle::ChannelIdentityState;
pub use self::record::ChannelIdentity;
pub use self::shape::{ChannelIdentityShape, SelfHeldShape};
pub use self::transition::DelegatedProvisionRequest;

pub(crate) use self::codec::{
    validate_channel_identity_body_bytes, validate_channel_identity_claim_structure,
};
pub(crate) use self::transition::{IdentityTransition, admit_channel_identity_transition_in_txn};

#[cfg(test)]
mod tests;

// The flat channel_identity.rs module used to provide its private crate/std import
// header to the sibling test module through `use super::*`. Items the tests name bare
// now resolve through the seam re-exports above; only the header names the tests do
// not import themselves are re-imported here so `tests.rs` resolves exactly as before.
#[cfg(test)]
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use rmpv::Value;
#[cfg(test)]
use std::io::Cursor;
