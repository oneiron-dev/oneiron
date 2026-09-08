//! Relationship-context channel-identity selection law (ONE-1826).
//!
//! One generic, vault-resident policy: given a relationship context and a
//! roster of host-classified candidate identities, choose which FACE the vault
//! presents. The law lives in `vault_meta` under
//! [`CHANNEL_IDENTITY_SELECTION_KEY`] as one strict-MessagePack rule set with a
//! schema version, a monotonic revision, and owner/agent-editable rows.
//!
//! # What this module is not
//!
//! Selection never mutates a `ChannelIdentity` record, never mints another
//! identity kind, and never grants or checks egress authority — authority is
//! the Gate's policy zone. It is also not a customization preference blob: a
//! rule table that decides which mailbox speaks for the owner is audited law,
//! so every write is compare-and-swap by revision and carries a derived
//! provenance stamp. Consent posture is ONE-1829; thread continuity is
//! ONE-1827 (which consumes [`ChannelIdentityThreadPin`] defined here).
//!
//! # Two roles for one rule-set type
//!
//! [`ChannelIdentitySelectionRuleSet`] wears two hats:
//!
//! * the **stored overlay** — only the rows an owner or agent has written,
//!   persisted under [`CHANNEL_IDENTITY_SELECTION_KEY`] with `revision >= 1`;
//! * the **compiled law** — [`compile_channel_identity_selection`] laying that
//!   overlay over [`builtin_channel_identity_selection_rules`]. A fresh vault
//!   compiles to the six builtins at `revision == 0`, which is also the
//!   `expected_revision` a first write must present.
//!
//! An overlay row whose `rule_id` matches a builtin REPLACES that builtin in
//! place; every other overlay row is appended. That is what keeps a builtin
//! owner-editable without deleting compiled law: an owner disables a builtin by
//! upserting a shadow with `enabled = false`, never by removing it.
//!
//! # Fails typed, never falls through
//!
//! Missing, malformed, duplicate, or revision-regressed storage is an error,
//! not permission to pick an arbitrary identity. "No active candidate wears the
//! selected face" is likewise a typed unresolved decision for the caller to
//! surface — never a licence to reach for a more valuable owner identity.

mod selection_codec;
mod selection_resolution;
mod selection_rules;
mod selection_storage;
mod selection_vocabulary;

pub use self::selection_resolution::{
    ChannelIdentityCandidate, ChannelIdentitySelectionDecision, ChannelIdentitySelectionError,
    ChannelIdentitySelectionPatch, ChannelIdentitySelectionQuery, ChannelIdentitySelectionResult,
    ChannelIdentityThreadPin, SelectionRuleScope, builtin_channel_identity_selection_rules,
    compile_channel_identity_selection, resolve_channel_identity_selection,
};
pub use self::selection_rules::{
    ChannelIdentitySelectionRule, ChannelIdentitySelectionRuleSet, ChannelIdentitySelectionWriter,
};
pub use self::selection_vocabulary::{
    CHANNEL_IDENTITY_SELECTION_KEY, CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION, ChannelIdentityFace,
    RelationshipContext, SelectionRuleWriterKind,
};

#[cfg(test)]
mod tests;

// The flat channel_identity_selection.rs module used to provide these names to
// the sibling test module through `use super::*`: its own private crate/std
// import header, and the private codec helpers the tests name bare (every
// other bare name is a `pub` item the seam above already re-exports). After
// the directory split the seam re-imports both so `tests.rs` resolves exactly
// as it did before.
#[cfg(test)]
use self::selection_codec::*;
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::channel_identity::ChannelIdentityShape;
#[cfg(test)]
use crate::edge::EdgeActorClass;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::write_envelope::WriteActor;
#[cfg(test)]
use rmpv::Value;
