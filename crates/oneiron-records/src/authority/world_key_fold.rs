//! Moved from `crates/oneiron/src/authority/world_key_fold.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::*;
use oneiron_contracts::entity_id::EntityId;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::btree_map::Entry;
use std::sync::Arc;

/// A record's commitment and owner.
pub type KeyBytes = ([u8; 32], EntityId);

pub type Slots = BTreeMap<SlotRank, PolicyRevision>;

/// A wrap slot's place among its signer's: the record's sequence, then its
/// hash. An ancestor always ranks before its descendants.
pub type SlotRank = (u64, AuthorityEntryHash);

/// One world key as this install's fold holds it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FoldedWorldKey {
    pub id: WorldKeyId,
    /// The vault owner PERSON its mint named.
    pub owner: EntityId,
    pub commitment: [u8; 32],
    /// Counted records named other bytes or another owner for this id.
    pub conflicted: bool,
    /// Per recipient, at most four counted envelopes from each signer of
    /// these bytes, standing signers' first.
    pub wraps: BTreeMap<WrapRecipient, Vec<WrappedKey>>,
    /// The machines that signed its counted records of these bytes, or of
    /// any bytes when it is conflicted.
    pub signers: BTreeSet<EntityId>,
}

/// One counted envelope of a key for one recipient.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WrappedKey {
    pub envelope: Vec<u8>,
    /// The world's settings revision the wrap was made under.
    pub policy: PolicyRevision,
    pub entry: AuthorityEntryHash,
}
