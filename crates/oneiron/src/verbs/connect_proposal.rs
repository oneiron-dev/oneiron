//! A Connect guest's proposals and the owner's review of them (FIX 3684).
use serde::{Deserialize, Serialize};

use crate::EntityId;

/// What a Connect guest proposes under its own live grant-bound credential:
/// the write of one record's text a peer's document frame would carry,
/// which document admission refuses a guest. It lands in the owner's review
/// inbox for the Connect and never writes the vault.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectProposeRequest {
    /// The guest's live Connect grant: the one its credential names.
    pub grant_ref: EntityId,
    /// The named world the record sits in under that grant.
    pub world_ref: EntityId,
    /// The record whose text the update edits.
    pub entity_ref: EntityId,
    /// The Loro update the guest's write would join to the record's text,
    /// as the guest made it.
    pub update: Vec<u8>,
}

/// Where a Connect guest's proposal landed: the owner's review inbox for
/// its Connect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectProposalLanded {
    pub proposal_ref: EntityId,
    pub grant_ref: EntityId,
    pub entity_ref: EntityId,
    /// When the inbox took it, unix seconds.
    pub proposed_at: u64,
}

/// The pending proposal an owner's accept or reject names.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectProposalRef {
    pub grant_ref: EntityId,
    pub proposal_ref: EntityId,
}

/// One Connect guest's proposal as the owner reviews it, or the record of
/// the owner's decision on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectProposal {
    pub proposal_ref: EntityId,
    /// The Connect grant it came under.
    pub grant_ref: EntityId,
    /// The vault-resident guest actor that proposed it.
    pub proposer_ref: EntityId,
    pub world_ref: EntityId,
    pub entity_ref: EntityId,
    /// When the inbox took it, unix seconds.
    pub proposed_at: u64,
    /// The update's length in bytes.
    pub update_len: u64,
    /// The update's BLAKE3, 64 hex.
    pub update_digest: String,
    /// The record's text as accepting the update would leave it, while the
    /// proposal is pending and the update joins cleanly; `None` otherwise.
    pub preview: Option<String>,
    /// The owner's decision; `None` while it is pending.
    pub decision: Option<ConnectProposalDecision>,
}

/// The owner's decision on a Connect guest's proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectProposalDecision {
    /// Accepted (its update joined the record's text as the owner's act) or
    /// rejected (nothing was written).
    pub accepted: bool,
    /// The owner who decided.
    pub by: EntityId,
    /// When, unix seconds.
    pub at: u64,
    /// The guest's grant no longer stood when the owner accepted; the accept
    /// applied all the same.
    pub grant_lapsed: bool,
}
