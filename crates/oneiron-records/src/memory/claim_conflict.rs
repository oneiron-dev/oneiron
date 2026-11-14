//! Moved from `crates/oneiron/src/memory/claim_conflict.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::authorship::*;
use oneiron_contracts::entity_id::EntityId;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;

/// Typed question, not a prompt string or an instruction hidden in a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimConflictQuestion {
    ConflictOfInterest,
}

/// One immutable context member. Bytes include the entity metadata header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimConflictMember {
    #[serde(with = "super::authorship::entity_serde")]
    pub entity: EntityId,
    pub row_digest: [u8; 32],
    /// Read projection only. Persistence strips this field's bytes.
    pub raw: Vec<u8>,
}

/// One packet: disputed claim, proposed revision, author and subject context.
/// Only the parties and authenticated owner/delegated reviewer can read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimConflictBundle {
    pub bundle_id: [u8; 32],
    pub question: ClaimConflictQuestion,
    #[serde(with = "super::authorship::entity_serde")]
    pub raised_by: EntityId,
    #[serde(with = "super::authorship::entity_serde")]
    pub author: EntityId,
    #[serde(with = "super::authorship::entity_serde")]
    pub subject: EntityId,
    #[serde(with = "super::authorship::entity_serde")]
    pub disputed: EntityId,
    #[serde(with = "super::authorship::entity_serde")]
    pub proposal: EntityId,
    pub authority_root: String,
    pub policy_frontier: [u8; 32],
    pub members: Vec<ClaimConflictMember>,
}

/// A ruling joins the existing Gate ledger. Both old and new claims survive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimConflictReceipt {
    pub bundle_id: [u8; 32],
    pub receipt_ref: String,
    #[serde(with = "super::authorship::entity_serde")]
    pub superseded_claim: EntityId,
    #[serde(with = "super::authorship::entity_serde")]
    pub ruling_claim: EntityId,
}
