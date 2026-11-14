//! Moved from `crates/oneiron/src/skill_attribution/credit_join.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_attribution::contribution_targets::CheckedEdge;
use oneiron_contracts::entity_id::EntityId;
use oneiron_verb_wire::skill_attribution::late_credit::LateCreditShare;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// One immutable change to an anchored outcome's effective late credit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreditAdjustmentReceipt {
    pub receipt_id: String,
    /// The sealed credit receipt it adjusts, whose evidence key it reuses.
    pub base: String,
    /// The adjustment it follows; `None` when it follows the sealed receipt.
    pub previous: Option<String>,
    /// Every matched check the effective credit joins beyond the sealed
    /// receipt's, by receipt.
    pub checks: Vec<String>,
    /// Every late landed use it joins beyond the sealed receipt's; each end
    /// `None` once that entity is erased.
    pub landed: Vec<CheckedEdge>,
    /// Each subject credited directly, the sealed receipt's first; `None`
    /// for one since erased.
    pub direct_subjects: Vec<Option<EntityId>>,
    /// The effective shares, each with its used chain.
    pub shares: Vec<LateCreditShare>,
    /// When it was appended.
    pub at: u64,
}
