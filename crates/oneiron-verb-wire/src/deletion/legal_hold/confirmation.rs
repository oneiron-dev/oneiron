//! Moved from `crates/oneiron/src/deletion/legal_hold/confirmation.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::deletion::legal_hold::types::LegalHold;
use crate::deletion::legal_hold::types::LegalHoldTarget;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// One standing customer hold as the confirm showed it, whole: a hold
/// widened since is not narrowed on an old confirm.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ShownCustomerHold {
    pub hold_id: EntityId,
    /// Everything the hold names, not only the confirm's records.
    pub targets: Vec<LegalHoldTarget>,
    pub placed_by: Option<String>,
    pub placed_at: u64,
    pub matter_ref: Option<String>,
}

impl ShownCustomerHold {
    fn of(hold: &LegalHold) -> Self {
        let mut targets = hold.targets.clone();
        targets.sort_unstable();
        targets.dedup();
        Self {
            hold_id: hold.hold_id,
            targets,
            placed_by: hold.placed_by.clone(),
            placed_at: hold.placed_at,
            matter_ref: hold.matter_ref.clone(),
        }
    }
}
