//! Moved from `crates/oneiron/src/deletion/legal_hold/confirmation.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::deletion::legal_hold::types::ErasePendingReason;
use crate::deletion::legal_hold::types::EraseWithdrawal;
use crate::deletion::legal_hold::types::LIFT_AND_ERASE_PROMPT;
use crate::deletion::legal_hold::types::LIFT_AND_ERASE_TITLE;
use crate::deletion::legal_hold::types::LegalHold;
use crate::deletion::legal_hold::types::LegalHoldEventKind;
use crate::deletion::legal_hold::types::LegalHoldKind;
use crate::deletion::legal_hold::types::LegalHoldReason;
use crate::deletion::legal_hold::types::LegalHoldTarget;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
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

/// What the owner's one confirm showed: its title and prompt, the records
/// it names, whether it names the claim-free gate-decision partition, and
/// each standing customer hold on them. The engine compares it, in one
/// order, with what it reads in the confirm's writer (FIX 1462).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LiftAndEraseShownState {
    /// [`LIFT_AND_ERASE_TITLE`].
    pub title: String,
    /// [`LIFT_AND_ERASE_PROMPT`].
    pub prompt: String,
    pub records: Vec<EntityId>,
    /// The confirm also releases the claim-free partition (FIX 9782).
    #[serde(default)]
    pub claim_free_partition: bool,
    pub holds: Vec<ShownCustomerHold>,
}

impl LiftAndEraseShownState {
    /// What the confirm shows over `records`, and the claim-free partition
    /// with `claim_free_partition`, from hold rows the owner was shown, such
    /// as the hold list's: each standing customer hold naming one of them,
    /// whole. Host orders are left out, so a client builds the same echo
    /// from the list it displayed.
    #[must_use]
    pub fn from_holds(
        records: &[EntityId],
        claim_free_partition: bool,
        holds: &[LegalHold],
    ) -> Self {
        let records: BTreeSet<EntityId> = records.iter().copied().collect();
        let mut shown: Vec<ShownCustomerHold> = holds
            .iter()
            .filter(|hold| hold.kind == LegalHoldKind::Customer && hold.stands())
            .filter(|hold| {
                hold.targets.iter().any(|target| match target.id() {
                    Some(id) => records.contains(&id),
                    None => claim_free_partition,
                })
            })
            .map(ShownCustomerHold::of)
            .collect();
        shown.sort_unstable();
        shown.dedup();
        Self {
            title: LIFT_AND_ERASE_TITLE.to_owned(),
            prompt: LIFT_AND_ERASE_PROMPT.to_owned(),
            records: records.into_iter().collect(),
            claim_free_partition,
            holds: shown,
        }
    }

    /// The same state, every set in the one order the engine compares.
    fn canonical(&self) -> Self {
        let mut records = self.records.clone();
        records.sort_unstable();
        records.dedup();
        let mut holds: Vec<ShownCustomerHold> = self
            .holds
            .iter()
            .map(|hold| {
                let mut hold = hold.clone();
                hold.targets.sort_unstable();
                hold.targets.dedup();
                hold
            })
            .collect();
        holds.sort_unstable();
        holds.dedup();
        Self {
            title: self.title.clone(),
            prompt: self.prompt.clone(),
            records,
            claim_free_partition: self.claim_free_partition,
            holds,
        }
    }
}
