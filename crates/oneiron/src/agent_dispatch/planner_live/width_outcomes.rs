//! The width evidence the live planner weighs (FIX 9568): each admitted
//! pattern skill's anchored team outcomes per width, read from one receipt
//! snapshot and folded at one evaluation time. Each outcome weighs what the
//! skill's reliability read fades it to (its window, at the outcome's age),
//! so an old win or loss halves as every other learned read's does. Own and
//! borrowed mass stay apart: a borrowed outcome adds mass, never own runs.

use std::collections::BTreeMap;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning::{TypeRef, Window};
use crate::team::{PlannerCard, ReceiptScan, TeamReceipt, model_mix, team_receipts_in_txn};

/// The weight of the vault's outcomes a project's skill with none of its
/// own borrows (FIX 6038, own scope then the vault): their faded mass as
/// it is, as the project read them before the scopes parted, now never own
/// runs. Canon names the order, not a weight (CALL).
pub(super) const VAULT_BACKOFF_WIDTH_WEIGHT: f64 = 1.0;

/// Every team receipt as one snapshot read it, and the time it is folded at.
pub(super) struct WidthOutcomes {
    receipts: Vec<TeamReceipt>,
    at: u64,
}

impl WidthOutcomes {
    /// Every receipt, read once and folded at `at`; none when `wanted` is
    /// false (no pattern skill to weigh).
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(super) fn read(vault: &Vault, at: u64, wanted: bool) -> Result<Self> {
        let txn = vault.store.env.read_txn()?;
        Self::read_in_txn(vault, &txn, at, wanted)
    }

    /// [`read`](Self::read) in the caller's snapshot, so the planner folds
    /// its width evidence on the same snapshot as every measured read.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(super) fn read_in_txn(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        at: u64,
        wanted: bool,
    ) -> Result<Self> {
        Ok(Self {
            receipts: if wanted {
                team_receipts_in_txn(vault, txn, ReceiptScan::AllScopes(None))?
            } else {
                Vec::new()
            },
            at,
        })
    }

    /// The faded `(wins, losses)` mass per `(skill, width)` of the anchored
    /// outcomes keyed at `type_ref` in `project`'s scope (`None`, the
    /// vault's alone; FIX 6038) on `card`'s executor mix. Each skill's
    /// outcomes fade by its reliability read's window on `card`; a skill the
    /// card does not read is not folded, and an open team is neither.
    pub(super) fn folded(
        &self,
        project: Option<EntityId>,
        type_ref: &TypeRef,
        card: &PlannerCard,
    ) -> BTreeMap<(EntityId, u32), (f64, f64)> {
        let windows: BTreeMap<EntityId, Window> = card
            .patterns
            .iter()
            .map(|entry| (entry.skill, entry.read.estimate.window))
            .collect();
        let mut mass: BTreeMap<(EntityId, u32), (f64, f64)> = BTreeMap::new();
        for receipt in &self.receipts {
            let (Some(outcome), Some(skill)) = (&receipt.outcome, &receipt.pattern_skill) else {
                continue;
            };
            if receipt.project != project
                || receipt.type_ref != *type_ref
                || model_mix(&receipt.models) != card.executor_mix
            {
                continue;
            }
            let (Some(window), Some(width)) = (
                windows.get(&skill.skill),
                shape_width(&receipt.shape.signature()),
            ) else {
                continue;
            };
            let weight = window.decay(self.at.saturating_sub(outcome.at));
            let cell = mass.entry((skill.skill, width)).or_default();
            if outcome.success {
                cell.0 += weight;
            } else {
                cell.1 += weight;
            }
        }
        mass
    }

    /// The vault scope's faded mass at `type_ref` on `card`, for each skill
    /// `own` (a project's own fold) holds no outcome of: the vault step of
    /// the width backoff (FIX 6038). Nothing for a vault run, whose own
    /// fold is the vault's.
    pub(super) fn vault_backoff(
        &self,
        project: Option<EntityId>,
        type_ref: &TypeRef,
        card: &PlannerCard,
        own: &BTreeMap<(EntityId, u32), (f64, f64)>,
    ) -> BTreeMap<(EntityId, u32), (f64, f64)> {
        if project.is_none() {
            return BTreeMap::new();
        }
        let mut vault = self.folded(None, type_ref, card);
        vault.retain(|(skill, _), _| !own.keys().any(|(mine, _)| mine == skill));
        vault
    }
}

/// The width a team shape's signature (`width|roles`) names.
fn shape_width(signature: &str) -> Option<u32> {
    signature.split('|').next()?.parse().ok()
}
