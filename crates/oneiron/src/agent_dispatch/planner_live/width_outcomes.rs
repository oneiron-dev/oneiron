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
use crate::team::{PlannerCard, TeamReceipt, model_mix, team_receipts};

/// Every team receipt as one snapshot read it, and the time it is folded at.
pub(super) struct WidthOutcomes {
    receipts: Vec<TeamReceipt>,
    at: u64,
}

impl WidthOutcomes {
    /// Every receipt, read once and folded at `at`; none when `wanted` is
    /// false (no pattern skill to weigh). [`team_receipts`] opens its own
    /// snapshot, so this runs before the planner opens its own.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(super) fn read(vault: &Vault, at: u64, wanted: bool) -> Result<Self> {
        Ok(Self {
            receipts: if wanted {
                team_receipts(vault, None)?
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
}

/// The width a team shape's signature (`width|roles`) names.
fn shape_width(signature: &str) -> Option<u32> {
    signature.split('|').next()?.parse().ok()
}
