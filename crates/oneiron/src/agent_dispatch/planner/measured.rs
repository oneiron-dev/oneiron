//! What the planner weighs for one candidate (ARCH-0079 #planner): its
//! measured rate on each seat, and a pattern skill's anchored team outcomes
//! per width, its own and, on a thin leaf of a project's own tree, those it
//! borrows from the vault tree (FIX 5496). Borrowed outcomes add mass to an
//! estimate, never own runs.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::llm::ModelId;
use crate::team::PatternSkillRef;

use super::super::team_shape::CoordinationPattern;

#[doc(hidden)]
pub use oneiron_records::agent_dispatch::planner::measured::MeasuredRate;

/// One bound pattern skill the planner may run, as the planner card reads
/// it: the skill revision, the shape it teaches, its `works well for` line,
/// its estimate per seat model, and the anchored team outcomes per measured
/// width and seat model, `(wins, losses)`: each outcome's mass as its
/// window fades it at the plan's one evaluation time (FIX 9568).
#[derive(Debug, Clone, PartialEq)]
pub struct PatternCandidate {
    pub skill: PatternSkillRef,
    pub pattern: CoordinationPattern,
    pub works_well_for: String,
    pub rates: BTreeMap<ModelId, MeasuredRate>,
    pub widths: BTreeMap<u32, BTreeMap<ModelId, (f64, f64)>>,
    /// The vault tree's anchored outcomes a thin project leaf borrows, per
    /// width and seat model, already at the borrow weight, `(wins, losses)`.
    /// Never own runs; empty where nothing is lent.
    pub borrowed_widths: BTreeMap<u32, BTreeMap<ModelId, (f64, f64)>>,
}

impl PatternCandidate {
    /// Every width with an anchored record, own or borrowed.
    pub(super) fn measured_widths(&self) -> BTreeSet<u32> {
        self.widths
            .keys()
            .chain(self.borrowed_widths.keys())
            .copied()
            .collect()
    }

    /// `rate` pooled with the record at `width` on `model`: own outcomes
    /// count as own runs, borrowed ones as mass alone. With no record at
    /// that width, `rate` as read.
    pub(super) fn width_rate(
        &self,
        width: u32,
        model: &ModelId,
        rate: MeasuredRate,
    ) -> MeasuredRate {
        let own = self
            .widths
            .get(&width)
            .and_then(|by_model| by_model.get(model));
        let borrowed = self
            .borrowed_widths
            .get(&width)
            .and_then(|by_model| by_model.get(model));
        if own.is_none() && borrowed.is_none() {
            return rate;
        }
        let (wins, losses) = own.copied().unwrap_or_default();
        let (lent_wins, lent_losses) = borrowed.copied().unwrap_or_default();
        rate.pooled(wins + lent_wins, losses + lent_losses, wins + losses)
    }
}
