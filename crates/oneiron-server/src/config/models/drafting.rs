//! `[models.dreamer.drafting]`: the role and the budget a stewardship
//! follow-up draft is written on (FIX 1002). Each ships today's, so nothing
//! changes until the owner writes one.
//!
//! * `role`: the model role the draft's call takes its seat and route from;
//!   the generative reasoner's, as a chat turn's, by default.
//! * `budget_units`: each draft's own line on the Dreamer's live budget
//!   policy rows; by default the Dreamer's resolved `pass_budget_units`.

use oneiron::llm::manifest::ModelRole;
use serde::Deserialize;

/// `[models.dreamer.drafting]` as written in the config file.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DraftingFile {
    role: Option<ModelRole>,
    budget_units: Option<u64>,
}

impl DraftingFile {
    /// The drafting this host runs: each piece the owner wrote, else its
    /// shipped default. A budget of zero is refused, as every budget is.
    pub(super) fn resolve(self) -> anyhow::Result<DraftingSettings> {
        if self.budget_units == Some(0) {
            anyhow::bail!("models.dreamer.drafting.budget_units must be greater than zero");
        }
        Ok(DraftingSettings {
            role: self.role.unwrap_or(ModelRole::GenerativeReasoner),
            budget_units: self.budget_units,
        })
    }
}

/// The role and the budget each stewardship follow-up draft is written on,
/// resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DraftingSettings {
    role: ModelRole,
    budget_units: Option<u64>,
}

impl DraftingSettings {
    /// The role a draft's call is seated, admitted and routed on.
    pub(crate) const fn role(&self) -> ModelRole {
        self.role
    }

    /// Each draft's budget: the owner's, else `pass_budget_units`, the
    /// Dreamer's own resolved pass budget.
    pub(crate) fn budget_units(&self, pass_budget_units: u64) -> u64 {
        self.budget_units.unwrap_or(pass_budget_units)
    }
}
