//! Manifest-owned runtime seat policy; shipped defaults are data, not routing code.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{ModelId, ModelWireFormat, ReasoningEffort, invalid};
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeatPrecedence {
    /// A holder's requested effort may only narrow the resolved default.
    NarrowOnly,
    /// A holder may choose another allowed rung, never above the vault ceiling.
    SeatOverride,
}

/// A v2 manifest row. Model-specific ladders may also come from the existing
/// description-policy row when that policy is configured for the model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeatPolicy {
    pub default_reasoning_ladder: Vec<ReasoningEffort>,
    pub default_plain_ladder: Vec<ReasoningEffort>,
    pub gemini_ladder: Vec<ReasoningEffort>,
    #[serde(default)]
    pub model_ladders: BTreeMap<ModelId, Vec<ReasoningEffort>>,
    pub vault_default: Option<ReasoningEffort>,
    #[serde(default)]
    pub purpose_defaults: BTreeMap<String, ReasoningEffort>,
    pub global_default: Option<ReasoningEffort>,
    pub vault_ceiling: ReasoningEffort,
    pub precedence: SeatPrecedence,
    pub facet_max_bytes: usize,
    pub line_max_bytes: usize,
}

pub(super) fn effort_rank(effort: ReasoningEffort) -> u8 {
    match effort {
        ReasoningEffort::None => 0,
        ReasoningEffort::Low => 1,
        ReasoningEffort::Medium => 2,
        ReasoningEffort::High => 3,
        ReasoningEffort::XHigh => 4,
    }
}

impl SeatPolicy {
    pub fn bundled() -> Result<Self> {
        let policy: Self = serde_json::from_slice(include_bytes!("seat-policy-default.json"))
            .map_err(|error| invalid(error.to_string()))?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<()> {
        let valid_ladder = |ladder: &[ReasoningEffort]| {
            !ladder.is_empty()
                && ladder
                    .iter()
                    .enumerate()
                    .all(|(index, effort)| !ladder[..index].contains(effort))
        };
        if !valid_ladder(&self.default_reasoning_ladder)
            || !valid_ladder(&self.default_plain_ladder)
            || !valid_ladder(&self.gemini_ladder)
            || self
                .model_ladders
                .values()
                .any(|ladder| !valid_ladder(ladder))
            || self
                .purpose_defaults
                .keys()
                .any(|key| key.trim().is_empty())
            || self.facet_max_bytes == 0
            || self.line_max_bytes == 0
        {
            return Err(invalid("invalid runtime seat policy"));
        }
        Ok(())
    }

    pub(super) fn ladder(
        &self,
        model: &ModelId,
        wire: ModelWireFormat,
        reasoning: bool,
    ) -> Vec<ReasoningEffort> {
        self.model_ladders.get(model).cloned().unwrap_or_else(|| {
            if wire == ModelWireFormat::Gemini {
                self.gemini_ladder.clone()
            } else if reasoning {
                self.default_reasoning_ladder.clone()
            } else {
                self.default_plain_ladder.clone()
            }
        })
    }

    pub(super) fn resolve_default(
        &self,
        ladder: &[ReasoningEffort],
        purpose: &str,
        vault_default: Option<ReasoningEffort>,
        purpose_default: Option<ReasoningEffort>,
        global_default: Option<ReasoningEffort>,
    ) -> Result<ReasoningEffort> {
        let effort = vault_default
            .or(self.vault_default)
            .or(purpose_default)
            .or_else(|| self.purpose_defaults.get(purpose).copied())
            .or(global_default)
            .or(self.global_default)
            .unwrap_or(ladder[0]);
        if !self.admits(effort, ladder) {
            return Err(invalid(
                "default effort exceeds model ladder or vault ceiling",
            ));
        }
        Ok(effort)
    }

    pub(super) fn admits(&self, effort: ReasoningEffort, ladder: &[ReasoningEffort]) -> bool {
        ladder.contains(&effort) && effort_rank(effort) <= effort_rank(self.vault_ceiling)
    }

    pub(super) fn choose(
        &self,
        baseline: ReasoningEffort,
        requested: Option<ReasoningEffort>,
        ladder: &[ReasoningEffort],
    ) -> Result<ReasoningEffort> {
        let selected = requested.unwrap_or(baseline);
        if !self.admits(selected, ladder)
            || (self.precedence == SeatPrecedence::NarrowOnly
                && effort_rank(selected) > effort_rank(baseline))
        {
            return Err(invalid("seat effort widens model ladder or vault policy"));
        }
        Ok(selected)
    }
}
