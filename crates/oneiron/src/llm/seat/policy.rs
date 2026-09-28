//! Manifest-owned runtime seat policy; shipped defaults are data, not routing code.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{DescriptionSource, ModelId, ModelWireFormat, ReasoningEffort, invalid};
use crate::error::Result;
use crate::llm::routing::DescriptionPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeatPrecedence {
    /// Each authored level (global, purpose, vault, then the holder or judge)
    /// may only narrow its nearest authored parent.
    NarrowOnly,
    /// The most specific authored level wins and a holder may choose another
    /// allowed rung; every level stays under the vault ceiling.
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
    /// Strongest provenance first; the judge sees every source in this order.
    pub evidence_order: Vec<DescriptionSource>,
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
            || !valid_evidence_order(&self.evidence_order)
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

    /// Compose the authored defaults parent-first: global, purpose, vault, and
    /// at each level the manifest row before the vault's description-policy
    /// row. Every level stays under the vault ceiling. Nested narrowing refuses
    /// a level above its nearest authored parent; seat override lets the most
    /// specific level win. `None` means no level was authored.
    pub(in crate::llm) fn compose_defaults(
        &self,
        purpose: &str,
        descriptions: Option<&DescriptionPolicy>,
    ) -> Result<Option<ReasoningEffort>> {
        let levels = [
            self.global_default,
            descriptions.and_then(|row| row.global_effort),
            self.purpose_defaults.get(purpose).copied(),
            descriptions.and_then(|row| row.purpose_effort.get(purpose).copied()),
            self.vault_default,
            descriptions.and_then(|row| row.vault_effort),
        ];
        let mut parent: Option<ReasoningEffort> = None;
        for effort in levels.into_iter().flatten() {
            if effort_rank(effort) > effort_rank(self.vault_ceiling)
                || (self.precedence == SeatPrecedence::NarrowOnly
                    && parent.is_some_and(|parent| effort_rank(effort) > effort_rank(parent)))
            {
                return Err(invalid(
                    "default effort widens its parent level or vault ceiling",
                ));
            }
            parent = Some(effort);
        }
        Ok(parent)
    }

    /// The model's cheap first rung is the fallback selection when no level
    /// is authored; it is not a parent bound.
    pub(super) fn resolve_default(
        &self,
        ladder: &[ReasoningEffort],
        composed: Option<ReasoningEffort>,
    ) -> Result<ReasoningEffort> {
        let effort = composed.unwrap_or(ladder[0]);
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

    /// The one effort choice for seats and verdicts: a holder or judge request
    /// is the child of the composed defaults.
    pub(in crate::llm) fn choose(
        &self,
        composed: Option<ReasoningEffort>,
        requested: Option<ReasoningEffort>,
        ladder: &[ReasoningEffort],
    ) -> Result<ReasoningEffort> {
        let selected = match requested {
            Some(effort) => effort,
            None => self.resolve_default(ladder, composed)?,
        };
        if !self.admits(selected, ladder)
            || (self.precedence == SeatPrecedence::NarrowOnly
                && composed.is_some_and(|parent| effort_rank(selected) > effort_rank(parent)))
        {
            return Err(invalid("seat effort widens model ladder or vault policy"));
        }
        Ok(selected)
    }
}

/// Source identities are substrate (listed here as a set); their ranking is
/// policy. A valid order names each source exactly once so no line is dropped.
fn valid_evidence_order(order: &[DescriptionSource]) -> bool {
    [
        DescriptionSource::Benchmarks,
        DescriptionSource::Measured,
        DescriptionSource::Owner,
        DescriptionSource::Vendor,
    ]
    .iter()
    .all(|source| order.iter().filter(|item| *item == source).count() == 1)
}
