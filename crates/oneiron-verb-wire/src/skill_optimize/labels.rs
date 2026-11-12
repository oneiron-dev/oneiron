//! Moved from `crates/oneiron/src/skill_optimize/labels.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// The evidence for raising a calibration question. Both kinds have two
/// explicit alternatives, so an uncertainty does not silently supply a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JudgeAskReason {
    RevisionDisagreement,
    Uncertainty,
    /// Whether a pick a rubric edit left waiting still fits the new rubric.
    /// Only [`record_judge_label_regrade`] answers it; it never mints a label.
    RubricRecheck,
    /// The case of a pick its person re-graded as no longer fitting, asked
    /// again under the new rubric: an ordinary A/B ask.
    RubricRegrade,
}

/// One question for the responsible human. `id` binds its complete immutable
/// question; `delivered_at` is only a delivery marker, never an answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JudgeAsk {
    pub id: [u8; 32],
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub skill: EntityId,
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub responsible: EntityId,
    pub campaign: String,
    pub evidence: String,
    pub reason: JudgeAskReason,
    pub option_a: String,
    pub option_b: String,
    pub delivered_at: Option<u64>,
    /// The label a re-grade or a re-ask is about, and the rubric it is asked
    /// under; part of the ask's identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regrade: Option<JudgeRegrade>,
}

/// What a [`JudgeAskReason::RubricRecheck`] or
/// [`JudgeAskReason::RubricRegrade`] ask is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JudgeRegrade {
    /// The label's ask id.
    pub label: [u8; 32],
    /// The rubric's text digest.
    pub rubric: [u8; 32],
}
