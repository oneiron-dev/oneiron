//! Moved from `crates/oneiron/src/autoreason_campaign/judge.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::autoreason_campaign::judge::BlindCampaignJudgeInput;
pub use oneiron_verb_wire::autoreason_campaign::judge::CampaignGoldAnchor;
use oneiron_wake_contract::llm::decision::types::DecisionReceipt;
use serde::Deserialize;
use serde::Serialize;
use std::time::Duration;
use std::time::Instant;

/// One arm's taste on a split, as the shared decision path answered it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignTaste {
    /// Quality score, finite in `[0, 1]`.
    pub score: f64,
    /// Binary usefulness reading, `None` when it abstained; audit-only — never
    /// read by verdict or validation logic.
    pub useful: Option<bool>,
    /// Digest of the external gold anchor the score was asked against.
    pub external_anchor_digest: String,
    /// The receipts of the score and usefulness decisions, in that order:
    /// the providers, rung, band and clock that answered each (FIX 447).
    pub receipts: Vec<DecisionReceipt>,
}

pub fn is_unit_interval_f64(value: f64) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}
