pub use crate::memory::claims::settle::ClaimChangeVerdict;
pub use crate::memory::claims::settle::ClaimProposalReviewRequest;
pub use crate::memory::claims::settle::ClaimSettleDecision;
pub use crate::memory::claims::settle::ClaimSettleRequest;
pub use crate::memory::claims::settle::ClaimSettlementAnswer;
pub use crate::memory::claims::settle::ClaimSettlementReason;
pub use crate::memory::claims::settle::ClaimSettlementRevert;
pub use crate::memory::claims::settle::ClaimSettlementVerdict;
pub use crate::memory::claims::settle::SettleWarning;
pub use crate::memory::claims::settle::SettleWarningCode;
use crate::memory::structural::*;
use crate::memory::*;
use oneiron_contracts::claim::ClaimSource;
pub use oneiron_store::reference_refusal::RefusalReason;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use std::sync::atomic::Ordering;

pub mod settle;

/// One claim to commit. `approval` is deliberately NOT settable by callers
/// (pin 2); the facade computes the request and the gate decides.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClaimInput {
    /// Caller-supplied deterministic 32-hex claim id; `None` ⇒ generated.
    /// Load-bearing for ONE-258's idempotent backfill.
    pub id: Option<String>,
    /// Dotted predicate (open vocabulary; `edge.*` reserved).
    pub predicate: String,
    /// Subject entity ref (short-id ref or 32-hex).
    pub subject_ref: String,
    /// Claim value (JSON, stored as MessagePack).
    pub value: serde_json::Value,
    /// Calibrated-absolute confidence in `[0, 1]`.
    pub confidence: f32,
    /// `ClaimSource::as_str` value: `user_stated`/`observed`/`inferred`/
    /// `imported`/`tool_output`/`generated`.
    pub source: String,
    /// Optional WORLD entity ref.
    pub world_ref: Option<String>,
    /// Optional RELATIONSHIP refs: absent means all relationships, `[]` the
    /// explicit empty set, otherwise every listed relationship. Unknown or
    /// wrong-kind refs are rejected.
    #[serde(default)]
    pub relationship_ref: Option<Vec<String>>,
    /// Optional scope map (e.g. `{"sensitivity": 0}`).
    pub scope: Option<serde_json::Value>,
    /// Validity window start (Unix seconds).
    pub valid_from: Option<u64>,
    /// Validity window end (Unix seconds).
    pub valid_to: Option<u64>,
    /// Backdating passthrough; `None` ⇒ now (Unix seconds).
    pub occurred_at: Option<u64>,
    /// Backdating passthrough; `None` ⇒ now (Unix seconds).
    pub learned_at: Option<u64>,
    /// Optional salience in `[0, 1]`.
    pub salience: Option<f32>,
    /// The band and basis a calibrated producer gave `confidence`; absent
    /// means the house band of the number (FIX 7761).
    #[serde(default)]
    pub confidence_details: Option<oneiron_contracts::claim::ConfidenceDetails>,
}
