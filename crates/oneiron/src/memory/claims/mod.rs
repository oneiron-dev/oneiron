//! Claim lifecycle verbs: commit/upsert/retract and the
//! internal commit-decision plumbing (gate request/resubmit, supersession).
//! Split from the flat `facade.rs`; surface re-exported by [`super`].

use super::support::*;
use super::*;

use std::sync::atomic::Ordering;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::batch::{ApplyOpsGateMode, BatchOp};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::companion::companion_value_to_json;
use crate::deletion::{DeleteReason, DeletionGateContext};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind};
use crate::temporal::TimeRange;
use crate::write_envelope::{
    ClaimCandidate, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY, WriteActor, WriteEnvelope, WriteProvenance,
};

/// Predicates with declared multi-cardinality supersession keys (B1c,
/// RATIFY-20260710 R0): the prior-claim match extends
/// `subject+scope+predicate` with `value.question_id`.
pub const MULTI_CARDINALITY_PREDICATES: [&str; 1] = ["companion.onboarding.answer"];

const MULTI_CARDINALITY_VALUE_KEY: &str = "question_id";

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
    /// Optional RELATIONSHIP ref; unknown or wrong-kind refs are rejected.
    #[serde(default)]
    pub relationship_ref: Option<String>,
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
}

/// Receipt for one committed (or rejected) claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitReceipt {
    /// Short-id ref of the written claim. For a rejected element (approval
    /// `rejected`) no entity exists; this carries the caller-supplied id
    /// hex (or empty when the id itself was invalid).
    pub claim_short_id: String,
    /// Final approval as stored: `auto`/`proposed` (or `rejected` when the
    /// element did not persist).
    pub approval: String,
    /// Short-id ref of the claim this write superseded, if any.
    pub superseded_short_id: Option<String>,
    /// Gate decision ref (`gate:<decision-hex>`) resolvable via
    /// [`Memory::receipts`]; falls back to a facade marker when no
    /// decision exists (e.g. rejected before the gate ran).
    pub receipt_ref: String,
}

/// Named deletion reasons (S7). There is deliberately NO bare bool delete on
/// this surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeDeleteReason {
    /// Tombstone delete: local body scrubbed to a shell, no receipt.
    UserDelete,
    /// Hard purge + redaction audit receipt + historical sweep.
    UserHardDelete,
    /// Compliance erase (soft-erase pass + purge + receipt + sweep).
    GdprDelete,
    /// Policy-driven erase (same machinery as GDPR).
    PolicyDelete,
}

impl SafeDeleteReason {
    /// Stable string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserDelete => "user_delete",
            Self::UserHardDelete => "user_hard_delete",
            Self::GdprDelete => "gdpr_delete",
            Self::PolicyDelete => "policy_delete",
        }
    }

    /// Parses the stable string form.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "user_delete" => Some(Self::UserDelete),
            "user_hard_delete" => Some(Self::UserHardDelete),
            "gdpr_delete" => Some(Self::GdprDelete),
            "policy_delete" => Some(Self::PolicyDelete),
            _ => None,
        }
    }

    pub(super) const fn delete_reason(self) -> DeleteReason {
        match self {
            Self::UserDelete => DeleteReason::UserDelete,
            Self::UserHardDelete => DeleteReason::UserHardDelete,
            Self::GdprDelete => DeleteReason::GdprDelete,
            Self::PolicyDelete => DeleteReason::PolicyDelete,
        }
    }
}

/// Receipt for one safe delete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteReceipt {
    /// Whether the entity existed before the delete.
    pub existed: bool,
    /// The reason the delete was performed under.
    pub reason: String,
    /// Redaction audit receipt ref (`redaction:<hex>`); `None` for
    /// `user_delete`, which writes no receipt entity by design.
    pub receipt_ref: Option<String>,
}

/// One pending gated write awaiting consent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingWrite {
    /// 32-hex id of the parked claim.
    pub claim_ref: String,
    /// Gate decision ref (`gate:<hex>`).
    pub decision_ref: String,
    /// Unix seconds the decision was recorded.
    pub created_at: u64,
    /// Gate reason codes (e.g. `gate.pending.actor_ceiling`).
    pub reason_codes: Vec<String>,
    /// Dreamer run lane, when the write came from a consolidation run.
    pub dreamer_run_id: Option<String>,
}

/// One gate decision receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryReceipt {
    /// Stable ref (`gate:<decision-hex>`).
    pub receipt_ref: String,
    /// Gate outcome: `allow`/`pending`/`deny`.
    pub outcome: String,
    /// Unix seconds.
    pub created_at: u64,
    /// Gate reason codes.
    pub reason_codes: Vec<String>,
    /// Actor class string the decision was made for.
    pub actor_class: String,
    /// Actor entity hex, when the write carried an envelope.
    pub actor_ref: Option<String>,
    /// Gate content kind (e.g. `claim`).
    pub content_kind: String,
    /// 32-hex id of the claim the decision covers, if any.
    pub claim_ref: Option<String>,
}

pub(super) fn parse_claim_source(value: &str) -> MemoryResult<ClaimSource> {
    ClaimSource::parse(value).ok_or_else(|| {
        MemoryError::bad_request_with(
            format!("unknown claim source {value:?}"),
            &["Use one of: user_stated, observed, inferred, imported, tool_output, generated."],
        )
    })
}

mod commit;
mod lifecycle;
