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
use crate::deletion::{DeleteReason, DeletionGateContext};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind};
use crate::serialize::msgpack_value_to_json;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY, WriteActor};

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

/// Receipt for one committed claim. A refused element of a batch never
/// gets one: it answers [`CommitOutcome::Refused`] instead (OF-063).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitReceipt {
    /// Short-id ref of the written claim.
    pub claim_short_id: String,
    /// Final approval as stored: `auto`/`proposed`.
    pub approval: String,
    /// Short-id ref of the claim this write superseded, if any.
    pub superseded_short_id: Option<String>,
    /// Gate decision ref (`gate:<decision-hex>`) resolvable via
    /// [`Memory::receipts`]; falls back to a facade marker when no
    /// decision exists (e.g. rejected before the gate ran).
    pub receipt_ref: String,
    /// The written claim as a typed record ref (OF-063), built from the id
    /// the write landed, with no read. `None` when the receipt's writer
    /// names no landed claim record.
    #[serde(default)]
    pub claim: Option<crate::lens::RecordRef>,
    /// The claim this write superseded, as a typed record ref, if any.
    #[serde(default)]
    pub superseded: Option<crate::lens::RecordRef>,
}

/// What became of one element of a per-element claim batch (`vault.commit`,
/// `vault.claims.seed`). Each element is its own gated write in its own
/// transaction, so one refused element sinks no other: each answers its
/// landed receipt or its typed refusal, never a success-shaped receipt for a
/// write that did not land (OF-063, Engine ruling 1221).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CommitOutcome {
    /// The claim landed.
    Landed(CommitReceipt),
    /// The element was refused and nothing of it persisted: its write
    /// rolled back whole, and the refusal names no record.
    Refused {
        /// Why, typed.
        refusal: RecordRefusal,
        /// The refusal's own reference-refusal receipt
        /// (`reference_refusal:<hex>`), written once the element's write had
        /// rolled back, so it survives the rollback. `None` when no record
        /// was kept: an anonymous off-record session keeps none (#1968), and
        /// a receipt write that failed is logged.
        receipt_ref: Option<String>,
    },
}

/// Why a write or an answer was refused (OF-063, Engine 10-18): the one
/// reason the refusal's reference-refusal receipt records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefusalReason {
    /// A record it named does not resolve for its writer: invented,
    /// missing, or one the writer may not read.
    #[serde(rename = "INVENTED_REFERENCE")]
    InventedReference,
    /// The gate, the door's authority or the write's own checks refused it.
    #[serde(rename = "GATE_REFUSED")]
    GateRefused,
}

impl RefusalReason {
    /// The stable form, as the receipt records it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InventedReference => MEMORY_CODE_INVENTED_REFERENCE,
            Self::GateRefused => "GATE_REFUSED",
        }
    }

    /// Parses the stable form.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        [Self::InventedReference, Self::GateRefused]
            .into_iter()
            .find(|reason| reason.as_str() == value)
    }

    /// The reason a refused claim element's error gives (the one policy
    /// hook for it): a record it named that does not resolve is an invented
    /// reference, and every other refusal the gate's or its door's.
    pub(crate) fn of_code(code: &str) -> Self {
        if code == MEMORY_CODE_INVENTED_REFERENCE || code == MEMORY_CODE_NOT_FOUND {
            Self::InventedReference
        } else {
            Self::GateRefused
        }
    }
}

/// A refusal as its caller hears it (OF-063, Engine rulings 1221 and 1231):
/// typed, and never shaped like a success. Nothing it was asked to write or
/// say landed, so it names no record; it says why, in the facade error's
/// code and words, and at which field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordRefusal {
    /// Why it was refused; its receipt records the same reason.
    pub reason: RefusalReason,
    /// The facade error code it was refused with (a `MEMORY_CODE_*`).
    pub code: String,
    /// What was refused, in words.
    pub message: String,
    /// Remediation hints.
    pub suggestions: Vec<String>,
    /// The JSON pointer of the refused element or slot (`/claims/2`), the
    /// field its receipt names.
    pub field: String,
}

impl RecordRefusal {
    /// The refusal `error` gives the element or slot at `field`.
    pub(crate) fn from_error(error: &MemoryError, field: String) -> Self {
        Self {
            reason: RefusalReason::of_code(&error.code),
            code: error.code.clone(),
            message: error.message.clone(),
            suggestions: error.suggestions.clone(),
            field,
        }
    }

    /// Receipts this refusal as `memory`'s writer's, under `row`, on its own
    /// write, outside the refused write's rolled-back transaction, and
    /// answers the receipt's id: `None` inside an anonymous off-record
    /// session, which keeps no record. A receipt that cannot be written is
    /// logged and answers `None`; the refusal stands either way.
    pub(crate) fn receipt(&self, memory: &Memory<'_>, row: &'static str) -> Option<String> {
        let facts = crate::receipt::ReferenceRefusalFacts {
            actor: memory.actor(),
            actor_class: memory.actor_class(),
            row,
            field: self.field.clone(),
            outcome: crate::receipt::ReferenceOutcome::Refused,
        };
        crate::receipt::receipt_refusal(memory, &facts, self.reason).unwrap_or_else(|error| {
            tracing::warn!(%error, row, "a refusal went unreceipted");
            None
        })
    }
}

/// Named deletion reasons (S7). There is deliberately NO bare bool delete on
/// this surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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

/// One receipt: a gate decision, or, when `vault.receipts` names `kinds`,
/// a receipt of the unified family in the same shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryReceipt {
    /// Stable ref (`gate:<decision-hex>`, or the family receipt's id).
    pub receipt_ref: String,
    /// The receipt family kind (`gate`, `hook`, `outbound`, ...).
    pub kind: String,
    /// Gate outcome: `allow`/`pending`/`deny`; the receipt's own outcome
    /// for another kind.
    pub outcome: String,
    /// Unix seconds.
    pub created_at: u64,
    /// Gate reason codes; the policy trace for another kind.
    pub reason_codes: Vec<String>,
    /// Actor class string the decision was made for; empty for a kind that
    /// names none.
    pub actor_class: String,
    /// Actor entity hex, when the write carried an envelope.
    pub actor_ref: Option<String>,
    /// Gate content kind (e.g. `claim`); empty for a kind that names none.
    pub content_kind: String,
    /// 32-hex id of the claim the decision covers, if any.
    pub claim_ref: Option<String>,
    /// That claim as a typed record ref (OF-063), built from its id with no
    /// read, so labelled with its kind and id.
    #[serde(default)]
    pub claim: Option<crate::lens::RecordRef>,
    /// A family receipt's own fields (a hook run's hook, CODE id, body hash
    /// and run key), with its trigger, job and principal refs. Empty on a
    /// gate-ledger row.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub fields: std::collections::BTreeMap<String, String>,
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
