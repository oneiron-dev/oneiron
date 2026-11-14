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
use crate::deletion::DeletionGateContext;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::serialize::msgpack_value_to_json;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY, WriteActor};

/// Predicates with declared multi-cardinality supersession keys (B1c,
/// RATIFY-20260710 R0): the prior-claim match extends
/// `subject+scope+predicate` with `value.question_id`.
pub const MULTI_CARDINALITY_PREDICATES: [&str; 1] = ["companion.onboarding.answer"];

const MULTI_CARDINALITY_VALUE_KEY: &str = "question_id";

/// How the facade chooses a prior head; keyed multi predicates additionally
/// retain the `value.question_id` identity above (ARCH-0044 S3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimCardinality {
    Single,
    Set,
}

/// Canon's `multi` rows use set semantics: only an agreeing answer is replaced.
const DECLARED_CARDINALITY: &[(&str, ClaimCardinality)] = &[
    // ARCH-0003 §G.1 predicate registry, line 242.
    ("preference.food", ClaimCardinality::Set),
    // ARCH-0003 §G.1 predicate registry, line 243.
    ("boundary.topic", ClaimCardinality::Set),
    // ARCH-0003 §G.1 predicate registry, line 244.
    ("goal.financial", ClaimCardinality::Set),
    // ARCH-0003 §G.1 predicate registry, line 245.
    ("commitment.promise", ClaimCardinality::Set),
    // ARCH-0022 predicate registry additions, line 267 (multi).
    ("decision.*", ClaimCardinality::Set),
    // ARCH-0022 predicate registry additions, line 268 (multi).
    ("decision.social", ClaimCardinality::Set),
    // ARCH-0022 predicate registry additions, line 269 (multi).
    ("decision.creative", ClaimCardinality::Set),
    // ARCH-0022 predicate registry additions, line 270 (multi).
    ("decision.moral", ClaimCardinality::Set),
    // ARCH-0022 predicate registry additions, line 271 (multi).
    ("decision.practical", ClaimCardinality::Set),
    // ARCH-0022 predicate registry additions, line 272 (multi).
    ("decision.emotional", ClaimCardinality::Set),
    // ARCH-0022 predicate registry additions, line 273 (multi).
    ("decision.strategic", ClaimCardinality::Set),
    // ARCH-0003 §G.1 predicate registry, line 263 (one superseding head).
    ("decision.settled", ClaimCardinality::Single),
    // ARCH-0022 predicate registry additions, line 274 (multi).
    ("storytelling.*", ClaimCardinality::Set),
    // ARCH-0022 predicate registry additions, line 275 (multi).
    ("storytelling.genre", ClaimCardinality::Set),
    // ARCH-0022 predicate registry additions, line 276 (single).
    ("storytelling.pacing", ClaimCardinality::Single),
    // ARCH-0022 predicate registry additions, line 277 (multi).
    ("storytelling.themes", ClaimCardinality::Set),
    // ARCH-0022 predicate registry additions, line 278 (multi).
    ("storytelling.style", ClaimCardinality::Set),
    // ARCH-0022 predicate registry additions, line 279 (multi).
    ("character.personality", ClaimCardinality::Set),
    // ARCH-0022 predicate registry additions, line 280 (multi).
    ("character.appearance", ClaimCardinality::Set),
    // ARCH-0022 predicate registry additions, line 281 (multi).
    ("character.backstory", ClaimCardinality::Set),
    // ARCH-0022 predicate registry additions, line 282 (multi).
    ("character.dynamic", ClaimCardinality::Set),
    // Engine ruling 13 Nov 12:58 (the linker's role edges): a person holds
    // many relationships of one word, so a second `relationship.friend`
    // stands beside the first and never supersedes it.
    ("relationship.*", ClaimCardinality::Set),
];

/// Exact rows beat namespace wildcards regardless of table order. A wildcard
/// matches every suffix, including deeper predicates (`ns.a.b` for `ns.*`).
/// Unknown predicates keep the single-head default (ARCH-0044 S3).
fn declared_cardinality(predicate: &str) -> ClaimCardinality {
    let mut wildcard: Option<(usize, ClaimCardinality)> = None;
    for &(pattern, cardinality) in DECLARED_CARDINALITY {
        if pattern == predicate {
            return cardinality;
        }
        if let Some(prefix) = pattern.strip_suffix('*')
            && predicate.starts_with(prefix)
            && wildcard.is_none_or(|(length, _)| prefix.len() > length)
        {
            wildcard = Some((prefix.len(), cardinality));
        }
    }
    wildcard.map_or(ClaimCardinality::Single, |(_, cardinality)| cardinality)
}

#[doc(hidden)]
pub use oneiron_verb_wire::memory::claims::ClaimInput;

/// Receipt for one committed claim. A refused element of a batch never
/// gets one: it answers [`CommitOutcome::Refused`] instead (OF-063).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CommitReceipt {
    /// Short-id ref of the written claim.
    pub claim_short_id: String,
    /// Final approval as stored: `auto`/`proposed`. A retract answers
    /// `pending` when it is parked for the holder's consent.
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

pub use crate::receipt::RefusalReason;

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
    /// The legal-hold notice behind this refusal, when its producer supplied one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_hold: Option<Box<crate::error::LegalHoldNotice>>,
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
            legal_hold: error.legal_hold.clone(),
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

pub use crate::deletion::SafeDeleteReason;

/// Where one delete request stands (FIX 1465). Neither says the erase is
/// complete: that is its deletion receipt's signed final row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeleteRequestState {
    /// The local delete rail applied it.
    Applied,
    /// Accepted and recorded, not applied yet: "erase confirmed; completion
    /// pending". It runs once nothing holds the record, or once the shared
    /// vault's veto window has run out.
    CompletionPending,
}

impl DeleteRequestState {
    /// Stable string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::CompletionPending => "completion_pending",
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
    /// `user_delete`, which writes no receipt entity by design, and for a
    /// request not applied yet.
    pub receipt_ref: Option<String>,
    /// Whether the local rail applied it or it waits (FIX 1465).
    pub state: DeleteRequestState,
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
    /// The recorded outcome: `allow`/`pending`/`deny` for policy decisions,
    /// `imported` for code captures, or another receipt's own outcome.
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
    /// 32-hex id of the decision's bound target, if any. A code snapshot
    /// capture binds its CODE_ARTIFACT; ordinary claim decisions bind CLAIM.
    pub claim_ref: Option<String>,
    /// That target as a typed record ref (OF-063), built from its id with no
    /// read, so labelled with its actual kind and id.
    #[serde(default)]
    pub claim: Option<crate::lens::RecordRef>,
    /// A receipt's own fields (a hook run's hook, CODE id, body hash
    /// and run key), with its trigger, job and principal refs. A code capture
    /// names its repo artifact and retained snapshot hash; the owner's ruling
    /// over their own agent's claim names the superseded claim and its author
    /// (`superseded`, `superseded_author`, `superseded_author_class`);
    /// otherwise empty on a gate-ledger row.
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

pub(in crate::memory) use self::commit::{BatchClaim, BatchRefusal};
mod prompted;
mod settle;

pub(in crate::memory) use settle::ConflictHeadIndex;
pub use settle::{
    ClaimChangeVerdict, ClaimProposalReview, ClaimProposalReviewRequest, ClaimSettleDecision,
    ClaimSettleRequest, ClaimSettlement, ClaimSettlementAnswer, ClaimSettlementReason,
    ClaimSettlementRevert, ClaimSettlementVerdict, SettleWarning, SettleWarningCode,
};
