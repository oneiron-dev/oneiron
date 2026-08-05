//! BRIDGE-01 (ONE-1454): transport-agnostic memory facade.
//!
//! The single write door for app-tier callers (ONE-WIRE-1 W1/W3, ONE-WIRE-2
//! S1/S3/S7/S8): every verb here rides EXISTING engine machinery — the gated
//! claim-candidate path, `BatchBuilder` structural puts, the named deletion
//! verbs, the blob-artifact store — and never bypasses
//! `check_claim_policy_for_write`. Bindings (napi, HTTP) lift this surface
//! verbatim; the facade is authored once, engine-side.
//!
//! Vocabulary (S1): short-id refs (`"ms3:a1"`) or 32-hex entity ids in,
//! typed DTOs out. No type bytes, no raw MessagePack on this surface.
//!
//! Approval policy (design §4.2): the facade REQUESTS `auto` only for
//! `user_stated`/`observed` claims whose scope carries no explicit
//! `sensitivity` key; everything else is submitted `proposed`. The gate
//! remains the enforcer: when it refuses an `auto` request
//! (`GateWriteRejected`), the facade resubmits the same claim `proposed`, so
//! writes park as pending consents instead of vanishing.

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptState, EnqueueAttempt, EnqueueOutcome,
};
use crate::batch::{
    ApplyOpsGateMode, BatchOp, apply_ops, apply_ops_with_gate_mode, parse_short_id_value,
};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    claim_surfaceable,
};
use crate::companion::{
    CompanionExportClassification, CompanionProvenance, CompanionRecord, CompanionScope,
    companion_value_to_json,
};
use crate::context_pack::{DEFAULT_MAX_FIELD_CHARS, FieldProfile, PackFormat};
use crate::deletion::{DeleteReason, DeletionGateContext};
use crate::dreamer_runner::{
    DreamerConsolidationScope, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
    EnqueueDreamerConsolidationAttempt,
};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind};
use crate::habit::TaskRole;
use crate::ingest::{
    INGEST_SOURCE_REGISTRY, ImportedEvidenceAdmission, ImportedEvidenceEntityResolution,
    NormalizedIngestClaim, admit_imported_evidence_claim,
};
use crate::llm::BudgetLease;
use crate::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchError,
    OutboundDispatchGate, OutboundDispatchOutcome, OutboundDispatchRequest,
    OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink, OutboundIntent,
    OutboundIntentDraft, OutboundIntentTrigger, connector_send_attempt_payload,
    outbound_verb_contract, put_connector_send_task_in_txn,
};
use crate::pipeline::{DEFAULT_RECENCY_HALF_LIFE_DAYS, FacetMode, WorldScope};
use crate::receipt::delivered_send_receipt_for_task;
use crate::registry::{
    ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MACHINE,
    ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON, ENTITY_TYPE_REGISTRY, ENTITY_TYPE_TASK,
    ENTITY_TYPE_TURN,
};
use crate::serialize::{SerializeConfig, serialize_pack};
use crate::temporal::TimeRange;
use crate::write_envelope::{
    ClaimCandidate, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY, WriteActor, WriteEnvelope, WriteProvenance,
};

/// Stable facade error codes, mirroring the `oneiron-server`
/// `ApiErrorDetails` code vocabulary (S8).
pub const FACADE_CODE_BAD_REQUEST: &str = "BAD_REQUEST";
/// See [`FACADE_CODE_BAD_REQUEST`].
pub const FACADE_CODE_NOT_FOUND: &str = "NOT_FOUND";
/// See [`FACADE_CODE_BAD_REQUEST`].
pub const FACADE_CODE_FORBIDDEN: &str = "FORBIDDEN";
/// See [`FACADE_CODE_BAD_REQUEST`].
pub const FACADE_CODE_INVALID_STATE: &str = "INVALID_STATE";
/// See [`FACADE_CODE_BAD_REQUEST`].
pub const FACADE_CODE_INTERNAL: &str = "INTERNAL_SERVER_ERROR";
/// `recall(Deep)` called without a budget lease (W4/C4 lease rule).
pub const FACADE_CODE_LEASE_REQUIRED: &str = "LEASE_REQUIRED";

/// The S6 `MemoryPack` schema version.
pub const MEMORY_PACK_VERSION: u32 = 1;

/// Predicates with declared multi-cardinality supersession keys (B1c,
/// RATIFY-20260710 R0): the prior-claim match extends
/// `subject+scope+predicate` with `value.question_id`.
pub const MULTI_CARDINALITY_PREDICATES: [&str; 1] = ["eiri.onboarding.answer"];

const MULTI_CARDINALITY_VALUE_KEY: &str = "question_id";
const SCOPE_SENSITIVITY_KEY: &str = "sensitivity";
const GATE_RECEIPT_SCAN_LIMIT: usize = 512;
const PPR_SEED_LIMIT: usize = 8;
const SNIPPET_MAX_CHARS: usize = 160;
/// Bounded claim scan behind scope-honesty world enumeration.
const SCOPE_HONESTY_SCAN_CAP: usize = 512;
const RECALL_TOKEN_BUDGET: usize = 4000;
/// Attempt-queue kind for bridge-scheduled outbound intents. Pending schedules
/// use the queue's kind-scoped dedupe index; delivered sends use the additive
/// durable client-idempotency index.
pub const BRIDGE_OUTBOUND_ATTEMPT_KIND: &str = "bridge.outbound.schedule";

/// Typed facade error: stable `code` + human `message` + remediation
/// `suggestions` (never empty). The central `From<Error>` impl is the one
/// engine→binding error mapping (S8); the HTTP mapping stays server-side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FacadeError {
    /// One of the `FACADE_CODE_*` strings.
    pub code: String,
    /// Human-readable description of the failure.
    pub message: String,
    /// Remediation hints for clients; always non-empty.
    pub suggestions: Vec<String>,
}

impl FacadeError {
    fn new(code: &str, message: impl Into<String>, suggestions: &[&str]) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
            suggestions: suggestions.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self::new(
            FACADE_CODE_BAD_REQUEST,
            message,
            &["Fix the request shape and retry."],
        )
    }

    pub(crate) fn bad_request_with(message: impl Into<String>, suggestions: &[&str]) -> Self {
        Self::new(FACADE_CODE_BAD_REQUEST, message, suggestions)
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self::new(
            FACADE_CODE_NOT_FOUND,
            message,
            &["Verify the identifier and retry."],
        )
    }
}

impl std::fmt::Display for FacadeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for FacadeError {}

impl From<Error> for FacadeError {
    fn from(err: Error) -> Self {
        let message = err.to_string();
        match err.kind() {
            ErrorKind::EntityNotFound | ErrorKind::EdgeNotFound => Self::new(
                FACADE_CODE_NOT_FOUND,
                message,
                &["Verify the identifier and retry."],
            ),
            ErrorKind::GateWriteRejected
            | ErrorKind::SourceNotTrustedForAuto
            | ErrorKind::GateConsentStale
            | ErrorKind::MaintenanceKindNotWritable
            | ErrorKind::ActorClassMismatch => Self::new(
                FACADE_CODE_FORBIDDEN,
                message,
                &[
                    "The gate refused this write; review pending consents via pending_writes.",
                    "Submit the claim as proposed or adjust the actor/scope.",
                ],
            ),
            ErrorKind::ClaimAlreadyClosed
            | ErrorKind::ClaimSelfSupersession
            | ErrorKind::CompanionRecordAlreadyExists
            | ErrorKind::ConcurrentWrite
            | ErrorKind::EntityTypeImmutable => Self::new(
                FACADE_CODE_INVALID_STATE,
                message,
                &["Refresh the resource, merge local changes, then retry."],
            ),
            ErrorKind::Storage
            | ErrorKind::Io
            | ErrorKind::CorruptedIndex
            | ErrorKind::InvariantViolation
            | ErrorKind::MapFull
            | ErrorKind::IndexOverflow
            | ErrorKind::MissingPostingEntry => Self::new(
                FACADE_CODE_INTERNAL,
                message,
                &["Retry; if the failure persists, inspect vault store health."],
            ),
            _ => Self::new(
                FACADE_CODE_BAD_REQUEST,
                message,
                &["Fix the request shape and retry."],
            ),
        }
    }
}

/// Facade result alias.
pub type FacadeResult<T> = std::result::Result<T, FacadeError>;

/// Who authored one witnessed message (facade vocabulary; the MESSAGE body
/// `author` key stores the snake_case string).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessAuthor {
    /// The vault owner.
    User,
    /// The companion persona.
    Companion,
    /// System/tooling rows; these get NO `AuthoredBy` edge (design §2.1).
    System,
}

impl WitnessAuthor {
    /// Stable string form (`user`/`companion`/`system`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Companion => "companion",
            Self::System => "system",
        }
    }

    /// Parses the stable string form.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "user" => Some(Self::User),
            "companion" => Some(Self::Companion),
            "system" => Some(Self::System),
            _ => None,
        }
    }
}

/// One message inside a witnessed turn.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WitnessMessage {
    /// Caller-supplied deterministic 32-hex entity id; `None` ⇒ generated.
    pub id: Option<String>,
    /// Author bucket; `System` rows get no `AuthoredBy` edge.
    pub author: WitnessAuthor,
    /// Message type string (closed set app-side, opaque here).
    pub message_type: String,
    /// Text content; BM25-indexed under the `content` field when non-empty.
    pub content: String,
    /// Opaque metadata, passed through as MessagePack.
    pub metadata: Option<serde_json::Value>,
    /// Visibility flag (default true app-side).
    pub is_visible: bool,
    /// Position of the message within its turn.
    pub order: u32,
}

/// One conversational turn to witness: create-or-get CONVERSATION/TURN plus
/// gated MESSAGE puts, edges, and text indexing in ONE batch (B2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WitnessTurn {
    /// CONVERSATION ref: short-id ref or 32-hex id (create-or-get for hex).
    pub conversation_ref: String,
    /// TURN ref (create-or-get for hex); `None` ⇒ a fresh TURN is created.
    pub turn_ref: Option<String>,
    /// Messages, all attributed to the bound actor unless `System`. A
    /// mixed-author turn is witnessed in multiple calls sharing `turn_ref`,
    /// each under its authoring actor.
    pub messages: Vec<WitnessMessage>,
    /// Unix seconds; used for both `occurred` and `learned_at` so
    /// migration backfill stays deterministic.
    pub occurred_at: u64,
}

/// Receipt for one witnessed turn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessReceipt {
    /// Short-id ref of the TURN (hex fallback if no short id exists).
    pub turn_short_id: String,
    /// Short-id refs of the written MESSAGE entities, input order.
    pub message_short_ids: Vec<String>,
    /// Facade write ref (`witness:<turn-hex>`). Structural puts produce no
    /// gate decision at base, so this is a write marker, not a
    /// `receipts()`-resolvable gate ref.
    pub receipt_ref: String,
}

/// One claim to commit. `approval` is deliberately NOT settable by callers
/// (pin 2); the facade computes the request and the gate decides.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// [`MemoryFacade::receipts`]; falls back to a facade marker when no
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

    const fn delete_reason(self) -> DeleteReason {
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
pub struct FacadeReceipt {
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

/// Typed read-back view of one entity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityView {
    /// 32-hex entity id.
    pub id_hex: String,
    /// Short-id ref, when one is assigned.
    pub short_ref: Option<String>,
    /// Registry kind string (e.g. `MESSAGE`); `TYPE_<n>` for unregistered.
    pub kind: String,
    /// Occurred interval start (Unix seconds).
    pub occurred_start: u64,
    /// Occurred interval end (Unix seconds).
    pub occurred_end: u64,
    /// Learned-at (Unix seconds).
    pub learned_at: u64,
    /// Body decoded MessagePack→JSON; `None` when absent or not
    /// JSON-shaped (binary values are redacted per the companion codec).
    pub body: Option<serde_json::Value>,
}

/// Typed read-back view of one claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimView {
    /// 32-hex claim id.
    pub claim_ref: String,
    /// Short-id ref, when assigned.
    pub short_ref: Option<String>,
    /// Predicate.
    pub predicate: String,
    /// Subject: entity hex, or `edge:<src>:<kind>:<tgt>` for edge subjects.
    pub subject_ref: String,
    /// Claim value as JSON.
    pub value: serde_json::Value,
    /// Confidence.
    pub confidence: f32,
    /// Approval string.
    pub approval: String,
    /// Lifecycle string.
    pub lifecycle: String,
    /// Source string, when stamped.
    pub source: Option<String>,
    /// World hex, when world-scoped.
    pub world_ref: Option<String>,
    /// Scope as JSON, when present.
    pub scope: Option<serde_json::Value>,
    /// Validity window start.
    pub valid_from: Option<u64>,
    /// Validity window end.
    pub valid_to: Option<u64>,
    /// Salience, when stamped.
    pub salience: Option<f32>,
    /// Stale marker.
    pub stale: bool,
}

/// Filter for [`MemoryFacade::claim_list`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimListFilter {
    /// Restrict to claims on this subject (short-id ref or hex).
    pub subject_ref: Option<String>,
    /// Restrict to this predicate.
    pub predicate: Option<String>,
    /// Restrict to this lifecycle (`active`/`superseded`/`retracted`).
    pub lifecycle: Option<String>,
    /// Maximum results (required; no unbounded scans).
    pub limit: usize,
}

/// One BM25 text-index field for a structural put.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextIndexField {
    /// Analyzer field name (e.g. `content`, `name`).
    pub field: String,
    /// Field text.
    pub value: String,
}

/// One outgoing edge for a structural put.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructuralEdgeSpec {
    /// snake_case `EdgeKind` name (e.g. `belongs_to`, `attached`).
    pub edge_kind: String,
    /// Target entity ref (short-id ref or hex).
    pub target_ref: String,
    /// Edge weight in `[0, 1]`; `None` ⇒ the kind's default (1.0 fallback).
    pub weight: Option<f32>,
}

/// Structural put carrying text-index fields and edges (B2 migrator group).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructuralPutInput {
    /// Caller-supplied deterministic 32-hex id; `None` ⇒ generated.
    pub id: Option<String>,
    /// Registry kind string (`MESSAGE`, `PERSON`, `TASK`, `ASSET`, …).
    /// `CLAIM` is rejected — claims go through [`MemoryFacade::commit`].
    pub kind: String,
    /// Entity body as a JSON object (stored as MessagePack).
    pub body: serde_json::Value,
    /// BM25 fields to index for this entity.
    pub text_fields: Option<Vec<TextIndexField>>,
    /// Outgoing edges from this entity.
    pub edges: Option<Vec<StructuralEdgeSpec>>,
    /// Unix seconds.
    pub occurred_at: u64,
    /// Unix seconds; `None` ⇒ `occurred_at`.
    pub learned_at: Option<u64>,
}

/// Receipt for a structural write (put/checkin/companion/blob artifact).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityRefReceipt {
    /// Short-id ref of the written entity (hex fallback).
    pub entity_ref: String,
    /// 32-hex id of the written entity.
    pub id_hex: String,
    /// Facade write marker (`put:<hex>`); structural puts produce no gate
    /// decision at base.
    pub receipt_ref: String,
}

/// One habit check-in append (B2 migrator group).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HabitCheckinInput {
    /// Habit-role TASK ref (short-id ref or hex); must exist.
    pub habit_ref: String,
    /// Caller-supplied deterministic 32-hex checkin id; `None` ⇒ generated.
    pub id: Option<String>,
    /// Extra body fields (JSON object). The facade injects the pinned
    /// `role` key (`HabitCheckin`); supplying `role` here is rejected.
    pub data: Option<serde_json::Value>,
    /// Unix seconds.
    pub occurred_at: u64,
    /// Unix seconds; `None` ⇒ `occurred_at`.
    pub learned_at: Option<u64>,
}

/// One companion persona registration (B2 migrator group, design §2.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompanionRecordInput {
    /// Caller-supplied deterministic 32-hex record id; `None` ⇒ generated.
    pub id: Option<String>,
    /// Owner PERSON ref (personal scope).
    pub owner_ref: String,
    /// Companion persona PERSON ref.
    pub persona_ref: String,
    /// Opaque record value (JSON, stored as MessagePack).
    pub value: serde_json::Value,
    /// Provenance source string; `None` ⇒ `user_stated`.
    pub source: Option<String>,
    /// When set, the record is retired at this time after creation
    /// (migration of `isActive == false` rows).
    pub retired_at: Option<u64>,
    /// Creation time (Unix seconds) — stamps the `created` lifecycle event.
    pub learned_at: u64,
}

/// One imported-evidence claim admission (B1a migration-admission verb over
/// `ingest.rs` `admit_imported_evidence_claim`; the gate still decides).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdmitImportedClaimInput {
    /// Registered ingest source id; unknown sources fail closed.
    pub source_id: String,
    /// Stable source record id (idempotency/provenance anchor).
    pub source_record_id: String,
    /// Caller-supplied deterministic 32-hex claim id; `None` ⇒ generated.
    pub id: Option<String>,
    /// Subject entity ref (must exist).
    pub subject_ref: String,
    /// Predicate.
    pub predicate: String,
    /// Claim value (JSON).
    pub value: serde_json::Value,
    /// Unix seconds.
    pub occurred_at: u64,
    /// Unix seconds; `None` ⇒ `occurred_at`.
    pub learned_at: Option<u64>,
}

/// One blob artifact registration (B8 blob door).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobArtifactInput {
    /// Caller-supplied deterministic 32-hex artifact id; `None` ⇒ generated.
    pub id: Option<String>,
    /// Display name (≤512 bytes).
    pub name: String,
    /// Media type (≤256 bytes).
    pub media_type: String,
    /// Unix seconds.
    pub occurred_at: u64,
    /// Unix seconds; `None` ⇒ `occurred_at`.
    pub learned_at: Option<u64>,
}

/// View of one appended blob artifact version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobVersionView {
    /// 32-hex artifact id.
    pub artifact_ref: String,
    /// Version number (1-based, append-only).
    pub version: u64,
    /// blake3 content hash, lowercase hex.
    pub content_hash_hex: String,
    /// 32-hex id of the `blob.version` LEDGER claim.
    pub claim_ref: String,
    /// Unix seconds.
    pub created_at: u64,
}

/// Retrieval effort dial (S6). Deliberately distinct from `llm.rs`
/// `ReasoningEffort` (the LLM dial) and `context_pack.rs` `FieldProfile`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effort {
    /// Pure lexical retrieval: text search only, no graph expansion, no
    /// hydration, minimal fields. No LLM, no lease.
    Minimal,
    /// Text + PPR graph expansion, 1-hop edges, hydration, standard
    /// fields, recency/salience/confidence boosts. No LLM, no lease.
    Standard,
    /// Lease-gated deep retrieval. No lease-issuer exists yet (OF-131
    /// IN_BUILD): without a lease this is a typed `LEASE_REQUIRED` error;
    /// with one it executes as `Standard` plus `deep_pending: true` until
    /// the LLMB chain wires execution.
    Deep,
}

impl Effort {
    /// Stable string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Standard => "standard",
            Self::Deep => "deep",
        }
    }

    /// Parses the stable string form.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "minimal" => Some(Self::Minimal),
            "standard" => Some(Self::Standard),
            "deep" => Some(Self::Deep),
            _ => None,
        }
    }
}

/// Recall scoping (S5): world/facet narrowing only — unset means the vault
/// floor; the scope never widens beyond it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecallScope {
    /// WORLD entity ref; scopes to that world plus base reality.
    pub world_ref: Option<String>,
    /// Facet entity ref; strict facet narrowing when set.
    pub facet: Option<String>,
}

/// One BM25 hit (engine index scores, never re-ranked app-side).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LexicalHit {
    /// Short ref (hex fallback).
    pub short_id: String,
    /// Registry kind string.
    pub kind: String,
    /// Engine BM25F score.
    pub score: f32,
    /// Content preview, when the body carries a `content` field.
    pub snippet: Option<String>,
}

/// Options for [`MemoryFacade::neighbors`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NeighborOpts {
    /// Restrict to this snake_case `EdgeKind` name.
    pub edge_kind: Option<String>,
    /// Drop edges below this weight (engine-side filter).
    pub min_weight: Option<f32>,
    /// Maximum hits (required; no unbounded scans).
    pub limit: usize,
}

/// One graph neighbor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NeighborHit {
    /// Short ref of the neighboring entity (hex fallback).
    pub short_id: String,
    /// Registry kind string of the neighbor.
    pub kind: String,
    /// snake_case `EdgeKind` name.
    pub edge_kind: String,
    /// Stored edge weight.
    pub weight: f32,
    /// `out` (edge from the anchor) or `in` (edge into the anchor).
    pub direction: String,
}

/// Item provenance (S6, default-on).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryProvenance {
    /// Claim source string, or `record` for structural source records.
    pub source: String,
    /// This revision plus superseded ancestors (32-hex ids).
    pub source_revision_ids: Vec<String>,
    /// Evidence TURN ids. Populated structurally for MESSAGE items; claim
    /// evidence stamping is the extraction pipeline's later responsibility.
    pub evidence_turn_ids: Vec<String>,
}

/// One memory pack item (S6 schema).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryItem {
    /// Short ref, hydratable via [`MemoryFacade::hydrate`].
    pub short_id: String,
    /// Registry kind string.
    pub kind: String,
    /// Predicate (claims only).
    pub predicate: Option<String>,
    /// Text rendering of the item value/content (capped).
    pub value_text: String,
    /// Calibrated-absolute confidence in [0, 1] — NEVER set-relative:
    /// read from the claim body, independent of the candidate set.
    pub confidence: f32,
    /// Hedge vocabulary bucket derived from `confidence`.
    pub hedge_bucket: String,
    /// Provenance (default-on).
    pub provenance: MemoryProvenance,
    /// World hex, when world-scoped.
    pub world: Option<String>,
    /// Facet hex, when faceted.
    pub facet: Option<String>,
    /// Salience, when stamped.
    pub salience: Option<f32>,
}

/// Scope honesty (S6): what the scope excluded.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeHonesty {
    /// Worlds holding surfaceable claims outside the requested scope.
    pub out_of_scope_worlds: Vec<String>,
}

/// Retrieval accounting (S6).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrievalMeta {
    /// True when only sparse (lexical/graph) signals ran — no dense
    /// vector signal is available until the embedder lane lands.
    pub sparse: Option<bool>,
    /// Candidates considered by the retrieval pipeline.
    pub total_candidates: u64,
    /// CLAIM items in the returned pack.
    pub claims_returned: u64,
    /// Set when a leased `Deep` call executed as `Standard` (LLMB chain
    /// not yet wired).
    pub deep_pending: Option<bool>,
}

/// The facade projection of a `ContextPack` (S6, `pack_version: 1`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryPack {
    /// Ranked items.
    pub items: Vec<MemoryItem>,
    /// What the scope excluded.
    pub scope_honesty: ScopeHonesty,
    /// Retrieval accounting.
    pub retrieval_meta: RetrievalMeta,
    /// Schema version (always [`MEMORY_PACK_VERSION`]).
    pub pack_version: u32,
    /// Text rendering in the requested OF-096 format; `None` = typed only.
    pub rendered: Option<String>,
}

/// One Dreamer consolidation enqueue (BRIDGE-03).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsolidationAttemptInput {
    /// Consolidation scope: `micro` | `meso` | `macro`.
    pub scope: String,
    /// Opaque attempt input (stored as MessagePack in the queue payload).
    pub input: serde_json::Value,
    /// Optional run correlation id.
    pub run_id: Option<String>,
    /// Optional advisory dedupe key (cost coalescer, not a lock).
    pub dedupe_key: Option<String>,
    /// Unix seconds; `None` ⇒ now.
    pub now: Option<u64>,
}

/// Reference to one queued Dreamer attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DreamerAttemptRef {
    /// 32-hex attempt id (poll via [`MemoryFacade::dreamer_attempt_status`]).
    pub job_ref: String,
    /// Queue state at enqueue time.
    pub state: String,
    /// True when the advisory dedupe key coalesced onto an existing attempt.
    pub existing: bool,
}

/// Poll-model view of one Dreamer attempt (W2: long work returns attempt ids).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DreamerAttemptView {
    /// 32-hex attempt id.
    pub job_ref: String,
    /// `queued` | `leased` | `paused` | `completed` | `failed` | `cancelled`.
    pub state: String,
    /// Queue attempt kind.
    pub kind: String,
    /// Worker label holding the lease, if leased.
    pub lease_owner: Option<String>,
    /// Admission attempts so far.
    pub attempt_count: u32,
    /// Run correlation id, if any.
    pub run_id: Option<String>,
    /// Last failure message, if any.
    pub last_error: Option<String>,
    /// Unix seconds.
    pub created_at: u64,
    /// Unix seconds.
    pub updated_at: u64,
}

/// One outbound schedule request (BRIDGE-03; rides OF-327 — the bridge
/// never implements delivery).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundDraftInput {
    /// Verb (e.g. `send`).
    pub verb: String,
    /// Channel (e.g. `email`).
    pub channel: String,
    /// Delivery target (address/handle).
    pub target: String,
    /// Principal the send acts for, if delegated.
    pub on_behalf_of: Option<String>,
    /// Reference to the content entity to send.
    pub content_ref: Option<String>,
    /// Facade-enforced idempotency key: a second schedule with the same
    /// key coalesces instead of double-enqueueing.
    pub idempotency_key: Option<String>,
    /// Advisory dedupe key carried onto the receipt.
    pub dedupe_key: Option<String>,
    /// Trigger source: `commitment_timer_wake` | `gap_queue` |
    /// `agent_immediate`.
    pub trigger: String,
    /// What fired the trigger (commitment/session/queue ref).
    pub trigger_ref: String,
    /// Owning attempt/brief ref, if any.
    pub job_ref: Option<String>,
    /// Unix seconds; `None` ⇒ now.
    pub occurred_at: Option<u64>,
}

/// Receipt for one scheduled outbound intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundIntentReceipt {
    /// Stable intent ref (`intent:<attempt-hex>`).
    pub intent_ref: String,
    /// Dispatch outcome (`held` expected on this schedule-only surface;
    /// `suppressed` on gate denial; `already_scheduled` for a pending schedule
    /// dedupe; `already_sent` for a durable delivered-send dedupe).
    pub outcome: String,
    /// Gate outcome (`allow`/`pending`/`deny`). On dedupe this re-surfaces
    /// the first schedule's outcome (absent only if its binding is missing).
    pub gate_outcome: Option<String>,
    /// Persisted gate decision ref (`gate:<hex>`), queryable via
    /// [`MemoryFacade::receipts`]. On dedupe this re-surfaces the first
    /// schedule's decision (absent only if its binding is missing).
    pub gate_decision_ref: Option<String>,
    /// Gate reason codes.
    pub gate_reason_codes: Vec<String>,
    /// True when the idempotency key coalesced onto an existing schedule.
    pub deduped: bool,
}

/// Internal side-index record: the gate surface a scheduled outbound attempt's
/// first dispatch produced, persisted by attempt id so an idempotent replay
/// (`EnqueueOutcome::Existing`) can re-surface the original decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OutboundGateBinding {
    gate_outcome: String,
    #[serde(default)]
    gate_decision_ref: Option<String>,
    #[serde(default)]
    gate_reason_codes: Vec<String>,
}

/// Parses the pinned actor-key grammar `"<actor_class>:<entity_ref>"`
/// (design §4.3): `actor_class ∈ human|agent|system`, `entity_ref` a
/// short-id ref or 32-hex id. Malformed keys are typed errors, never a
/// defaulted class.
pub fn parse_actor_key(vault: &Vault, key: &str) -> FacadeResult<(EntityId, EdgeActorClass)> {
    let Some((class_str, entity_ref)) = key.split_once(':') else {
        return Err(FacadeError::bad_request_with(
            format!("actor key {key:?} is not of the form <actor_class>:<entity_ref>"),
            &["Use \"human:<ref>\", \"agent:<ref>\", or \"system:<ref>\"."],
        ));
    };
    let actor_class = match class_str {
        "human" => EdgeActorClass::Human,
        "agent" => EdgeActorClass::Agent,
        "system" => EdgeActorClass::System,
        other => {
            return Err(FacadeError::bad_request_with(
                format!("unknown actor class {other:?}"),
                &["Use one of: human, agent, system."],
            ));
        }
    };
    let actor = resolve_entity_ref(vault, entity_ref)?;
    verify_actor_binding(vault, actor, actor_class)?;
    Ok((actor, actor_class))
}

/// Resolves a facade entity ref — 32-hex id or `"<short_id>:<hash-hex>"`
/// short ref — to an [`EntityId`]. Short refs must resolve in the vault.
pub fn resolve_entity_ref(vault: &Vault, reference: &str) -> FacadeResult<EntityId> {
    let reference = reference.trim();
    if reference.len() == 32 && reference.chars().all(|c| c.is_ascii_hexdigit()) {
        return EntityId::from_hex(reference)
            .map_err(|_| FacadeError::bad_request(format!("invalid entity id {reference:?}")));
    }
    if let Some((short_id, content_hash)) = parse_short_ref(reference) {
        let hydrated = vault.hydrate_short_id(&short_id, content_hash)?;
        return match hydrated {
            Some(entry) => Ok(entry.id),
            None => Err(FacadeError::not_found(format!(
                "short ref {reference:?} does not resolve"
            ))),
        };
    }
    Err(FacadeError::bad_request_with(
        format!("entity ref {reference:?} is neither a 32-hex id nor a short ref"),
        &["Pass a 32-character hex entity id or a short ref like \"ms1:a3\"."],
    ))
}

/// Store-truth check behind every actor binding: the entity must exist
/// and its stored type must permit the asserted class.
///
/// DA-0 audit: every actor-gated non-claim mutation uses
/// [`MemoryFacade::with_verified_actor_write_txn`] so the store-truth actor
/// check and mutation share one LMDB write transaction. The enumerated verbs
/// are witness, claim_retract, put_structural, put_habit_checkin,
/// put_companion_record, put_blob_artifact, append_blob_version,
/// enqueue_consolidation, and schedule_outbound's schedule-time Gate decision
/// followed by its durable enqueue. The claim
/// doors (commit, claim_upsert, admit_imported_claim, seed_claims) are skipped:
/// `apply_claim_candidate` already revalidates their actor in the claim write
/// transaction. Reads and status/query verbs are ungated and non-mutating.
/// safe_delete is the ordered multi-transaction exception; its gate is
/// evaluated before TXN1, staged for recovery there, and appended on TXN3.
pub(crate) fn verify_actor_binding(
    vault: &Vault,
    actor: EntityId,
    actor_class: EdgeActorClass,
) -> FacadeResult<()> {
    let entity_type = vault.get_entity_type(&actor)?;
    verify_actor_entity_type(actor, actor_class, entity_type)
}

fn verify_actor_binding_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    actor_class: EdgeActorClass,
) -> FacadeResult<()> {
    let entity_type = vault
        .get_raw_in(txn, &actor)?
        .map(|raw| {
            crate::batch::EntityMetadataHeader::parse(&raw)
                .ok_or_else(|| FacadeError::from(Error::CorruptedIndex("entity header")))
                .map(|header| header.entity_type)
        })
        .transpose()?;
    verify_actor_entity_type(actor, actor_class, entity_type)
}

/// Owner-verb teeth (ONE-1604-D2 / ESB-C).
///
/// [`verify_actor_binding`] proves the asserted actor EXISTS and that its
/// entity type admits the class. That is store truth, not authority: any
/// facade holder could name a pre-existing PERSON as `human` and exercise
/// owner verbs. This check demands the authority log agree — a folded ACTIVE
/// binding `{signing key in the live owner-capable roster, actor_ref == actor,
/// actor_class == "human" EXACTLY, live epoch}`.
///
/// Enforcement scales with declared authority: a vault with no folded genesis
/// has not declared an authority root, so it keeps the store-truth check only.
/// The moment a host establishes a root, owner verbs require the binding —
/// which is exactly the pressure that makes the atomic `[genesis, bind]`
/// ceremony the natural path. No dual-mode shim, no flag.
///
/// A missing `vault_id` is NOT one state. The fold also returns `None` when the
/// log carries several independently rooted vaults, and that collapse clears
/// `actor_bindings` wholesale — so treating every `None` as "unrooted" would
/// hand full owner rights to exactly the vault whose authority root is under
/// attack. Multi-root therefore fails CLOSED and unrooted keeps the spec'd
/// pass-through.
///
/// An UNCOMPUTABLE fold is a third state, and it is the one this gate must not
/// paper over. When an AUTHORITY_LOG row has lost its first-seen sidecar after
/// the one-shot migration ran, the readonly fold cannot decide whether a
/// delayable widen elapsed — and a `RotateKey` or `RecoveryReboot` left
/// un-applied keeps the key it RETIRES live and owner-bound. So the fold
/// refuses instead of guessing, and the refusal surfaces here as INVALID_STATE
/// (the vault's authority is broken, not the caller's request), suspending
/// every owner verb until the log is re-folded through the write path.
///
/// A PRE-MIGRATION log takes the same door for the same reason. There the
/// first-seen time is not lost but never recorded, and the only other candidate
/// — the header's `learned_at` — is peer-written: trusting it lets a legacy
/// `EnrollDevice(learned_at = 0)` present as long matured, so a child
/// `BindActor` on the freshly owner-capable key would fold ACTIVE with no veto
/// window. The fold assumes first-seen-now instead, which leaves the affected
/// widens pending, and refuses while any of them is load-bearing. Unlike the
/// lost-sidecar case this clears itself: one write-path fold records the
/// observation and the delay runs from there.
fn verify_owner_actor_binding_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
) -> FacadeResult<()> {
    let fold = vault.authority_fold_readonly_in_txn(txn).map_err(|err| {
        if crate::authority::is_corrupt_first_seen_sidecar(&err) {
            return FacadeError::new(
                FACADE_CODE_INVALID_STATE,
                format!("{err}; owner verbs are suspended"),
                &[
                    "Restore this vault's sync_state from backup, or re-import the authority log into a fresh vault so first-seen times are observed again.",
                    "A widen whose local first-seen time is lost cannot be judged elapsed or pending; no binding authorizes until it can.",
                ],
            );
        }
        if crate::authority::is_indeterminate_first_seen(&err) {
            return FacadeError::new(
                FACADE_CODE_INVALID_STATE,
                format!("{err}; owner verbs are suspended"),
                &[
                    "Run a write-path authority fold (any authority-log write, or `authority_fold`) so this vault records when it first observed the pending entries.",
                    "The delay then runs from that local observation; a widen's first-seen time is never taken from the peer-claimed learned_at metadata.",
                ],
            );
        }
        FacadeError::from(err)
    })?;
    if fold.vault_root_is_conflicted() {
        return Err(FacadeError::new(
            FACADE_CODE_INVALID_STATE,
            "authority log folds to conflicting vault roots; owner verbs are suspended".to_owned(),
            &[
                "Resolve the authority fork: keep the entries of the legitimate root and drop the foreign ones.",
                "A vault cannot have two authority roots; no binding authorizes until one wins.",
            ],
        ));
    }
    if fold.vault_id.is_none() {
        return Ok(());
    }
    if crate::authority::actor_binding_is_active(&fold, &actor, "human") {
        return Ok(());
    }
    Err(FacadeError::new(
        FACADE_CODE_FORBIDDEN,
        format!(
            "actor {} holds no active owner binding in the authority log",
            actor.to_hex()
        ),
        &[
            "Establish an owner binding with a BindActor entry signed by an owner device.",
            "Actor keys assert identity; the authority log decides whether it holds.",
        ],
    ))
}

/// The COMPLETE deletion-authority predicate, evaluatable inside any read or
/// write transaction: actor binding + human class + folded owner binding.
///
/// It exists as one function because it is evaluated TWICE per gated delete and
/// the two evaluations must be identical. `evaluate_deletion_gate` runs it in
/// its own read txn to mint the decision record; `delete_entity_with_reason_impl`
/// runs it AGAIN inside the destructive write txn. Anything checked only in the
/// first pass is checked in a snapshot that is already stale by the time the
/// purge commits — a revocation landing in that window would be invisible, which
/// is exactly the TOCTOU the second pass closes. Split the two lists and they
/// drift; keep them here and they cannot.
///
/// The sibling owner verbs already fold inside their write txns
/// (`claim_retract`, `put_structural`), so this makes deletion the third
/// consistent arm rather than introducing a new rule.
pub(crate) fn verify_deletion_authority_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    actor_class: EdgeActorClass,
) -> FacadeResult<()> {
    verify_actor_binding_in_txn(vault, txn, actor, actor_class)?;
    if actor_class != EdgeActorClass::Human {
        return Err(FacadeError::new(
            FACADE_CODE_FORBIDDEN,
            format!(
                "actor class {} may not delete entities; deletion is an owner verb",
                actor_class.gate_actor_class(),
            ),
            &[
                "Bind a human-class owner actor key to delete.",
                "Agents withdraw their own claims via claim_retract.",
            ],
        ));
    }
    verify_owner_actor_binding_in_txn(vault, txn, actor)
}

fn verify_actor_entity_type(
    actor: EntityId,
    actor_class: EdgeActorClass,
    entity_type: Option<u8>,
) -> FacadeResult<()> {
    let Some(entity_type) = entity_type else {
        return Err(FacadeError::new(
            FACADE_CODE_FORBIDDEN,
            format!(
                "bound actor {} does not exist in this vault",
                actor.to_hex()
            ),
            &[
                "Provision the actor entity before binding its key.",
                "Actor keys assert identity; the store decides whether it holds.",
            ],
        ));
    };
    crate::provenance::validate_actor_class(entity_type, actor_class).map_err(|_| {
        FacadeError::new(
            FACADE_CODE_FORBIDDEN,
            format!(
                "bound actor {} is a {} entity and cannot act as class {}",
                actor.to_hex(),
                kind_string_for_type(entity_type),
                actor_class.gate_actor_class(),
            ),
            &["Bind an actor key whose entity type matches its asserted class."],
        )
    })
}

fn parse_short_ref(reference: &str) -> Option<(String, u8)> {
    let (short_id, hash) = reference.split_once(':')?;
    let bytes = short_id.as_bytes();
    if bytes.len() < 3
        || !bytes[..2].iter().all(u8::is_ascii_lowercase)
        || !bytes[2..].iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    if hash.len() != 2 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let content_hash = u8::from_str_radix(hash, 16).ok()?;
    Some((short_id.to_owned(), content_hash))
}

fn parse_claim_source(value: &str) -> FacadeResult<ClaimSource> {
    ClaimSource::parse(value).ok_or_else(|| {
        FacadeError::bad_request_with(
            format!("unknown claim source {value:?}"),
            &["Use one of: user_stated, observed, inferred, imported, tool_output, generated."],
        )
    })
}

fn json_to_rmpv(value: &serde_json::Value) -> Value {
    match value {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(b) => Value::Boolean(*b),
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                Value::from(u)
            } else if let Some(i) = n.as_i64() {
                Value::from(i)
            } else {
                Value::from(n.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(s) => Value::from(s.as_str()),
        serde_json::Value::Array(items) => Value::Array(items.iter().map(json_to_rmpv).collect()),
        serde_json::Value::Object(entries) => Value::Map(
            entries
                .iter()
                .map(|(k, v)| (Value::from(k.as_str()), json_to_rmpv(v)))
                .collect(),
        ),
    }
}

fn encode_rmpv(value: &Value) -> FacadeResult<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value)
        .map_err(|_| FacadeError::bad_request("body is not MessagePack-encodable"))?;
    Ok(out)
}

fn decode_body_json(bytes: &[u8]) -> Option<serde_json::Value> {
    if bytes.is_empty() {
        return None;
    }
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor).ok()?;
    if !cursor.is_empty() {
        return None;
    }
    Some(companion_value_to_json(&value))
}

fn edge_kind_from_str(value: &str) -> Option<EdgeKind> {
    let kind = match value {
        "authored_by" => EdgeKind::AuthoredBy,
        "scoped_to" => EdgeKind::ScopedTo,
        "part_of" => EdgeKind::PartOf,
        "supersedes" => EdgeKind::Supersedes,
        "belongs_to" => EdgeKind::BelongsTo,
        "claim_of" => EdgeKind::ClaimOf,
        "child_of" => EdgeKind::ChildOf,
        "assigned_to" => EdgeKind::AssignedTo,
        "derived_from" => EdgeKind::DerivedFrom,
        "mentions" => EdgeKind::Mentions,
        "about" => EdgeKind::About,
        "supports" => EdgeKind::Supports,
        "opposes" => EdgeKind::Opposes,
        "participates_in" => EdgeKind::ParticipatesIn,
        "attached" => EdgeKind::Attached,
        "employed_by" => EdgeKind::EmployedBy,
        "has_facet" => EdgeKind::HasFacet,
        "facet_of" => EdgeKind::FacetOf,
        "in_world" => EdgeKind::InWorld,
        "set_in" => EdgeKind::SetIn,
        "merged_into" => EdgeKind::MergedInto,
        "split_into" => EdgeKind::SplitInto,
        _ => return None,
    };
    Some(kind)
}

fn type_byte_for_kind(kind: &str) -> FacadeResult<u8> {
    ENTITY_TYPE_REGISTRY
        .iter()
        .find(|entry| entry.kind == kind)
        .map(|entry| entry.type_byte)
        .ok_or_else(|| {
            FacadeError::bad_request_with(
                format!("unknown entity kind {kind:?}"),
                &["Use a registry kind string such as MESSAGE, PERSON, TASK, ASSET."],
            )
        })
}

fn kind_string_for_type(entity_type: u8) -> String {
    crate::registry::entity_type_registry_entry(entity_type).map_or_else(
        || format!("TYPE_{entity_type}"),
        |entry| entry.kind.to_owned(),
    )
}

pub(crate) fn facade_provenance(verb: &str) -> Value {
    Value::Map(vec![
        (Value::from("surface"), Value::from("facade")),
        (Value::from("verb"), Value::from(verb)),
    ])
}

fn requested_approval(
    source: ClaimSource,
    scope: Option<&serde_json::Value>,
) -> ClaimApprovalStatus {
    let auto_source = matches!(source, ClaimSource::UserStated | ClaimSource::Observed);
    let has_sensitivity_key = scope
        .and_then(serde_json::Value::as_object)
        .is_some_and(|map| map.contains_key(SCOPE_SENSITIVITY_KEY));
    if auto_source && !has_sensitivity_key {
        ClaimApprovalStatus::Auto
    } else {
        ClaimApprovalStatus::Proposed
    }
}

fn id_from_optional_hex(id: Option<&str>) -> FacadeResult<EntityId> {
    match id {
        Some(hex) => EntityId::from_hex(hex)
            .map_err(|_| FacadeError::bad_request(format!("invalid entity id {hex:?}"))),
        None => Ok(EntityId::now()),
    }
}

fn subject_ref_string(subject: &ClaimSubject) -> String {
    match subject {
        ClaimSubject::Entity(id) => id.to_hex(),
        ClaimSubject::Edge {
            source,
            kind,
            target,
        } => {
            format!(
                "edge:{}:{}:{}",
                source.to_hex(),
                *kind as u8,
                target.to_hex()
            )
        }
    }
}

/// The actor-bound memory facade: every verb takes the actor context bound
/// at construction (W3 — construction is not authority; the gate decides).
pub struct MemoryFacade<'v> {
    vault: &'v Vault,
    actor: EntityId,
    actor_class: EdgeActorClass,
}

impl Vault {
    /// Binds the memory facade to an actor. The actor entity must exist and
    /// match the class (PERSON for human/agent, MACHINE for system) by the
    /// time a gated write runs — the engine enforces this per write.
    #[must_use]
    pub fn memory_facade(&self, actor: EntityId, actor_class: EdgeActorClass) -> MemoryFacade<'_> {
        MemoryFacade {
            vault: self,
            actor,
            actor_class,
        }
    }
}

impl MemoryFacade<'_> {
    pub(crate) fn vault(&self) -> &Vault {
        self.vault
    }

    /// The bound actor entity id.
    #[must_use]
    pub fn actor(&self) -> EntityId {
        self.actor
    }

    /// The bound actor class.
    #[must_use]
    pub fn actor_class(&self) -> EdgeActorClass {
        self.actor_class
    }

    pub(crate) fn with_verified_actor_write_txn<T>(
        &self,
        write: impl FnOnce(&mut heed::RwTxn<'_>) -> FacadeResult<T>,
    ) -> FacadeResult<T> {
        self.vault.try_with_write_txn(|wtxn| {
            verify_actor_binding_in_txn(self.vault, &*wtxn, self.actor, self.actor_class)?;
            write(wtxn)
        })
    }

    fn evaluate_deletion_gate(&self) -> FacadeResult<DeletionGateContext> {
        let rtxn = self.vault.store.env.read_txn().map_err(Error::from)?;
        verify_deletion_authority_in_txn(self.vault, &rtxn, self.actor, self.actor_class)?;
        let policy = crate::gate::resolve_policy_manifest(&self.vault.store, &rtxn)?;
        Ok(DeletionGateContext::new(
            self.actor,
            self.actor_class,
            crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
            policy.read_frontier_hash()?,
        ))
    }

    // ── write verbs ─────────────────────────────────────────────────────

    /// Witnesses one turn: create-or-get CONVERSATION/TURN, MESSAGE puts,
    /// `PartOf`/`BelongsTo`/`AuthoredBy` edges, and BM25 `content`
    /// indexing — all in ONE atomic batch.
    pub fn witness(&self, turn: &WitnessTurn) -> FacadeResult<WitnessReceipt> {
        if turn.messages.is_empty() {
            return Err(FacadeError::bad_request("witness turn carries no messages"));
        }
        let occurred = TimeRange {
            start: turn.occurred_at,
            end: turn.occurred_at,
        };
        let learned_at = turn.occurred_at;
        let (conversation_id, conversation_is_new) =
            self.resolve_or_new_container(&turn.conversation_ref, ENTITY_TYPE_CONVERSATION)?;
        let (turn_id, turn_is_new) = match &turn.turn_ref {
            Some(reference) => self.resolve_or_new_container(reference, ENTITY_TYPE_TURN)?,
            None => (EntityId::now(), true),
        };

        let container_body = encode_rmpv(&Value::Map(Vec::new()))?;
        let mut message_ids = Vec::with_capacity(turn.messages.len());
        let mut bodies = Vec::with_capacity(turn.messages.len());
        for message in &turn.messages {
            message_ids.push(id_from_optional_hex(message.id.as_deref())?);
            bodies.push(encode_witness_message_body(message)?);
        }
        // Ids created by this call must be marker-free; checked INSIDE the
        // write transaction below so a concurrent hard delete cannot land
        // between check and commit (A1 atomicity).
        let mut created_ids = message_ids.clone();
        if conversation_is_new {
            created_ids.push(conversation_id);
        }
        if turn_is_new {
            created_ids.push(turn_id);
        }
        let text_ops: Vec<BatchOp> = turn
            .messages
            .iter()
            .zip(&message_ids)
            .filter(|(message, _)| !message.content.is_empty())
            .map(|(message, id)| BatchOp::Text {
                id: *id,
                fields: vec![("content".to_owned(), message.content.clone())],
            })
            .collect();
        let text_index_trusted = if text_ops.is_empty() {
            self.vault.text_index_trusted.load(Ordering::Acquire)
        } else {
            self.vault.ensure_text_index_trusted()?;
            true
        };

        let refused = self.with_verified_actor_write_txn(|wtxn| {
            for id in &created_ids {
                if self
                    .vault
                    .local_hard_delete_marker_exists_in_txn(wtxn, id)?
                {
                    return Ok(Some(*id));
                }
            }
            let mut batch = self.vault.batch_in();
            if conversation_is_new {
                batch = batch.put(
                    &conversation_id,
                    ENTITY_TYPE_CONVERSATION,
                    occurred,
                    learned_at,
                    &container_body,
                );
            }
            if turn_is_new {
                batch = batch.put(
                    &turn_id,
                    ENTITY_TYPE_TURN,
                    occurred,
                    learned_at,
                    &container_body,
                );
            }
            for (message, (id, body)) in turn.messages.iter().zip(message_ids.iter().zip(&bodies)) {
                batch = batch
                    .put(id, ENTITY_TYPE_MESSAGE, occurred, learned_at, body)
                    .edge(id, EdgeKind::PartOf, &turn_id, 1.0)
                    .edge(id, EdgeKind::BelongsTo, &conversation_id, 1.0);
                if message.author != WitnessAuthor::System {
                    batch = batch.edge(id, EdgeKind::AuthoredBy, &self.actor, 1.0);
                }
            }
            batch.apply(wtxn)?;
            if !text_ops.is_empty() {
                apply_ops(
                    &self.vault.store,
                    &self.vault.config,
                    &self.vault.analyzer,
                    wtxn,
                    text_ops,
                    text_index_trusted,
                    false,
                    true,
                )?;
            }
            // RT-03 (ONE-1685): a witnessed turn bumps the open session's
            // activity clock — atomically with the turn write, so a crash
            // cannot record the turn without the bump.
            let _bumped_session = crate::session_lifecycle::bump_open_session_activity_in_txn(
                &self.vault.store,
                wtxn,
                learned_at,
            )?;
            Ok(None)
        })?;
        if let Some(id) = refused {
            return Err(hard_deleted_refusal(&id));
        }

        let mut message_short_ids = Vec::with_capacity(message_ids.len());
        for id in &message_ids {
            message_short_ids.push(self.short_ref_or_hex(id)?);
        }
        Ok(WitnessReceipt {
            turn_short_id: self.short_ref_or_hex(&turn_id)?,
            message_short_ids,
            receipt_ref: format!("witness:{}", turn_id.to_hex()),
        })
    }

    /// Commits claims through the gated candidate path, one individually
    /// gated write per element (C3: per-element decisions; one bad element
    /// never sinks the others). Rejected elements come back with approval
    /// `rejected` and do not persist.
    pub fn commit(&self, claims: &[ClaimInput]) -> FacadeResult<Vec<CommitReceipt>> {
        Ok(self.commit_all(claims, true, None))
    }

    /// Commits one claim with single-cardinality auto-supersede (S3):
    /// prior Active claim matching `subject+scope+predicate` (plus
    /// `value.question_id` for declared multi-cardinality predicates, B1c)
    /// is superseded by the new revision.
    pub fn claim_upsert(&self, input: &ClaimInput) -> FacadeResult<CommitReceipt> {
        self.commit_one(input, true, None)
    }

    /// Retracts an active claim (deliberate withdrawal; record preserved).
    ///
    /// Authority (fail-closed): the asserted actor is RESOLVED against the
    /// store in the SAME write transaction as the lifecycle change. A verified
    /// `human`-class actor holds the vault owner's memory authority and
    /// may retract any claim; `agent`/`system` actors may retract ONLY
    /// claims whose write-envelope evidence names them as the writing
    /// actor. Everything else is a typed denial — binding an actor key is
    /// not authority (W3).
    ///
    /// Actor binding, authorship, pending-consent closure, gate receipt, and
    /// lifecycle transition share one write transaction, so a same-id
    /// intervening writer cannot turn prior authorization into authority over
    /// the replacement body or recreate actionable pending consent.
    pub fn claim_retract(&self, claim_ref: &str) -> FacadeResult<CommitReceipt> {
        self.claim_retract_with_before_txn(claim_ref, || {})
    }

    fn claim_retract_with_before_txn(
        &self,
        claim_ref: &str,
        before_txn: impl FnOnce(),
    ) -> FacadeResult<CommitReceipt> {
        let id = self.resolve_ref(claim_ref)?;
        let now = crate::unix_seconds_now();
        before_txn();
        let (approval, consent_decision_id) = self.vault.try_with_write_txn(|wtxn| {
            verify_actor_binding_in_txn(self.vault, wtxn, self.actor, self.actor_class)?;
            let body = self
                .vault
                .get_claim_in_txn(wtxn, &id)?
                .ok_or(Error::EntityNotFound)?;
            // Retracting your OWN claim is not an owner power and needs no
            // owner binding; retracting SOMEONE ELSE'S is, so it gets the
            // authority-log teeth.
            if claim_envelope_actor(&body) != Some(self.actor) {
                if self.actor_class != EdgeActorClass::Human {
                    return Err(FacadeError::new(
                        FACADE_CODE_FORBIDDEN,
                        format!(
                            "actor {} ({}) may not retract a claim it did not write",
                            self.actor.to_hex(),
                            self.actor_class.gate_actor_class(),
                        ),
                        &[
                            "Only the writing actor or a human-class owner actor may retract.",
                            "Bind the owner actor key for cross-actor retraction.",
                        ],
                    ));
                }
                verify_owner_actor_binding_in_txn(self.vault, &*wtxn, self.actor)?;
            }
            let consent_receipt = self.vault.retract_claim_in_txn(wtxn, &id, now)?;
            let approval = self.vault.get_claim_in_txn(wtxn, &id)?.map_or_else(
                || "retracted".to_owned(),
                |body| body.approval.as_str().to_owned(),
            );
            Ok((approval, consent_receipt.map(|record| record.decision_id)))
        })?;
        let receipt_ref = match consent_decision_id {
            Some(decision_id) => format!("gate:{}", decision_id.to_hex()),
            None => self
                .latest_decision_ref_for(&id)?
                .unwrap_or_else(|| format!("retract:{}", id.to_hex())),
        };
        Ok(CommitReceipt {
            claim_short_id: self.short_ref_or_hex(&id)?,
            approval,
            superseded_short_id: None,
            receipt_ref,
        })
    }

    #[cfg(test)]
    fn claim_retract_with_pre_txn_hook(
        &self,
        claim_ref: &str,
        before_txn: impl FnOnce(),
    ) -> FacadeResult<CommitReceipt> {
        self.claim_retract_with_before_txn(claim_ref, before_txn)
    }

    /// Deletes an entity under a NAMED reason (S7). `user_delete` is the
    /// tombstone path; the other three run the redaction-audit machinery.
    ///
    /// Authority (fail-closed): deletion is an OWNER verb — the named
    /// reasons are `user_*`/compliance erasures. Only a VERIFIED
    /// `human`-class actor may delete (`Self::verified_actor_class`:
    /// the asserted actor must exist and be a PERSON — asserted class
    /// strings are never trusted); `agent`/`system` actors get a typed
    /// denial (agents withdraw their own claims via
    /// [`Self::claim_retract`]).
    ///
    /// The owner gate is evaluated before deletion TXN1. Sync-enabled deletes
    /// durably stage an authority-required marker + request-keyed recovery
    /// sidecar before the tombstone can commit; TXN3 consumes that sidecar
    /// with `append_gate_decision_in_txn` alongside the purge and distinct
    /// REDACTION_AUDIT execution receipt. Sync-disabled builds append directly
    /// on their first local scrub/purge.
    pub fn safe_delete(
        &self,
        entity_ref: &str,
        reason: SafeDeleteReason,
    ) -> FacadeResult<DeleteReceipt> {
        let gate = self.evaluate_deletion_gate()?;
        let id = self.resolve_ref(entity_ref)?;
        // The re-check the destructive transactions re-run against their OWN
        // views (fix-leg 5 item 1). `FacadeError` is a binding-layer type the
        // engine's `Result` cannot carry, so the refusal is PARKED here and the
        // engine is handed the accurate typed stand-in: a concurrent write
        // invalidated the snapshot the gate decided on. `safe_delete` then swaps
        // the parked error back, so a caller sees the EXACT code and message the
        // pre-transaction gate would have produced (FORBIDDEN for a revoked
        // binding, INVALID_STATE for a broken authority log) rather than a
        // second, weaker vocabulary for the same refusal.
        let refusal: std::cell::RefCell<Option<FacadeError>> = std::cell::RefCell::new(None);
        let reverify = |txn: &heed::RoTxn<'_>| -> Result<(), Error> {
            verify_deletion_authority_in_txn(self.vault, txn, self.actor, self.actor_class).map_err(
                |err| {
                    *refusal.borrow_mut() = Some(err);
                    Error::ConcurrentWrite(
                        "deletion authority changed before the destructive commit",
                    )
                },
            )
        };
        let outcome = self
            .vault
            .delete_entity_with_reason_gated(
                &id,
                reason.delete_reason(),
                crate::deletion::GatedDeletion::new(gate, &reverify),
            )
            .map_err(|err| refusal.take().unwrap_or_else(|| FacadeError::from(err)))?;
        Ok(DeleteReceipt {
            existed: outcome.existed,
            reason: reason.as_str().to_owned(),
            receipt_ref: outcome
                .receipt_id
                .map(|receipt| format!("redaction:{}", receipt.to_hex())),
        })
    }

    // ── B2 migrator write-verb group ────────────────────────────────────

    /// Structural put carrying text-index fields and outgoing edges, in one
    /// atomic batch. CLAIM-kind writes are rejected — claims go through
    /// [`Self::commit`] so the gate always sees them.
    ///
    /// Actor-capable kinds are provisioning-gated (the facade is not an
    /// actor-forgery door): MACHINE (the `system` class type) is never
    /// writable here — system actors are provisioned by the engine host —
    /// and PERSON (rebindable as `human`/`agent`, where the default
    /// manifest grants the human class an auto ceiling) may be minted
    /// only by a VERIFIED human-class owner actor. Companion-persona and
    /// owner PERSON creation stays available to the owner-bound migrator
    /// (design §2.3/§2.8); no non-owner actor can create an entity that
    /// binds to any actor class. Fresh TASK mints remain available for the
    /// productivity pack, but existing TASK ids are immutable at this broad
    /// structural door and must use their typed mutation verbs.
    pub fn put_structural(&self, input: &StructuralPutInput) -> FacadeResult<EntityRefReceipt> {
        let type_byte = type_byte_for_kind(&input.kind)?;
        if type_byte == ENTITY_TYPE_CLAIM {
            return Err(FacadeError::bad_request_with(
                "CLAIM entities cannot be written structurally",
                &["Use commit/claim_upsert so the write gate sees the claim."],
            ));
        }
        if type_byte == ENTITY_TYPE_MACHINE {
            return Err(FacadeError::new(
                FACADE_CODE_FORBIDDEN,
                "MACHINE entities cannot be written through the facade",
                &[
                    "MACHINE is the system-actor class type; minting one would forge an actor.",
                    "System actors are provisioned by the engine host, not the bridge.",
                ],
            ));
        }
        if type_byte == ENTITY_TYPE_PERSON && self.actor_class != EdgeActorClass::Human {
            return Err(FacadeError::new(
                FACADE_CODE_FORBIDDEN,
                format!(
                    "actor class {} may not mint PERSON entities; PERSON is actor-capable",
                    self.actor_class.gate_actor_class(),
                ),
                &[
                    "PERSON entities rebind as human/agent actors; only the owner mints them.",
                    "Bind a verified human-class owner actor key to create people.",
                ],
            ));
        }
        if !input.body.is_object() {
            return Err(FacadeError::bad_request(
                "structural body must be a JSON object",
            ));
        }
        let id = id_from_optional_hex(input.id.as_deref())?;
        let occurred = TimeRange {
            start: input.occurred_at,
            end: input.occurred_at,
        };
        let learned_at = input.learned_at.unwrap_or(input.occurred_at);
        let data = encode_rmpv(&json_to_rmpv(&input.body))?;

        let mut resolved_edges = Vec::new();
        if let Some(edges) = &input.edges {
            for spec in edges {
                let kind = edge_kind_from_str(&spec.edge_kind).ok_or_else(|| {
                    FacadeError::bad_request_with(
                        format!("unknown edge kind {:?}", spec.edge_kind),
                        &["Use a snake_case EdgeKind name such as belongs_to or attached."],
                    )
                })?;
                let target = self.resolve_ref(&spec.target_ref)?;
                let weight = spec.weight.or_else(|| kind.default_weight()).unwrap_or(1.0);
                resolved_edges.push((kind, target, weight));
            }
        }
        let text_fields: Vec<(String, String)> = input
            .text_fields
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|field| (field.field.clone(), field.value.clone()))
            .collect();
        let text_index_trusted = if text_fields.is_empty() {
            self.vault.text_index_trusted.load(Ordering::Acquire)
        } else {
            self.vault.ensure_text_index_trusted()?;
            true
        };

        // Marker check and put share ONE write transaction (A1): a
        // concurrent hard delete either commits first (refused here) or
        // after this txn (its purge then erases what we wrote).
        let refused = self.with_verified_actor_write_txn(|wtxn| {
            // Minting a PERSON mints a future actor identity, so it is an
            // owner verb. The pre-txn class check above gives the fast typed
            // error; the authority-log teeth run in-txn (TOCTOU-free).
            if type_byte == ENTITY_TYPE_PERSON {
                verify_owner_actor_binding_in_txn(self.vault, &*wtxn, self.actor)?;
            }
            if self
                .vault
                .local_hard_delete_marker_exists_in_txn(wtxn, &id)?
            {
                return Ok(true);
            }
            // TASK ids are immutable at this structural door regardless of the
            // incoming kind: gate on the STORED type, so a non-TASK put cannot
            // clobber an existing TASK body by reusing its id.
            if self.vault.get_entity_type_in_txn(&*wtxn, &id)? == Some(ENTITY_TYPE_TASK) {
                return Err(FacadeError::new(
                    FACADE_CODE_FORBIDDEN,
                    "TASK entities cannot be overwritten through the facade",
                    &["Create a new TASK or use its typed mutation verb."],
                ));
            }
            let mut batch = self
                .vault
                .batch_in()
                .put(&id, type_byte, occurred, learned_at, &data);
            for (kind, target, weight) in &resolved_edges {
                batch = batch.edge(&id, *kind, target, *weight);
            }
            batch.apply(wtxn)?;
            if !text_fields.is_empty() {
                apply_ops(
                    &self.vault.store,
                    &self.vault.config,
                    &self.vault.analyzer,
                    wtxn,
                    vec![BatchOp::Text {
                        id,
                        fields: text_fields.clone(),
                    }],
                    text_index_trusted,
                    false,
                    true,
                )?;
            }
            Ok(false)
        })?;
        if refused {
            return Err(hard_deleted_refusal(&id));
        }
        self.entity_ref_receipt(&id)
    }

    /// Appends one immutable habit check-in child (`ChildOf` edge written by
    /// the pack contract). The pinned `role` body key is facade-injected.
    pub fn put_habit_checkin(&self, input: &HabitCheckinInput) -> FacadeResult<EntityRefReceipt> {
        let habit_id = self.resolve_ref(&input.habit_ref)?;
        let checkin_id = id_from_optional_hex(input.id.as_deref())?;
        let mut entries = vec![(
            Value::from("role"),
            Value::from(u64::from(TaskRole::HabitCheckin.role_byte())),
        )];
        if let Some(data) = &input.data {
            let Some(map) = data.as_object() else {
                return Err(FacadeError::bad_request(
                    "checkin data must be a JSON object",
                ));
            };
            for (key, value) in map {
                if key == "role" {
                    return Err(FacadeError::bad_request_with(
                        "checkin data must not carry the pinned role key",
                        &["Drop the role field; the facade stamps HabitCheckin."],
                    ));
                }
                entries.push((Value::from(key.as_str()), json_to_rmpv(value)));
            }
        }
        let data = encode_rmpv(&Value::Map(entries))?;
        let occurred = TimeRange {
            start: input.occurred_at,
            end: input.occurred_at,
        };
        let learned_at = input.learned_at.unwrap_or(input.occurred_at);
        // Marker check and checkin put share one write transaction (A1).
        let refused = self.with_verified_actor_write_txn(|wtxn| {
            if self
                .vault
                .local_hard_delete_marker_exists_in_txn(wtxn, &checkin_id)?
            {
                return Ok(true);
            }
            self.vault
                .batch_in()
                .put_habit_checkin(&habit_id, &checkin_id, occurred, learned_at, &data)
                .apply(wtxn)?;
            Ok(false)
        })?;
        if refused {
            return Err(hard_deleted_refusal(&checkin_id));
        }
        self.entity_ref_receipt(&checkin_id)
    }

    /// Registers a companion persona record (personal scope) with a
    /// `created` lifecycle event, retiring it when `retired_at` is set.
    pub fn put_companion_record(
        &self,
        input: &CompanionRecordInput,
    ) -> FacadeResult<EntityRefReceipt> {
        let id = id_from_optional_hex(input.id.as_deref())?;
        self.refuse_hard_deleted_id(&id)?;
        let owner = self.resolve_ref(&input.owner_ref)?;
        let persona = self.resolve_ref(&input.persona_ref)?;
        let source = match &input.source {
            Some(source) => parse_claim_source(source)?,
            None => ClaimSource::UserStated,
        };
        let envelope = WriteEnvelope::new(
            WriteActor::new(self.actor, self.actor_class),
            source,
            WriteProvenance::new(facade_provenance("put_companion_record"))?,
            ClaimApprovalStatus::Approved,
        );
        let record = CompanionRecord::persona(
            CompanionScope::personal(owner),
            persona,
            json_to_rmpv(&input.value),
            CompanionProvenance::from_envelope(&envelope),
            CompanionExportClassification::LocalOnly,
        );
        self.with_verified_actor_write_txn(|wtxn| {
            // The early refusal above is only a fast path. Recheck in this
            // transaction so a concurrent hard delete cannot land between
            // the probe and companion creation, resurrecting a purged id.
            if self
                .vault
                .local_hard_delete_marker_exists_in_txn(wtxn, &id)?
            {
                return Err(hard_deleted_refusal(&id));
            }
            self.vault
                .create_companion_record_in_txn(wtxn, &id, &record, input.learned_at)?;
            if let Some(retired_at) = input.retired_at {
                self.vault
                    .retire_companion_record_in_txn(wtxn, &id, retired_at)?;
            }
            Ok(())
        })?;
        self.entity_ref_receipt(&id)
    }

    /// Admits one imported-evidence claim through the registered ingest
    /// source's trust ceiling (B1a). Unknown sources fail closed. The
    /// requested approval is `auto` only when the ceiling permits it at
    /// band 0; the gate still decides, and a refused `auto` request is
    /// resubmitted `proposed`.
    pub fn admit_imported_claim(
        &self,
        input: &AdmitImportedClaimInput,
    ) -> FacadeResult<CommitReceipt> {
        self.verified_actor_class()?;
        let Some(config) = INGEST_SOURCE_REGISTRY.get_config(&input.source_id) else {
            return Err(FacadeError::bad_request_with(
                format!("unknown ingest source {:?}", input.source_id),
                &["Register the source in the ingest source registry first."],
            ));
        };
        let id = id_from_optional_hex(input.id.as_deref())?;
        self.refuse_hard_deleted_id(&id)?;
        let subject = self.resolve_ref(&input.subject_ref)?;
        if self.vault.get_entity_type(&subject)?.is_none() {
            return Err(FacadeError::not_found(format!(
                "claim subject {} does not exist",
                subject.to_hex()
            )));
        }
        let claim = NormalizedIngestClaim {
            source_record_id: input.source_record_id.clone(),
            predicate: input.predicate.clone(),
            value: input.value.clone(),
        };
        let occurred = TimeRange {
            start: input.occurred_at,
            end: input.occurred_at,
        };
        let learned_at = input.learned_at.unwrap_or(input.occurred_at);
        let mut approval = if config.trust_ceiling.permits_auto(Some(0)) {
            ClaimApprovalStatus::Auto
        } else {
            config.default_admission
        };
        let admit = |approval: ClaimApprovalStatus| {
            let admission = ImportedEvidenceAdmission::proposed(
                input.source_id.clone(),
                id,
                ImportedEvidenceEntityResolution::subject(subject),
                WriteActor::new(self.actor, self.actor_class),
                occurred,
                learned_at,
            )
            .with_approval(approval);
            admit_imported_evidence_claim(self.vault, &claim, admission)
        };
        match admit(approval) {
            Ok(()) => {}
            Err(err)
                if approval == ClaimApprovalStatus::Auto
                    && err.kind() == ErrorKind::GateWriteRejected =>
            {
                approval = ClaimApprovalStatus::Proposed;
                admit(approval)?;
            }
            Err(err) => return Err(err.into()),
        }
        let final_approval = self.vault.get_claim(&id)?.map_or_else(
            || approval.as_str().to_owned(),
            |b| b.approval.as_str().to_owned(),
        );
        let receipt_ref = self
            .latest_decision_ref_for(&id)?
            .unwrap_or_else(|| format!("claim:{}", id.to_hex()));
        Ok(CommitReceipt {
            claim_short_id: self.short_ref_or_hex(&id)?,
            approval: final_approval,
            superseded_short_id: None,
            receipt_ref,
        })
    }

    /// Registers a blob artifact (B8 blob door; bytes ride
    /// [`Self::append_blob_version`]).
    pub fn put_blob_artifact(&self, input: &BlobArtifactInput) -> FacadeResult<EntityRefReceipt> {
        let id = id_from_optional_hex(input.id.as_deref())?;
        let body = crate::blob_artifact::BlobArtifactBody::new(
            input.name.clone(),
            input.media_type.clone(),
        );
        let data = crate::blob_artifact::encode_blob_artifact_body(&body)?;
        let occurred = TimeRange {
            start: input.occurred_at,
            end: input.occurred_at,
        };
        let learned_at = input.learned_at.unwrap_or(input.occurred_at);
        // Marker check and artifact put share one write transaction (A1);
        // the encoded body matches Vault::put_blob_artifact exactly.
        let refused = self.with_verified_actor_write_txn(|wtxn| {
            if self
                .vault
                .local_hard_delete_marker_exists_in_txn(wtxn, &id)?
            {
                return Ok(true);
            }
            self.vault
                .batch_in()
                .put(&id, ENTITY_TYPE_BLOB_ARTIFACT, occurred, learned_at, &data)
                .apply(wtxn)?;
            Ok(false)
        })?;
        if refused {
            return Err(hard_deleted_refusal(&id));
        }
        self.entity_ref_receipt(&id)
    }

    /// Appends one content-addressed version to a blob artifact. The whole
    /// append (ASSET bytes + `blob.version` LEDGER claim + version chain)
    /// is one engine transaction; re-appending head bytes is a dedupe no-op.
    ///
    /// Exempt from the hard-delete recreation refusal BY CONSTRUCTION: no
    /// caller-supplied id is written here — the ASSET id is content-derived
    /// inside the engine (module-private derivation) and the LEDGER claim
    /// id is a fresh `EntityId::now()`. The inherent edge of erasure
    /// integrity for content-addressed storage remains: a hard-deleted
    /// ASSET can be re-materialized by re-supplying identical bytes to a
    /// live artifact.
    pub fn append_blob_version(
        &self,
        artifact_ref: &str,
        bytes: &[u8],
        run_ref: Option<&str>,
        occurred_at: u64,
        learned_at: Option<u64>,
    ) -> FacadeResult<BlobVersionView> {
        let artifact_id = self.resolve_ref(artifact_ref)?;
        let provenance = match run_ref {
            Some(run_ref) => crate::blob_artifact::BlobVersionProvenance::AgentRun {
                run_ref: run_ref.to_owned(),
            },
            None => crate::blob_artifact::BlobVersionProvenance::UserUpload,
        };
        let occurred = TimeRange {
            start: occurred_at,
            end: occurred_at,
        };
        let record = self.with_verified_actor_write_txn(|wtxn| {
            self.vault
                .append_blob_artifact_version_in_txn(
                    wtxn,
                    &artifact_id,
                    bytes,
                    &provenance,
                    WriteActor::new(self.actor, self.actor_class),
                    occurred,
                    learned_at.unwrap_or(occurred_at),
                )
                .map_err(FacadeError::from)
        })?;
        Ok(BlobVersionView {
            artifact_ref: artifact_id.to_hex(),
            version: record.version,
            content_hash_hex: hex_string(&record.content_hash),
            claim_ref: record.claim_id.to_hex(),
            created_at: record.created_at,
        })
    }

    /// Reads one blob artifact version's bytes (hash-verified by the engine).
    pub fn read_blob_version(
        &self,
        artifact_ref: &str,
        version: u64,
    ) -> FacadeResult<Option<Vec<u8>>> {
        let artifact_id = self.resolve_ref(artifact_ref)?;
        self.vault
            .read_blob_artifact_version(&artifact_id, version)
            .map_err(FacadeError::from)
    }

    // ── read verbs ──────────────────────────────────────────────────────

    /// Reads one entity as a typed view. `Ok(None)` when absent.
    pub fn get_entity(&self, entity_ref: &str) -> FacadeResult<Option<EntityView>> {
        let id = match self.resolve_ref(entity_ref) {
            Ok(id) => id,
            Err(err) if err.code == FACADE_CODE_NOT_FOUND => return Ok(None),
            Err(err) => return Err(err),
        };
        self.entity_view(&id)
    }

    /// Hydrates short refs (or hex ids) to full entity views. Unresolvable
    /// refs are typed errors — hydrate is the OF-096 round-trip contract.
    pub fn hydrate(&self, refs: &[String]) -> FacadeResult<Vec<EntityView>> {
        let mut views = Vec::with_capacity(refs.len());
        for reference in refs {
            let id = self.resolve_ref(reference)?;
            let Some(view) = self.entity_view(&id)? else {
                return Err(FacadeError::not_found(format!(
                    "entity {reference:?} does not resolve"
                )));
            };
            views.push(view);
        }
        Ok(views)
    }

    /// Lists claims by subject/predicate/lifecycle, bounded by
    /// `filter.limit`.
    pub fn claim_list(&self, filter: &ClaimListFilter) -> FacadeResult<Vec<ClaimView>> {
        if filter.limit == 0 {
            return Err(FacadeError::bad_request(
                "claim_list limit must be at least 1",
            ));
        }
        let lifecycle = match filter.lifecycle.as_deref() {
            Some(value) => Some(ClaimLifecycleStatus::parse(value).ok_or_else(|| {
                FacadeError::bad_request_with(
                    format!("unknown lifecycle {value:?}"),
                    &["Use one of: active, superseded, retracted."],
                )
            })?),
            None => None,
        };
        let ids = match &filter.subject_ref {
            Some(subject_ref) => {
                let subject = self.resolve_ref(subject_ref)?;
                self.vault.claims_for_subject(&subject)?
            }
            None => self.vault.entities_by_type(ENTITY_TYPE_CLAIM)?,
        };
        let mut views = Vec::new();
        for id in ids {
            if views.len() >= filter.limit {
                break;
            }
            let Some(body) = self.vault.get_claim(&id)? else {
                continue;
            };
            if let Some(predicate) = &filter.predicate
                && body.predicate != *predicate
            {
                continue;
            }
            if let Some(lifecycle) = lifecycle
                && body.lifecycle != lifecycle
            {
                continue;
            }
            views.push(self.claim_view(&id, &body)?);
        }
        Ok(views)
    }

    /// Returns the supersession timeline for one claim, oldest first.
    pub fn claim_history(&self, claim_ref: &str) -> FacadeResult<Vec<ClaimView>> {
        let id = self.resolve_ref(claim_ref)?;
        let timeline = self.vault.memory_timeline(&id)?;
        let mut records: Vec<_> = timeline
            .records
            .into_iter()
            .filter(|record| record.entity_type == Some(ENTITY_TYPE_CLAIM))
            .collect();
        records.sort_by_key(|record| (record.learned_at.unwrap_or(0), record.id.to_hex()));
        let mut views = Vec::with_capacity(records.len());
        for record in records {
            if let Some(body) = self.vault.get_claim(&record.id)? {
                views.push(self.claim_view(&record.id, &body)?);
            }
        }
        Ok(views)
    }

    /// Lists gated writes parked for consent, newest lane state first.
    pub fn pending_writes(&self, limit: usize) -> FacadeResult<Vec<PendingWrite>> {
        let records = self.vault.pending_gate_consents(limit)?;
        Ok(records
            .into_iter()
            .map(|record| PendingWrite {
                claim_ref: hex_string(&record.claim_id),
                decision_ref: format!("gate:{}", record.decision_id.to_hex()),
                created_at: record.created_at,
                reason_codes: record.reason_codes,
                dreamer_run_id: record.dreamer_run_id,
            })
            .collect())
    }

    /// Lists gate decision receipts.
    pub fn receipts(&self, limit: usize) -> FacadeResult<Vec<FacadeReceipt>> {
        let records = self.vault.gate_decisions(limit)?;
        Ok(records
            .into_iter()
            .map(|record| FacadeReceipt {
                receipt_ref: format!("gate:{}", record.decision_id.to_hex()),
                outcome: record.outcome,
                created_at: record.created_at,
                reason_codes: record.reason_codes,
                actor_class: record.actor_class,
                actor_ref: record.actor_ref,
                content_kind: record.content_kind,
                claim_ref: record.claim_id.map(|id| hex_string(&id)),
            })
            .collect())
    }

    // ── query verbs (BRIDGE-02) ─────────────────────────────────────────

    /// BM25 text query over the engine index (engine scores, never a
    /// re-implementation).
    pub fn query_bm25(&self, query: &str, limit: usize) -> FacadeResult<Vec<LexicalHit>> {
        if limit == 0 {
            return Err(FacadeError::bad_request(
                "query_bm25 limit must be at least 1",
            ));
        }
        let hits = self.vault.search_text(query, limit)?;
        let mut out = Vec::with_capacity(hits.len());
        for hit in hits {
            let Some(entity_type) = self.vault.get_entity_type(&hit.id)? else {
                continue;
            };
            let snippet = self
                .entity_view(&hit.id)?
                .and_then(|view| view.body)
                .and_then(|body| {
                    body.get("content")
                        .and_then(serde_json::Value::as_str)
                        .map(|content| truncate_text(content, SNIPPET_MAX_CHARS))
                });
            out.push(LexicalHit {
                short_id: self.short_ref_or_hex(&hit.id)?,
                kind: kind_string_for_type(entity_type),
                score: hit.score,
                snippet,
            });
        }
        Ok(out)
    }

    /// Weighted-edge neighborhood of one entity, filtered engine-side by
    /// edge kind and minimum weight.
    pub fn neighbors(
        &self,
        entity_ref: &str,
        opts: &NeighborOpts,
    ) -> FacadeResult<Vec<NeighborHit>> {
        if opts.limit == 0 {
            return Err(FacadeError::bad_request(
                "neighbors limit must be at least 1",
            ));
        }
        let kind_filter = match opts.edge_kind.as_deref() {
            Some(name) => Some(edge_kind_from_str(name).ok_or_else(|| {
                FacadeError::bad_request_with(
                    format!("unknown edge kind {name:?}"),
                    &["Use a snake_case EdgeKind name such as belongs_to or attached."],
                )
            })?),
            None => None,
        };
        let id = self.resolve_ref(entity_ref)?;
        let mut hits = Vec::new();
        // Push kind/min_weight/limit into the LMDB prefix walk per direction
        // so a high-degree node stops after `limit` matches instead of
        // materializing its full edge set (which errors with IndexOverflow
        // past MAX_EDGE_QUERY_RESULTS).
        for (direction, outbound) in [("out", true), ("in", false)] {
            let remaining = opts.limit - hits.len();
            if remaining == 0 {
                break;
            }
            let edges = self.vault.neighbor_edges_bounded(
                &id,
                outbound,
                kind_filter,
                opts.min_weight,
                remaining,
            )?;
            for edge in edges {
                let kind = self
                    .vault
                    .get_entity_type(&edge.target)?
                    .map_or_else(|| "UNKNOWN".to_owned(), kind_string_for_type);
                hits.push(NeighborHit {
                    short_id: self.short_ref_or_hex(&edge.target)?,
                    kind,
                    edge_kind: edge_kind_name(edge.kind).to_owned(),
                    weight: edge.weight,
                    direction: direction.to_owned(),
                });
            }
        }
        Ok(hits)
    }

    /// Effort-dialed retrieval into an S6 `MemoryPack`.
    ///
    /// `Deep` requires a [`BudgetLease`] (W4/C4). No lease-issuer exists at
    /// base (OF-131), so `Deep` without a lease is a typed
    /// `LEASE_REQUIRED` error, and a leased `Deep` executes as `Standard`
    /// with `retrieval_meta.deep_pending = true`.
    ///
    /// Retrieval is sparse-only today (`retrieval_meta.sparse = true`): the
    /// engine takes caller-supplied query vectors and no embedder lane has
    /// landed, so the vector signal joins later without a contract change.
    pub fn recall(
        &self,
        query: &str,
        effort: Effort,
        scope: &RecallScope,
        limit: usize,
        format: Option<&str>,
        lease: Option<&BudgetLease>,
    ) -> FacadeResult<MemoryPack> {
        if limit == 0 {
            return Err(FacadeError::bad_request("recall limit must be at least 1"));
        }
        let mut deep_pending = None;
        let effective = match effort {
            Effort::Deep => {
                if lease.is_none() {
                    return Err(FacadeError::new(
                        FACADE_CODE_LEASE_REQUIRED,
                        "deep recall requires a budget lease and no lease was presented",
                        &[
                            "Use standard effort or present a budget lease.",
                            "The lease issuer lands with the LLMB chain (OF-131).",
                        ],
                    ));
                }
                deep_pending = Some(true);
                Effort::Standard
            }
            other => other,
        };
        let world_scope = match &scope.world_ref {
            Some(world_ref) => WorldScope::World(self.resolve_ref(world_ref)?),
            None => WorldScope::All,
        };
        let pack_format = format.map(parse_pack_format).transpose()?;

        let (items, total_candidates, rendered) = match &scope.facet {
            Some(facet_ref) => {
                // Facet-strict narrowing rides the raw retrieval pipeline:
                // ContextPackBuilder exposes no facet passthrough and
                // pipeline.rs/context_pack.rs are consume-only for this
                // chain. No pack rendering on this path.
                let facet_id = self.resolve_ref(facet_ref)?;
                let mut pipeline = self
                    .vault
                    .query()
                    .search_text(query, limit)
                    .facet(&facet_id, FacetMode::Strict)
                    .world(world_scope);
                if effective == Effort::Standard {
                    pipeline = pipeline
                        .boost_recency(DEFAULT_RECENCY_HALF_LIFE_DAYS)
                        .boost_salience()
                        .boost_confidence();
                }
                let hits = pipeline.run()?;
                let total = hits.len() as u64;
                let mut items = Vec::new();
                for hit in hits.into_iter().take(limit) {
                    if let Some(item) = self.memory_item_for(&hit.id, Some(facet_id))? {
                        items.push(item);
                    }
                }
                (items, total, None)
            }
            None => {
                let mut builder = self
                    .vault
                    .context_pack()
                    .search_text(query, limit)
                    .limit(limit)
                    .world(world_scope);
                match effective {
                    Effort::Minimal => {
                        builder = builder
                            .hydrate(false)
                            .include_edges(false)
                            .field_profile(FieldProfile::Minimal);
                    }
                    Effort::Standard | Effort::Deep => {
                        let seeds: Vec<EntityId> = self
                            .vault
                            .search_text(query, PPR_SEED_LIMIT)?
                            .into_iter()
                            .map(|hit| hit.id)
                            .collect();
                        if !seeds.is_empty() {
                            builder = builder.expand_ppr(&seeds, 1);
                        }
                        builder = builder
                            .include_edges(true)
                            .edge_hop(1)
                            .hydrate(true)
                            .field_profile(FieldProfile::Standard)
                            .boost_recency(DEFAULT_RECENCY_HALF_LIFE_DAYS)
                            .boost_salience()
                            .boost_confidence();
                    }
                }
                let pack = builder.run()?;
                let total = pack.stats.candidates_considered as u64;
                let rendered = pack_format.map(|fmt| {
                    let config = SerializeConfig {
                        format: fmt,
                        profile: match effective {
                            Effort::Minimal => FieldProfile::Minimal,
                            Effort::Standard | Effort::Deep => FieldProfile::Standard,
                        },
                        budget: RECALL_TOKEN_BUDGET,
                        allocation: crate::context_pack::TokenAllocation::default(),
                        include_stats: false,
                        merge_neighbors: true,
                        max_field_chars: DEFAULT_MAX_FIELD_CHARS,
                        max_item_tokens: 0,
                    };
                    String::from_utf8_lossy(&serialize_pack(&pack, &config)).into_owned()
                });
                let mut items = Vec::new();
                for entity in pack.results.iter().take(limit) {
                    if let Some(item) = self.memory_item_for(&entity.id, None)? {
                        items.push(item);
                    }
                }
                (items, total, rendered)
            }
        };

        let claims_returned = items.iter().filter(|item| item.kind == "CLAIM").count() as u64;
        Ok(MemoryPack {
            scope_honesty: ScopeHonesty {
                out_of_scope_worlds: self.out_of_scope_worlds(scope.world_ref.as_deref())?,
            },
            retrieval_meta: RetrievalMeta {
                sparse: Some(true),
                total_candidates,
                claims_returned,
                deep_pending,
            },
            items,
            pack_version: MEMORY_PACK_VERSION,
            rendered,
        })
    }

    // ── BRIDGE-03: Dreamer + seed + outbound wiring ─────────────────────

    /// Enqueues one Dreamer consolidation attempt (expose, don't rebuild: the
    /// queue verbs and leases stay engine-side; long work returns an attempt
    /// ref to poll, W2).
    pub fn enqueue_consolidation(
        &self,
        input: &ConsolidationAttemptInput,
    ) -> FacadeResult<DreamerAttemptRef> {
        let scope = match input.scope.as_str() {
            "micro" => DreamerConsolidationScope::Micro,
            "meso" => DreamerConsolidationScope::Meso,
            "macro" => DreamerConsolidationScope::Macro,
            other => {
                return Err(FacadeError::bad_request_with(
                    format!("unknown consolidation scope {other:?}"),
                    &["Use one of: micro, meso, macro."],
                ));
            }
        };
        let store = DreamerRunnerStore::new(self.vault);
        let outcome = self.with_verified_actor_write_txn(|wtxn| {
            store
                .enqueue_consolidation_in_txn(
                    wtxn,
                    EnqueueDreamerConsolidationAttempt {
                        scope,
                        input: json_to_rmpv(&input.input),
                        parent_attempt: None,
                        dedupe_key: input.dedupe_key.clone(),
                        run_id: input.run_id.clone(),
                        now: input.now.unwrap_or_else(crate::unix_seconds_now),
                    },
                )
                .map_err(FacadeError::from)
        })?;
        let (status, existing) = match outcome {
            EnqueueDreamerAttemptOutcome::Enqueued(status) => (status, false),
            EnqueueDreamerAttemptOutcome::Existing(status) => (status, true),
        };
        Ok(DreamerAttemptRef {
            job_ref: hex_string(status.attempt.id.as_bytes()),
            state: attempt_state_str(status.attempt.state).to_owned(),
            existing,
        })
    }

    /// Polls one Dreamer attempt's status (poll model, no FFI await).
    pub fn dreamer_attempt_status(
        &self,
        job_ref: &str,
    ) -> FacadeResult<Option<DreamerAttemptView>> {
        let id = parse_job_ref(job_ref)?;
        let store = DreamerRunnerStore::new(self.vault);
        let Some(status) = store.status(id)? else {
            return Ok(None);
        };
        Ok(Some(attempt_view_from_record(&status.attempt)))
    }

    /// Seed-write entry point (EF-301 consumer): every element is FORCED
    /// `proposed` regardless of source — cold-start claims land below the
    /// auto-approve line, individually gated, each with a receipt.
    pub fn seed_claims(&self, claims: &[ClaimInput]) -> FacadeResult<Vec<CommitReceipt>> {
        Ok(self.commit_all(claims, false, Some(ClaimApprovalStatus::Proposed)))
    }

    /// Schedules one connector-send TASK through the OF-327 chokepoint. The
    /// bridge never delivers: it gate-checks under a `Hold` window first, then
    /// durably co-commits the shared TASK and ready execution attempt. Thus no
    /// connector worker can claim the send before schedule admission finishes,
    /// while the gate decision remains a queryable governance receipt.
    pub fn schedule_outbound(
        &self,
        draft: &OutboundDraftInput,
    ) -> FacadeResult<OutboundIntentReceipt> {
        let trigger = match draft.trigger.as_str() {
            "commitment" | "commitment_timer_wake" => {
                OutboundIntentTrigger::commitment_timer_wake(draft.trigger_ref.clone())
            }
            "gap_queue" => OutboundIntentTrigger::gap_queue(draft.trigger_ref.clone()),
            "agent_immediate" => OutboundIntentTrigger::agent_immediate(draft.trigger_ref.clone()),
            other => {
                return Err(FacadeError::bad_request_with(
                    format!("unknown outbound trigger {other:?}"),
                    &["Use one of: commitment_timer_wake, gap_queue, agent_immediate."],
                ));
            }
        };
        let trigger = match &draft.job_ref {
            Some(job_ref) => trigger.job_ref(job_ref.clone()),
            None => trigger,
        };
        let originating_session_ref =
            (draft.trigger == "agent_immediate").then(|| draft.trigger_ref.clone());
        let now = draft.occurred_at.unwrap_or_else(crate::unix_seconds_now);

        // A completed attempt no longer owns the generic queue dedupe row.
        // Consult the additive delivered-only index before any new gate or
        // enqueue work so a client retry cannot charge or send twice.
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        if let Some(idempotency_key) = draft.idempotency_key.as_deref()
            && let Some(task_ref) = self
                .vault
                .store
                .get_delivered_send_task_by_idempotency(&self.actor, idempotency_key)?
        {
            let receipt =
                delivered_send_receipt_for_task(self.vault, task_ref)?.ok_or_else(|| {
                    FacadeError::from(Error::CorruptedIndex("send idempotency index"))
                })?;
            let actor_ref = self.actor.to_hex();
            if receipt.actor.as_deref() != Some(actor_ref.as_str())
                || receipt.fields.get("idempotency_key").map(String::as_str)
                    != Some(idempotency_key)
            {
                return Err(FacadeError::from(Error::CorruptedIndex(
                    "send idempotency index",
                )));
            }
            return Ok(OutboundIntentReceipt {
                intent_ref: receipt
                    .fields
                    .get("intent_ref")
                    .cloned()
                    .unwrap_or_else(|| format!("intent:task:{}", task_ref.to_hex())),
                outcome: "already_sent".to_owned(),
                gate_outcome: receipt.fields.get("gate_outcome").cloned(),
                gate_decision_ref: receipt.fields.get("gate_decision_ref").cloned(),
                gate_reason_codes: receipt
                    .fields
                    .get("gate_reason_codes")
                    .map(|codes| {
                        codes
                            .split(',')
                            .filter(|code| !code.is_empty())
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
                deduped: true,
            });
        }

        // Pre-validate the channel/verb capability before either the gate or
        // durable enqueue, preserving a clean retry for malformed requests.
        outbound_verb_contract(&draft.channel, &draft.verb).map_err(|capability| {
            FacadeError::bad_request_with(
                format!("unsupported outbound capability: {capability}"),
                &["Use a registered channel/verb pair from the connector manifest."],
            )
        })?;

        let mut intent_draft = OutboundIntentDraft::new(
            self.actor.to_hex(),
            draft.verb.clone(),
            draft.channel.clone(),
            draft.target.clone(),
        );
        if let Some(on_behalf_of) = &draft.on_behalf_of {
            intent_draft = intent_draft.on_behalf_of(on_behalf_of.clone());
        }
        if let Some(content_ref) = &draft.content_ref {
            intent_draft = intent_draft.content_ref(content_ref.clone());
        }
        if let Some(idempotency_key) = &draft.idempotency_key {
            intent_draft = intent_draft.idempotency_key(idempotency_key.clone());
        }
        if let Some(dedupe_key) = &draft.dedupe_key {
            intent_draft = intent_draft.dedupe_key(dedupe_key.clone());
        }
        let intent = OutboundIntent::from_trigger(intent_draft, trigger);

        let queue = AttemptQueue::new(self.vault);
        let task_ref = EntityId::now();
        let payload = connector_send_attempt_payload(task_ref)?;

        // Abort-only enqueue preflight validates queue inputs and recovers an
        // existing live schedule without appending a second Gate decision. A
        // missing key writes only inside this uncommitted transaction and is
        // therefore neither durable nor claimable.
        let mut preflight_txn = self.vault.store.env.write_txn().map_err(Error::from)?;
        verify_actor_binding_in_txn(self.vault, &preflight_txn, self.actor, self.actor_class)?;
        let preflight = queue.enqueue_in_txn(
            &mut preflight_txn,
            EnqueueAttempt {
                kind: BRIDGE_OUTBOUND_ATTEMPT_KIND.to_owned(),
                payload: payload.clone(),
                dedupe_key: draft.idempotency_key.clone(),
                run_id: draft.job_ref.clone(),
                now,
            },
        )?;
        drop(preflight_txn);
        if let EnqueueOutcome::Existing(attempt) = preflight {
            return Ok(self.already_scheduled_outbound_receipt(attempt.id));
        }

        let gate_intent_ref = format!("intent:task:{}", task_ref.to_hex());
        let actor = OutboundDispatchActor {
            actor_class: self.actor_class.gate_actor_class().to_owned(),
            actor_ref: Some(self.actor.to_hex()),
            actor_entity_ref: Some(self.actor),
        };
        let mut request = OutboundDispatchRequest::new(
            format!("outbound:{gate_intent_ref}"),
            gate_intent_ref.clone(),
            intent.clone(),
            actor,
            OutboundDispatchGate::allow_when_policy_grants(),
            now,
            OutboundDeliveryWindowDecision::Hold {
                reason: "bridge_scheduled".to_owned(),
                retry_at: None,
            },
        );
        if let Some(session_ref) = originating_session_ref.as_deref() {
            request = request.originating_session(session_ref);
        }
        let mut sink = ScheduleOnlySink;
        let result = self
            .vault
            .dispatch_outbound_intent_with_verified_actor(
                request,
                &mut sink,
                self.actor,
                self.actor_class,
            )
            .map_err(facade_error_from_outbound_dispatch)?;

        // A denied schedule is fully audited by its Gate decision but never
        // becomes executable. Under the schedule-only Hold window, Held is the
        // sole outcome admitted to the durable queue.
        if result.outcome != OutboundDispatchOutcome::Held {
            return Ok(OutboundIntentReceipt {
                intent_ref: gate_intent_ref,
                outcome: dispatch_outcome_str(&result.outcome).to_owned(),
                gate_outcome: Some(result.gate_outcome),
                gate_decision_ref: result.gate_decision_id,
                gate_reason_codes: result.gate_reason_codes,
                deduped: false,
            });
        }

        let outcome = self.with_verified_actor_write_txn(|wtxn| {
            let outcome = queue.enqueue_with_task_ref_in_txn(
                wtxn,
                EnqueueAttempt {
                    kind: BRIDGE_OUTBOUND_ATTEMPT_KIND.to_owned(),
                    payload,
                    dedupe_key: draft.idempotency_key.clone(),
                    run_id: draft.job_ref.clone(),
                    now,
                },
                Some(task_ref.to_hex()),
            )?;
            if matches!(&outcome, EnqueueOutcome::Enqueued(_)) {
                put_connector_send_task_in_txn(
                    self.vault,
                    wtxn,
                    task_ref,
                    &intent,
                    self.actor,
                    self.actor_class,
                    originating_session_ref.as_deref(),
                    now,
                )?;
            }
            Ok(outcome)
        })?;
        let attempt = match outcome {
            EnqueueOutcome::Enqueued(attempt) => attempt,
            EnqueueOutcome::Existing(attempt) => {
                return Ok(self.already_scheduled_outbound_receipt(attempt.id));
            }
        };
        let intent_ref = outbound_intent_ref(attempt.id);
        // Persist the gate surface keyed by attempt id so an idempotent replay
        // recovers this decision (best-effort; a missing binding degrades a
        // replay to no gate fields, never a wrong decision) (#484b).
        self.persist_outbound_gate_binding(
            attempt.id,
            &result.gate_outcome,
            result.gate_decision_id.as_deref(),
            &result.gate_reason_codes,
        );
        Ok(OutboundIntentReceipt {
            intent_ref,
            outcome: dispatch_outcome_str(&result.outcome).to_owned(),
            gate_outcome: Some(result.gate_outcome),
            gate_decision_ref: result.gate_decision_id,
            gate_reason_codes: result.gate_reason_codes,
            deduped: false,
        })
    }

    fn already_scheduled_outbound_receipt(&self, attempt_id: AttemptId) -> OutboundIntentReceipt {
        // Re-surface the ORIGINAL gate decision the first schedule persisted,
        // keyed by attempt id, so an idempotent retry recovers its receipt.
        let binding = self.outbound_gate_binding(attempt_id);
        OutboundIntentReceipt {
            intent_ref: outbound_intent_ref(attempt_id),
            outcome: "already_scheduled".to_owned(),
            gate_outcome: binding.as_ref().map(|binding| binding.gate_outcome.clone()),
            gate_decision_ref: binding
                .as_ref()
                .and_then(|binding| binding.gate_decision_ref.clone()),
            gate_reason_codes: binding
                .map(|binding| binding.gate_reason_codes)
                .unwrap_or_default(),
            deduped: true,
        }
    }

    /// Persists the gate surface of a scheduled outbound attempt (best-effort).
    fn persist_outbound_gate_binding(
        &self,
        attempt_id: AttemptId,
        gate_outcome: &str,
        gate_decision_ref: Option<&str>,
        gate_reason_codes: &[String],
    ) {
        let binding = OutboundGateBinding {
            gate_outcome: gate_outcome.to_owned(),
            gate_decision_ref: gate_decision_ref.map(ToOwned::to_owned),
            gate_reason_codes: gate_reason_codes.to_vec(),
        };
        if let Ok(encoded) = serde_json::to_vec(&binding) {
            let _ = self
                .vault
                .store
                .put_outbound_gate_binding(attempt_id.as_bytes(), &encoded);
        }
    }

    /// Reads the persisted gate surface of a scheduled outbound attempt, if any.
    fn outbound_gate_binding(&self, attempt_id: AttemptId) -> Option<OutboundGateBinding> {
        self.vault
            .store
            .outbound_gate_binding(attempt_id.as_bytes())
            .ok()
            .flatten()
            .and_then(|raw| serde_json::from_slice(&raw).ok())
    }

    // ── internals ───────────────────────────────────────────────────────

    fn commit_all(
        &self,
        claims: &[ClaimInput],
        auto_supersede: bool,
        forced_approval: Option<ClaimApprovalStatus>,
    ) -> Vec<CommitReceipt> {
        let mut receipts = Vec::with_capacity(claims.len());
        for input in claims {
            match self.commit_one(input, auto_supersede, forced_approval) {
                Ok(receipt) => receipts.push(receipt),
                Err(err) => receipts.push(CommitReceipt {
                    claim_short_id: input.id.clone().unwrap_or_default(),
                    approval: "rejected".to_owned(),
                    superseded_short_id: None,
                    receipt_ref: format!("rejected:{}", err.code),
                }),
            }
        }
        receipts
    }

    /// Builds one S6 memory item from an entity id. Returns `Ok(None)` for
    /// missing entities and non-surfaceable claims (D19 admission).
    fn memory_item_for(
        &self,
        id: &EntityId,
        facet_hint: Option<EntityId>,
    ) -> FacadeResult<Option<MemoryItem>> {
        let Some(entity_type) = self.vault.get_entity_type(id)? else {
            return Ok(None);
        };
        let edges = self.vault.edges_out(id)?;
        let mut source_revision_ids = vec![id.to_hex()];
        source_revision_ids.extend(
            edges
                .iter()
                .filter(|edge| edge.kind == EdgeKind::Supersedes)
                .map(|edge| edge.target.to_hex()),
        );
        let facet = facet_hint.map(|facet| facet.to_hex()).or_else(|| {
            edges
                .iter()
                .find(|edge| edge.kind == EdgeKind::HasFacet)
                .map(|edge| edge.target.to_hex())
        });
        let short_id = self.short_ref_or_hex(id)?;
        let kind = kind_string_for_type(entity_type);

        if entity_type == ENTITY_TYPE_CLAIM {
            let Some(body) = self.vault.get_claim(id)? else {
                return Ok(None);
            };
            if !claim_surfaceable(&body) {
                return Ok(None);
            }
            let value_json = companion_value_to_json(&body.value);
            Ok(Some(MemoryItem {
                short_id,
                kind,
                predicate: Some(body.predicate.clone()),
                value_text: truncate_text(&value_text_of(&value_json), DEFAULT_MAX_FIELD_CHARS),
                confidence: body.confidence,
                hedge_bucket: hedge_bucket_for(body.confidence).to_owned(),
                provenance: MemoryProvenance {
                    source: body
                        .source
                        .map_or_else(|| "unattributed".to_owned(), |s| s.as_str().to_owned()),
                    source_revision_ids,
                    evidence_turn_ids: Vec::new(),
                },
                world: body.world.map(|world| world.to_hex()),
                facet,
                salience: body.salience,
            }))
        } else {
            let Some(view) = self.entity_view(id)? else {
                return Ok(None);
            };
            let value_text = view
                .body
                .as_ref()
                .and_then(|body| body.get("content"))
                .and_then(serde_json::Value::as_str)
                .map_or_else(
                    || {
                        view.body
                            .as_ref()
                            .map(|body| serde_json::to_string(body).unwrap_or_default())
                            .unwrap_or_default()
                    },
                    str::to_owned,
                );
            let evidence_turn_ids = if entity_type == ENTITY_TYPE_MESSAGE {
                edges
                    .iter()
                    .filter(|edge| edge.kind == EdgeKind::PartOf)
                    .map(|edge| edge.target.to_hex())
                    .collect()
            } else {
                Vec::new()
            };
            Ok(Some(MemoryItem {
                short_id,
                kind,
                predicate: None,
                value_text: truncate_text(&value_text, DEFAULT_MAX_FIELD_CHARS),
                confidence: 1.0,
                hedge_bucket: hedge_bucket_for(1.0).to_owned(),
                provenance: MemoryProvenance {
                    source: "record".to_owned(),
                    source_revision_ids,
                    evidence_turn_ids,
                },
                world: None,
                facet,
                salience: None,
            }))
        }
    }

    /// Scope honesty: worlds holding surfaceable claims outside the
    /// requested world scope. Bounded scan (first
    /// [`SCOPE_HONESTY_SCAN_CAP`] claims); unset scope excludes nothing.
    fn out_of_scope_worlds(&self, scope_world_ref: Option<&str>) -> FacadeResult<Vec<String>> {
        let Some(world_ref) = scope_world_ref else {
            return Ok(Vec::new());
        };
        let scope_world = self.resolve_ref(world_ref)?;
        // Bounded page primitive, not `entities_by_type().take(cap)`: the
        // latter materializes the whole CLAIM index and errors with
        // IndexOverflow past MAX_TYPE_QUERY_RESULTS before `take` can run, so
        // a large vault would hard-fail world-scoped recall.
        let ids =
            self.vault
                .entities_by_type_page(ENTITY_TYPE_CLAIM, None, SCOPE_HONESTY_SCAN_CAP)?;
        let mut worlds = BTreeSet::new();
        for id in ids {
            let Some(body) = self.vault.get_claim(&id)? else {
                continue;
            };
            if !claim_surfaceable(&body) {
                continue;
            }
            if let Some(world) = body.world
                && world != scope_world
            {
                worlds.insert(world.to_hex());
            }
        }
        Ok(worlds.into_iter().collect())
    }

    fn commit_one(
        &self,
        input: &ClaimInput,
        auto_supersede: bool,
        forced_approval: Option<ClaimApprovalStatus>,
    ) -> FacadeResult<CommitReceipt> {
        self.verified_actor_class()?;
        let id = id_from_optional_hex(input.id.as_deref())?;
        let subject = self.resolve_ref(&input.subject_ref)?;
        if self.vault.get_entity_type(&subject)?.is_none() {
            return Err(FacadeError::not_found(format!(
                "claim subject {} does not exist",
                subject.to_hex()
            )));
        }
        let source = parse_claim_source(&input.source)?;
        let value = json_to_rmpv(&input.value);
        let world = match &input.world_ref {
            Some(world_ref) => Some(self.resolve_ref(world_ref)?),
            None => None,
        };
        let scope_rmpv = input.scope.as_ref().map(json_to_rmpv);
        let now = crate::unix_seconds_now();
        let occurred_at = input.occurred_at.unwrap_or(now);
        let learned_at = input.learned_at.unwrap_or(now);

        let prior = if auto_supersede {
            self.find_prior_claim(&subject, input, &id)?
        } else {
            None
        };

        let mut approval =
            forced_approval.unwrap_or_else(|| requested_approval(source, input.scope.as_ref()));
        // Every commit is ONE engine transaction: gate decision, claim
        // write, and (with a prior revision) the supersession commit or
        // roll back together. No phantom receipts (a decision can never
        // outlive a write that failed later validation) and no orphan
        // revisions behind a rejected receipt. The fail-closed trade: a
        // rolled-back write also drops its gate decision.
        let write = |approval: ClaimApprovalStatus| -> Result<bool, Error> {
            let mut candidate = ClaimCandidate::new(
                input.predicate.clone(),
                ClaimSubject::Entity(subject),
                value.clone(),
                input.confidence,
            )
            .with_validity(input.valid_from, input.valid_to);
            if let Some(salience) = input.salience {
                candidate = candidate.with_salience(salience);
            }
            if let Some(world) = world {
                candidate = candidate.with_world(world);
            }
            if let Some(scope) = scope_rmpv.clone() {
                candidate = candidate.with_scope(scope);
            }
            let envelope = WriteEnvelope::new(
                WriteActor::new(self.actor, self.actor_class),
                source,
                WriteProvenance::new(facade_provenance("commit"))?,
                approval,
            );
            let occurred = TimeRange {
                start: occurred_at,
                end: occurred_at,
            };
            self.vault.with_write_txn(|wtxn| {
                if self
                    .vault
                    .local_hard_delete_marker_exists_in_txn(wtxn, &id)?
                {
                    return Ok(true);
                }
                apply_ops_with_gate_mode(
                    &self.vault.store,
                    &self.vault.config,
                    &self.vault.analyzer,
                    wtxn,
                    vec![BatchOp::ClaimCandidate {
                        id,
                        candidate: Box::new(candidate),
                        envelope,
                        occurred,
                        learned_at,
                        internal_lexical_query_hint: false,
                    }],
                    self.vault.text_index_trusted.load(Ordering::Acquire),
                    ApplyOpsGateMode::new(true, true),
                )?;
                if let Some(old_id) = prior {
                    self.vault
                        .supersede_claim_in_txn(wtxn, &id, &old_id, learned_at)?;
                }
                Ok(false)
            })
        };
        let refused = match write(approval) {
            Ok(refused) => refused,
            Err(err)
                if approval == ClaimApprovalStatus::Auto
                    && err.kind() == ErrorKind::GateWriteRejected =>
            {
                approval = ClaimApprovalStatus::Proposed;
                write(approval)?
            }
            Err(err) => return Err(err.into()),
        };
        if refused {
            return Err(hard_deleted_refusal(&id));
        }

        let superseded_short_id = match prior {
            Some(old_id) => Some(self.short_ref_or_hex(&old_id)?),
            None => None,
        };
        let final_approval = self.vault.get_claim(&id)?.map_or_else(
            || approval.as_str().to_owned(),
            |b| b.approval.as_str().to_owned(),
        );
        let receipt_ref = self
            .latest_decision_ref_for(&id)?
            .unwrap_or_else(|| format!("claim:{}", id.to_hex()));
        Ok(CommitReceipt {
            claim_short_id: self.short_ref_or_hex(&id)?,
            approval: final_approval,
            superseded_short_id,
            receipt_ref,
        })
    }

    /// Prior-claim match for auto-supersede: `subject+scope+predicate`,
    /// extended with `value.question_id` for declared multi-cardinality
    /// predicates (B1c). Deterministic when multiple actives match: the
    /// newest id (UUIDv7 order) wins.
    fn find_prior_claim(
        &self,
        subject: &EntityId,
        input: &ClaimInput,
        exclude: &EntityId,
    ) -> FacadeResult<Option<EntityId>> {
        let multi_key = if MULTI_CARDINALITY_PREDICATES.contains(&input.predicate.as_str()) {
            Some(input.value.get(MULTI_CARDINALITY_VALUE_KEY).cloned())
        } else {
            None
        };
        let new_scope = input.scope.clone();
        let ids = self.vault.claims_for_subject(subject)?;
        let mut best: Option<EntityId> = None;
        for id in ids {
            if id == *exclude {
                continue;
            }
            let Some(body) = self.vault.get_claim(&id)? else {
                continue;
            };
            if body.lifecycle != ClaimLifecycleStatus::Active || body.predicate != input.predicate {
                continue;
            }
            let prior_scope = body.scope.as_ref().map(companion_value_to_json);
            if prior_scope != new_scope {
                continue;
            }
            if let Some(new_qid) = &multi_key {
                let prior_value = companion_value_to_json(&body.value);
                let prior_qid = prior_value.get(MULTI_CARDINALITY_VALUE_KEY).cloned();
                if prior_qid != *new_qid {
                    continue;
                }
            }
            best = match best {
                Some(current) if current.to_hex() >= id.to_hex() => Some(current),
                _ => Some(id),
            };
        }
        Ok(best)
    }

    fn resolve_or_new_container(
        &self,
        reference: &str,
        expected_type: u8,
    ) -> FacadeResult<(EntityId, bool)> {
        let trimmed = reference.trim();
        if trimmed.len() == 32 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            let id = EntityId::from_hex(trimmed)
                .map_err(|_| FacadeError::bad_request(format!("invalid entity id {trimmed:?}")))?;
            return match self.vault.get_entity_type(&id)? {
                Some(entity_type) if entity_type == expected_type => Ok((id, false)),
                Some(entity_type) => Err(FacadeError::bad_request(format!(
                    "ref {trimmed:?} resolves to kind {} but {} was expected",
                    kind_string_for_type(entity_type),
                    kind_string_for_type(expected_type),
                ))),
                None => Ok((id, true)),
            };
        }
        let id = self.resolve_ref(reference)?;
        match self.vault.get_entity_type(&id)? {
            Some(entity_type) if entity_type == expected_type => Ok((id, false)),
            Some(entity_type) => Err(FacadeError::bad_request(format!(
                "ref {reference:?} resolves to kind {} but {} was expected",
                kind_string_for_type(entity_type),
                kind_string_for_type(expected_type),
            ))),
            None => Err(FacadeError::not_found(format!(
                "entity {reference:?} does not resolve"
            ))),
        }
    }

    fn resolve_ref(&self, reference: &str) -> FacadeResult<EntityId> {
        resolve_entity_ref(self.vault, reference)
    }

    /// PRE-TRANSACTION variant of the hard-delete refusal, used ONLY where
    /// the engine owns the write transaction internally (companion create,
    /// ingest admission) and the marker check cannot ride it. Residual for
    /// those two verbs: a hard delete landing between this check and the
    /// engine's commit recreates at the purged id; closing it needs in-txn
    /// engine seams (`create_companion_record_in_txn`, ingest). Every other
    /// id-accepting verb checks the marker INSIDE its own write
    /// transaction (A1).
    fn refuse_hard_deleted_id(&self, id: &EntityId) -> FacadeResult<()> {
        let rtxn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(|err| FacadeError::from(Error::from(err)))?;
        if self
            .vault
            .local_hard_delete_marker_exists_in_txn(&rtxn, id)?
        {
            return Err(hard_deleted_refusal(id));
        }
        Ok(())
    }

    /// Resolves the caller-asserted actor against the STORE before any
    /// authority is granted (asserted class strings are never trusted):
    /// the actor entity must exist, and its stored type must match the
    /// asserted class (PERSON ⇒ human/agent, MACHINE ⇒ system — the same
    /// rule the gated write path enforces via
    /// `provenance::validate_actor_class`). Anything unresolvable fails
    /// closed with a typed denial.
    fn verified_actor_class(&self) -> FacadeResult<EdgeActorClass> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        Ok(self.actor_class)
    }

    fn entity_view(&self, id: &EntityId) -> FacadeResult<Option<EntityView>> {
        let Some(raw) = self.vault.get_raw(id)? else {
            return Ok(None);
        };
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or_else(|| FacadeError::from(Error::CorruptedIndex("entity header")))?;
        let body = decode_body_json(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]);
        Ok(Some(EntityView {
            id_hex: id.to_hex(),
            short_ref: self.short_ref_of(id)?,
            kind: kind_string_for_type(header.entity_type),
            occurred_start: header.occurred_start,
            occurred_end: header.occurred_end,
            learned_at: header.learned_at,
            body,
        }))
    }

    fn claim_view(&self, id: &EntityId, body: &ClaimBody) -> FacadeResult<ClaimView> {
        Ok(ClaimView {
            claim_ref: id.to_hex(),
            short_ref: self.short_ref_of(id)?,
            predicate: body.predicate.clone(),
            subject_ref: subject_ref_string(&body.subject),
            value: companion_value_to_json(&body.value),
            confidence: body.confidence,
            approval: body.approval.as_str().to_owned(),
            lifecycle: body.lifecycle.as_str().to_owned(),
            source: body.source.map(|source| source.as_str().to_owned()),
            world_ref: body.world.map(|world| world.to_hex()),
            scope: body.scope.as_ref().map(companion_value_to_json),
            valid_from: body.valid_from,
            valid_to: body.valid_to,
            salience: body.salience,
            stale: body.stale,
        })
    }

    fn entity_ref_receipt(&self, id: &EntityId) -> FacadeResult<EntityRefReceipt> {
        Ok(EntityRefReceipt {
            entity_ref: self.short_ref_or_hex(id)?,
            id_hex: id.to_hex(),
            receipt_ref: format!("put:{}", id.to_hex()),
        })
    }

    fn short_ref_of(&self, id: &EntityId) -> FacadeResult<Option<String>> {
        let rtxn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(|err| FacadeError::from(Error::from(err)))?;
        let Some(raw) = self
            .vault
            .store
            .short_ids_reverse
            .get(&rtxn, id.as_bytes())?
        else {
            return Ok(None);
        };
        let (short_id, content_hash) = parse_short_id_value(&raw)?;
        Ok(Some(format!("{short_id}:{content_hash:02x}")))
    }

    fn short_ref_or_hex(&self, id: &EntityId) -> FacadeResult<String> {
        Ok(self.short_ref_of(id)?.unwrap_or_else(|| id.to_hex()))
    }

    fn latest_decision_ref_for(&self, id: &EntityId) -> FacadeResult<Option<String>> {
        let decisions = self.vault.gate_decisions(GATE_RECEIPT_SCAN_LIMIT)?;
        let latest = decisions
            .into_iter()
            .filter(|record| record.claim_id.as_ref() == Some(id.as_bytes()))
            .max_by_key(|record| record.decision_id.to_hex());
        Ok(latest.map(|record| format!("gate:{}", record.decision_id.to_hex())))
    }
}

fn facade_error_from_outbound_dispatch(err: OutboundDispatchError) -> FacadeError {
    match err {
        OutboundDispatchError::Engine(engine) => FacadeError::from(engine),
        OutboundDispatchError::Chokepoint(_) => FacadeError::new(
            FACADE_CODE_INTERNAL,
            "outbound effect durability failed",
            &["Retry after checking local storage health."],
        ),
        OutboundDispatchError::InvalidBoundActor => FacadeError::new(
            FACADE_CODE_FORBIDDEN,
            "the bound actor is no longer authorized for outbound dispatch",
            &["Refresh the actor binding and retry."],
        ),
        OutboundDispatchError::UnsupportedCapability(capability) => FacadeError::bad_request_with(
            format!("unsupported outbound capability: {capability}"),
            &["Use a registered channel/verb pair from the connector manifest."],
        ),
    }
}

fn encode_witness_message_body(message: &WitnessMessage) -> FacadeResult<Vec<u8>> {
    let mut entries = vec![
        (Value::from("author"), Value::from(message.author.as_str())),
        (
            Value::from("type"),
            Value::from(message.message_type.as_str()),
        ),
        (
            Value::from("content"),
            Value::from(message.content.as_str()),
        ),
    ];
    if let Some(metadata) = &message.metadata {
        entries.push((Value::from("metadata"), json_to_rmpv(metadata)));
    }
    entries.push((
        Value::from("is_visible"),
        Value::Boolean(message.is_visible),
    ));
    entries.push((Value::from("order"), Value::from(u64::from(message.order))));
    encode_rmpv(&Value::Map(entries))
}

/// Extracts the write-envelope actor stamped into a claim's evidence
/// (gated candidate path). `None` for claims written without an envelope.
fn claim_envelope_actor(body: &ClaimBody) -> Option<EntityId> {
    let Value::Map(entries) = body.evidence.as_ref()? else {
        return None;
    };
    for (key, value) in entries {
        if key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY)
            && let Value::Binary(bytes) = value
        {
            let raw: [u8; 16] = bytes.as_slice().try_into().ok()?;
            return EntityId::from_bytes(raw).ok();
        }
    }
    None
}

/// Typed refusal for creation at an id carrying the durable `dt:`
/// hard-delete marker (hard-once-seen — the same presence-only marker the
/// sync replay path consults). Without this refusal a delete-authorized
/// caller could two-step retype an entity (hard delete, then recreate
/// under a different type), and a migration re-run could resurrect data
/// the user erased.
fn hard_deleted_refusal(id: &EntityId) -> FacadeError {
    FacadeError::new(
        FACADE_CODE_FORBIDDEN,
        format!(
            "id {} was hard-deleted and cannot be recreated through the facade",
            id.to_hex()
        ),
        &[
            "Hard-deleted ids are permanent (hard-once-seen); use a fresh id.",
            "Recreation at a purged id would resurrect erased data or retype an actor.",
        ],
    )
}

/// Schedule-only execution sink: unreachable under the `Hold` window this
/// facade always dispatches with; fails closed if a future path ever
/// reaches it — the bridge carries no channel adapters (OF-327).
struct ScheduleOnlySink;

impl OutboundExecutionSink for ScheduleOnlySink {
    fn execute(&mut self, _request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        OutboundExecutionOutcome::failed("bridge schedule-only surface has no channel adapter")
    }
}

fn outbound_intent_ref(attempt_id: AttemptId) -> String {
    format!("intent:{}", hex_string(attempt_id.as_bytes()))
}

fn parse_job_ref(job_ref: &str) -> FacadeResult<AttemptId> {
    let reference = job_ref
        .trim()
        .strip_prefix("job:")
        .unwrap_or_else(|| job_ref.trim());
    if reference.len() != 32 || !reference.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(FacadeError::bad_request(format!(
            "attempt ref {job_ref:?} is not a 32-hex attempt id"
        )));
    }
    let mut bytes = [0_u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&reference[index * 2..index * 2 + 2], 16)
            .map_err(|_| FacadeError::bad_request(format!("attempt ref {job_ref:?} is not hex")))?;
    }
    AttemptId::from_bytes(&bytes).map_err(|_| {
        FacadeError::bad_request(format!("attempt ref {job_ref:?} is not an attempt id"))
    })
}

const fn attempt_state_str(state: AttemptState) -> &'static str {
    match state {
        AttemptState::Queued => "queued",
        AttemptState::Leased => "leased",
        AttemptState::Paused => "paused",
        AttemptState::Completed => "completed",
        AttemptState::Failed => "failed",
        AttemptState::Cancelled => "cancelled",
        AttemptState::Scheduled => "scheduled",
    }
}

fn attempt_view_from_record(attempt: &AttemptRecord) -> DreamerAttemptView {
    DreamerAttemptView {
        job_ref: hex_string(attempt.id.as_bytes()),
        state: attempt_state_str(attempt.state).to_owned(),
        kind: attempt.kind.clone(),
        lease_owner: attempt.lease_owner.clone(),
        attempt_count: attempt.attempt_count,
        run_id: attempt.run_id.clone(),
        last_error: attempt.last_error.clone(),
        created_at: attempt.created_at,
        updated_at: attempt.updated_at,
    }
}

const fn dispatch_outcome_str(outcome: &OutboundDispatchOutcome) -> &'static str {
    match outcome {
        OutboundDispatchOutcome::DeliveredToChannel => "delivered_to_channel",
        OutboundDispatchOutcome::Held => "held",
        OutboundDispatchOutcome::Degraded => "degraded",
        OutboundDispatchOutcome::Suppressed => "suppressed",
        OutboundDispatchOutcome::LetGo => "let_go",
        OutboundDispatchOutcome::Failed => "failed",
    }
}

/// Hedge vocabulary over calibrated-absolute confidence (scour:A176 —
/// never rank-relative).
fn hedge_bucket_for(confidence: f32) -> &'static str {
    if confidence >= 0.9 {
        "confident"
    } else if confidence >= 0.7 {
        "likely"
    } else if confidence >= 0.4 {
        "tentative"
    } else {
        "uncertain"
    }
}

/// snake_case name of an `EdgeKind` (inverse of `edge_kind_from_str`).
const fn edge_kind_name(kind: EdgeKind) -> &'static str {
    match kind {
        EdgeKind::AuthoredBy => "authored_by",
        EdgeKind::ScopedTo => "scoped_to",
        EdgeKind::PartOf => "part_of",
        EdgeKind::Supersedes => "supersedes",
        EdgeKind::BelongsTo => "belongs_to",
        EdgeKind::ClaimOf => "claim_of",
        EdgeKind::ChildOf => "child_of",
        EdgeKind::AssignedTo => "assigned_to",
        EdgeKind::DerivedFrom => "derived_from",
        EdgeKind::Mentions => "mentions",
        EdgeKind::About => "about",
        EdgeKind::Supports => "supports",
        EdgeKind::Opposes => "opposes",
        EdgeKind::ParticipatesIn => "participates_in",
        EdgeKind::Attached => "attached",
        EdgeKind::EmployedBy => "employed_by",
        EdgeKind::HasFacet => "has_facet",
        EdgeKind::FacetOf => "facet_of",
        EdgeKind::InWorld => "in_world",
        EdgeKind::SetIn => "set_in",
        EdgeKind::MergedInto => "merged_into",
        EdgeKind::SplitInto => "split_into",
    }
}

/// Maps the OF-096 format strings (`toon|md|json|yaml|txt`) to the pack
/// serializer formats.
fn parse_pack_format(format: &str) -> FacadeResult<PackFormat> {
    match format {
        "json" => Ok(PackFormat::Json),
        "yaml" => Ok(PackFormat::Yaml),
        "toon" => Ok(PackFormat::Toon),
        "md" => Ok(PackFormat::Markdown),
        "txt" => Ok(PackFormat::Plaintext),
        other => Err(FacadeError::bad_request_with(
            format!("unknown pack format {other:?}"),
            &["Use one of: toon, md, json, yaml, txt."],
        )),
    }
}

fn value_text_of(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

fn truncate_text(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_owned()
    } else {
        let mut out: String = text.chars().take(max_chars).collect();
        out.push('…');
        out
    }
}

fn hex_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests;
