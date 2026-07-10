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

use std::sync::atomic::Ordering;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::batch::{ApplyOpsGateMode, BatchOp, apply_ops_with_gate_mode, parse_short_id_value};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::companion::{
    CompanionExportClassification, CompanionProvenance, CompanionRecord, CompanionScope,
    companion_value_to_json,
};
use crate::deletion::DeleteReason;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind};
use crate::habit::TaskRole;
use crate::ingest::{
    INGEST_SOURCE_REGISTRY, ImportedEvidenceAdmission, ImportedEvidenceEntityResolution,
    NormalizedIngestClaim, admit_imported_evidence_claim,
};
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MACHINE, ENTITY_TYPE_MESSAGE,
    ENTITY_TYPE_PERSON, ENTITY_TYPE_REGISTRY, ENTITY_TYPE_TURN,
};
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

/// Predicates with declared multi-cardinality supersession keys (B1c,
/// RATIFY-20260710 R0): the prior-claim match extends
/// `subject+scope+predicate` with `value.question_id`.
pub const MULTI_CARDINALITY_PREDICATES: [&str; 1] = ["eiri.onboarding.answer"];

const MULTI_CARDINALITY_VALUE_KEY: &str = "question_id";
const SCOPE_SENSITIVITY_KEY: &str = "sensitivity";
const GATE_RECEIPT_SCAN_LIMIT: usize = 512;

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
        let hydrated = vault
            .hydrate_short_id(&short_id, content_hash)
            .map_err(FacadeError::from)?;
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
/// The gated claim path re-validates the actor INSIDE its write
/// transaction (`apply_claim_candidate`), closing the bind/use race
/// there; retract/delete cannot re-validate in-txn today — see the race
/// notes on [`MemoryFacade::claim_retract`] / [`MemoryFacade::safe_delete`].
fn verify_actor_binding(
    vault: &Vault,
    actor: EntityId,
    actor_class: EdgeActorClass,
) -> FacadeResult<()> {
    let Some(entity_type) = vault.get_entity_type(&actor).map_err(FacadeError::from)? else {
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

fn facade_provenance(verb: &str) -> Value {
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

    // ── write verbs ─────────────────────────────────────────────────────

    /// Witnesses one turn: create-or-get CONVERSATION/TURN, MESSAGE puts,
    /// `PartOf`/`BelongsTo`/`AuthoredBy` edges, and BM25 `content`
    /// indexing — all in ONE atomic batch.
    pub fn witness(&self, turn: &WitnessTurn) -> FacadeResult<WitnessReceipt> {
        self.verified_actor_class()?;
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

        let mut batch = self.vault.batch();
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
            if !message.content.is_empty() {
                batch = batch.text(id, &[("content", message.content.as_str())]);
            }
        }
        batch.commit().map_err(FacadeError::from)?;

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
        let mut receipts = Vec::with_capacity(claims.len());
        for input in claims {
            match self.commit_one(input, true) {
                Ok(receipt) => receipts.push(receipt),
                Err(err) => receipts.push(CommitReceipt {
                    claim_short_id: input.id.clone().unwrap_or_default(),
                    approval: "rejected".to_owned(),
                    superseded_short_id: None,
                    receipt_ref: format!("rejected:{}", err.code),
                }),
            }
        }
        Ok(receipts)
    }

    /// Commits one claim with single-cardinality auto-supersede (S3):
    /// prior Active claim matching `subject+scope+predicate` (plus
    /// `value.question_id` for declared multi-cardinality predicates, B1c)
    /// is superseded by the new revision.
    pub fn claim_upsert(&self, input: &ClaimInput) -> FacadeResult<CommitReceipt> {
        self.commit_one(input, true)
    }

    /// Retracts an active claim (deliberate withdrawal; record preserved).
    ///
    /// Authority (fail-closed): the asserted actor is first RESOLVED
    /// against the store ([`Self::verified_actor_class`] — it must exist
    /// and its stored type must match the asserted class). A verified
    /// `human`-class actor holds the vault owner's memory authority and
    /// may retract any claim; `agent`/`system` actors may retract ONLY
    /// claims whose write-envelope evidence names them as the writing
    /// actor. Everything else is a typed denial — binding an actor key is
    /// not authority (W3).
    ///
    /// Race window (documented, not closable in-facade): the actor check
    /// runs in its own read transaction while `Vault::retract_claim` opens
    /// its own write transaction — the engine exposes no in-txn retract
    /// seam to compose them. Entity types are immutable engine-wide
    /// (`apply_put` rejects type changes with `EntityTypeImmutable`), so
    /// the actor cannot be RETYPED in the window; the only mutation that
    /// fits is the actor entity being DELETED between check and apply,
    /// and deletion itself requires verified owner authority. Closing the
    /// window fully needs a `retract_claim_in_txn` engine seam
    /// (follow-up, outside this module's walls).
    pub fn claim_retract(&self, claim_ref: &str) -> FacadeResult<CommitReceipt> {
        let actor_class = self.verified_actor_class()?;
        let id = self.resolve_ref(claim_ref)?;
        if actor_class != EdgeActorClass::Human {
            let authored = self
                .vault
                .get_claim(&id)
                .map_err(FacadeError::from)?
                .as_ref()
                .and_then(claim_envelope_actor)
                .is_some_and(|writer| writer == self.actor);
            if !authored {
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
        }
        let now = crate::unix_seconds_now();
        self.vault
            .retract_claim(&id, now)
            .map_err(FacadeError::from)?;
        let approval = self
            .vault
            .get_claim(&id)
            .map_err(FacadeError::from)?
            .map_or_else(
                || "retracted".to_owned(),
                |body| body.approval.as_str().to_owned(),
            );
        let receipt_ref = self
            .latest_decision_ref_for(&id)?
            .unwrap_or_else(|| format!("retract:{}", id.to_hex()));
        Ok(CommitReceipt {
            claim_short_id: self.short_ref_or_hex(&id)?,
            approval,
            superseded_short_id: None,
            receipt_ref,
        })
    }

    /// Deletes an entity under a NAMED reason (S7). `user_delete` is the
    /// tombstone path; the other three run the redaction-audit machinery.
    ///
    /// Authority (fail-closed): deletion is an OWNER verb — the named
    /// reasons are `user_*`/compliance erasures. Only a VERIFIED
    /// `human`-class actor may delete ([`Self::verified_actor_class`]:
    /// the asserted actor must exist and be a PERSON — asserted class
    /// strings are never trusted); `agent`/`system` actors get a typed
    /// denial (agents withdraw their own claims via
    /// [`Self::claim_retract`]).
    ///
    /// Race window (documented, not closable in-facade): the actor check
    /// and `Vault::delete_entity_with_reason` run in separate
    /// transactions — no in-txn delete seam exists. Retyping the actor in
    /// the window is impossible (`EntityTypeImmutable`); the residual is
    /// the actor entity being deleted between check and apply, which
    /// itself requires verified owner authority. Closing it fully needs a
    /// `delete_entity_with_reason_in_txn` engine seam (follow-up).
    pub fn safe_delete(
        &self,
        entity_ref: &str,
        reason: SafeDeleteReason,
    ) -> FacadeResult<DeleteReceipt> {
        if self.verified_actor_class()? != EdgeActorClass::Human {
            return Err(FacadeError::new(
                FACADE_CODE_FORBIDDEN,
                format!(
                    "actor class {} may not delete entities; deletion is an owner verb",
                    self.actor_class.gate_actor_class(),
                ),
                &[
                    "Bind a human-class owner actor key to delete.",
                    "Agents withdraw their own claims via claim_retract.",
                ],
            ));
        }
        let id = self.resolve_ref(entity_ref)?;
        let outcome = self
            .vault
            .delete_entity_with_reason(&id, reason.delete_reason())
            .map_err(FacadeError::from)?;
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
    /// binds to any actor class.
    pub fn put_structural(&self, input: &StructuralPutInput) -> FacadeResult<EntityRefReceipt> {
        let actor_class = self.verified_actor_class()?;
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
        if type_byte == ENTITY_TYPE_PERSON && actor_class != EdgeActorClass::Human {
            return Err(FacadeError::new(
                FACADE_CODE_FORBIDDEN,
                format!(
                    "actor class {} may not mint PERSON entities; PERSON is actor-capable",
                    actor_class.gate_actor_class(),
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

        let mut batch = self
            .vault
            .batch()
            .put(&id, type_byte, occurred, learned_at, &data);
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
                batch = batch.edge(&id, kind, &target, weight);
            }
        }
        let pairs: Vec<(&str, &str)> = input
            .text_fields
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|field| (field.field.as_str(), field.value.as_str()))
            .collect();
        if !pairs.is_empty() {
            batch = batch.text(&id, &pairs);
        }
        batch.commit().map_err(FacadeError::from)?;
        self.entity_ref_receipt(&id)
    }

    /// Appends one immutable habit check-in child (`ChildOf` edge written by
    /// the pack contract). The pinned `role` body key is facade-injected.
    pub fn put_habit_checkin(&self, input: &HabitCheckinInput) -> FacadeResult<EntityRefReceipt> {
        self.verified_actor_class()?;
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
        self.vault
            .put_habit_checkin(&habit_id, &checkin_id, occurred, learned_at, &data)
            .map_err(FacadeError::from)?;
        self.entity_ref_receipt(&checkin_id)
    }

    /// Registers a companion persona record (personal scope) with a
    /// `created` lifecycle event, retiring it when `retired_at` is set.
    pub fn put_companion_record(
        &self,
        input: &CompanionRecordInput,
    ) -> FacadeResult<EntityRefReceipt> {
        self.verified_actor_class()?;
        let id = id_from_optional_hex(input.id.as_deref())?;
        let owner = self.resolve_ref(&input.owner_ref)?;
        let persona = self.resolve_ref(&input.persona_ref)?;
        let source = match &input.source {
            Some(source) => parse_claim_source(source)?,
            None => ClaimSource::UserStated,
        };
        let envelope = WriteEnvelope::new(
            WriteActor::new(self.actor, self.actor_class),
            source,
            WriteProvenance::new(facade_provenance("put_companion_record"))
                .map_err(FacadeError::from)?,
            ClaimApprovalStatus::Approved,
        );
        let record = CompanionRecord::persona(
            CompanionScope::personal(owner),
            persona,
            json_to_rmpv(&input.value),
            CompanionProvenance::from_envelope(&envelope),
            CompanionExportClassification::LocalOnly,
        );
        self.vault
            .create_companion_record(&id, &record, input.learned_at)
            .map_err(FacadeError::from)?;
        if let Some(retired_at) = input.retired_at {
            self.vault
                .retire_companion_record(&id, retired_at)
                .map_err(FacadeError::from)?;
        }
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
        let subject = self.resolve_ref(&input.subject_ref)?;
        if self
            .vault
            .get_entity_type(&subject)
            .map_err(FacadeError::from)?
            .is_none()
        {
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
                admit(approval).map_err(FacadeError::from)?;
            }
            Err(err) => return Err(err.into()),
        }
        let final_approval = self
            .vault
            .get_claim(&id)
            .map_err(FacadeError::from)?
            .map_or_else(
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
        self.verified_actor_class()?;
        let id = id_from_optional_hex(input.id.as_deref())?;
        let body = crate::blob_artifact::BlobArtifactBody::new(
            input.name.clone(),
            input.media_type.clone(),
        );
        let occurred = TimeRange {
            start: input.occurred_at,
            end: input.occurred_at,
        };
        let learned_at = input.learned_at.unwrap_or(input.occurred_at);
        self.vault
            .put_blob_artifact(&id, &body, occurred, learned_at)
            .map_err(FacadeError::from)?;
        self.entity_ref_receipt(&id)
    }

    /// Appends one content-addressed version to a blob artifact. The whole
    /// append (ASSET bytes + `blob.version` LEDGER claim + version chain)
    /// is one engine transaction; re-appending head bytes is a dedupe no-op.
    pub fn append_blob_version(
        &self,
        artifact_ref: &str,
        bytes: &[u8],
        run_ref: Option<&str>,
        occurred_at: u64,
        learned_at: Option<u64>,
    ) -> FacadeResult<BlobVersionView> {
        self.verified_actor_class()?;
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
        let record = self
            .vault
            .append_blob_artifact_version(
                &artifact_id,
                bytes,
                &provenance,
                WriteActor::new(self.actor, self.actor_class),
                occurred,
                learned_at.unwrap_or(occurred_at),
            )
            .map_err(FacadeError::from)?;
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
                self.vault
                    .claims_for_subject(&subject)
                    .map_err(FacadeError::from)?
            }
            None => self
                .vault
                .entities_by_type(ENTITY_TYPE_CLAIM)
                .map_err(FacadeError::from)?,
        };
        let mut views = Vec::new();
        for id in ids {
            if views.len() >= filter.limit {
                break;
            }
            let Some(body) = self.vault.get_claim(&id).map_err(FacadeError::from)? else {
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
        let timeline = self.vault.memory_timeline(&id).map_err(FacadeError::from)?;
        let mut records: Vec<_> = timeline
            .records
            .into_iter()
            .filter(|record| record.entity_type == Some(ENTITY_TYPE_CLAIM))
            .collect();
        records.sort_by_key(|record| (record.learned_at.unwrap_or(0), record.id.to_hex()));
        let mut views = Vec::with_capacity(records.len());
        for record in records {
            if let Some(body) = self
                .vault
                .get_claim(&record.id)
                .map_err(FacadeError::from)?
            {
                views.push(self.claim_view(&record.id, &body)?);
            }
        }
        Ok(views)
    }

    /// Lists gated writes parked for consent, newest lane state first.
    pub fn pending_writes(&self, limit: usize) -> FacadeResult<Vec<PendingWrite>> {
        let records = self
            .vault
            .pending_gate_consents(limit)
            .map_err(FacadeError::from)?;
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
        let records = self
            .vault
            .gate_decisions(limit)
            .map_err(FacadeError::from)?;
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

    // ── internals ───────────────────────────────────────────────────────

    fn commit_one(&self, input: &ClaimInput, auto_supersede: bool) -> FacadeResult<CommitReceipt> {
        self.verified_actor_class()?;
        let id = id_from_optional_hex(input.id.as_deref())?;
        let subject = self.resolve_ref(&input.subject_ref)?;
        if self
            .vault
            .get_entity_type(&subject)
            .map_err(FacadeError::from)?
            .is_none()
        {
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

        let mut approval = requested_approval(source, input.scope.as_ref());
        // Every commit is ONE engine transaction: gate decision, claim
        // write, and (with a prior revision) the supersession commit or
        // roll back together. No phantom receipts (a decision can never
        // outlive a write that failed later validation) and no orphan
        // revisions behind a rejected receipt. The fail-closed trade: a
        // rolled-back write also drops its gate decision.
        let write = |approval: ClaimApprovalStatus| -> Result<(), Error> {
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
                match prior {
                    Some(old_id) => self
                        .vault
                        .supersede_claim_in_txn(wtxn, &id, &old_id, learned_at),
                    None => Ok(()),
                }
            })
        };
        match write(approval) {
            Ok(()) => {}
            Err(err)
                if approval == ClaimApprovalStatus::Auto
                    && err.kind() == ErrorKind::GateWriteRejected =>
            {
                approval = ClaimApprovalStatus::Proposed;
                write(approval).map_err(FacadeError::from)?;
            }
            Err(err) => return Err(err.into()),
        }

        let superseded_short_id = match prior {
            Some(old_id) => Some(self.short_ref_or_hex(&old_id)?),
            None => None,
        };
        let final_approval = self
            .vault
            .get_claim(&id)
            .map_err(FacadeError::from)?
            .map_or_else(
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
        let ids = self
            .vault
            .claims_for_subject(subject)
            .map_err(FacadeError::from)?;
        let mut best: Option<EntityId> = None;
        for id in ids {
            if id == *exclude {
                continue;
            }
            let Some(body) = self.vault.get_claim(&id).map_err(FacadeError::from)? else {
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
            return match self.vault.get_entity_type(&id).map_err(FacadeError::from)? {
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
        match self.vault.get_entity_type(&id).map_err(FacadeError::from)? {
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
        let Some(raw) = self.vault.get_raw(id).map_err(FacadeError::from)? else {
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
            .get(&rtxn, id.as_bytes())
            .map_err(|err| FacadeError::from(Error::from(err)))?
        else {
            return Ok(None);
        };
        let (short_id, content_hash) = parse_short_id_value(raw).map_err(FacadeError::from)?;
        Ok(Some(format!("{short_id}:{content_hash:02x}")))
    }

    fn short_ref_or_hex(&self, id: &EntityId) -> FacadeResult<String> {
        Ok(self.short_ref_of(id)?.unwrap_or_else(|| id.to_hex()))
    }

    fn latest_decision_ref_for(&self, id: &EntityId) -> FacadeResult<Option<String>> {
        let decisions = self
            .vault
            .gate_decisions(GATE_RECEIPT_SCAN_LIMIT)
            .map_err(FacadeError::from)?;
        let latest = decisions
            .into_iter()
            .filter(|record| record.claim_id.as_ref() == Some(id.as_bytes()))
            .max_by_key(|record| record.decision_id.to_hex());
        Ok(latest.map(|record| format!("gate:{}", record.decision_id.to_hex())))
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

fn hex_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests;
