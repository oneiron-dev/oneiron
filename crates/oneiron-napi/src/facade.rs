//! BRIDGE-01 (ONE-1454): napi lift of the engine memory facade.
//!
//! `VaultBridge.open(path)` → `asActor("<actor_class>:<entity_ref>")` →
//! `ActorScopedVault` carrying every facade verb (W3 ABI). All methods are
//! sync `&self` (W2 — no async FFI, no `&mut`). Facade vocabulary only:
//! short-id refs, registry kind strings, typed DTOs — no byte buffers, no
//! type bytes, no JSON-as-bytes anywhere on this surface (S1; enforced by
//! the fitness scan). Blob content crosses as standard base64 strings.
//!
//! Errors cross the boundary as `napi::Error` whose reason is the
//! JSON-serialized engine `MemoryError` (`{code, message, suggestions}`),
//! so the TS wrapper (deferred this wave) can rehydrate typed errors.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use napi_derive::napi;
use oneiron::{
    AdmitImportedClaimInput, BlobArtifactInput, CalendarEventView, CalendarInviteSurfaceInput,
    CalendarInviteSurfaceMethod, CalendarRangeDto, CalendarReadRequest, CalendarSearchRequest,
    CalendarSel, ClaimInput, ClaimListFilter, CompanionRecordInput, ConsolidationAttemptInput,
    Effort, EntityId, HabitCheckinInput, Memory, MemoryError, NeighborOpts, OutboundDraftInput,
    RecallScope, SafeDeleteReason, StructuralEdgeSpec, StructuralPutInput, TextIndexField,
    TimeRange, Vault, VaultConfig, WitnessAuthor, WitnessMessage, WitnessTurn, parse_actor_key,
};

pub(crate) type BoundaryResult<T> = std::result::Result<T, String>;

pub(crate) fn facade_error(err: MemoryError) -> napi::Error {
    napi::Error::from_reason(serde_json::to_string(&err).unwrap_or_else(|_| err.to_string()))
}

pub(crate) fn boundary_error(reason: String) -> napi::Error {
    napi::Error::from_reason(reason)
}

pub(crate) fn ts_to_engine(value: i64, field: &str) -> BoundaryResult<u64> {
    u64::try_from(value).map_err(|_| format!("{field} must be a non-negative Unix timestamp"))
}

fn ts_opt_to_engine(value: Option<i64>, field: &str) -> BoundaryResult<Option<u64>> {
    value.map(|v| ts_to_engine(v, field)).transpose()
}

fn ts_from_engine(value: u64, field: &str) -> BoundaryResult<i64> {
    i64::try_from(value).map_err(|_| format!("{field} does not fit a signed 64-bit integer"))
}

/// Converts the host's optional clock-authority fields into the engine's
/// schedule context. Fail-closed by construction: every rejection happens here,
/// before the draft reaches the facade, so no invalid offset, label, or level
/// can produce a TASK or attempt write.
///
/// JS has no integer type, so the offset arrives as `f64` and must be proven
/// finite, whole, and inside the current civil range `-840..=840` before it is
/// narrowed to `i16`.
fn outbound_schedule_context_to_engine(
    draft: &NapiOutboundDraftInput,
) -> BoundaryResult<oneiron::memory::OutboundScheduleContext> {
    let utc_offset_minutes = match draft.utc_offset_minutes {
        Some(value)
            if !value.is_finite() || value.fract() != 0.0 || !(-840.0..=840.0).contains(&value) =>
        {
            return Err("utc_offset_minutes must be a finite integer in -840..=840".to_owned());
        }
        Some(value) => Some(value as i16),
        None => None,
    };
    let iana_timezone = draft.iana_timezone.clone();
    // An IANA label without an offset is unusable: execution derives local time
    // from the numeric offset alone and never opens a timezone database.
    if iana_timezone.is_some() && utc_offset_minutes.is_none() {
        return Err("iana_timezone requires utc_offset_minutes".to_owned());
    }
    if iana_timezone.as_deref().is_some_and(|label| {
        label.trim().is_empty() || label.chars().any(char::is_control) || label.len() > 255
    }) {
        return Err("iana_timezone must be non-blank and contain no controls".to_owned());
    }
    let apns_interruption_level = match draft.apns_interruption_level.as_deref() {
        Some(label) => Some(
            oneiron::DeliveryWindowApnsInterruptionLevel::parse(label).ok_or_else(|| {
                "unknown APNs interruption level: use passive, active, time_sensitive, or critical"
                    .to_owned()
            })?,
        ),
        None => None,
    };
    let resolved_level = match draft.resolved_level.as_deref() {
        Some(label) => Some(
            oneiron::delivery_window::DeliveryWindowResolvedLevel::parse(label)
                .ok_or_else(|| "unknown resolved level: use plain_chat or push".to_owned())?,
        ),
        None => None,
    };
    Ok(oneiron::memory::OutboundScheduleContext {
        utc_offset_minutes,
        iana_timezone,
        human_explicit_instant: draft.human_explicit_instant.unwrap_or(false),
        apns_interruption_level,
        resolved_level,
    })
}

/// Page size for `forget`'s active-claim drain. `forget` re-lists `active`
/// after each page, so this bounds only per-iteration work, never the total
/// number of claims retracted.
const FORGET_PAGE_SIZE: usize = 64;

/// Blob content ceiling for the N-API boundary: 32 MiB raw (double the
/// B8-validated 16 MiB probe). The base64 length is bounded BEFORE any
/// decode allocation, so oversized inputs cannot exhaust process memory.
const MAX_NAPI_BLOB_CONTENT_BYTES: usize = 32 * 1024 * 1024;
const MAX_NAPI_BLOB_BASE64_LEN: usize = MAX_NAPI_BLOB_CONTENT_BYTES / 3 * 4 + 4;

fn decode_blob_base64(input: &str) -> BoundaryResult<Vec<u8>> {
    if input.len() > MAX_NAPI_BLOB_BASE64_LEN {
        return Err(format!(
            "bytes_base64 exceeds the {MAX_NAPI_BLOB_CONTENT_BYTES}-byte blob content ceiling"
        ));
    }
    BASE64_STANDARD
        .decode(input.as_bytes())
        .map_err(|_| "bytes_base64 is not valid standard base64".to_owned())
}

/// Narrows an f64 to f32 at the N-API boundary, rejecting NaN and ±Inf
/// (including a finite f64 that overflows f32 to ±Inf). A non-finite
/// `min_weight` would otherwise silently disable the filter — NaN compares
/// false against every edge weight — or reject every edge (+Inf).
#[expect(
    clippy::cast_possible_truncation,
    reason = "f64→f32 narrowing at the N-API boundary is intentional"
)]
fn narrow_to_f32(value: f64) -> BoundaryResult<f32> {
    let narrowed = value as f32;
    if !narrowed.is_finite() {
        return Err(format!("min_weight must be a finite number, got {value}"));
    }
    Ok(narrowed)
}

// ── DTOs (napi objects mirroring the engine facade DTOs) ────────────────

/// One message inside a witnessed turn.
///
/// ONE-1686: every field here is an axis of ONE gated envelope. The engine's
/// witness ceiling door authorizes all six together, immediately before the
/// MESSAGE write, and this boundary is a convenience layer in front of it —
/// never the authority. In particular:
///
/// - `author: "system"` rows carry no `AuthoredBy` edge, so they need a
///   loaded policy with an explicit owner-authored `actor_ceilings` row bound
///   to the acting actor and resolving to `auto`. A system-class identity alone
///   and an ordinary `human:`/`agent:` scope are both refused.
/// - `messageType` must be a bounded printable token (`dialogue`,
///   `executor.speak`); it is not a free-text field.
/// - `metadata` must be a JSON object, bounded in depth and size, and may not
///   carry a key that restates an envelope axis (`author`, `type`, `content`,
///   `metadata`, `isVisible`, `order`, `speaker`) at any depth.
/// - `order` must be unique within the call and inside the engine's ceiling.
/// - `isVisible: false` is legal for companion/system rows and refused for
///   `user` rows.
#[napi(object)]
pub struct NapiWitnessMessage {
    /// Deterministic 32-hex entity id; omitted ⇒ generated.
    pub id: Option<String>,
    /// `user` | `companion` | `system` (system rows get no AuthoredBy edge,
    /// and authoring one takes engine-voice authority — see the type docs).
    pub author: String,
    /// Message type token (bounded, printable, no whitespace).
    pub message_type: String,
    /// Text content (BM25-indexed when non-empty).
    pub content: String,
    /// Opaque metadata; must be a JSON object when present.
    pub metadata: Option<serde_json::Value>,
    /// Visibility flag; omitted ⇒ true.
    pub is_visible: Option<bool>,
    /// Position within the turn; unique across the call.
    pub order: u32,
}

/// One turn to witness.
#[napi(object)]
pub struct NapiWitnessTurn {
    /// CONVERSATION ref (32-hex create-or-get, or existing short ref).
    pub conversation_ref: String,
    /// TURN ref (create-or-get); omitted ⇒ a fresh TURN.
    pub turn_ref: Option<String>,
    /// Messages, attributed to the bound actor unless `system`.
    pub messages: Vec<NapiWitnessMessage>,
    /// Unix seconds (occurred + learned_at).
    pub occurred_at: i64,
}

/// Receipt for one witnessed turn.
#[napi(object)]
pub struct NapiWitnessReceipt {
    /// TURN short ref.
    pub turn_short_id: String,
    /// MESSAGE short refs, input order.
    pub message_short_ids: Vec<String>,
    /// Facade write marker (`witness:<hex>`).
    pub receipt_ref: String,
}

/// One claim to commit (`approval` is not settable by callers).
#[napi(object)]
pub struct NapiClaimInput {
    /// Deterministic 32-hex claim id; omitted ⇒ generated.
    pub id: Option<String>,
    /// Dotted predicate.
    pub predicate: String,
    /// Subject entity ref.
    pub subject_ref: String,
    /// Claim value.
    pub value: serde_json::Value,
    /// Confidence in [0, 1].
    pub confidence: f64,
    /// Claim source string.
    pub source: String,
    /// Optional WORLD ref.
    pub world_ref: Option<String>,
    /// Optional scope map.
    pub scope: Option<serde_json::Value>,
    /// Validity window start (Unix seconds).
    pub valid_from: Option<i64>,
    /// Validity window end (Unix seconds).
    pub valid_to: Option<i64>,
    /// Backdating passthrough (Unix seconds).
    pub occurred_at: Option<i64>,
    /// Backdating passthrough (Unix seconds).
    pub learned_at: Option<i64>,
    /// Optional salience in [0, 1].
    pub salience: Option<f64>,
}

/// Receipt for one committed (or rejected) claim.
#[napi(object)]
pub struct NapiCommitReceipt {
    /// Short ref of the written claim (hash suffix tracks body revisions).
    pub claim_short_id: String,
    /// `auto` | `proposed` | `rejected`.
    pub approval: String,
    /// Short ref of the superseded prior claim, if any.
    pub superseded_short_id: Option<String>,
    /// Gate decision ref (`gate:<hex>`) resolvable via `receipts()`.
    pub receipt_ref: String,
}

/// Receipt for one safe delete.
#[napi(object)]
pub struct NapiDeleteReceipt {
    /// Whether the entity existed.
    pub existed: bool,
    /// The named reason used.
    pub reason: String,
    /// Redaction audit ref; absent for `user_delete`.
    pub receipt_ref: Option<String>,
}

/// One gated write parked for consent.
#[napi(object)]
pub struct NapiPendingWrite {
    /// 32-hex claim id.
    pub claim_ref: String,
    /// Gate decision ref.
    pub decision_ref: String,
    /// Unix seconds.
    pub created_at: i64,
    /// Gate reason codes.
    pub reason_codes: Vec<String>,
    /// Dreamer run lane, if any.
    pub dreamer_run_id: Option<String>,
}

/// One gate decision receipt.
#[napi(object)]
pub struct NapiGateReceipt {
    /// `gate:<hex>`.
    pub receipt_ref: String,
    /// `allow` | `pending` | `deny`.
    pub outcome: String,
    /// Unix seconds.
    pub created_at: i64,
    /// Gate reason codes.
    pub reason_codes: Vec<String>,
    /// Actor class string.
    pub actor_class: String,
    /// Actor entity hex, if enveloped.
    pub actor_ref: Option<String>,
    /// Gate content kind.
    pub content_kind: String,
    /// 32-hex claim id, if any.
    pub claim_ref: Option<String>,
}

/// Typed entity view.
#[napi(object)]
pub struct NapiEntityView {
    /// 32-hex entity id.
    pub id_hex: String,
    /// Short ref, when assigned.
    pub short_ref: Option<String>,
    /// Registry kind string.
    pub kind: String,
    /// Unix seconds.
    pub occurred_start: i64,
    /// Unix seconds.
    pub occurred_end: i64,
    /// Unix seconds.
    pub learned_at: i64,
    /// Body as JSON, when decodable.
    pub body: Option<serde_json::Value>,
}

/// Typed claim view.
#[napi(object)]
pub struct NapiClaimView {
    /// 32-hex claim id.
    pub claim_ref: String,
    /// Short ref, when assigned.
    pub short_ref: Option<String>,
    /// Predicate.
    pub predicate: String,
    /// Subject ref.
    pub subject_ref: String,
    /// Value as JSON.
    pub value: serde_json::Value,
    /// Confidence.
    pub confidence: f64,
    /// Approval string.
    pub approval: String,
    /// Lifecycle string.
    pub lifecycle: String,
    /// Source string.
    pub source: Option<String>,
    /// World hex.
    pub world_ref: Option<String>,
    /// Scope as JSON.
    pub scope: Option<serde_json::Value>,
    /// Validity window start.
    pub valid_from: Option<i64>,
    /// Validity window end.
    pub valid_to: Option<i64>,
    /// Salience.
    pub salience: Option<f64>,
    /// Stale marker.
    pub stale: bool,
}

/// Filter for `claimList`.
#[napi(object)]
pub struct NapiClaimListFilter {
    /// Restrict to this subject.
    pub subject_ref: Option<String>,
    /// Restrict to this predicate.
    pub predicate: Option<String>,
    /// Restrict to this lifecycle.
    pub lifecycle: Option<String>,
    /// Maximum results (required).
    pub limit: u32,
}

/// One BM25 field for a structural put.
#[napi(object)]
pub struct NapiTextIndexField {
    /// Analyzer field name.
    pub field: String,
    /// Field text.
    pub value: String,
}

/// One outgoing edge for a structural put.
#[napi(object)]
pub struct NapiStructuralEdgeSpec {
    /// snake_case EdgeKind name.
    pub edge_kind: String,
    /// Target entity ref.
    pub target_ref: String,
    /// Weight in [0, 1]; omitted ⇒ kind default.
    pub weight: Option<f64>,
}

/// Structural put input (B2 migrator group).
#[napi(object)]
pub struct NapiStructuralPutInput {
    /// Deterministic 32-hex id; omitted ⇒ generated.
    pub id: Option<String>,
    /// Registry kind string (CLAIM rejected — use commit).
    pub kind: String,
    /// Entity body (JSON object).
    pub body: serde_json::Value,
    /// BM25 fields.
    pub text_fields: Option<Vec<NapiTextIndexField>>,
    /// Outgoing edges.
    pub edges: Option<Vec<NapiStructuralEdgeSpec>>,
    /// Unix seconds.
    pub occurred_at: i64,
    /// Unix seconds; omitted ⇒ occurred_at.
    pub learned_at: Option<i64>,
}

/// Receipt for a structural write.
#[napi(object)]
pub struct NapiEntityRefReceipt {
    /// Short ref (hex fallback).
    pub entity_ref: String,
    /// 32-hex id.
    pub id_hex: String,
    /// Facade write marker.
    pub receipt_ref: String,
}

/// One habit check-in append.
#[napi(object)]
pub struct NapiHabitCheckinInput {
    /// Habit-role TASK ref.
    pub habit_ref: String,
    /// Deterministic 32-hex checkin id; omitted ⇒ generated.
    pub id: Option<String>,
    /// Extra body fields (JSON object, no `role` key).
    pub data: Option<serde_json::Value>,
    /// Unix seconds.
    pub occurred_at: i64,
    /// Unix seconds; omitted ⇒ occurred_at.
    pub learned_at: Option<i64>,
}

/// One companion persona registration.
#[napi(object)]
pub struct NapiCompanionRecordInput {
    /// Deterministic 32-hex record id; omitted ⇒ generated.
    pub id: Option<String>,
    /// Owner PERSON ref (personal scope).
    pub owner_ref: String,
    /// Companion persona PERSON ref.
    pub persona_ref: String,
    /// Opaque record value.
    pub value: serde_json::Value,
    /// Provenance source; omitted ⇒ user_stated.
    pub source: Option<String>,
    /// Retire the record at this time after creation.
    pub retired_at: Option<i64>,
    /// Creation time (Unix seconds).
    pub learned_at: i64,
}

/// One imported-evidence claim admission (B1a).
#[napi(object)]
pub struct NapiAdmitImportedClaimInput {
    /// Registered ingest source id (fail-closed for unknown sources).
    pub source_id: String,
    /// Stable source record id.
    pub source_record_id: String,
    /// Deterministic 32-hex claim id; omitted ⇒ generated.
    pub id: Option<String>,
    /// Subject entity ref.
    pub subject_ref: String,
    /// Predicate.
    pub predicate: String,
    /// Claim value.
    pub value: serde_json::Value,
    /// Unix seconds.
    pub occurred_at: i64,
    /// Unix seconds; omitted ⇒ occurred_at.
    pub learned_at: Option<i64>,
}

/// One blob artifact registration (B8 blob door).
#[napi(object)]
pub struct NapiBlobArtifactInput {
    /// Deterministic 32-hex artifact id; omitted ⇒ generated.
    pub id: Option<String>,
    /// Display name.
    pub name: String,
    /// Media type.
    pub media_type: String,
    /// Unix seconds.
    pub occurred_at: i64,
    /// Unix seconds; omitted ⇒ occurred_at.
    pub learned_at: Option<i64>,
}

/// View of one appended blob version.
#[napi(object)]
pub struct NapiBlobVersionView {
    /// 32-hex artifact id.
    pub artifact_ref: String,
    /// 1-based version number.
    pub version: i64,
    /// blake3 content hash (lowercase hex).
    pub content_hash_hex: String,
    /// 32-hex id of the blob.version LEDGER claim.
    pub claim_ref: String,
    /// Unix seconds.
    pub created_at: i64,
}

/// Recall scoping (S5): narrowing only; unset = vault floor.
#[napi(object)]
pub struct NapiRecallScope {
    /// WORLD entity ref; scopes to that world plus base reality.
    pub world_ref: Option<String>,
    /// Facet entity ref; strict facet narrowing when set.
    pub facet: Option<String>,
}

/// One BM25 hit (engine index scores).
#[napi(object)]
pub struct NapiLexicalHit {
    /// Short ref (hex fallback).
    pub short_id: String,
    /// Registry kind string.
    pub kind: String,
    /// Engine BM25F score.
    pub score: f64,
    /// Content preview, when available.
    pub snippet: Option<String>,
}

/// Options for `neighbors`.
#[napi(object)]
pub struct NapiNeighborOpts {
    /// Restrict to this snake_case EdgeKind name.
    pub edge_kind: Option<String>,
    /// Drop edges below this weight.
    pub min_weight: Option<f64>,
    /// Maximum hits.
    pub limit: u32,
}

/// One graph neighbor.
#[napi(object)]
pub struct NapiNeighborHit {
    /// Short ref of the neighbor.
    pub short_id: String,
    /// Registry kind string of the neighbor.
    pub kind: String,
    /// snake_case EdgeKind name.
    pub edge_kind: String,
    /// Stored edge weight.
    pub weight: f64,
    /// `out` | `in` relative to the anchor.
    pub direction: String,
}

/// Item provenance (S6, default-on).
#[napi(object)]
pub struct NapiMemoryProvenance {
    /// Claim source string, or `record` for structural records.
    pub source: String,
    /// This revision plus superseded ancestors.
    pub source_revision_ids: Vec<String>,
    /// Evidence TURN ids.
    pub evidence_turn_ids: Vec<String>,
}

/// One memory pack item (S6).
#[napi(object)]
pub struct NapiMemoryItem {
    /// Short ref, hydratable via `hydrate`.
    pub short_id: String,
    /// Registry kind string.
    pub kind: String,
    /// Predicate (claims only).
    pub predicate: Option<String>,
    /// Text rendering of the value/content.
    pub value_text: String,
    /// Calibrated-absolute confidence in [0, 1].
    pub confidence: f64,
    /// Hedge vocabulary bucket.
    pub hedge_bucket: String,
    /// Provenance.
    pub provenance: NapiMemoryProvenance,
    /// World hex, when world-scoped.
    pub world: Option<String>,
    /// Facet hex, when faceted.
    pub facet: Option<String>,
    /// Salience, when stamped.
    pub salience: Option<f64>,
}

/// Scope honesty (S6).
#[napi(object)]
pub struct NapiScopeHonesty {
    /// Worlds excluded by the requested scope.
    pub out_of_scope_worlds: Vec<String>,
}

/// Retrieval accounting (S6).
#[napi(object)]
pub struct NapiRetrievalMeta {
    /// True when only sparse signals ran.
    pub sparse: Option<bool>,
    /// Candidates considered.
    pub total_candidates: i64,
    /// CLAIM items returned.
    pub claims_returned: i64,
    /// Set when a leased deep call executed as standard.
    pub deep_pending: Option<bool>,
}

/// The S6 memory pack (`packVersion: 1`).
#[napi(object)]
pub struct NapiMemoryPack {
    /// Ranked items.
    pub items: Vec<NapiMemoryItem>,
    /// What the scope excluded.
    pub scope_honesty: NapiScopeHonesty,
    /// Retrieval accounting.
    pub retrieval_meta: NapiRetrievalMeta,
    /// Schema version.
    pub pack_version: u32,
    /// Text rendering in the requested format; absent = typed only.
    pub rendered: Option<String>,
}

/// One Dreamer consolidation enqueue (BRIDGE-03).
#[napi(object)]
pub struct NapiConsolidationJobInput {
    /// `micro` | `meso` | `macro`.
    pub scope: String,
    /// Opaque job input.
    pub input: serde_json::Value,
    /// Optional run correlation id.
    pub run_id: Option<String>,
    /// Optional advisory dedupe key.
    pub dedupe_key: Option<String>,
    /// Unix seconds; omitted ⇒ now.
    pub now: Option<i64>,
}

/// Reference to one queued Dreamer job (poll model, W2).
#[napi(object)]
pub struct NapiDreamerJobRef {
    /// 32-hex job id.
    pub job_ref: String,
    /// Queue state at enqueue time.
    pub state: String,
    /// True when the dedupe key coalesced onto an existing job.
    pub existing: bool,
}

/// Poll view of one Dreamer job.
#[napi(object)]
pub struct NapiDreamerJobView {
    /// 32-hex job id.
    pub job_ref: String,
    /// `queued` | `leased` | `paused` | `completed` | `failed` | `cancelled`.
    pub state: String,
    /// Queue job kind.
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
    pub created_at: i64,
    /// Unix seconds.
    pub updated_at: i64,
}

/// One outbound schedule request (rides OF-327; the bridge never delivers).
#[napi(object)]
#[derive(Clone)]
pub struct NapiOutboundDraftInput {
    /// Verb (e.g. `send`).
    pub verb: String,
    /// Channel (e.g. `email`).
    pub channel: String,
    /// Delivery target.
    pub target: String,
    /// Principal the send acts for, if delegated.
    pub on_behalf_of: Option<String>,
    /// Content entity ref.
    pub content_ref: Option<String>,
    /// Facade-enforced idempotency key (no double-enqueue).
    pub idempotency_key: Option<String>,
    /// Advisory dedupe key carried onto the receipt.
    pub dedupe_key: Option<String>,
    /// `commitment_timer_wake` | `gap_queue` | `agent_immediate`.
    pub trigger: String,
    /// What fired the trigger.
    pub trigger_ref: String,
    /// Owning job/brief ref, if any.
    pub job_ref: Option<String>,
    /// Unix seconds; omitted ⇒ now.
    pub occurred_at: Option<i64>,
    /// Current civil UTC offset in minutes, `-840..=840`. Required whenever
    /// `ianaTimezone` is supplied; omitted ⇒ hostless (fail-closed) schedule.
    pub utc_offset_minutes: Option<f64>,
    /// IANA label kept as provenance only; execution never reads a tz database.
    pub iana_timezone: Option<String>,
    /// A human explicitly chose this instant ("send at 23:30").
    pub human_explicit_instant: Option<bool>,
    /// `passive` | `active` | `time_sensitive` | `critical` (APNs push only).
    pub apns_interruption_level: Option<String>,
    /// `plain_chat` | `push` — the resolved level for a compatibility verb.
    pub resolved_level: Option<String>,
}

/// Receipt for one scheduled outbound intent.
#[napi(object)]
pub struct NapiOutboundIntentReceipt {
    /// Stable intent ref (`intent:<job-hex>`).
    pub intent_ref: String,
    /// `held` expected; `suppressed` on gate denial; `already_scheduled`
    /// on dedupe.
    pub outcome: String,
    /// Gate outcome, absent on dedupe.
    pub gate_outcome: Option<String>,
    /// Persisted gate decision ref, queryable via `receipts()`.
    pub gate_decision_ref: Option<String>,
    /// Gate reason codes.
    pub gate_reason_codes: Vec<String>,
    /// True when the idempotency key coalesced.
    pub deduped: bool,
}

/// Inclusive UTC window for the calendar verbs.
#[napi(object)]
pub struct NapiCalendarRange {
    /// Inclusive start, Unix seconds.
    pub start: i64,
    /// Inclusive end, Unix seconds.
    pub end: i64,
}

/// One calendar selector. `system` is accepted and ignored until CAL-02's
/// passport index lands; it never empties a result set on this baseline.
#[napi(object)]
pub struct NapiCalendarSel {
    /// Calendar system key.
    pub system: Option<String>,
}

/// One projected calendar EVENT.
#[napi(object)]
pub struct NapiCalendarEventView {
    /// Hex EVENT entity id.
    pub event_ref: String,
    /// EVENT display name, when the body carries one.
    pub name: Option<String>,
    /// Inclusive UTC occurrence start.
    pub start_utc: Option<i64>,
    /// Inclusive UTC occurrence end.
    pub end_utc: Option<i64>,
    /// Calendar systems this EVENT holds a passport for.
    pub calendar_systems: Vec<String>,
    /// Whether this EVENT consumes availability.
    pub blocks_time: bool,
}

/// `calendarSearch` request.
#[napi(object)]
pub struct NapiCalendarSearchRequest {
    /// Calendar selectors; omitted ⇒ every readable calendar EVENT.
    pub calendars: Option<Vec<NapiCalendarSel>>,
    /// Inclusive UTC window; omitted ⇒ unbounded.
    pub range: Option<NapiCalendarRange>,
    /// Case-insensitive substring matched against the EVENT name.
    pub text: Option<String>,
    /// Maximum rows returned, clamped engine-side.
    pub limit: u32,
}

/// One source-redacted busy interval, half-open `[startUtc, endUtc)`.
///
/// The internal `BusyInterval.source` never crosses this boundary: the bridge
/// surface carries occupancy only.
#[napi(object)]
pub struct NapiCalendarFreebusyInterval {
    /// Inclusive half-open start, Unix seconds.
    pub start_utc: i64,
    /// Exclusive half-open end, Unix seconds.
    pub end_utc: i64,
}

/// C7's exact five-field invite payload (never an outbound draft).
#[napi(object)]
pub struct NapiCalendarInviteInput {
    /// `REQUEST` | `CANCEL`.
    pub method: String,
    /// EVENT UID the invite addresses.
    pub uid: String,
    /// iTIP SEQUENCE of this revision.
    pub sequence: u32,
    /// Blob ref of the rendered ICS payload.
    pub ics_blob_ref: String,
    /// Delivery target.
    pub recipient: String,
}

/// Selector for `forget`: a claim short ref, or `{subjectRef, predicate}`.
#[napi(object)]
pub struct NapiForgetSelector {
    /// Claim short ref (or 32-hex id).
    pub short_ref: Option<String>,
    /// Subject ref (used with `predicate`).
    pub subject_ref: Option<String>,
    /// Predicate (used with `subject_ref`).
    pub predicate: Option<String>,
}

// ── conversions ─────────────────────────────────────────────────────────

fn calendar_selectors_to_engine(selectors: Option<Vec<NapiCalendarSel>>) -> Vec<CalendarSel> {
    selectors
        .unwrap_or_default()
        .into_iter()
        .map(|selector| CalendarSel {
            system: selector.system,
        })
        .collect()
}

fn calendar_range_to_engine(range: Option<NapiCalendarRange>) -> BoundaryResult<Option<TimeRange>> {
    range
        .map(|range| {
            Ok(TimeRange {
                start: ts_to_engine(range.start, "range.start")?,
                end: ts_to_engine(range.end, "range.end")?,
            })
        })
        .transpose()
}

fn calendar_event_from_engine(view: CalendarEventView) -> BoundaryResult<NapiCalendarEventView> {
    Ok(NapiCalendarEventView {
        event_ref: view.event_ref,
        name: view.name,
        start_utc: view
            .start_utc
            .map(|value| ts_from_engine(value, "start_utc"))
            .transpose()?,
        end_utc: view
            .end_utc
            .map(|value| ts_from_engine(value, "end_utc"))
            .transpose()?,
        calendar_systems: view.calendar_systems,
        blocks_time: view.blocks_time,
    })
}

/// Converts a host turn into the engine turn.
///
/// ONE-1686: this is a CONVENIENCE boundary, not a gate. It rejects the two
/// shapes whose engine refusal a host could not otherwise read off its own
/// input — an unknown author string and a non-object `metadata` — and leaves
/// every other axis to the engine's witness ceiling door, which runs inside the
/// write transaction and answers for EVERY caller (uniffi, HTTP, in-process
/// Rust), not just this one. Re-implementing the ceiling here would create a
/// second set of bounds to drift out of sync with the authoritative one, and
/// would still not protect the callers that never cross this boundary.
fn witness_turn_to_engine(turn: &NapiWitnessTurn) -> BoundaryResult<WitnessTurn> {
    let mut messages = Vec::with_capacity(turn.messages.len());
    for message in &turn.messages {
        let author = WitnessAuthor::parse(&message.author).ok_or_else(|| {
            format!(
                "author must be one of user, companion, system; got {:?}",
                message.author
            )
        })?;
        if message
            .metadata
            .as_ref()
            .is_some_and(|metadata| !metadata.is_object())
        {
            return Err(format!(
                "metadata must be a JSON object; message at order {} carries {}",
                message.order,
                match message.metadata.as_ref() {
                    Some(serde_json::Value::Array(_)) => "an array",
                    Some(serde_json::Value::Null) => "null",
                    _ => "a scalar",
                }
            ));
        }
        messages.push(WitnessMessage {
            id: message.id.clone(),
            author,
            message_type: message.message_type.clone(),
            content: message.content.clone(),
            metadata: message.metadata.clone(),
            is_visible: message.is_visible.unwrap_or(true),
            order: message.order,
        });
    }
    Ok(WitnessTurn {
        conversation_ref: turn.conversation_ref.clone(),
        turn_ref: turn.turn_ref.clone(),
        messages,
        occurred_at: ts_to_engine(turn.occurred_at, "occurred_at")?,
    })
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "f64→f32 confidence/salience narrowing at the N-API boundary is intentional"
)]
fn claim_input_to_engine(input: &NapiClaimInput) -> BoundaryResult<ClaimInput> {
    Ok(ClaimInput {
        id: input.id.clone(),
        predicate: input.predicate.clone(),
        subject_ref: input.subject_ref.clone(),
        value: input.value.clone(),
        confidence: input.confidence as f32,
        source: input.source.clone(),
        world_ref: input.world_ref.clone(),
        scope: input.scope.clone(),
        valid_from: ts_opt_to_engine(input.valid_from, "valid_from")?,
        valid_to: ts_opt_to_engine(input.valid_to, "valid_to")?,
        occurred_at: ts_opt_to_engine(input.occurred_at, "occurred_at")?,
        learned_at: ts_opt_to_engine(input.learned_at, "learned_at")?,
        salience: input.salience.map(|s| s as f32),
    })
}

fn commit_receipt_from_engine(receipt: oneiron::CommitReceipt) -> NapiCommitReceipt {
    NapiCommitReceipt {
        claim_short_id: receipt.claim_short_id,
        approval: receipt.approval,
        superseded_short_id: receipt.superseded_short_id,
        receipt_ref: receipt.receipt_ref,
    }
}

/// Retracts EVERY active claim matching `subject_ref` + `predicate`, not just
/// the first page. Each retract moves its claim out of the `active`
/// lifecycle, so re-listing `active` excludes the already-retracted claims and
/// the loop drains to an empty page with no offset bookkeeping. Engine-typed
/// so it is unit-testable without the N-API runtime.
fn forget_active_matches(
    facade: &Memory<'_>,
    subject_ref: &str,
    predicate: &str,
) -> std::result::Result<Vec<oneiron::CommitReceipt>, MemoryError> {
    let mut receipts = Vec::new();
    loop {
        let matches = facade.claim_list(&ClaimListFilter {
            subject_ref: Some(subject_ref.to_owned()),
            predicate: Some(predicate.to_owned()),
            lifecycle: Some("active".to_owned()),
            limit: FORGET_PAGE_SIZE,
        })?;
        if matches.is_empty() {
            break;
        }
        for claim in matches {
            receipts.push(facade.claim_retract(&claim.claim_ref)?);
        }
    }
    Ok(receipts)
}

fn entity_view_from_engine(view: oneiron::EntityView) -> BoundaryResult<NapiEntityView> {
    Ok(NapiEntityView {
        id_hex: view.id_hex,
        short_ref: view.short_ref,
        kind: view.kind,
        occurred_start: ts_from_engine(view.occurred_start, "occurred_start")?,
        occurred_end: ts_from_engine(view.occurred_end, "occurred_end")?,
        learned_at: ts_from_engine(view.learned_at, "learned_at")?,
        body: view.body,
    })
}

fn claim_view_from_engine(view: oneiron::ClaimView) -> BoundaryResult<NapiClaimView> {
    Ok(NapiClaimView {
        claim_ref: view.claim_ref,
        short_ref: view.short_ref,
        predicate: view.predicate,
        subject_ref: view.subject_ref,
        value: view.value,
        confidence: f64::from(view.confidence),
        approval: view.approval,
        lifecycle: view.lifecycle,
        source: view.source,
        world_ref: view.world_ref,
        scope: view.scope,
        valid_from: view
            .valid_from
            .map(|v| ts_from_engine(v, "valid_from"))
            .transpose()?,
        valid_to: view
            .valid_to
            .map(|v| ts_from_engine(v, "valid_to"))
            .transpose()?,
        salience: view.salience.map(f64::from),
        stale: view.stale,
    })
}

fn entity_ref_receipt_from_engine(receipt: oneiron::EntityRefReceipt) -> NapiEntityRefReceipt {
    NapiEntityRefReceipt {
        entity_ref: receipt.entity_ref,
        id_hex: receipt.id_hex,
        receipt_ref: receipt.receipt_ref,
    }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "f64→f32 edge-weight narrowing at the N-API boundary is intentional"
)]
fn structural_put_to_engine(input: &NapiStructuralPutInput) -> BoundaryResult<StructuralPutInput> {
    Ok(StructuralPutInput {
        id: input.id.clone(),
        kind: input.kind.clone(),
        body: input.body.clone(),
        text_fields: input.text_fields.as_ref().map(|fields| {
            fields
                .iter()
                .map(|field| TextIndexField {
                    field: field.field.clone(),
                    value: field.value.clone(),
                })
                .collect()
        }),
        edges: input.edges.as_ref().map(|edges| {
            edges
                .iter()
                .map(|edge| StructuralEdgeSpec {
                    edge_kind: edge.edge_kind.clone(),
                    target_ref: edge.target_ref.clone(),
                    weight: edge.weight.map(|w| w as f32),
                })
                .collect()
        }),
        occurred_at: ts_to_engine(input.occurred_at, "occurred_at")?,
        learned_at: ts_opt_to_engine(input.learned_at, "learned_at")?,
    })
}

// ── classes ─────────────────────────────────────────────────────────────

/// The vault bridge root: opens a vault and mints actor-scoped handles.
/// Carries NO write verbs itself (W3: construction is not authority).
#[napi]
pub struct VaultBridge {
    vault: Arc<Vault>,
}

#[napi]
impl VaultBridge {
    /// Opens (or creates) a vault at `path` with the device preset.
    #[napi(factory)]
    pub fn open(path: String, dimensions: Option<u32>) -> napi::Result<Self> {
        let mut config = VaultConfig::device();
        if let Some(dimensions) = dimensions {
            config.dimensions = dimensions as usize;
        }
        let vault = Vault::open(&path, config)
            .map_err(|e| boundary_error(format!("failed to open vault: {e}")))?;
        Ok(Self {
            vault: Arc::new(vault),
        })
    }

    /// Binds an actor scope from the pinned key grammar
    /// `"<actor_class>:<entity_ref>"` (`human|agent|system`). Malformed
    /// keys are typed errors — never a defaulted class.
    #[napi]
    pub fn as_actor(&self, actor_key: String) -> napi::Result<ActorScopedVault> {
        let (actor, actor_class) =
            parse_actor_key(&self.vault, &actor_key).map_err(facade_error)?;
        Ok(ActorScopedVault {
            vault: Arc::clone(&self.vault),
            actor_hex: actor.to_hex(),
            actor_class: actor_class as u8,
        })
    }
}

/// Actor-scoped facade handle: every memory verb lives here.
#[napi]
pub struct ActorScopedVault {
    vault: Arc<Vault>,
    actor_hex: String,
    actor_class: u8,
}

impl ActorScopedVault {
    pub(crate) fn facade(&self) -> napi::Result<Memory<'_>> {
        let actor = EntityId::from_hex(&self.actor_hex)
            .map_err(|e| boundary_error(format!("invalid bound actor id: {e}")))?;
        let actor_class = match self.actor_class {
            0 => oneiron::EdgeActorClass::Human,
            1 => oneiron::EdgeActorClass::Agent,
            2 => oneiron::EdgeActorClass::System,
            other => {
                return Err(boundary_error(format!("invalid bound actor class {other}")));
            }
        };
        Ok(self.vault.memory(actor, actor_class))
    }
}

#[napi]
impl ActorScopedVault {
    /// Witnesses one turn (create-or-get CONVERSATION/TURN + gated MESSAGE
    /// puts + edges + BM25 indexing, one atomic batch).
    ///
    /// Every MESSAGE clears the engine's approval-ceiling door (ONE-1686)
    /// inside that batch's transaction: the bound actor scope must carry
    /// authority for the envelope it presents, and a refusal on any message
    /// lands nothing at all — no message, turn, edge or text posting.
    #[napi]
    pub fn witness(&self, turn: NapiWitnessTurn) -> napi::Result<NapiWitnessReceipt> {
        let engine_turn = witness_turn_to_engine(&turn).map_err(boundary_error)?;
        let receipt = self.facade()?.witness(&engine_turn).map_err(facade_error)?;
        Ok(NapiWitnessReceipt {
            turn_short_id: receipt.turn_short_id,
            message_short_ids: receipt.message_short_ids,
            receipt_ref: receipt.receipt_ref,
        })
    }

    /// Commits claims, one individually gated write per element; rejected
    /// elements come back with approval `rejected` and persist nothing.
    #[napi]
    pub fn commit(&self, claims: Vec<NapiClaimInput>) -> napi::Result<Vec<NapiCommitReceipt>> {
        let mut engine_claims = Vec::with_capacity(claims.len());
        for claim in &claims {
            engine_claims.push(claim_input_to_engine(claim).map_err(boundary_error)?);
        }
        let receipts = self
            .facade()?
            .commit(&engine_claims)
            .map_err(facade_error)?;
        Ok(receipts
            .into_iter()
            .map(commit_receipt_from_engine)
            .collect())
    }

    /// Commits one claim with single-cardinality auto-supersede.
    #[napi]
    pub fn claim_upsert(&self, claim: NapiClaimInput) -> napi::Result<NapiCommitReceipt> {
        let engine_claim = claim_input_to_engine(&claim).map_err(boundary_error)?;
        let receipt = self
            .facade()?
            .claim_upsert(&engine_claim)
            .map_err(facade_error)?;
        Ok(commit_receipt_from_engine(receipt))
    }

    /// Typed convenience: `remember` = claimUpsert with auto-supersede.
    /// NO natural-language parsing on this surface (EF-126 out of chain).
    #[napi]
    pub fn remember(&self, claim: NapiClaimInput) -> napi::Result<NapiCommitReceipt> {
        self.claim_upsert(claim)
    }

    /// Retracts an active claim by ref.
    #[napi]
    pub fn claim_retract(&self, claim_ref: String) -> napi::Result<NapiCommitReceipt> {
        let receipt = self
            .facade()?
            .claim_retract(&claim_ref)
            .map_err(facade_error)?;
        Ok(commit_receipt_from_engine(receipt))
    }

    /// Typed convenience: retract-with-receipt by short ref or
    /// `{subjectRef, predicate}` selector (all active matches retract).
    #[napi]
    pub fn forget(&self, selector: NapiForgetSelector) -> napi::Result<Vec<NapiCommitReceipt>> {
        let facade = self.facade()?;
        if let Some(short_ref) = &selector.short_ref {
            let receipt = facade.claim_retract(short_ref).map_err(facade_error)?;
            return Ok(vec![commit_receipt_from_engine(receipt)]);
        }
        let (Some(subject_ref), Some(predicate)) = (&selector.subject_ref, &selector.predicate)
        else {
            return Err(boundary_error(
                "forget selector needs shortRef, or subjectRef + predicate".to_owned(),
            ));
        };
        let receipts =
            forget_active_matches(&facade, subject_ref, predicate).map_err(facade_error)?;
        Ok(receipts
            .into_iter()
            .map(commit_receipt_from_engine)
            .collect())
    }

    /// Lists claims by subject/predicate/lifecycle, bounded by `limit`.
    #[napi]
    pub fn claim_list(&self, filter: NapiClaimListFilter) -> napi::Result<Vec<NapiClaimView>> {
        let views = self
            .facade()?
            .claim_list(&ClaimListFilter {
                subject_ref: filter.subject_ref,
                predicate: filter.predicate,
                lifecycle: filter.lifecycle,
                limit: filter.limit as usize,
            })
            .map_err(facade_error)?;
        views
            .into_iter()
            .map(|view| claim_view_from_engine(view).map_err(boundary_error))
            .collect()
    }

    /// Supersession timeline for one claim, oldest first.
    #[napi]
    pub fn claim_history(&self, claim_ref: String) -> napi::Result<Vec<NapiClaimView>> {
        let views = self
            .facade()?
            .claim_history(&claim_ref)
            .map_err(facade_error)?;
        views
            .into_iter()
            .map(|view| claim_view_from_engine(view).map_err(boundary_error))
            .collect()
    }

    /// Deletes an entity under a NAMED reason (`user_delete` |
    /// `user_hard_delete` | `gdpr_delete` | `policy_delete`). There is no
    /// bool-delete on this surface.
    #[napi]
    pub fn safe_delete(
        &self,
        entity_ref: String,
        reason: String,
    ) -> napi::Result<NapiDeleteReceipt> {
        let reason = SafeDeleteReason::parse(&reason).ok_or_else(|| {
            boundary_error(format!(
                "unknown delete reason {reason:?}; use user_delete, user_hard_delete, gdpr_delete, or policy_delete"
            ))
        })?;
        let receipt = self
            .facade()?
            .safe_delete(&entity_ref, reason)
            .map_err(facade_error)?;
        Ok(NapiDeleteReceipt {
            existed: receipt.existed,
            reason: receipt.reason,
            receipt_ref: receipt.receipt_ref,
        })
    }

    /// Gated writes parked for consent.
    #[napi]
    pub fn pending_writes(&self, limit: u32) -> napi::Result<Vec<NapiPendingWrite>> {
        let records = self
            .facade()?
            .pending_writes(limit as usize)
            .map_err(facade_error)?;
        records
            .into_iter()
            .map(|record| {
                Ok(NapiPendingWrite {
                    claim_ref: record.claim_ref,
                    decision_ref: record.decision_ref,
                    created_at: ts_from_engine(record.created_at, "created_at")
                        .map_err(boundary_error)?,
                    reason_codes: record.reason_codes,
                    dreamer_run_id: record.dreamer_run_id,
                })
            })
            .collect()
    }

    /// Gate decision receipts.
    #[napi]
    pub fn receipts(&self, limit: u32) -> napi::Result<Vec<NapiGateReceipt>> {
        let records = self
            .facade()?
            .receipts(limit as usize)
            .map_err(facade_error)?;
        records
            .into_iter()
            .map(|record| {
                Ok(NapiGateReceipt {
                    receipt_ref: record.receipt_ref,
                    outcome: record.outcome,
                    created_at: ts_from_engine(record.created_at, "created_at")
                        .map_err(boundary_error)?,
                    reason_codes: record.reason_codes,
                    actor_class: record.actor_class,
                    actor_ref: record.actor_ref,
                    content_kind: record.content_kind,
                    claim_ref: record.claim_ref,
                })
            })
            .collect()
    }

    /// Hydrates short refs (or hex ids) to full entity views.
    #[napi]
    pub fn hydrate(&self, refs: Vec<String>) -> napi::Result<Vec<NapiEntityView>> {
        let views = self.facade()?.hydrate(&refs).map_err(facade_error)?;
        views
            .into_iter()
            .map(|view| entity_view_from_engine(view).map_err(boundary_error))
            .collect()
    }

    /// Reads one entity; `null` when absent.
    #[napi]
    pub fn get_entity(&self, entity_ref: String) -> napi::Result<Option<NapiEntityView>> {
        let view = self
            .facade()?
            .get_entity(&entity_ref)
            .map_err(facade_error)?;
        view.map(|v| entity_view_from_engine(v).map_err(boundary_error))
            .transpose()
    }

    /// Structural CREATE carrying text-index fields and edges (B2).
    ///
    /// Create-only (ONE-1889): an id that already holds a stored entity is
    /// refused by the engine, whatever its stored kind. The typed refusal
    /// propagates unchanged — it is never translated into success and never
    /// retried as an overwrite. Mutating a stored entity is its typed verb's
    /// job; there is no force or overwrite option here.
    #[napi]
    pub fn put_structural(
        &self,
        input: NapiStructuralPutInput,
    ) -> napi::Result<NapiEntityRefReceipt> {
        let engine_input = structural_put_to_engine(&input).map_err(boundary_error)?;
        let receipt = self
            .facade()?
            .put_structural(&engine_input)
            .map_err(facade_error)?;
        Ok(entity_ref_receipt_from_engine(receipt))
    }

    /// Appends one habit check-in child (pinned `role` key stamped by the
    /// facade; `ChildOf` edge written by the pack contract).
    #[napi]
    pub fn put_habit_checkin(
        &self,
        input: NapiHabitCheckinInput,
    ) -> napi::Result<NapiEntityRefReceipt> {
        let engine_input = HabitCheckinInput {
            habit_ref: input.habit_ref,
            id: input.id,
            data: input.data,
            occurred_at: ts_to_engine(input.occurred_at, "occurred_at").map_err(boundary_error)?,
            learned_at: ts_opt_to_engine(input.learned_at, "learned_at").map_err(boundary_error)?,
        };
        let receipt = self
            .facade()?
            .put_habit_checkin(&engine_input)
            .map_err(facade_error)?;
        Ok(entity_ref_receipt_from_engine(receipt))
    }

    /// Registers a companion persona record (personal scope), optionally
    /// retiring it (migration of inactive companions).
    #[napi]
    pub fn put_companion_record(
        &self,
        input: NapiCompanionRecordInput,
    ) -> napi::Result<NapiEntityRefReceipt> {
        let engine_input = CompanionRecordInput {
            id: input.id,
            owner_ref: input.owner_ref,
            persona_ref: input.persona_ref,
            value: input.value,
            source: input.source,
            retired_at: ts_opt_to_engine(input.retired_at, "retired_at").map_err(boundary_error)?,
            learned_at: ts_to_engine(input.learned_at, "learned_at").map_err(boundary_error)?,
        };
        let receipt = self
            .facade()?
            .put_companion_record(&engine_input)
            .map_err(facade_error)?;
        Ok(entity_ref_receipt_from_engine(receipt))
    }

    /// Admits one imported-evidence claim through the registered ingest
    /// source's trust ceiling (B1a; unknown sources fail closed).
    #[napi]
    pub fn admit_imported_claim(
        &self,
        input: NapiAdmitImportedClaimInput,
    ) -> napi::Result<NapiCommitReceipt> {
        let engine_input = AdmitImportedClaimInput {
            source_id: input.source_id,
            source_record_id: input.source_record_id,
            id: input.id,
            subject_ref: input.subject_ref,
            predicate: input.predicate,
            value: input.value,
            occurred_at: ts_to_engine(input.occurred_at, "occurred_at").map_err(boundary_error)?,
            learned_at: ts_opt_to_engine(input.learned_at, "learned_at").map_err(boundary_error)?,
        };
        let receipt = self
            .facade()?
            .admit_imported_claim(&engine_input)
            .map_err(facade_error)?;
        Ok(commit_receipt_from_engine(receipt))
    }

    /// Registers a blob artifact (B8 blob door).
    #[napi]
    pub fn put_blob_artifact(
        &self,
        input: NapiBlobArtifactInput,
    ) -> napi::Result<NapiEntityRefReceipt> {
        let engine_input = BlobArtifactInput {
            id: input.id,
            name: input.name,
            media_type: input.media_type,
            occurred_at: ts_to_engine(input.occurred_at, "occurred_at").map_err(boundary_error)?,
            learned_at: ts_opt_to_engine(input.learned_at, "learned_at").map_err(boundary_error)?,
        };
        let receipt = self
            .facade()?
            .put_blob_artifact(&engine_input)
            .map_err(facade_error)?;
        Ok(entity_ref_receipt_from_engine(receipt))
    }

    /// Appends one content-addressed blob version. Content crosses as a
    /// standard base64 string (buffer-free S1 ABI, B8).
    #[napi]
    pub fn append_blob_version(
        &self,
        artifact_ref: String,
        bytes_base64: String,
        run_ref: Option<String>,
        occurred_at: i64,
        learned_at: Option<i64>,
    ) -> napi::Result<NapiBlobVersionView> {
        let bytes = decode_blob_base64(&bytes_base64).map_err(boundary_error)?;
        let view = self
            .facade()?
            .append_blob_version(
                &artifact_ref,
                &bytes,
                run_ref.as_deref(),
                ts_to_engine(occurred_at, "occurred_at").map_err(boundary_error)?,
                ts_opt_to_engine(learned_at, "learned_at").map_err(boundary_error)?,
            )
            .map_err(facade_error)?;
        Ok(NapiBlobVersionView {
            artifact_ref: view.artifact_ref,
            version: ts_from_engine(view.version, "version").map_err(boundary_error)?,
            content_hash_hex: view.content_hash_hex,
            claim_ref: view.claim_ref,
            created_at: ts_from_engine(view.created_at, "created_at").map_err(boundary_error)?,
        })
    }

    /// BM25 text query over the engine index. The standard N-API query
    /// (8 KiB) and result (1,000) caps apply.
    #[napi]
    pub fn query_bm25(&self, query: String, limit: u32) -> napi::Result<Vec<NapiLexicalHit>> {
        crate::validate_query_len(&query).map_err(boundary_error)?;
        let limit = crate::parse_search_limit(limit).map_err(boundary_error)?;
        let hits = self
            .facade()?
            .query_bm25(&query, limit)
            .map_err(facade_error)?;
        Ok(hits
            .into_iter()
            .map(|hit| NapiLexicalHit {
                short_id: hit.short_id,
                kind: hit.kind,
                score: f64::from(hit.score),
                snippet: hit.snippet,
            })
            .collect())
    }

    /// Weighted-edge neighborhood, filtered engine-side.
    #[napi]
    pub fn neighbors(
        &self,
        entity_ref: String,
        opts: NapiNeighborOpts,
    ) -> napi::Result<Vec<NapiNeighborHit>> {
        let hits = self
            .facade()?
            .neighbors(
                &entity_ref,
                &NeighborOpts {
                    edge_kind: opts.edge_kind,
                    min_weight: opts
                        .min_weight
                        .map(narrow_to_f32)
                        .transpose()
                        .map_err(boundary_error)?,
                    limit: opts.limit as usize,
                },
            )
            .map_err(facade_error)?;
        Ok(hits
            .into_iter()
            .map(|hit| NapiNeighborHit {
                short_id: hit.short_id,
                kind: hit.kind,
                edge_kind: hit.edge_kind,
                weight: f64::from(hit.weight),
                direction: hit.direction,
            })
            .collect())
    }

    /// Effort-dialed retrieval into an S6 memory pack. `effort` is
    /// `minimal` | `standard` | `deep`; no lease handle exists on this
    /// surface yet (OF-131), so `deep` returns the typed `LEASE_REQUIRED`
    /// error until the LLMB chain lands the issuer.
    #[napi]
    pub fn recall(
        &self,
        query: String,
        effort: String,
        scope: Option<NapiRecallScope>,
        limit: u32,
        format: Option<String>,
    ) -> napi::Result<NapiMemoryPack> {
        crate::validate_query_len(&query).map_err(boundary_error)?;
        let limit = crate::parse_search_limit(limit).map_err(boundary_error)?;
        let effort = Effort::parse(&effort).ok_or_else(|| {
            boundary_error(format!(
                "unknown effort {effort:?}; use minimal, standard, or deep"
            ))
        })?;
        let scope = scope.map_or_else(RecallScope::default, |scope| RecallScope {
            world_ref: scope.world_ref,
            facet: scope.facet,
        });
        let pack = self
            .facade()?
            .recall(&query, effort, &scope, limit, format.as_deref(), None)
            .map_err(facade_error)?;
        Ok(NapiMemoryPack {
            items: pack
                .items
                .into_iter()
                .map(|item| NapiMemoryItem {
                    short_id: item.short_id,
                    kind: item.kind,
                    predicate: item.predicate,
                    value_text: item.value_text,
                    confidence: f64::from(item.confidence),
                    hedge_bucket: item.hedge_bucket,
                    provenance: NapiMemoryProvenance {
                        source: item.provenance.source,
                        source_revision_ids: item.provenance.source_revision_ids,
                        evidence_turn_ids: item.provenance.evidence_turn_ids,
                    },
                    world: item.world,
                    facet: item.facet,
                    salience: item.salience.map(f64::from),
                })
                .collect(),
            scope_honesty: NapiScopeHonesty {
                out_of_scope_worlds: pack.scope_honesty.out_of_scope_worlds,
            },
            retrieval_meta: NapiRetrievalMeta {
                sparse: pack.retrieval_meta.sparse,
                total_candidates: ts_from_engine(
                    pack.retrieval_meta.total_candidates,
                    "total_candidates",
                )
                .map_err(boundary_error)?,
                claims_returned: ts_from_engine(
                    pack.retrieval_meta.claims_returned,
                    "claims_returned",
                )
                .map_err(boundary_error)?,
                deep_pending: pack.retrieval_meta.deep_pending,
            },
            pack_version: pack.pack_version,
            rendered: pack.rendered,
        })
    }

    /// Enqueues one Dreamer consolidation job; long work returns a job
    /// ref to poll (W2 — no async FFI).
    #[napi]
    pub fn enqueue_consolidation(
        &self,
        input: NapiConsolidationJobInput,
    ) -> napi::Result<NapiDreamerJobRef> {
        let engine_input = ConsolidationAttemptInput {
            scope: input.scope,
            input: input.input,
            run_id: input.run_id,
            dedupe_key: input.dedupe_key,
            now: ts_opt_to_engine(input.now, "now").map_err(boundary_error)?,
        };
        let job = self
            .facade()?
            .enqueue_consolidation(&engine_input)
            .map_err(facade_error)?;
        Ok(NapiDreamerJobRef {
            job_ref: job.job_ref,
            state: job.state,
            existing: job.existing,
        })
    }

    /// Polls one Dreamer job's status; `null` for unknown job refs.
    #[napi]
    pub fn dreamer_job_status(&self, job_ref: String) -> napi::Result<Option<NapiDreamerJobView>> {
        let view = self
            .facade()?
            .dreamer_attempt_status(&job_ref)
            .map_err(facade_error)?;
        view.map(|view| {
            Ok(NapiDreamerJobView {
                job_ref: view.job_ref,
                state: view.state,
                kind: view.kind,
                lease_owner: view.lease_owner,
                attempt_count: view.attempt_count,
                run_id: view.run_id,
                last_error: view.last_error,
                created_at: ts_from_engine(view.created_at, "created_at")
                    .map_err(boundary_error)?,
                updated_at: ts_from_engine(view.updated_at, "updated_at")
                    .map_err(boundary_error)?,
            })
        })
        .transpose()
    }

    /// Seed-write entry point (EF-301 consumer): every element is FORCED
    /// proposed regardless of source, individually gated, with receipts.
    #[napi]
    pub fn seed_claims(&self, claims: Vec<NapiClaimInput>) -> napi::Result<Vec<NapiCommitReceipt>> {
        let mut engine_claims = Vec::with_capacity(claims.len());
        for claim in &claims {
            engine_claims.push(claim_input_to_engine(claim).map_err(boundary_error)?);
        }
        let receipts = self
            .facade()?
            .seed_claims(&engine_claims)
            .map_err(facade_error)?;
        Ok(receipts
            .into_iter()
            .map(commit_receipt_from_engine)
            .collect())
    }

    /// Schedules one outbound intent through the OF-327 chokepoint: durable
    /// idempotent enqueue + gate check under a Hold window. The bridge
    /// never delivers; receipts surface via `receipts()`.
    #[napi]
    pub fn schedule_outbound(
        &self,
        draft: NapiOutboundDraftInput,
    ) -> napi::Result<NapiOutboundIntentReceipt> {
        // The clock-authority conversion runs FIRST and fails closed: an
        // invalid offset/label/level is rejected at the boundary, before any
        // TASK or attempt row can be written.
        let schedule_context =
            outbound_schedule_context_to_engine(&draft).map_err(boundary_error)?;
        let engine_draft = OutboundDraftInput {
            verb: draft.verb,
            channel: draft.channel,
            target: draft.target,
            on_behalf_of: draft.on_behalf_of,
            content_ref: draft.content_ref,
            idempotency_key: draft.idempotency_key,
            dedupe_key: draft.dedupe_key,
            trigger: draft.trigger,
            trigger_ref: draft.trigger_ref,
            job_ref: draft.job_ref,
            occurred_at: ts_opt_to_engine(draft.occurred_at, "occurred_at")
                .map_err(boundary_error)?,
        };
        let receipt = self
            .facade()?
            .schedule_outbound_with_context(&engine_draft, &schedule_context)
            .map_err(facade_error)?;
        Ok(NapiOutboundIntentReceipt {
            intent_ref: receipt.intent_ref,
            outcome: receipt.outcome,
            gate_outcome: receipt.gate_outcome,
            gate_decision_ref: receipt.gate_decision_ref,
            gate_reason_codes: receipt.gate_reason_codes,
            deduped: receipt.deduped,
        })
    }

    /// Reads one calendar EVENT under the bound actor's read scope; `null`
    /// when the id is unknown, unreadable, or not a calendar EVENT.
    #[napi]
    pub fn calendar_read(&self, event_ref: String) -> napi::Result<Option<NapiCalendarEventView>> {
        self.facade()?
            .calendar_read(&CalendarReadRequest { event_ref })
            .map_err(facade_error)?
            .map(calendar_event_from_engine)
            .transpose()
            .map_err(boundary_error)
    }

    /// Searches calendar EVENTs under the bound actor's read scope.
    #[napi]
    pub fn calendar_search(
        &self,
        request: NapiCalendarSearchRequest,
    ) -> napi::Result<Vec<NapiCalendarEventView>> {
        let engine_request = CalendarSearchRequest {
            calendars: calendar_selectors_to_engine(request.calendars),
            range: calendar_range_to_engine(request.range)
                .map_err(boundary_error)?
                .map(|range| CalendarRangeDto {
                    start: range.start,
                    end: range.end,
                }),
            text: request.text,
            limit: request.limit,
        };
        self.facade()?
            .calendar_search(&engine_request)
            .map_err(facade_error)?
            .into_iter()
            .map(calendar_event_from_engine)
            .collect::<BoundaryResult<Vec<_>>>()
            .map_err(boundary_error)
    }

    /// Projects busy-only occupancy over an inclusive UTC window.
    #[napi]
    pub fn calendar_freebusy(
        &self,
        calendars: Option<Vec<NapiCalendarSel>>,
        range: NapiCalendarRange,
    ) -> napi::Result<Vec<NapiCalendarFreebusyInterval>> {
        let engine_range = calendar_range_to_engine(Some(range))
            .map_err(boundary_error)?
            .ok_or_else(|| boundary_error("range is required".to_owned()))?;
        self.facade()?
            .calendar_freebusy(&calendar_selectors_to_engine(calendars), engine_range)
            .map_err(facade_error)?
            .into_iter()
            .map(|interval| {
                Ok(NapiCalendarFreebusyInterval {
                    start_utc: ts_from_engine(interval.start_utc, "start_utc")?,
                    end_utc: ts_from_engine(interval.end_utc, "end_utc")?,
                })
            })
            .collect::<BoundaryResult<Vec<_>>>()
            .map_err(boundary_error)
    }

    /// Schedules one calendar invite through the ordinary outbound gate. The
    /// bridge never delivers; receipts surface via `receipts()`.
    #[napi]
    pub fn calendar_invite(
        &self,
        input: NapiCalendarInviteInput,
    ) -> napi::Result<NapiOutboundIntentReceipt> {
        let method = CalendarInviteSurfaceMethod::parse(&input.method).ok_or_else(|| {
            boundary_error(format!(
                "method must be one of REQUEST, CANCEL; got {:?}",
                input.method
            ))
        })?;
        let receipt = self
            .facade()?
            .calendar_invite(&CalendarInviteSurfaceInput {
                method,
                uid: input.uid,
                sequence: input.sequence,
                ics_blob_ref: input.ics_blob_ref,
                recipient: input.recipient,
            })
            .map_err(facade_error)?;
        Ok(NapiOutboundIntentReceipt {
            intent_ref: receipt.intent_ref,
            outcome: receipt.outcome,
            gate_outcome: receipt.gate_outcome,
            gate_decision_ref: receipt.gate_decision_ref,
            gate_reason_codes: receipt.gate_reason_codes,
            deduped: receipt.deduped,
        })
    }

    /// Reads one blob version's bytes (hash-verified engine-side) as a
    /// standard base64 string; `null` when the version does not exist.
    #[napi]
    pub fn read_blob_version(
        &self,
        artifact_ref: String,
        version: i64,
    ) -> napi::Result<Option<String>> {
        let bytes = self
            .facade()?
            .read_blob_version(
                &artifact_ref,
                ts_to_engine(version, "version").map_err(boundary_error)?,
            )
            .map_err(facade_error)?;
        Ok(bytes.map(|bytes| BASE64_STANDARD.encode(bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reason<T: std::fmt::Debug>(result: BoundaryResult<T>) -> String {
        result.expect_err("expected N-API boundary error")
    }

    fn tz_draft(
        utc_offset_minutes: Option<f64>,
        iana_timezone: Option<&str>,
    ) -> NapiOutboundDraftInput {
        NapiOutboundDraftInput {
            verb: "send".to_owned(),
            channel: "email".to_owned(),
            target: "counterparty:napi".to_owned(),
            on_behalf_of: None,
            content_ref: None,
            idempotency_key: None,
            dedupe_key: None,
            trigger: "agent_immediate".to_owned(),
            trigger_ref: "session:napi".to_owned(),
            job_ref: None,
            occurred_at: None,
            utc_offset_minutes,
            iana_timezone: iana_timezone.map(str::to_owned),
            human_explicit_instant: None,
            apns_interruption_level: None,
            resolved_level: None,
        }
    }

    /// ONE-1768 done-means (`napi_schedule_outbound_forwards_timezone_context`):
    /// omitted fields preserve hostless behavior, valid fields convert, and
    /// every invalid clock authority is rejected AT THE BOUNDARY — before the
    /// draft can reach the facade and write a TASK or attempt.
    #[test]
    fn napi_schedule_context_conversion_fails_closed_on_invalid_clock_authority() {
        // Omitted ⇒ hostless: no offset, no label, no promotion.
        let hostless = outbound_schedule_context_to_engine(&tz_draft(None, None))
            .expect("omitted timezone fields stay hostless");
        assert_eq!(hostless.utc_offset_minutes, None);
        assert_eq!(hostless.iana_timezone, None);
        assert!(!hostless.human_explicit_instant);
        assert_eq!(hostless.apns_interruption_level, None);
        assert_eq!(hostless.resolved_level, None);

        // Valid offset + label convert intact.
        let valid = outbound_schedule_context_to_engine(&tz_draft(
            Some(-480.0),
            Some("America/Los_Angeles"),
        ))
        .expect("valid clock authority converts");
        assert_eq!(valid.utc_offset_minutes, Some(-480));
        assert_eq!(valid.iana_timezone.as_deref(), Some("America/Los_Angeles"));

        // IANA label without an offset is unusable.
        let err = reason(outbound_schedule_context_to_engine(&tz_draft(
            None,
            Some("Europe/Paris"),
        )));
        assert!(
            err.contains("iana_timezone requires utc_offset_minutes"),
            "got: {err}"
        );

        // Range is inclusive at both edges and closed just outside them.
        for edge in [-840.0, 840.0] {
            assert!(outbound_schedule_context_to_engine(&tz_draft(Some(edge), None)).is_ok());
        }
        for outside in [-841.0, 841.0, 1_440.0] {
            let err = reason(outbound_schedule_context_to_engine(&tz_draft(
                Some(outside),
                None,
            )));
            assert!(err.contains("-840..=840"), "got: {err}");
        }
        // Non-integer and non-finite offsets are not silently truncated.
        for bad in [30.5, f64::NAN, f64::INFINITY] {
            let err = reason(outbound_schedule_context_to_engine(&tz_draft(
                Some(bad),
                None,
            )));
            assert!(err.contains("finite integer"), "got: {err}");
        }

        // Blank and control-bearing labels are rejected.
        for bad_label in ["", "   ", "Europe/\u{7}Paris", "Europe/Paris\n"] {
            let err = reason(outbound_schedule_context_to_engine(&tz_draft(
                Some(60.0),
                Some(bad_label),
            )));
            assert!(err.contains("non-blank"), "{bad_label:?} got: {err}");
        }

        // Unknown enum labels fail closed rather than defaulting.
        let mut unknown_apns = tz_draft(Some(0.0), None);
        unknown_apns.apns_interruption_level = Some("shout".to_owned());
        assert!(
            reason(outbound_schedule_context_to_engine(&unknown_apns))
                .contains("unknown APNs interruption level")
        );

        let mut unknown_level = tz_draft(Some(0.0), None);
        unknown_level.resolved_level = Some("whisper".to_owned());
        assert!(
            reason(outbound_schedule_context_to_engine(&unknown_level))
                .contains("unknown resolved level")
        );

        // Known enum labels convert.
        let mut resolved = tz_draft(Some(0.0), None);
        resolved.resolved_level = Some("plain_chat".to_owned());
        resolved.human_explicit_instant = Some(true);
        let resolved =
            outbound_schedule_context_to_engine(&resolved).expect("known labels convert");
        assert!(resolved.human_explicit_instant);
        assert_eq!(
            resolved.resolved_level,
            Some(oneiron::delivery_window::DeliveryWindowResolvedLevel::PlainChat)
        );
    }

    /// F4: the blob base64 input is length-bounded BEFORE decode
    /// allocation; an oversized input is rejected without allocating the
    /// output vector.
    #[test]
    fn boundary_rejects_oversized_blob_base64_before_decoding() {
        let oversized = "A".repeat(MAX_NAPI_BLOB_BASE64_LEN + 8);
        let err = reason(decode_blob_base64(&oversized));
        assert!(err.contains("ceiling"), "got: {err}");

        assert_eq!(decode_blob_base64("aGVsbG8=").unwrap(), b"hello");
        assert!(decode_blob_base64("not base64!").is_err());
    }

    /// N1: queryBm25/recall honor the standard N-API query and result
    /// caps (helpers shared with the systems layer in lib.rs).
    #[test]
    fn boundary_applies_search_caps_to_query_verbs() {
        let oversized_query = "q".repeat(crate::MAX_NAPI_QUERY_BYTES + 1);
        let err = reason(crate::validate_query_len(&oversized_query));
        assert!(err.contains("query must be <="), "got: {err}");

        let err = reason(crate::parse_search_limit(crate::MAX_NAPI_SEARCH_LIMIT + 1));
        assert!(err.contains("limit must be <="), "got: {err}");
        assert_eq!(
            crate::parse_search_limit(crate::MAX_NAPI_SEARCH_LIMIT).unwrap(),
            crate::MAX_NAPI_SEARCH_LIMIT as usize
        );
    }

    #[test]
    fn boundary_rejects_negative_timestamps() {
        assert_eq!(ts_to_engine(0, "t").unwrap(), 0);
        assert_eq!(ts_to_engine(i64::MAX, "t").unwrap(), i64::MAX as u64);
        assert_eq!(
            reason(ts_to_engine(-1, "occurred_at")),
            "occurred_at must be a non-negative Unix timestamp"
        );
        assert_eq!(ts_opt_to_engine(None, "t").unwrap(), None);
    }

    #[test]
    fn boundary_rejects_unknown_witness_author() {
        let turn = NapiWitnessTurn {
            conversation_ref: "00".repeat(16),
            turn_ref: None,
            messages: vec![NapiWitnessMessage {
                id: None,
                author: "assistant".to_owned(),
                message_type: "dialogue".to_owned(),
                content: "hi".to_owned(),
                metadata: None,
                is_visible: None,
                order: 0,
            }],
            occurred_at: 100,
        };
        let err = reason(witness_turn_to_engine(&turn));
        assert!(err.contains("user, companion, system"), "got: {err}");
    }

    /// ONE-1686: `metadata` that is not a JSON object is refused where the host
    /// can read the reason. The engine refuses it too — this only makes the
    /// message about the field the host actually typed.
    #[test]
    fn boundary_rejects_non_object_witness_metadata() {
        let turn = NapiWitnessTurn {
            conversation_ref: "00".repeat(16),
            turn_ref: None,
            messages: vec![NapiWitnessMessage {
                id: None,
                author: "user".to_owned(),
                message_type: "dialogue".to_owned(),
                content: "hi".to_owned(),
                metadata: Some(serde_json::json!(["side", "channel"])),
                is_visible: None,
                order: 0,
            }],
            occurred_at: 100,
        };
        let err = reason(witness_turn_to_engine(&turn));
        assert!(err.contains("metadata must be a JSON object"), "got: {err}");
    }

    /// ONE-1686 adversarial: direct N-API ingress is NOT a bypass.
    ///
    /// The host DTO carries `author: "system"`, `isVisible: false` and metadata
    /// that restates an envelope axis — a shape the conversion layer happily
    /// converts, because the conversion layer is not the gate. The engine
    /// witness door refuses it under a `human:` actor scope and leaves nothing
    /// behind, while the same scope's ordinary user row lands.
    ///
    /// Exercises the engine-typed helper directly so the test never links the
    /// N-API runtime, exactly as the forget regression above does.
    #[test]
    fn napi_witness_ingress_cannot_smuggle_a_system_row_past_the_engine_ceiling() {
        use oneiron::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON};

        let dir = unique_vault_dir("witness-ceiling");
        let path = dir.to_str().expect("utf8 path").to_owned();
        let actor = EntityId::from_bytes([0x51; 16]).expect("actor id");
        let conversation = EntityId::from_bytes([0x52; 16]).expect("conversation id");

        {
            let vault = Vault::open(&path, VaultConfig::device()).expect("open vault");
            let time = oneiron::TimeRange { start: 1, end: 1 };
            vault
                .put_entity(&actor, ENTITY_TYPE_PERSON, time, 1, b"actor")
                .expect("put actor");
            let facade = vault.memory(actor, oneiron::EdgeActorClass::Human);

            let napi_message = |author: &str, order: u32| NapiWitnessMessage {
                id: None,
                author: author.to_owned(),
                message_type: "dialogue".to_owned(),
                content: format!("row-{order}"),
                metadata: None,
                is_visible: None,
                order,
            };

            // The honest turn crosses the boundary and lands.
            let honest = witness_turn_to_engine(&NapiWitnessTurn {
                conversation_ref: conversation.to_hex(),
                turn_ref: None,
                messages: vec![napi_message("user", 0)],
                occurred_at: 700,
            })
            .expect("an ordinary user turn converts");
            facade.witness(&honest).expect("and lands");

            // The hostile turn converts just as happily — and the ENGINE stops
            // it. The conversion layer is a convenience, not the ceiling.
            let hostile = witness_turn_to_engine(&NapiWitnessTurn {
                conversation_ref: conversation.to_hex(),
                turn_ref: None,
                messages: vec![
                    napi_message("user", 0),
                    NapiWitnessMessage {
                        is_visible: Some(false),
                        metadata: Some(serde_json::json!({"tool": "shell"})),
                        ..napi_message("system", 1)
                    },
                ],
                occurred_at: 701,
            })
            .expect("the boundary converts the hostile shape");
            let err = facade
                .witness(&hostile)
                .expect_err("the engine ceiling refuses it");
            assert_eq!(err.code, oneiron::MEMORY_CODE_FORBIDDEN, "{err:?}");
            assert!(
                err.message
                    .contains("gate.deny.witness_message.author_not_authorized"),
                "got: {}",
                err.message
            );

            // The metadata side channel is refused at the same door, for an
            // envelope whose AUTHORSHIP is beyond reproach: a nested key that
            // restates an envelope axis is a second, ungated copy of it.
            let side_channel = witness_turn_to_engine(&NapiWitnessTurn {
                conversation_ref: conversation.to_hex(),
                turn_ref: None,
                messages: vec![NapiWitnessMessage {
                    metadata: Some(serde_json::json!({"trace": {"author": "system"}})),
                    ..napi_message("user", 0)
                }],
                occurred_at: 702,
            })
            .expect("the boundary converts the side-channel shape");
            let err = facade
                .witness(&side_channel)
                .expect_err("metadata may not restate an envelope axis");
            assert!(
                err.message
                    .contains("gate.deny.witness_message.malformed_envelope"),
                "got: {}",
                err.message
            );

            assert_eq!(
                vault
                    .entities_by_type(ENTITY_TYPE_MESSAGE)
                    .expect("messages")
                    .len(),
                1,
                "only the honest row survives; the refused batch landed nothing"
            );
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    /// #482c: a non-finite `minWeight` is rejected at the boundary. NaN would
    /// otherwise disable the engine filter silently (every `weight < NaN` is
    /// false) and ±Inf would over-apply it.
    /// N-API parity: the bridge DTOs mirror the engine calendar DTOs field for
    /// field, with the same meanings and the same EntityId encoding (hex, only
    /// where an entity ref is part of the external schema at all).
    #[test]
    fn calendar_bridge_dtos_mirror_the_engine_surface() {
        let engine = CalendarEventView {
            event_ref: "44444444444444444444444444444444".to_owned(),
            name: Some("Design review".to_owned()),
            start_utc: Some(1_000),
            end_utc: Some(1_099),
            calendar_systems: vec!["google".to_owned()],
            blocks_time: true,
        };
        let bridged = calendar_event_from_engine(engine.clone()).expect("event crosses");
        assert_eq!(bridged.event_ref, engine.event_ref);
        assert_eq!(bridged.name, engine.name);
        assert_eq!(bridged.start_utc, Some(1_000));
        assert_eq!(bridged.end_utc, Some(1_099));
        assert_eq!(bridged.calendar_systems, engine.calendar_systems);
        assert!(bridged.blocks_time);

        // An unanchored EVENT stays unanchored rather than becoming epoch zero.
        let unanchored = calendar_event_from_engine(CalendarEventView {
            start_utc: None,
            end_utc: None,
            ..engine
        })
        .expect("unanchored event crosses");
        assert_eq!(unanchored.start_utc, None);
        assert_eq!(unanchored.end_utc, None);

        // The freebusy interval type carries occupancy only — there is no field
        // on this side of the bridge that could hold the internal source ref.
        let interval = NapiCalendarFreebusyInterval {
            start_utc: 1_000,
            end_utc: 1_100,
        };
        assert_eq!((interval.start_utc, interval.end_utc), (1_000, 1_100));

        // Selectors and ranges convert without inventing values.
        assert!(calendar_selectors_to_engine(None).is_empty());
        assert_eq!(
            calendar_selectors_to_engine(Some(vec![NapiCalendarSel {
                system: Some("google".to_owned()),
            }]))[0]
                .system
                .as_deref(),
            Some("google")
        );
        assert_eq!(
            calendar_range_to_engine(Some(NapiCalendarRange { start: 5, end: 9 })).expect("range"),
            Some(TimeRange { start: 5, end: 9 })
        );
        assert!(
            calendar_range_to_engine(Some(NapiCalendarRange { start: -1, end: 9 })).is_err(),
            "a negative bridge timestamp is a typed rejection, never a wrap"
        );

        // The invite method stays a closed set across the boundary.
        assert_eq!(
            CalendarInviteSurfaceMethod::parse("REQUEST"),
            Some(CalendarInviteSurfaceMethod::Request)
        );
        assert_eq!(
            CalendarInviteSurfaceMethod::parse("CANCEL"),
            Some(CalendarInviteSurfaceMethod::Cancel)
        );
        assert_eq!(CalendarInviteSurfaceMethod::parse("REPLY"), None);
    }

    #[test]
    fn boundary_rejects_non_finite_min_weight() {
        assert_eq!(narrow_to_f32(0.5).expect("finite narrows"), 0.5_f32);
        assert!(narrow_to_f32(f64::NAN).is_err(), "NaN rejected");
        assert!(narrow_to_f32(f64::INFINITY).is_err(), "+Inf rejected");
        assert!(narrow_to_f32(f64::NEG_INFINITY).is_err(), "-Inf rejected");
        // A finite f64 beyond f32's range overflows to +Inf and is rejected.
        assert!(narrow_to_f32(f64::MAX).is_err(), "overflow-to-Inf rejected");
    }

    fn unique_vault_dir(tag: &str) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("oneiron-napi-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp vault dir");
        dir
    }

    /// #471 regression: `forget({subjectRef, predicate})` drains EVERY active
    /// match, not just the first page. Seeds 70 co-active claims (distinct
    /// `scope` keeps supersession from collapsing them) and asserts the paging
    /// loop retracts all of them. Exercises the engine-typed helper directly so
    /// the test never links the N-API runtime (cdylib unit tests dead-strip
    /// napi::Error only while it stays unreferenced).
    #[test]
    fn forget_drains_all_active_matches_beyond_one_page() {
        use oneiron::registry::ENTITY_TYPE_PERSON;

        // More than one page so the single-page bug leaves a remainder.
        const ACTIVE_CLAIMS: usize = FORGET_PAGE_SIZE + 6;

        let dir = unique_vault_dir("forget");
        let path = dir.to_str().expect("utf8 path").to_owned();
        let actor = EntityId::from_bytes([0x41; 16]).expect("actor id");
        let subject = EntityId::from_bytes([0x42; 16]).expect("subject id");

        // Scope the vault so its LMDB env closes before the temp dir removal.
        {
            let vault = Vault::open(&path, VaultConfig::device()).expect("open vault");
            let time = oneiron::TimeRange { start: 1, end: 1 };
            vault
                .put_entity(&actor, ENTITY_TYPE_PERSON, time, 1, b"actor")
                .expect("put actor");
            vault
                .put_entity(&subject, ENTITY_TYPE_PERSON, time, 1, b"subject")
                .expect("put subject");
            let facade = vault.memory(actor, oneiron::EdgeActorClass::Human);
            for i in 0..ACTIVE_CLAIMS {
                facade
                    .claim_upsert(&ClaimInput {
                        id: None,
                        predicate: "profile.city".to_owned(),
                        subject_ref: subject.to_hex(),
                        value: serde_json::json!(format!("city-{i}")),
                        confidence: 1.0,
                        source: "user_stated".to_owned(),
                        world_ref: None,
                        scope: Some(serde_json::json!({ "idx": i })),
                        valid_from: None,
                        valid_to: None,
                        occurred_at: Some(100),
                        learned_at: Some(100),
                        salience: None,
                    })
                    .expect("seed claim");
            }

            let count_active = || {
                facade
                    .claim_list(&ClaimListFilter {
                        subject_ref: Some(subject.to_hex()),
                        predicate: Some("profile.city".to_owned()),
                        lifecycle: Some("active".to_owned()),
                        limit: 500,
                    })
                    .expect("claim_list")
                    .len()
            };
            assert_eq!(
                count_active(),
                ACTIVE_CLAIMS,
                "seeded claims are all active before forget"
            );

            let receipts =
                forget_active_matches(&facade, &subject.to_hex(), "profile.city").expect("forget");
            assert_eq!(
                receipts.len(),
                ACTIVE_CLAIMS,
                "forget retracts every active match across pages"
            );
            assert_eq!(count_active(), 0, "subject+predicate is fully forgotten");
        }

        std::fs::remove_dir_all(&dir).ok();
    }
}
