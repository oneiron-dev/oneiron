//! All napi(object) DTO structs for the actor-scoped surface.

use napi_derive::napi;

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
    pub valid_from: Option<f64>,
    /// Validity window end (Unix seconds).
    pub valid_to: Option<f64>,
    /// Backdating passthrough (Unix seconds).
    pub occurred_at: Option<f64>,
    /// Backdating passthrough (Unix seconds).
    pub learned_at: Option<f64>,
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
