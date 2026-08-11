//! The complete DTO inventory for the WIRE head contract.
//!
//! Every type here is an owned, liftable UniFFI value. No borrowed reference,
//! raw pointer, C union, manual data carrier, or dynamic JSON value crosses
//! the authored boundary.
//!
//! Width rules:
//!
//! - identifiers and short refs are `String`;
//! - Unix timestamps are signed `i64` on both request and response sides;
//! - request-side counts and limits are `u32`;
//! - response numerics mirror the core facade widths exactly and are neither
//!   widened nor narrowed here;
//! - opaque JSON travels as [`WireJson`], never as an unconstrained map;
//! - blob content travels as `Vec<u8>` (generated `Data`).

/// One opaque JSON value crossing the boundary in canonical text form.
///
/// Field names stay semantic (`value`, `metadata`, `scope`, `body`, `data`,
/// `input`) while this wrapper makes the transport representation explicit.
/// The future runtime arm validates a single complete JSON value before it
/// dispatches into the core facade.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct WireJson {
    /// A single complete JSON value in canonical text form.
    pub canonical_json: String,
}

// ── construction ────────────────────────────────────────────────────────

/// Embedded-construction options.
///
/// This carries only what the direct-link constructor contract already
/// carries. No transport, auth, cache, callback, or budget knob belongs here.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct OpenOptions {
    /// Embedding width for the opened directory; omitted uses the engine
    /// default.
    pub dimensions: Option<u32>,
}

// ── witness ─────────────────────────────────────────────────────────────

/// Closed authorship vocabulary for a witnessed message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum WitnessAuthor {
    /// The owner of the memory directory.
    User,
    /// The companion persona.
    Companion,
    /// System/tooling rows; these get no authorship edge.
    System,
}

/// One message inside a witnessed turn.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct WitnessMessage {
    /// Deterministic 32-hex entity id; omitted means generated.
    pub id: Option<String>,
    /// Who authored the message.
    pub author: WitnessAuthor,
    /// Message type string.
    pub message_type: String,
    /// Text content (lexically indexed when non-empty).
    pub content: String,
    /// Opaque metadata.
    pub metadata: Option<WireJson>,
    /// Visibility flag; omitted means visible.
    pub is_visible: Option<bool>,
    /// Position within the turn.
    pub order: u32,
}

/// One turn to witness.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct WitnessTurn {
    /// Conversation ref (create-or-get, or an existing short ref).
    pub conversation_ref: String,
    /// Turn ref (create-or-get); omitted means a fresh turn.
    pub turn_ref: Option<String>,
    /// Messages, attributed to the bound actor unless authored by `System`.
    pub messages: Vec<WitnessMessage>,
    /// Unix seconds; omitted is stamped at the call boundary by the future
    /// runtime arm.
    pub occurred_at: Option<i64>,
}

/// Receipt for one witnessed turn.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct WitnessReceipt {
    /// Turn short ref.
    pub turn_short_id: String,
    /// Message short refs, in input order.
    pub message_short_ids: Vec<String>,
    /// Write marker for the witnessed turn.
    pub receipt_ref: String,
}

// ── claims ──────────────────────────────────────────────────────────────

/// One claim to commit. Approval is decided by the gate, never by callers.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct ClaimInput {
    /// Deterministic 32-hex claim id; omitted means generated.
    pub id: Option<String>,
    /// Dotted predicate.
    pub predicate: String,
    /// Subject entity ref.
    pub subject_ref: String,
    /// Claim value.
    pub value: WireJson,
    /// Calibrated-absolute confidence in `[0, 1]`.
    pub confidence: f32,
    /// Claim source string.
    pub source: String,
    /// Optional world ref.
    pub world_ref: Option<String>,
    /// Optional scope map.
    pub scope: Option<WireJson>,
    /// Validity window start (Unix seconds).
    pub valid_from: Option<i64>,
    /// Validity window end (Unix seconds).
    pub valid_to: Option<i64>,
    /// Backdating passthrough (Unix seconds).
    pub occurred_at: Option<i64>,
    /// Backdating passthrough (Unix seconds).
    pub learned_at: Option<i64>,
    /// Optional salience in `[0, 1]`.
    pub salience: Option<f32>,
}

/// Receipt for one committed (or refused) claim.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CommitReceipt {
    /// Short ref of the written claim.
    pub claim_short_id: String,
    /// Gate approval string.
    pub approval: String,
    /// Short ref of the superseded prior claim, if any.
    pub superseded_short_id: Option<String>,
    /// Gate decision ref, resolvable through `receipts`.
    pub receipt_ref: String,
}

/// Selector for `forget`: a claim ref, or a subject/predicate pair.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ForgetSelector {
    /// Claim short ref (or 32-hex id).
    pub short_ref: Option<String>,
    /// Subject ref, used together with `predicate`.
    pub subject_ref: Option<String>,
    /// Predicate, used together with `subject_ref`.
    pub predicate: Option<String>,
}

/// Bounded filter for `claim_list`.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ClaimListFilter {
    /// Restrict to this subject.
    pub subject_ref: Option<String>,
    /// Restrict to this predicate.
    pub predicate: Option<String>,
    /// Restrict to this lifecycle.
    pub lifecycle: Option<String>,
    /// Maximum results.
    pub limit: u32,
}

/// Typed claim view.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct ClaimView {
    /// 32-hex claim id.
    pub claim_ref: String,
    /// Short ref, when assigned.
    pub short_ref: Option<String>,
    /// Predicate.
    pub predicate: String,
    /// Subject ref.
    pub subject_ref: String,
    /// Claim value.
    pub value: WireJson,
    /// Confidence.
    pub confidence: f32,
    /// Approval string.
    pub approval: String,
    /// Lifecycle string.
    pub lifecycle: String,
    /// Source string, when stamped.
    pub source: Option<String>,
    /// World ref, when world-scoped.
    pub world_ref: Option<String>,
    /// Scope map, when present.
    pub scope: Option<WireJson>,
    /// Validity window start (Unix seconds).
    pub valid_from: Option<i64>,
    /// Validity window end (Unix seconds).
    pub valid_to: Option<i64>,
    /// Salience, when stamped.
    pub salience: Option<f32>,
    /// Stale marker.
    pub stale: bool,
}

// ── deletion and consent ────────────────────────────────────────────────

/// Named deletion reasons. There is deliberately no bare boolean delete.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SafeDeleteReason {
    /// Tombstone delete.
    UserDelete,
    /// Hard purge with a redaction audit receipt.
    UserHardDelete,
    /// Compliance erase.
    GdprDelete,
    /// Policy-driven erase.
    PolicyDelete,
}

/// Receipt for one named deletion.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DeleteReceipt {
    /// Whether the entity existed.
    pub existed: bool,
    /// The named reason used.
    pub reason: String,
    /// Redaction audit ref, when the reason produces one.
    pub receipt_ref: Option<String>,
}

/// One gated write parked for consent.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PendingWrite {
    /// 32-hex claim id.
    pub claim_ref: String,
    /// Gate decision ref.
    pub decision_ref: String,
    /// Unix seconds.
    pub created_at: i64,
    /// Gate reason codes.
    pub reason_codes: Vec<String>,
    /// Consolidation run lane, if any.
    pub dreamer_run_id: Option<String>,
}

/// One gate decision receipt.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct FacadeReceipt {
    /// Stable decision ref.
    pub receipt_ref: String,
    /// Gate outcome.
    pub outcome: String,
    /// Unix seconds.
    pub created_at: i64,
    /// Gate reason codes.
    pub reason_codes: Vec<String>,
    /// Actor class the decision was made for.
    pub actor_class: String,
    /// Actor entity ref, when the write carried an envelope.
    pub actor_ref: Option<String>,
    /// Gate content kind.
    pub content_kind: String,
    /// 32-hex id of the claim the decision covers, if any.
    pub claim_ref: Option<String>,
}

// ── entities and graph ──────────────────────────────────────────────────

/// Typed read-back view of one entity.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct EntityView {
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
    /// Entity body, when decodable.
    pub body: Option<WireJson>,
}

/// One lexical index field for a structural put.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct TextIndexField {
    /// Analyzer field name.
    pub field: String,
    /// Field text.
    pub value: String,
}

/// One outgoing edge for a structural put.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct StructuralEdgeSpec {
    /// snake_case edge kind name.
    pub edge_kind: String,
    /// Target entity ref.
    pub target_ref: String,
    /// Weight in `[0, 1]`; omitted uses the kind default.
    pub weight: Option<f32>,
}

/// Structural put input.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct StructuralPutInput {
    /// Deterministic 32-hex id; omitted means generated.
    pub id: Option<String>,
    /// Registry kind string; claim kinds are refused, use the claim verbs.
    pub kind: String,
    /// Entity body.
    pub body: WireJson,
    /// Lexical index fields.
    pub text_fields: Option<Vec<TextIndexField>>,
    /// Outgoing edges.
    pub edges: Option<Vec<StructuralEdgeSpec>>,
    /// Unix seconds; omitted is stamped at the call boundary by the future
    /// runtime arm.
    pub occurred_at: Option<i64>,
    /// Unix seconds; omitted follows `occurred_at`.
    pub learned_at: Option<i64>,
}

/// Receipt for one structural write.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct EntityRefReceipt {
    /// Short ref, falling back to hex.
    pub entity_ref: String,
    /// 32-hex id.
    pub id_hex: String,
    /// Write marker.
    pub receipt_ref: String,
}

/// One lexical hit, carrying engine index scores verbatim.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct LexicalHit {
    /// Short ref, falling back to hex.
    pub short_id: String,
    /// Registry kind string.
    pub kind: String,
    /// Engine lexical score.
    pub score: f32,
    /// Content preview, when available.
    pub snippet: Option<String>,
}

/// Options for `neighbors`.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct NeighborOpts {
    /// Restrict to this snake_case edge kind name.
    pub edge_kind: Option<String>,
    /// Drop edges below this weight.
    pub min_weight: Option<f32>,
    /// Maximum hits.
    pub limit: u32,
}

/// One graph neighbor.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct NeighborHit {
    /// Short ref of the neighbor.
    pub short_id: String,
    /// Registry kind string of the neighbor.
    pub kind: String,
    /// snake_case edge kind name.
    pub edge_kind: String,
    /// Stored edge weight.
    pub weight: f32,
    /// Direction relative to the anchor.
    pub direction: String,
}

// ── specialized facade inputs ───────────────────────────────────────────

/// One habit check-in append.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct HabitCheckinInput {
    /// Habit-role task ref.
    pub habit_ref: String,
    /// Deterministic 32-hex check-in id; omitted means generated.
    pub id: Option<String>,
    /// Extra body fields.
    pub data: Option<WireJson>,
    /// Unix seconds; omitted is stamped at the call boundary by the future
    /// runtime arm.
    pub occurred_at: Option<i64>,
    /// Unix seconds; omitted follows `occurred_at`.
    pub learned_at: Option<i64>,
}

/// One companion persona registration.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CompanionRecordInput {
    /// Deterministic 32-hex record id; omitted means generated.
    pub id: Option<String>,
    /// Owner ref (personal scope).
    pub owner_ref: String,
    /// Companion persona ref.
    pub persona_ref: String,
    /// Opaque record value.
    pub value: WireJson,
    /// Provenance source; omitted uses the engine default.
    pub source: Option<String>,
    /// Retire the record at this time after creation (Unix seconds).
    pub retired_at: Option<i64>,
    /// Creation time (Unix seconds).
    pub learned_at: i64,
}

/// One imported-evidence claim admission.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AdmitImportedClaimInput {
    /// Registered ingest source id; unknown sources fail closed.
    pub source_id: String,
    /// Stable source record id.
    pub source_record_id: String,
    /// Deterministic 32-hex claim id; omitted means generated.
    pub id: Option<String>,
    /// Subject entity ref.
    pub subject_ref: String,
    /// Predicate.
    pub predicate: String,
    /// Claim value.
    pub value: WireJson,
    /// Unix seconds; omitted is stamped at the call boundary by the future
    /// runtime arm.
    pub occurred_at: Option<i64>,
    /// Unix seconds; omitted follows `occurred_at`.
    pub learned_at: Option<i64>,
}

// ── blob ────────────────────────────────────────────────────────────────

/// One blob artifact registration.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct BlobArtifactInput {
    /// Deterministic 32-hex artifact id; omitted means generated.
    pub id: Option<String>,
    /// Display name.
    pub name: String,
    /// Media type.
    pub media_type: String,
    /// Unix seconds; omitted is stamped at the call boundary by the future
    /// runtime arm.
    pub occurred_at: Option<i64>,
    /// Unix seconds; omitted follows `occurred_at`.
    pub learned_at: Option<i64>,
}

/// View of one appended blob version.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct BlobVersionView {
    /// 32-hex artifact id.
    pub artifact_ref: String,
    /// Append-only version number, mirroring the core width.
    pub version: u64,
    /// Content hash, lowercase hex.
    pub content_hash_hex: String,
    /// 32-hex id of the ledger claim recording the version.
    pub claim_ref: String,
    /// Unix seconds.
    pub created_at: i64,
}

// ── recall ──────────────────────────────────────────────────────────────

/// Retrieval effort dial. Closed vocabulary: there is no escape hatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Effort {
    /// Lexical retrieval only.
    Minimal,
    /// Lexical plus graph expansion and hydration.
    Standard,
    /// Budget-gated deep retrieval; the boundary never mints the budget.
    Deep,
}

/// Recall scoping: narrowing only; unset means the directory floor.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct RecallScope {
    /// World ref; scopes to that world plus base reality.
    pub world_ref: Option<String>,
    /// Facet ref; strict facet narrowing when set.
    pub facet: Option<String>,
}

/// Item provenance; default-on, never stripped.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MemoryProvenance {
    /// Claim source string, or the structural-record marker.
    pub source: String,
    /// This revision plus its superseded ancestors.
    pub source_revision_ids: Vec<String>,
    /// Evidence turn ids.
    pub evidence_turn_ids: Vec<String>,
}

/// One memory pack item.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MemoryItem {
    /// Short ref, hydratable through `hydrate`.
    pub short_id: String,
    /// Registry kind string.
    pub kind: String,
    /// Predicate (claims only).
    pub predicate: Option<String>,
    /// Text rendering of the value or content.
    pub value_text: String,
    /// Calibrated-absolute confidence in `[0, 1]`.
    pub confidence: f32,
    /// Hedge vocabulary bucket derived from confidence.
    pub hedge_bucket: String,
    /// Provenance.
    pub provenance: MemoryProvenance,
    /// World ref, when world-scoped.
    pub world: Option<String>,
    /// Facet ref, when faceted.
    pub facet: Option<String>,
    /// Salience, when stamped.
    pub salience: Option<f32>,
}

/// What the requested scope excluded.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ScopeHonesty {
    /// Worlds excluded by the requested scope.
    pub out_of_scope_worlds: Vec<String>,
}

/// Retrieval accounting.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct RetrievalMeta {
    /// True when only sparse signals ran.
    pub sparse: Option<bool>,
    /// Candidates considered by the pipeline.
    pub total_candidates: u64,
    /// Claim items in the returned pack.
    pub claims_returned: u64,
    /// Set when a budgeted deep call executed at standard effort.
    pub deep_pending: Option<bool>,
}

/// The versioned memory pack returned by `recall`.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MemoryPack {
    /// Ranked items.
    pub items: Vec<MemoryItem>,
    /// What the scope excluded.
    pub scope_honesty: ScopeHonesty,
    /// Retrieval accounting.
    pub retrieval_meta: RetrievalMeta,
    /// Schema version; the first runtime consumer populates this from
    /// [`crate::HEAD_MEMORY_PACK_SCHEMA_VERSION`].
    pub pack_version: u32,
    /// Text rendering in the requested format; absent means typed only.
    pub rendered: Option<String>,
}

// ── jobs and effects ────────────────────────────────────────────────────

/// One consolidation enqueue request.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ConsolidationJobInput {
    /// Consolidation scope string.
    pub scope: String,
    /// Opaque job input.
    pub input: WireJson,
    /// Optional run correlation id.
    pub run_id: Option<String>,
    /// Optional advisory dedupe key.
    pub dedupe_key: Option<String>,
    /// Unix seconds; omitted means now.
    pub now: Option<i64>,
}

/// Reference to one queued consolidation job.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DreamerJobRef {
    /// 32-hex job id.
    pub job_ref: String,
    /// Queue state at enqueue time.
    pub state: String,
    /// True when the dedupe key coalesced onto an existing job.
    pub existing: bool,
}

/// Poll view of one consolidation job.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DreamerJobView {
    /// 32-hex job id.
    pub job_ref: String,
    /// Queue state string.
    pub state: String,
    /// Queue job kind.
    pub kind: String,
    /// Worker label currently holding the job, if any.
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

/// One outbound schedule request. Scheduling only; this surface never
/// delivers.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct OutboundDraftInput {
    /// Verb.
    pub verb: String,
    /// Channel.
    pub channel: String,
    /// Delivery target.
    pub target: String,
    /// Principal the send acts for, if delegated.
    pub on_behalf_of: Option<String>,
    /// Content entity ref.
    pub content_ref: Option<String>,
    /// Idempotency key enforced by the core chokepoint.
    pub idempotency_key: Option<String>,
    /// Advisory dedupe key carried onto the receipt.
    pub dedupe_key: Option<String>,
    /// Trigger source string.
    pub trigger: String,
    /// What fired the trigger.
    pub trigger_ref: String,
    /// Owning job or brief ref, if any.
    pub job_ref: Option<String>,
    /// Unix seconds; omitted means now.
    pub occurred_at: Option<i64>,
}

/// Receipt for one scheduled outbound intent.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct OutboundIntentReceipt {
    /// Stable intent ref.
    pub intent_ref: String,
    /// Dispatch outcome.
    pub outcome: String,
    /// Gate outcome, absent on dedupe with a missing binding.
    pub gate_outcome: Option<String>,
    /// Persisted gate decision ref, queryable through `receipts`.
    pub gate_decision_ref: Option<String>,
    /// Gate reason codes.
    pub gate_reason_codes: Vec<String>,
    /// True when the idempotency key coalesced.
    pub deduped: bool,
}
