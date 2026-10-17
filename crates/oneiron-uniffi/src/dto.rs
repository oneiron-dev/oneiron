//! The typed UniFFI records of the SDK surface.
//!
//! Every type here is an owned, liftable UniFFI value. No borrowed reference,
//! raw pointer, C union, manual data carrier, or dynamic JSON value crosses
//! the authored boundary. `crate::codec` lowers each input record into the
//! engine type the shared `OneironClient` takes and lifts each engine output
//! back. A verb row with no record here crosses its input and output as
//! [`WireJson`], parsed into and written from the row's engine types on the
//! Rust side.
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
/// The runtime parses it as one complete JSON value (a verb input: as that
/// verb's engine input type) before anything reaches the engine.
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

/// What `pair` returns: the server origin and the credential `connect` takes.
///
/// Store the credential as one secret; the pairing link cannot be redeemed
/// twice.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct Paired {
    /// The server origin to pass to `connect`.
    pub url: String,
    /// The credential to pass to `connect`.
    pub credential: String,
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
    /// A quote on a project room's thread reply: a scalar span of one MESSAGE
    /// in the room. Omitted means no quote.
    pub quote: Option<QuoteSpan>,
    /// Messages, attributed to the bound actor unless authored by `System`.
    pub messages: Vec<WitnessMessage>,
    /// Unix seconds; omitted is stamped with the current time at the call
    /// boundary.
    pub occurred_at: Option<i64>,
}

/// The quoted span of one MESSAGE: the message and its scalar range.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct QuoteSpan {
    /// The quoted MESSAGE (not the TURN that holds it), as 32 hex.
    pub message: String,
    /// First quoted scalar.
    pub start: u32,
    /// One past the last quoted scalar.
    pub end: u32,
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
    pub relationship_ref: Option<String>,
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
    /// Gate decision ref, resolvable through `vault.receipts`.
    pub receipt_ref: String,
}

/// Selector for `vault.forget`: a claim ref, or a subject/predicate pair.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ForgetSelector {
    /// Claim short ref (or 32-hex id).
    pub short_ref: Option<String>,
    /// Subject ref, used together with `predicate`.
    pub subject_ref: Option<String>,
    /// Predicate, used together with `subject_ref`.
    pub predicate: Option<String>,
}

/// Bounded filter for `vault.claims.list`.
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
    /// Unix seconds; omitted is stamped with the current time at the call
    /// boundary.
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

/// Options for `vault.neighbors`.
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

// ── read receipts ──────────────────────────────────────────────────────

/// One read scope on a receipt: the requested, ceiling, or applied tuple.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct ReadScope {
    /// Admitted entity type bytes; absent means every registered type.
    pub entity_types: Option<Vec<u8>>,
    /// Highest admitted sensitivity band.
    pub max_sensitivity_band: u8,
    /// Whether stale claims are admitted.
    pub include_stale: bool,
    /// Lowest admitted claim confidence.
    pub min_confidence: f32,
    /// Lowest admitted claim salience.
    pub min_salience: f32,
    /// Whether the scope admits nothing.
    pub deny_all: bool,
}

/// The mandatory receipt every read returns: what was asked, the actor's
/// ceiling, what applied, and which axes narrowed.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct ReadReceipt {
    /// The scope the caller asked for.
    pub requested: ReadScope,
    /// The actor's ceiling.
    pub actor_ceiling: ReadScope,
    /// The intersection that applied.
    pub applied: ReadScope,
    /// Axes that narrowed the read.
    pub narrowed_axes: Vec<String>,
    /// Stored rows this actor may not read.
    pub suppressed_count: u64,
    /// Machine-readable re-plan hint: the narrowed axes.
    pub replan_hint: Vec<String>,
}

/// `vault.get` result: the view, or none, with the read's receipt.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct EntityRead {
    /// The entity view; absent when missing or withheld.
    pub value: Option<EntityView>,
    /// The read's receipt.
    pub narrowing: ReadReceipt,
}

/// `vault.hydrate` result: every view, with the read's receipt.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct EntityViews {
    /// Views, in request order.
    pub value: Vec<EntityView>,
    /// The read's receipt.
    pub narrowing: ReadReceipt,
}

/// `vault.claims.list` / `vault.claims.history` result, with the read's receipt.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct ClaimViews {
    /// Claim views.
    pub value: Vec<ClaimView>,
    /// The read's receipt.
    pub narrowing: ReadReceipt,
}

/// `vault.search.bm25` result, with the read's receipt.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct LexicalHits {
    /// Hits, in engine score order.
    pub value: Vec<LexicalHit>,
    /// The read's receipt.
    pub narrowing: ReadReceipt,
}

/// `vault.neighbors` result, with the read's receipt.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct NeighborHits {
    /// Neighbors, outbound first.
    pub value: Vec<NeighborHit>,
    /// The read's receipt.
    pub narrowing: ReadReceipt,
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
    /// Unix seconds; omitted is stamped with the current time at the call
    /// boundary.
    pub occurred_at: Option<i64>,
    /// Unix seconds; omitted follows `occurred_at`.
    pub learned_at: Option<i64>,
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
    /// Unix seconds; omitted is stamped with the current time at the call
    /// boundary.
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
    /// Unix seconds; omitted is stamped with the current time at the call
    /// boundary.
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
    Light,
    Medium,
    High,
    Xhigh,
    Max,
    /// Call mode for live calls: light effort under a hard deadline, the
    /// request's `deadline_ms` or else the vault's call-mode deadline.
    Call,
}

/// Recall scoping: narrowing only; unset means the directory floor.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct RecallScope {
    /// World ref; scopes to that world plus base reality.
    pub world_ref: Option<String>,
    /// Facet ref; strict facet narrowing when set.
    pub facet: Option<String>,
    /// Registry kinds to return; unset returns every kind but
    /// conversations, sessions, facets and worlds.
    pub kinds: Option<Vec<String>>,
}

/// A recall's media query (OF-370): bytes the server embeds into one
/// declared space, searched as that space's list beside the query's.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct RecallMedia {
    /// Declared embedding space id (an `ai.embed` rung id, then `@where`).
    pub space: String,
    /// Media type of the bytes: `image/*`, `audio/*` or `text/*`.
    pub mime: String,
    /// The bytes, standard base64.
    pub bytes_b64: String,
    /// The kinds of item the space's list keeps; every kind when empty.
    pub kinds: Vec<crate::InputKind>,
}

/// Item provenance; default-on, never stripped.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MemoryProvenance {
    /// Claim source string, or the structural-record marker.
    pub source: String,
    /// This revision plus its superseded ancestors; a turn's also names the
    /// messages its text is read from.
    pub source_revision_ids: Vec<String>,
    /// Evidence turn ids.
    pub evidence_turn_ids: Vec<String>,
}

/// One memory pack item.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MemoryItem {
    /// Short ref, hydratable through `vault.hydrate`; never revision-qualified.
    pub short_id: String,
    /// The revision the item was read at; `short_id@source_revision_ref` hydrates it.
    pub source_revision_ref: Option<String>,
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
    /// A conversation record's current reactions, one grouped line per
    /// glyph; a TURN's lines are followed by those of each message it
    /// quotes. Empty for every other item.
    pub reactions: Vec<String>,
    /// For a TURN item, the messages whose words the query matched, best
    /// first. Empty for every other item.
    pub cited_messages: Vec<CitedMessage>,
    /// For a TURN or MESSAGE item, the conversation it is in (32 hex), when
    /// the reader may read that conversation.
    pub conversation_id: Option<String>,
}

/// A MESSAGE a TURN item quotes: the words a query matched, as they were said.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CitedMessage {
    /// The message's short ref, the one its witness receipt returned.
    pub short_id: String,
    /// The message's text (capped), as the turn's text revision pins it.
    pub value_text: String,
}

/// What the requested scope excluded.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ScopeHonesty {
    /// Worlds excluded by the requested scope.
    pub out_of_scope_worlds: Vec<String>,
    /// The census stopped at its scan cap or at the answer's deadline, so a
    /// world past it may be missing.
    pub census_capped: bool,
}

/// Execution health, independent of result count.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RetrievalQuality {
    Full,
    Degraded,
    Passthrough,
}

/// A cause of degraded retrieval.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RetrievalDegradation {
    PprCacheMiss,
    EmbeddingTimeout,
    Bm25Stale,
    TemporalSignalSkipped,
}

/// The paid rerank stage's result.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RerankReport {
    Applied {
        model: String,
        served_model: Option<String>,
        candidates: u64,
        calls: u32,
    },
    Skipped {
        reason: RerankSkip,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RerankSkip {
    NoReranker,
    NoCandidates,
    Deadline,
    DeviceOnly,
}

/// Retrieval accounting.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct RetrievalMeta {
    pub quality: RetrievalQuality,
    pub degradation: Vec<RetrievalDegradation>,
    pub confidence_adjustment: f64,
    pub rerank: Option<RerankReport>,
    /// True when only sparse signals ran.
    pub sparse: Option<bool>,
    /// Candidates considered by the pipeline.
    pub total_candidates: u64,
    /// Claim items in the returned pack.
    pub claims_returned: u64,
    /// Set when a budgeted deep call executed at standard effort.
    pub deep_pending: Option<bool>,
    /// Retrieval ended before all requested stages completed.
    pub partial: bool,
    /// Time phrases read from the query and what recall did with each.
    pub temporal_hints: Vec<TemporalHint>,
    /// The request's `limit` was past the ceiling and was served at it.
    pub limit_clamped: bool,
}

/// One time phrase read from a recall query.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct TemporalHint {
    /// The phrase, lowercased with punctuation dropped.
    pub phrase: String,
    /// `used` narrowed the window; `unresolved` and `future` were skipped.
    pub status: String,
    /// Inclusive Unix-second start, when the phrase resolved.
    pub start: Option<u64>,
    /// Inclusive Unix-second end, when the phrase resolved.
    pub end: Option<u64>,
}

/// The versioned memory pack returned by `vault.recall`.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MemoryPack {
    /// Ranked items.
    pub items: Vec<MemoryItem>,
    /// What the scope excluded.
    pub scope_honesty: ScopeHonesty,
    /// Retrieval accounting.
    pub retrieval_meta: RetrievalMeta,
    /// Schema version, the engine's
    /// [`crate::HEAD_MEMORY_PACK_SCHEMA_VERSION`].
    pub pack_version: u32,
    /// Text rendering in the requested format; absent means typed only.
    pub rendered: Option<String>,
    /// The actor-scoped read receipt.
    pub narrowing: ReadReceipt,
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
    /// The saved mention `target` came from, when the agent named the person:
    /// the send refuses while that mention is unsettled.
    pub mention: Option<MentionProvenance>,
}

/// Where a saved mention sits: the turn and message holding it, and its byte
/// span in the message text.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MentionProvenance {
    /// The turn whose tags hold the mention, as 32 hex.
    pub turn: String,
    /// The message the mention is in, as 32 hex.
    pub message: String,
    /// The mention's byte span start in the message text.
    pub start: u64,
    /// The mention's byte span end in the message text.
    pub end: u64,
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
    /// Persisted gate decision ref, queryable through `vault.receipts`.
    pub gate_decision_ref: Option<String>,
    /// Gate reason codes.
    pub gate_reason_codes: Vec<String>,
    /// True when the idempotency key coalesced.
    pub deduped: bool,
}
