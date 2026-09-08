use super::MemoriesRequest;
use super::VadPayload;
use super::advance_memories_cursor;
use super::auth_bound_principal_ref;
use super::core_engine_error;
use super::default_limit;
use super::hex_bytes;
use super::json_payload;
use super::non_empty_query;
use super::parse_entity_id_param;
use super::scoped_read_for_core_auth;
use super::validate_core_query_seeds;
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;
use crate::error::ApiErrorEnvelope;
use crate::error::EnvelopedApiError;
use crate::projection::View;
use crate::server::SyncServer;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use oneiron::retrieval_quality::{ConfidenceAdjustment, RetrievalDegradation, RetrievalQuality};
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;
use utoipa::ToSchema;

/// Maximum `interlocutors.third_parties` entries per context-pack request.
/// Each party can trigger vault reads during resolution, so the block is
/// capped like the crate's other request-controlled collections.
pub(crate) const MAX_INTERLOCUTOR_THIRD_PARTIES: usize = 32;

/// Engine invariant for counterparty keys (`counterparty_contact`'s private
/// `MAX_COUNTERPARTY_BYTES`): stored keys are trimmed and at most 512 bytes.
/// Enforced at the DTO boundary so caller input surfaces as a typed 400
/// instead of an engine error.
pub(crate) const MAX_INTERLOCUTOR_COUNTERPARTY_BYTES: usize = 512;

/// Display labels ride stamps, notices, and receipts; bounded to the same
/// scale as the counterparty key so up to [`MAX_INTERLOCUTOR_THIRD_PARTIES`]
/// labels stay a bounded echo/work cost.
pub(crate) const MAX_INTERLOCUTOR_LABEL_BYTES: usize = 512;

/// Edge expansion depth controls for context-pack assembly.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct ContextPackDepthControls {
    /// Edge expansion depth for neighbor hydration.
    #[serde(default, rename = "edge_hop", alias = "edgeHop")]
    #[schema(example = 1)]
    edge_hop: Option<u32>,
    /// Maximum neighbors to hydrate during edge expansion.
    #[serde(default, rename = "max_neighbors", alias = "maxNeighbors")]
    #[schema(example = 50)]
    max_neighbors: Option<usize>,
}

/// Ranking and projection policy controls for context-pack assembly.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct ContextPackPolicyControls {
    /// Whether to include hydrated fields.
    #[serde(default)]
    #[schema(example = true)]
    hydrate: Option<bool>,
    /// Whether to include edge records in hydrated entities.
    #[serde(default, rename = "include_edges", alias = "includeEdges")]
    #[schema(example = true)]
    include_edges: Option<bool>,
    /// Whether to include stored vectors when present.
    #[serde(default, rename = "include_vectors", alias = "includeVectors")]
    #[schema(example = false)]
    include_vectors: Option<bool>,
    /// Field profile for hydrated fields.
    #[serde(default)]
    #[schema(example = "standard")]
    view: Option<View>,
    /// Apply recency boost with the supplied half-life in days.
    #[serde(default, rename = "boost_recency_days", alias = "boostRecencyDays")]
    #[schema(example = 7.0)]
    boost_recency_days: Option<f32>,
    /// Apply salience boost.
    #[serde(default, rename = "boost_salience", alias = "boostSalience")]
    #[schema(example = true)]
    boost_salience: Option<bool>,
    /// Apply confidence boost.
    #[serde(default, rename = "boost_confidence", alias = "boostConfidence")]
    #[schema(example = true)]
    boost_confidence: Option<bool>,
    /// Apply contiguity boost.
    #[serde(default, rename = "boost_contiguity", alias = "boostContiguity")]
    #[schema(example = true)]
    boost_contiguity: Option<bool>,
}

/// Time-window controls for context-pack assembly.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct ContextPackTimeControls {
    /// Keep entities learned at or after this Unix timestamp.
    #[serde(default)]
    #[schema(example = 1_782_357_600_u64)]
    since: Option<u64>,
    /// Occurrence window start, inclusive.
    #[serde(default, rename = "occurred_start", alias = "occurredStart")]
    #[schema(example = 1_782_357_600_u64)]
    occurred_start: Option<u64>,
    /// Occurrence window end, inclusive.
    #[serde(default, rename = "occurred_end", alias = "occurredEnd")]
    #[schema(example = 1_782_357_900_u64)]
    occurred_end: Option<u64>,
    /// Learned-at window start, inclusive.
    #[serde(default, rename = "learned_start", alias = "learnedStart")]
    #[schema(example = 1_782_357_600_u64)]
    learned_start: Option<u64>,
    /// Learned-at window end, inclusive.
    #[serde(default, rename = "learned_end", alias = "learnedEnd")]
    #[schema(example = 1_782_357_900_u64)]
    learned_end: Option<u64>,
}

/// Per-kind retrieval item budget for context-pack assembly.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct ContextPackRetrievalBudgetControls {
    #[serde(default)]
    #[schema(example = 4)]
    pub(crate) claims: Option<usize>,
    #[serde(default)]
    #[schema(example = 2)]
    pub(crate) turns: Option<usize>,
    #[serde(default)]
    #[schema(example = 2)]
    pub(crate) summaries: Option<usize>,
    #[serde(default)]
    #[schema(example = 1)]
    pub(crate) facets: Option<usize>,
    #[serde(default)]
    #[schema(example = 1)]
    pub(crate) other: Option<usize>,
    #[serde(default, rename = "selected_edges", alias = "selectedEdges")]
    #[schema(example = 50)]
    pub(crate) selected_edges: Option<usize>,
}

/// Token and item budget controls for context-pack assembly.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct ContextPackBudgetControls {
    /// Serialized token budget for context-pack responses, including structured JSON projection.
    #[serde(default, rename = "token_budget", alias = "tokenBudget")]
    #[schema(example = 4000)]
    token_budget: Option<usize>,
    /// Per-item token cap for context-pack serialization; 0 disables it.
    #[serde(default, rename = "max_item_tokens", alias = "maxItemTokens")]
    #[schema(example = 512)]
    max_item_tokens: Option<usize>,
    /// Maximum field characters before serialization truncation.
    #[serde(default, rename = "max_field_chars", alias = "maxFieldChars")]
    #[schema(example = 500)]
    max_field_chars: Option<usize>,
    /// Per-kind retrieval item budgets before final result truncation.
    #[serde(default)]
    retrieval: Option<ContextPackRetrievalBudgetControls>,
}

/// Interlocutor presence controls for context-pack assembly (OF-365 ILD-1).
///
/// The wire shape deliberately cannot express interlocutor class or presence
/// evidence: owner presence keys to the authenticated session, and every
/// supplied party resolves to a non-owner entry.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct CoreInterlocutorControls {
    /// Physical owner presence asserted by the embedder. May only be `true`
    /// on an owner-grade credential — un-narrowed on both the scope and the
    /// `principal_ref` axis (403 otherwise); `false` always narrows.
    #[serde(default, rename = "owner_present", alias = "ownerPresent")]
    #[schema(example = true)]
    owner_present: Option<bool>,
    /// Third-party conversation participants.
    #[serde(default, rename = "third_parties", alias = "thirdParties")]
    third_parties: Vec<CoreInterlocutorParty>,
    /// Voice session roster reference. Accepted now; the roster merge lands
    /// with ILD-3 (ONE-1518).
    #[serde(default, rename = "voice_session_ref", alias = "voiceSessionRef")]
    #[schema(example = "call-123")]
    voice_session_ref: Option<String>,
}

/// One third-party interlocutor. Exactly one of `contact_ref`,
/// `channel_identity_ref`+`counterparty`, or `label` must be supplied.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct CoreInterlocutorParty {
    /// Hex CounterpartyContact entity id.
    #[serde(default, rename = "contact_ref", alias = "contactRef")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    contact_ref: Option<String>,
    /// Hex ChannelIdentity entity id; requires `counterparty`.
    #[serde(default, rename = "channel_identity_ref", alias = "channelIdentityRef")]
    #[schema(example = "fedcba9876543210fedcba9876543210")]
    channel_identity_ref: Option<String>,
    /// Provider-native counterparty key; requires `channel_identity_ref`.
    #[serde(default)]
    #[schema(example = "kenji@example.com")]
    counterparty: Option<String>,
    /// Display label for an untyped party.
    #[serde(default)]
    #[schema(example = "unknown speaker 2")]
    label: Option<String>,
    /// Label-only owner claim carried on the stamp; never authority.
    #[serde(default, rename = "claimed_owner", alias = "claimedOwner")]
    #[schema(example = false)]
    claimed_owner: Option<bool>,
}

/// Agent-visible disclosure block for a clamped context assembly (OF-365
/// ILD-2).
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreDisclosureAssembly {
    /// Disclosure mode: owner_alone, supervised, or absence_clamp.
    #[schema(example = "absence_clamp")]
    mode: String,
    /// Named-presence discretion notice; present iff supervised.
    #[schema(example = "Others present: Kenji (known_contact).")]
    notice: Option<String>,
    /// Per-speaker interlocutor stamps for the clamped assembly.
    interlocutors: Vec<CoreInterlocutorStamp>,
    /// Scored candidates dropped by the clamp's candidate sweep.
    #[serde(rename = "clamped_out")]
    #[schema(example = 2)]
    clamped_out: u64,
}

/// Per-speaker interlocutor stamp echoed with a context pack (OF-365 ILD-1).
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreInterlocutorStamp {
    /// Contact entity hex id when known, else the display label or "owner".
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    speaker: String,
    /// Interlocutor class: owner, known_contact, or unknown.
    #[schema(example = "known_contact")]
    class: String,
    /// Non-owner speech is claims, not executable owner instructions.
    #[serde(rename = "claims_not_instructions")]
    #[schema(example = true)]
    claims_not_instructions: bool,
}

/// Context-pack request on the canonical core route.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "query": "blue hallway",
    "limit": 10,
    "include_edges": true,
    "edge_hop": 1,
    "view": "full"
}))]
pub(crate) struct CoreContextPackRequest {
    /// Optional BM25 text query.
    #[serde(default)]
    #[schema(example = "blue hallway")]
    query: Option<String>,
    /// Optional vector query.
    #[serde(default, rename = "query_vector", alias = "queryVector")]
    #[schema(example = json!([0.1, 0.2, 0.3, 0.4]))]
    query_vector: Option<Vec<f32>>,
    /// Maximum primary candidates to retrieve.
    #[serde(default = "default_limit")]
    #[schema(default = default_limit, example = 10)]
    limit: usize,
    /// Whether to include hydrated fields. Defaults to true.
    #[serde(default = "default_true")]
    #[schema(default = default_true, example = true)]
    hydrate: bool,
    /// Whether to include edge records in hydrated entities.
    #[serde(default, rename = "include_edges", alias = "includeEdges")]
    #[schema(example = true)]
    include_edges: bool,
    /// Edge expansion depth for neighbor hydration.
    #[serde(default, rename = "edge_hop", alias = "edgeHop")]
    #[schema(example = 1)]
    edge_hop: u32,
    /// Maximum neighbors to hydrate during edge expansion.
    #[serde(
        default = "default_context_neighbors",
        rename = "max_neighbors",
        alias = "maxNeighbors"
    )]
    #[schema(default = default_context_neighbors, example = 50)]
    max_neighbors: usize,
    /// Whether to include vectors in hydrated entities.
    #[serde(default, rename = "include_vectors", alias = "includeVectors")]
    #[schema(example = false)]
    include_vectors: bool,
    /// Field profile for hydrated fields. Defaults to standard.
    #[serde(default)]
    #[schema(example = "standard")]
    view: Option<View>,
    /// Optional nested depth controls. Overrides top-level edge_hop/max_neighbors when set.
    #[serde(default)]
    depth: Option<ContextPackDepthControls>,
    /// Optional nested ranking/projection policy controls.
    #[serde(default)]
    policy: Option<ContextPackPolicyControls>,
    /// Optional time-window filters.
    #[serde(default)]
    time: Option<ContextPackTimeControls>,
    /// Optional retrieval and serialization budget controls.
    #[serde(default)]
    budget: Option<ContextPackBudgetControls>,
    /// Optional interlocutor presence controls (OF-365 ILD-1).
    #[serde(default)]
    interlocutors: Option<CoreInterlocutorControls>,
}

impl CoreContextPackRequest {
    /// The `(limit, max_neighbors)` shape the MEMORIES slot defaults derive
    /// from, resolved the same way the pipeline resolves depth.
    pub(crate) fn retrieval_budget_shape(&self) -> (usize, usize) {
        let (_, _, max_neighbors, _) =
            resolved_context_pack_depth(self.depth.as_ref(), self.edge_hop, self.max_neighbors);
        (self.limit, max_neighbors)
    }
}

/// Hydrated context edge.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreContextEdge {
    /// Numeric edge-kind discriminant.
    #[schema(example = 1)]
    kind: u8,
    /// Hex target entity id.
    #[schema(example = "fedcba9876543210fedcba9876543210")]
    target: String,
    /// Target short id when the target is present in the same context pack.
    #[serde(rename = "target_short_id", skip_serializing_if = "Option::is_none")]
    #[schema(example = "tn2")]
    target_short_id: Option<String>,
    /// Edge weight.
    #[schema(example = 1.0)]
    weight: f32,
    /// Edge creation timestamp in Unix seconds.
    #[schema(example = 1782357635_u64)]
    created_at: u64,
    /// Optional edge VAD payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    vad: Option<VadPayload>,
}

/// Hydrated context entity.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreContextEntity {
    /// Hex entity id.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: String,
    /// Short id allocated by the vault, or hex fallback when no short id exists.
    #[serde(rename = "short_id")]
    #[schema(example = "tn1")]
    short_id: String,
    /// One-byte content hash as two lowercase hex digits.
    #[serde(rename = "content_hash")]
    #[schema(example = "a7")]
    content_hash: String,
    /// Numeric entity type byte.
    #[schema(example = 1)]
    entity_type: u8,
    /// Retrieval score.
    #[schema(example = 0.87)]
    score: f32,
    /// Hydrated fields when requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    fields: Option<BTreeMap<String, Value>>,
    /// Hydrated edges when requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    edges: Option<Vec<CoreContextEdge>>,
    /// Stored vector when requested and present.
    #[serde(skip_serializing_if = "Option::is_none")]
    vector: Option<Vec<f32>>,
}

/// Context-pack item accounting.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreContextPackItemAccounting {
    /// Number of items affected.
    #[schema(example = 0)]
    count: usize,
    /// Accounting reason.
    #[schema(example = "token_budget")]
    reason: String,
}

/// Context-pack stats.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreContextPackStats {
    /// Candidate count considered by the pack.
    #[schema(example = 1)]
    candidates_considered: usize,
    /// Retrieval signals used.
    signals_used: Vec<String>,
    /// Query execution duration in microseconds.
    #[schema(example = 1000_u64)]
    query_time_us: u64,
    /// Primary entities hydrated.
    #[schema(example = 1)]
    entities_hydrated: usize,
    /// Neighbor entities hydrated.
    #[schema(example = 0)]
    neighbors_hydrated: usize,
    /// Vector-only candidates dampened by cosine-ghost suppression.
    #[schema(example = 0)]
    cosine_ghosts_dampened: usize,
    /// Claims suppressed by read-path gates.
    #[schema(example = 0)]
    claims_suppressed: usize,
    /// Item truncation accounting.
    items_truncated: CoreContextPackItemAccounting,
    /// Item drop accounting.
    items_dropped: CoreContextPackItemAccounting,
}

/// Typed context-pack result state.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreContextPackState {
    /// Stable state discriminator.
    kind: CoreContextPackStateKind,
    /// Empty-result reason when the pack did not surface entities.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<CoreContextPackStateReason>,
    /// Total records in scope when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    total_in_scope: Option<usize>,
    /// Caller-facing hint from the retrieval layer.
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<String>,
}

/// Stable context-pack state discriminator.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoreContextPackStateKind {
    Ok,
    MissingData,
    LowConfidence,
}

/// Stable context-pack empty-result reason.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoreContextPackStateReason {
    FilterMatchedNone,
    NoData,
    AllActivated,
    BelowThreshold,
}

/// Score component that contributed to a context-pack result.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreContextPackScoreComponent {
    /// Retrieval signal name.
    signal: String,
    /// Rank within the signal.
    rank: u32,
    /// Raw signal score.
    score: f32,
}

/// Per-result context-pack score evidence.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreContextPackScoreEvidence {
    /// Hex entity id.
    result_id: String,
    /// Final rank after context-pack hydration.
    final_rank: u32,
    /// Final fused score.
    final_score: f32,
    /// Read-side access factor applied to the fused score, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    access_factor: Option<f32>,
    /// Signal-level score components.
    components: Vec<CoreContextPackScoreComponent>,
}

/// Retrieval evidence attached to a context-pack response.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreContextPackEvidence {
    /// Whether the retrieval telemetry row was persisted and finalized.
    pub(crate) telemetry_persisted: bool,
    /// Retrieval telemetry run id when persistence succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) retrieval_run_id: Option<String>,
    /// Surfaced result ids recorded in telemetry.
    pub(crate) result_ids: Vec<String>,
    /// Final score evidence recorded in telemetry.
    pub(crate) scores: Vec<CoreContextPackScoreEvidence>,
}

/// Context-pack response envelope.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreContextPackResponse {
    /// Execution quality projected from the engine's shared report.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    quality: Option<RetrievalQuality>,
    /// Observed reasons for degraded execution; absent when none were recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Vec<String>>)]
    degradation: Option<Vec<RetrievalDegradation>>,
    /// Pinned presentation confidence adjustment for the execution tier: 0, -0.15, or -0.35.
    #[serde(
        rename = "confidenceAdjustment",
        skip_serializing_if = "Option::is_none"
    )]
    #[schema(value_type = Option<f32>, example = -0.15)]
    confidence_adjustment: Option<ConfidenceAdjustment>,
    /// Primary hydrated retrieval results.
    results: Vec<CoreContextEntity>,
    /// Neighbor entities hydrated through edge expansion.
    neighbors: Vec<CoreContextEntity>,
    /// Retrieval and hydration stats.
    stats: CoreContextPackStats,
    /// Typed missing-data / low-confidence state.
    state: CoreContextPackState,
    /// Retrieval evidence and score breakdown.
    evidence: CoreContextPackEvidence,
    /// Resolved per-speaker interlocutor stamps when an interlocutors block
    /// was supplied or the auth is principal_ref-scoped (OF-365 ILD-1).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Vec<CoreInterlocutorStamp>>)]
    interlocutors: Option<Vec<oneiron::InterlocutorStamp>>,
    /// Disclosure block for the clamp applied to this assembly (OF-365
    /// ILD-2); present under the same rule as `interlocutors`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<CoreDisclosureAssembly>)]
    disclosure: Option<oneiron::DisclosureAssembly>,
    /// Empty-result context when no entities surface.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    empty: Option<Value>,
}

/// Assemble a context pack from existing retrieval and hydration APIs.
#[utoipa::path(
    post,
    path = "/v1/core/context-pack",
    request_body(content = CoreContextPackRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Context pack assembled.", body = CoreContextPackResponse, content_type = "application/json"),
        (status = 400, description = "Malformed context-pack request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Context-pack assembly failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn core_context_pack(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<CoreContextPackRequest>, JsonRejection>,
) -> Result<Json<CoreContextPackResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let req = json_payload(payload)?;
    let (response, _, _) = run_context_pack(&server, &auth, req, None).await?;
    Ok(Json(response))
}

/// The shared context-pack pipeline behind `/v1/core/context-pack` and the
/// context board: validation, scoped retrieval, projection, and evidence.
///
/// When a memories request rides along, the MEMORIES section is projected
/// over the finished pack and the caller's cursor is advanced; both come back
/// beside the response. The caller has already required `CoreScope::Read`.
pub(crate) async fn run_context_pack(
    server: &SyncServer,
    auth: &CoreAuth,
    req: CoreContextPackRequest,
    memories: Option<MemoriesRequest>,
) -> Result<
    (
        CoreContextPackResponse,
        Option<oneiron::MemoriesSection>,
        Option<oneiron::MemoriesCursor>,
    ),
    ApiError,
> {
    let interlocutors =
        resolve_core_interlocutor_set(&server.vault, auth, req.interlocutors.as_ref())?;
    let query = non_empty_query(req.query.as_deref());
    validate_core_query_seeds(query, req.query_vector.as_deref())?;
    let (edge_hop, edge_hop_field, max_neighbors, max_neighbors_field) =
        resolved_context_pack_depth(req.depth.as_ref(), req.edge_hop, req.max_neighbors);
    validate_context_pack_depth(edge_hop, edge_hop_field, max_neighbors, max_neighbors_field)?;
    let hydrate = req
        .policy
        .as_ref()
        .and_then(|policy| policy.hydrate)
        .unwrap_or(req.hydrate);
    let include_edges = req
        .policy
        .as_ref()
        .and_then(|policy| policy.include_edges)
        .unwrap_or(req.include_edges);
    let include_vectors = req
        .policy
        .as_ref()
        .and_then(|policy| policy.include_vectors)
        .unwrap_or(req.include_vectors);
    let view = req
        .policy
        .as_ref()
        .and_then(|policy| policy.view)
        .or(req.view)
        .unwrap_or(View::Standard);
    let projection = context_pack_json_projection_config(view, req.budget.as_ref());
    let scoped_read = scoped_read_for_core_auth(&server.vault, auth)?;
    let candidate_limit = scoped_read
        .search_candidate_limit(req.limit, query.is_some(), req.query_vector.is_some())
        .map_err(|error| {
            tracing::error!(error = %error, "core context-pack scoped read setup failed");
            core_engine_error("core context-pack scoped read setup failed", error)
        })?;
    // OF-365 ILD-2: one DisclosureContext value feeds builder, board, and
    // response, so the response can never describe a different clamp than
    // the one applied (design §11 rule 6).
    let disclosure = interlocutors
        .as_ref()
        .map(|set| oneiron::DisclosureContext::resolve(&server.vault, set.clone()))
        .transpose()
        .map_err(|error| {
            tracing::error!(error = %error, "core context-pack disclosure resolution failed");
            core_engine_error("core context-pack disclosure resolution failed", error)
        })?;

    let mut builder = server
        .vault
        .context_pack()
        .limit(candidate_limit)
        .hydrate(hydrate)
        .include_edges(include_edges)
        .edge_hop(edge_hop)
        .max_neighbors(max_neighbors)
        .include_vectors(include_vectors)
        .field_profile(projection.profile);
    if let Some(query) = query {
        builder = builder.search_text(query, candidate_limit);
    }
    if let Some(vector) = req.query_vector.as_deref() {
        builder = builder.search_vector(vector, candidate_limit);
    }
    builder = apply_context_pack_policy(builder, req.policy.as_ref())?;
    builder = apply_context_pack_time(builder, req.time.as_ref())?;
    let (mut builder, retrieval_budget) = apply_context_pack_budget(
        builder,
        req.budget.as_ref(),
        candidate_limit,
        req.limit,
        max_neighbors,
    )?;
    if let Some(ctx) = disclosure.as_ref() {
        builder = builder.disclosure_context(ctx.clone());
    }

    let (mut response, memories, cursor) = run_context_pack_builder(
        &server.vault,
        &scoped_read,
        builder,
        projection,
        ContextPackResponseLimits {
            results: req.limit,
            neighbors: max_neighbors,
            retrieval: retrieval_budget,
        },
        memories,
        disclosure,
    )
    .await?;
    response.interlocutors = interlocutors.as_ref().map(oneiron::InterlocutorSet::stamps);
    Ok((response, memories, cursor))
}

/// Resolves the effective interlocutor set for a core context-pack request
/// (OF-365 ILD-1, design §11).
///
/// Returns `None` exactly when no interlocutors block was supplied on an
/// owner-grade credential: that request/response pair stays byte-identical to
/// pre-ILD behavior. In every other case the resolved set is echoed as
/// stamps on the response.
///
/// Owner-grade is `CoreAuth::is_owner_grade` — un-narrowed on BOTH axes. A
/// delegated token narrowed by scope alone is NOT owner-grade, so it takes
/// the clamp like any other narrowed credential rather than silently
/// skipping the gate.
pub(crate) fn resolve_core_interlocutor_set(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    controls: Option<&CoreInterlocutorControls>,
) -> Result<Option<oneiron::InterlocutorSet>, ApiError> {
    if controls.is_none() && auth.is_owner_grade() {
        return Ok(None);
    }

    let mut owner_present = None;
    let mut parties = Vec::new();
    let mut voice_session_ref = None;
    if let Some(controls) = controls {
        if controls.owner_present == Some(true) && !auth.is_owner_grade() {
            return Err(ApiError::forbidden_scope("interlocutors.owner_present"));
        }
        if controls.third_parties.len() > MAX_INTERLOCUTOR_THIRD_PARTIES {
            return Err(ApiError::bad_request(
                format!(
                    "third_parties must contain at most {MAX_INTERLOCUTOR_THIRD_PARTIES} entries"
                ),
                Some("interlocutors.third_parties"),
            ));
        }
        owner_present = controls.owner_present;
        for (index, party) in controls.third_parties.iter().enumerate() {
            parties.push(core_interlocutor_party_input(party, index)?);
        }
        voice_session_ref = controls.voice_session_ref.clone();
    }

    // Merge-always (RATIFY-20260710 R8): on principal_ref auth the implicit
    // principal-derived party ALWAYS enters the resolved set, regardless of
    // block presence, so DEC-0005 scope intersection can only narrow.
    if let Some(principal_ref) = auth.principal_ref() {
        let principal_id = parse_entity_id_param(principal_ref, "principal_ref")?;
        let party = match vault.get_counterparty_contact(&principal_id) {
            Ok(Some(_)) => oneiron::InterlocutorPartyInput::ContactRef(principal_id),
            // Companion principals are person/persona ids, not contact rows.
            Ok(None) | Err(oneiron::Error::InvalidEntityType(_)) => {
                oneiron::InterlocutorPartyInput::UnknownLabel {
                    label: principal_id.to_hex(),
                    claimed_owner: false,
                }
            }
            Err(error) => {
                tracing::error!(
                    error = %error,
                    "core context-pack interlocutor principal lookup failed"
                );
                return Err(core_engine_error(
                    "core context-pack interlocutor principal lookup failed",
                    error,
                ));
            }
        };
        parties.push(party);
    }

    // Owner presence is a conjunction, never a request assertion: the
    // credential must be owner-grade AND the caller must not have narrowed
    // itself away. `owner_present == Some(true)` was already rejected above
    // for non-owner-grade auth, so the `&&` here is the belt to that
    // suspenders — a narrowed credential can only ever resolve to `false`.
    let owner_session = auth.is_owner_grade() && owner_present.unwrap_or(true);
    let input = oneiron::InterlocutorResolutionInput {
        owner_session,
        parties,
        voice_session_ref,
    };
    vault
        .resolve_interlocutors(&input)
        .map(Some)
        .map_err(|error| {
            tracing::error!(error = %error, "core context-pack interlocutor resolution failed");
            core_engine_error("core context-pack interlocutor resolution failed", error)
        })
}

pub(crate) fn core_interlocutor_party_input(
    party: &CoreInterlocutorParty,
    index: usize,
) -> Result<oneiron::InterlocutorPartyInput, ApiError> {
    let field_path = |field: &str| format!("interlocutors.third_parties[{index}].{field}");
    let reject_claimed_owner = |party: &CoreInterlocutorParty| {
        if party.claimed_owner.is_some() {
            Err(ApiError::bad_request(
                "claimed_owner is only valid alongside label",
                Some(&field_path("claimed_owner")),
            ))
        } else {
            Ok(())
        }
    };
    match (
        party.contact_ref.as_deref(),
        party.channel_identity_ref.as_deref(),
        party.counterparty.as_deref(),
        party.label.as_deref(),
    ) {
        (Some(contact_ref), None, None, None) => {
            reject_claimed_owner(party)?;
            let field = field_path("contact_ref");
            let id = oneiron::EntityId::from_hex(contact_ref).map_err(|_| {
                ApiError::bad_request(
                    "contact_ref must be a 32-character hex entity id",
                    Some(&field),
                )
            })?;
            Ok(oneiron::InterlocutorPartyInput::ContactRef(id))
        }
        (None, Some(channel_identity_ref), Some(counterparty), None) => {
            reject_claimed_owner(party)?;
            let field = field_path("channel_identity_ref");
            let identity_ref = oneiron::EntityId::from_hex(channel_identity_ref).map_err(|_| {
                ApiError::bad_request(
                    "channel_identity_ref must be a 32-character hex entity id",
                    Some(&field),
                )
            })?;
            if counterparty.trim().is_empty() {
                return Err(ApiError::bad_request(
                    "counterparty must be non-empty",
                    Some(&field_path("counterparty")),
                ));
            }
            // Engine invariant enforced at the boundary: an untrimmed or
            // over-long key would otherwise surface from the contact lookup
            // as an engine error instead of a client error.
            if counterparty.trim() != counterparty
                || counterparty.len() > MAX_INTERLOCUTOR_COUNTERPARTY_BYTES
            {
                return Err(ApiError::bad_request(
                    format!(
                        "counterparty must be trimmed and at most \
                         {MAX_INTERLOCUTOR_COUNTERPARTY_BYTES} bytes"
                    ),
                    Some(&field_path("counterparty")),
                ));
            }
            Ok(oneiron::InterlocutorPartyInput::ChannelCounterparty {
                identity_ref,
                counterparty: counterparty.to_owned(),
            })
        }
        (None, None, None, Some(label)) => {
            if label.trim().is_empty() {
                return Err(ApiError::bad_request(
                    "label must be non-empty",
                    Some(&field_path("label")),
                ));
            }
            if label.len() > MAX_INTERLOCUTOR_LABEL_BYTES {
                return Err(ApiError::bad_request(
                    format!("label must be at most {MAX_INTERLOCUTOR_LABEL_BYTES} bytes"),
                    Some(&field_path("label")),
                ));
            }
            Ok(oneiron::InterlocutorPartyInput::UnknownLabel {
                label: label.to_owned(),
                claimed_owner: party.claimed_owner.unwrap_or(false),
            })
        }
        _ => Err(ApiError::bad_request(
            "each third party must supply exactly one of contact_ref, \
             channel_identity_ref+counterparty, or label",
            Some(&format!("interlocutors.third_parties[{index}]")),
        )),
    }
}

pub(crate) fn default_true() -> bool {
    true
}

pub(crate) fn default_context_neighbors() -> usize {
    50
}

pub(crate) fn resolved_context_pack_depth(
    depth: Option<&ContextPackDepthControls>,
    edge_hop: u32,
    max_neighbors: usize,
) -> (u32, &'static str, usize, &'static str) {
    let depth_edge_hop = depth.and_then(|depth| depth.edge_hop);
    let depth_max_neighbors = depth.and_then(|depth| depth.max_neighbors);
    (
        depth_edge_hop.unwrap_or(edge_hop),
        if depth_edge_hop.is_some() {
            "depth.edge_hop"
        } else {
            "edge_hop"
        },
        depth_max_neighbors.unwrap_or(max_neighbors),
        if depth_max_neighbors.is_some() {
            "depth.max_neighbors"
        } else {
            "max_neighbors"
        },
    )
}

pub(crate) fn validate_context_pack_depth(
    edge_hop: u32,
    edge_hop_field: &'static str,
    max_neighbors: usize,
    max_neighbors_field: &'static str,
) -> Result<(), ApiError> {
    if edge_hop > oneiron::context_pack::MAX_EDGE_HOP {
        return Err(ApiError::bad_request(
            format!(
                "edge_hop must be less than or equal to {}",
                oneiron::context_pack::MAX_EDGE_HOP
            ),
            Some(edge_hop_field),
        ));
    }
    if max_neighbors > oneiron::context_pack::MAX_CONTEXT_NEIGHBORS {
        return Err(ApiError::bad_request(
            format!(
                "max_neighbors must be less than or equal to {}",
                oneiron::context_pack::MAX_CONTEXT_NEIGHBORS
            ),
            Some(max_neighbors_field),
        ));
    }
    Ok(())
}

pub(crate) fn apply_context_pack_policy<'a>(
    mut builder: oneiron::ContextPackBuilder<'a>,
    policy: Option<&ContextPackPolicyControls>,
) -> Result<oneiron::ContextPackBuilder<'a>, ApiError> {
    let Some(policy) = policy else {
        return Ok(builder);
    };
    if let Some(half_life_days) = policy.boost_recency_days {
        if !half_life_days.is_finite() || half_life_days <= 0.0 {
            return Err(ApiError::bad_request(
                "boost_recency_days must be finite and positive",
                Some("policy.boost_recency_days"),
            ));
        }
        builder = builder.boost_recency(half_life_days);
    }
    if policy.boost_salience.unwrap_or(false) {
        builder = builder.boost_salience();
    }
    if policy.boost_confidence.unwrap_or(false) {
        builder = builder.boost_confidence();
    }
    if policy.boost_contiguity.unwrap_or(false) {
        builder = builder.boost_contiguity();
    }
    Ok(builder)
}

pub(crate) fn apply_context_pack_time<'a>(
    mut builder: oneiron::ContextPackBuilder<'a>,
    time: Option<&ContextPackTimeControls>,
) -> Result<oneiron::ContextPackBuilder<'a>, ApiError> {
    let Some(time) = time else {
        return Ok(builder);
    };
    let occurred_range = match (time.occurred_start, time.occurred_end) {
        (Some(start), Some(end)) if start <= end => Some((start, end)),
        (Some(_), Some(_)) => {
            return Err(ApiError::bad_request(
                "occurred_start must be less than or equal to occurred_end",
                Some("time.occurred_start"),
            ));
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(ApiError::bad_request(
                "occurred_start and occurred_end must be supplied together",
                Some("time"),
            ));
        }
        (None, None) => None,
    };
    let learned_range = match (time.learned_start, time.learned_end) {
        (Some(start), Some(end)) if start <= end => Some((start, end)),
        (Some(_), Some(_)) => {
            return Err(ApiError::bad_request(
                "learned_start must be less than or equal to learned_end",
                Some("time.learned_start"),
            ));
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(ApiError::bad_request(
                "learned_start and learned_end must be supplied together",
                Some("time"),
            ));
        }
        (None, None) => None,
    };
    if let (Some(since), Some((_, learned_end))) = (time.since, learned_range)
        && since > learned_end
    {
        return Err(ApiError::bad_request(
            "since must be less than or equal to learned_end",
            Some("time.since"),
        ));
    }
    if let Some(since) = time.since {
        builder = builder.filter_since(since);
    }
    if let Some((start, end)) = occurred_range {
        builder = builder.filter_occurred_range(start, end);
    }
    if let Some((start, end)) = learned_range {
        builder = builder.filter_learned_range(start, end);
    }
    Ok(builder)
}

pub(crate) fn apply_context_pack_budget<'a>(
    mut builder: oneiron::ContextPackBuilder<'a>,
    budget: Option<&ContextPackBudgetControls>,
    scoped_candidate_limit: usize,
    result_limit: usize,
    default_selected_edges: usize,
) -> Result<
    (
        oneiron::ContextPackBuilder<'a>,
        oneiron::ContextPackRetrievalBudget,
    ),
    ApiError,
> {
    if let Some(max_item_tokens) = budget.and_then(|budget| budget.max_item_tokens)
        && max_item_tokens > 0
    {
        builder = builder.max_item_tokens(max_item_tokens);
    }
    if let Some(budget) = budget {
        if let Some(token_budget) = budget.token_budget {
            builder = builder.token_budget(token_budget);
        }
        if let Some(max_field_chars) = budget.max_field_chars {
            builder = builder.max_field_chars(max_field_chars);
        }
    }
    let retrieval = budget.and_then(|budget| budget.retrieval.as_ref());
    if let Some(retrieval) = retrieval
        && retrieval.selected_edges.is_some_and(|selected_edges| {
            selected_edges > oneiron::context_pack::MAX_CONTEXT_NEIGHBORS
        })
    {
        return Err(ApiError::bad_request(
            format!(
                "selected_edges must be less than or equal to {}",
                oneiron::context_pack::MAX_CONTEXT_NEIGHBORS
            ),
            Some("budget.retrieval.selected_edges"),
        ));
    }
    let (response_budget, internal_budget) = resolve_context_pack_retrieval_budgets(
        retrieval,
        result_limit,
        scoped_candidate_limit,
        default_selected_edges,
    );
    builder = builder.retrieval_budget(internal_budget);
    Ok((builder, response_budget))
}

pub(crate) fn resolve_context_pack_retrieval_budgets(
    retrieval: Option<&ContextPackRetrievalBudgetControls>,
    result_limit: usize,
    scoped_candidate_limit: usize,
    default_selected_edges: usize,
) -> (
    oneiron::ContextPackRetrievalBudget,
    oneiron::ContextPackRetrievalBudget,
) {
    let selected_edges = retrieval
        .and_then(|retrieval| retrieval.selected_edges)
        .unwrap_or(default_selected_edges);
    let mut response_budget = oneiron::ContextPackRetrievalBudget::from_limit(
        result_limit,
        oneiron::TokenAllocation::default(),
        selected_edges,
    );
    if let Some(retrieval) = retrieval {
        if let Some(claims) = retrieval.claims {
            response_budget.claims = claims;
        }
        if let Some(turns) = retrieval.turns {
            response_budget.turns = turns;
        }
        if let Some(summaries) = retrieval.summaries {
            response_budget.summaries = summaries;
        }
        if let Some(facets) = retrieval.facets {
            response_budget.facets = facets;
        }
        if let Some(other) = retrieval.other {
            response_budget.other = other;
        }
    }
    let internal_budget =
        widen_context_pack_retrieval_budget(response_budget, scoped_candidate_limit);
    (response_budget, internal_budget)
}

pub(crate) fn widen_context_pack_retrieval_budget(
    budget: oneiron::ContextPackRetrievalBudget,
    scoped_candidate_limit: usize,
) -> oneiron::ContextPackRetrievalBudget {
    let widen = |bucket: usize| {
        if bucket == 0 {
            0
        } else {
            bucket.max(scoped_candidate_limit)
        }
    };
    oneiron::ContextPackRetrievalBudget::new(
        widen(budget.claims),
        widen(budget.turns),
        widen(budget.summaries),
        widen(budget.facets),
        widen(budget.other),
        budget.selected_edges,
    )
}

pub(crate) fn companion_scope_resolution_authorized(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    person_ref: Option<oneiron::EntityId>,
    persona_ref: Option<oneiron::EntityId>,
) -> Result<bool, ApiError> {
    if auth.has_scope(CoreScope::CompanionRegisterRead) || auth.has_scope(CoreScope::Auth) {
        return Ok(true);
    }
    let (Some(person_ref), Some(persona_ref)) = (person_ref, persona_ref) else {
        return Ok(false);
    };
    let Some(principal_ref) = auth_bound_principal_ref(auth)? else {
        return Ok(false);
    };
    vault
        .companion_profile_access_grant(&principal_ref, &person_ref, &persona_ref)
        .map(|grant| grant.is_some())
        .map_err(|error| {
            tracing::error!(
                error = %error,
                principal_ref = %principal_ref.to_hex(),
                person_ref = %person_ref.to_hex(),
                persona_ref = %persona_ref.to_hex(),
                "companion profile grant lookup failed"
            );
            core_engine_error("companion profile grant lookup failed", error)
        })
}

#[derive(Clone, Copy)]
pub(crate) struct ContextPackResponseLimits {
    pub(crate) results: usize,
    pub(crate) neighbors: usize,
    pub(crate) retrieval: oneiron::ContextPackRetrievalBudget,
}

pub(crate) fn apply_context_pack_response_limits(
    pack: &mut oneiron::ContextPack,
    limits: ContextPackResponseLimits,
) {
    apply_context_pack_response_retrieval_budget(pack, limits.retrieval);
    pack.results.truncate(limits.results);
    pack.neighbors.truncate(limits.neighbors);
    scrub_context_pack_visible_stats(pack);
}

pub(crate) fn apply_context_pack_response_retrieval_budget(
    pack: &mut oneiron::ContextPack,
    budget: oneiron::ContextPackRetrievalBudget,
) {
    let mut claims = 0_usize;
    let mut turns = 0_usize;
    let mut summaries = 0_usize;
    let mut facets = 0_usize;
    let mut other = 0_usize;
    pack.results.retain(|entity| {
        let (count, limit) = match entity.entity_type {
            oneiron::registry::ENTITY_TYPE_CLAIM => (&mut claims, budget.claims),
            oneiron::registry::ENTITY_TYPE_TURN => (&mut turns, budget.turns),
            oneiron::registry::ENTITY_TYPE_SUMMARY => (&mut summaries, budget.summaries),
            oneiron::registry::ENTITY_TYPE_FACET => (&mut facets, budget.facets),
            _ => (&mut other, budget.other),
        };
        if *count >= limit {
            return false;
        }
        *count += 1;
        true
    });
}

pub(crate) fn scrub_context_pack_visible_stats(pack: &mut oneiron::ContextPack) {
    pack.stats.candidates_considered = pack.results.len();
    pack.stats.entities_hydrated = pack.results.len();
    pack.stats.neighbors_hydrated = pack.neighbors.len();

    if pack.results.is_empty() && pack.neighbors.is_empty() {
        if let Some(empty) = pack.empty.as_mut() {
            empty.total_in_scope = 0;
        } else {
            pack.empty = Some(oneiron::EmptyContext {
                retrieval_quality: pack.retrieval_quality.clone(),
                reason: oneiron::EmptyReason::FilterMatchedNone,
                total_in_scope: 0,
                hint: "Try removing filters or widening the world, type, or time scope".to_owned(),
            });
        }
    } else {
        pack.empty = None;
    }
}

pub(crate) async fn run_context_pack_builder(
    vault: &oneiron::Vault,
    scoped_read: &oneiron::claim::ScopedRead<'_>,
    builder: oneiron::ContextPackBuilder<'_>,
    projection: oneiron::serialize::SerializeConfig,
    response_limits: ContextPackResponseLimits,
    memories: Option<MemoriesRequest>,
    disclosure: Option<oneiron::DisclosureContext>,
) -> Result<
    (
        CoreContextPackResponse,
        Option<oneiron::MemoriesSection>,
        Option<oneiron::MemoriesCursor>,
    ),
    ApiError,
> {
    let mut pack = builder.run_unfinalized_with_telemetry().map_err(|error| {
        tracing::error!(error = %error, "core context-pack failed");
        core_engine_error("core context-pack failed", error)
    })?;
    let clamped_out = pack.clamped_out();
    scoped_read
        .filter_context_pack(&mut pack.value)
        .map_err(|error| {
            pack.discard_telemetry();
            tracing::error!(error = %error, "core context-pack scoped read failed");
            core_engine_error("core context-pack scoped read failed", error)
        })?;
    apply_context_pack_response_limits(&mut pack.value, response_limits);
    let pack = pack.finish_projected_json(&projection);
    let run_id = pack.run_id;
    let pack = pack.value;
    let evidence = core_context_pack_evidence(vault, run_id)?;
    let evidence = core_context_pack_evidence_for_results(evidence, &pack.results);
    let assembly = disclosure.as_ref().map(|ctx| ctx.assembly(clamped_out));
    let (section, cursor) = match memories.as_ref() {
        Some(request) => {
            let section = request.memory_board_budget.map(|budget| {
                oneiron::context_board::project_memories_section(
                    &pack,
                    budget,
                    request.companion.clone(),
                    assembly.clone(),
                )
            });
            let cursor = advance_memories_cursor(
                vault,
                &request.session_scope_id,
                &request.session_id,
                &pack,
                &evidence,
            )
            .await;
            (section, Some(cursor))
        }
        None => (None, None),
    };
    Ok((
        core_context_pack_response(pack, evidence, assembly),
        section,
        cursor,
    ))
}

pub(crate) fn field_profile_for_view(view: View) -> oneiron::FieldProfile {
    match view {
        View::Summary => oneiron::FieldProfile::Minimal,
        View::Standard => oneiron::FieldProfile::Standard,
        View::Full => oneiron::FieldProfile::Full,
    }
}

pub(crate) fn context_pack_json_projection_config(
    view: View,
    budget: Option<&ContextPackBudgetControls>,
) -> oneiron::serialize::SerializeConfig {
    oneiron::serialize::SerializeConfig {
        format: oneiron::PackFormat::Json,
        profile: field_profile_for_view(view),
        budget: budget.and_then(|budget| budget.token_budget).unwrap_or(0),
        allocation: oneiron::TokenAllocation::default(),
        include_stats: false,
        merge_neighbors: false,
        max_field_chars: budget
            .and_then(|budget| budget.max_field_chars)
            .unwrap_or(oneiron::context_pack::DEFAULT_MAX_FIELD_CHARS),
        max_item_tokens: budget
            .and_then(|budget| budget.max_item_tokens)
            .unwrap_or(0),
    }
}

pub(crate) fn core_context_pack_evidence_for_results(
    mut evidence: CoreContextPackEvidence,
    results: &[oneiron::ContextEntity],
) -> CoreContextPackEvidence {
    let result_ids: BTreeSet<String> = results.iter().map(|entity| entity.id.to_hex()).collect();
    evidence
        .result_ids
        .retain(|result_id| result_ids.contains(result_id));
    evidence
        .scores
        .retain(|score| result_ids.contains(&score.result_id));
    evidence
}

pub(crate) fn core_context_pack_response(
    pack: oneiron::ContextPack,
    evidence: CoreContextPackEvidence,
    disclosure: Option<oneiron::DisclosureAssembly>,
) -> CoreContextPackResponse {
    let state = core_context_pack_state(pack.empty.as_ref());
    CoreContextPackResponse {
        quality: Some(pack.retrieval_quality.quality),
        degradation: (!pack.retrieval_quality.degradation.is_empty())
            .then_some(pack.retrieval_quality.degradation),
        confidence_adjustment: Some(pack.retrieval_quality.confidence_adjustment),
        results: pack.results.into_iter().map(core_context_entity).collect(),
        neighbors: pack
            .neighbors
            .into_iter()
            .map(core_context_entity)
            .collect(),
        stats: core_context_pack_stats(pack.stats),
        state,
        evidence,
        interlocutors: None,
        disclosure,
        empty: pack
            .empty
            .map(|empty| serde_json::to_value(empty).expect("EmptyContext serializes")),
    }
}

pub(crate) fn core_context_entity(entity: oneiron::ContextEntity) -> CoreContextEntity {
    CoreContextEntity {
        id: entity.id.to_hex(),
        short_id: entity.short_id,
        content_hash: format!("{:02x}", entity.content_hash),
        entity_type: entity.entity_type,
        score: entity.score,
        fields: entity.fields.map(BTreeMap::from_iter),
        edges: entity
            .edges
            .map(|edges| edges.into_iter().map(core_context_edge).collect()),
        vector: entity.vector,
    }
}

pub(crate) fn core_context_edge(edge: oneiron::EdgeInfo) -> CoreContextEdge {
    CoreContextEdge {
        kind: edge.kind as u8,
        target: edge.target.to_hex(),
        target_short_id: edge.target_short_id,
        weight: edge.weight,
        created_at: edge.created_at,
        vad: edge.vad.map(Into::into),
    }
}

pub(crate) fn core_context_pack_stats(stats: oneiron::PackStats) -> CoreContextPackStats {
    CoreContextPackStats {
        candidates_considered: stats.candidates_considered,
        signals_used: stats
            .signals_used
            .into_iter()
            .map(|signal| signal_name(signal).to_owned())
            .collect(),
        query_time_us: stats.query_time_us,
        entities_hydrated: stats.entities_hydrated,
        neighbors_hydrated: stats.neighbors_hydrated,
        cosine_ghosts_dampened: stats.cosine_ghosts_dampened,
        claims_suppressed: stats.claims_suppressed,
        items_truncated: CoreContextPackItemAccounting {
            count: stats.items_truncated.count,
            reason: stats.items_truncated.reason.as_str().to_owned(),
        },
        items_dropped: CoreContextPackItemAccounting {
            count: stats.items_dropped.count,
            reason: stats.items_dropped.reason.as_str().to_owned(),
        },
    }
}

pub(crate) fn core_context_pack_state(
    empty: Option<&oneiron::EmptyContext>,
) -> CoreContextPackState {
    let Some(empty) = empty else {
        return CoreContextPackState {
            kind: CoreContextPackStateKind::Ok,
            reason: None,
            total_in_scope: None,
            hint: None,
        };
    };
    CoreContextPackState {
        kind: match empty.reason {
            oneiron::EmptyReason::BelowThreshold => CoreContextPackStateKind::LowConfidence,
            oneiron::EmptyReason::FilterMatchedNone
            | oneiron::EmptyReason::NoData
            | oneiron::EmptyReason::AllActivated => CoreContextPackStateKind::MissingData,
        },
        reason: Some(core_context_pack_state_reason(empty.reason)),
        total_in_scope: Some(empty.total_in_scope),
        hint: Some(empty.hint.clone()),
    }
}

pub(crate) fn core_context_pack_state_reason(
    reason: oneiron::EmptyReason,
) -> CoreContextPackStateReason {
    match reason {
        oneiron::EmptyReason::FilterMatchedNone => CoreContextPackStateReason::FilterMatchedNone,
        oneiron::EmptyReason::NoData => CoreContextPackStateReason::NoData,
        oneiron::EmptyReason::AllActivated => CoreContextPackStateReason::AllActivated,
        oneiron::EmptyReason::BelowThreshold => CoreContextPackStateReason::BelowThreshold,
    }
}

pub(crate) fn core_context_pack_evidence(
    vault: &oneiron::Vault,
    run_id: Option<oneiron::RetrievalRunId>,
) -> Result<CoreContextPackEvidence, ApiError> {
    let Some(run_id) = run_id else {
        return Ok(CoreContextPackEvidence {
            telemetry_persisted: false,
            retrieval_run_id: None,
            result_ids: Vec::new(),
            scores: Vec::new(),
        });
    };
    let Some(record) = vault.retrieval_run(run_id).map_err(|error| {
        tracing::error!(error = %error, "context-pack telemetry lookup failed");
        core_engine_error("context-pack telemetry lookup failed", error)
    })?
    else {
        return Ok(CoreContextPackEvidence {
            telemetry_persisted: false,
            retrieval_run_id: None,
            result_ids: Vec::new(),
            scores: Vec::new(),
        });
    };
    Ok(CoreContextPackEvidence {
        telemetry_persisted: true,
        retrieval_run_id: Some(record.run_id.to_hex()),
        result_ids: record.result_ids.iter().map(|id| hex_bytes(id)).collect(),
        scores: record
            .score_breakdown
            .into_iter()
            .map(core_context_pack_score_evidence)
            .collect(),
    })
}

pub(crate) fn core_context_pack_score_evidence(
    score: oneiron::RetrievalScoreBreakdown,
) -> CoreContextPackScoreEvidence {
    CoreContextPackScoreEvidence {
        result_id: hex_bytes(&score.result_id),
        final_rank: score.final_rank,
        final_score: score.final_score,
        access_factor: score.access_factor,
        components: score
            .components
            .into_iter()
            .map(core_context_pack_score_component)
            .collect(),
    }
}

pub(crate) fn core_context_pack_score_component(
    component: oneiron::RetrievalScoreComponent,
) -> CoreContextPackScoreComponent {
    CoreContextPackScoreComponent {
        signal: retrieval_signal_name(component.signal).to_owned(),
        rank: component.rank,
        score: component.score,
    }
}

pub(crate) fn signal_name(signal: oneiron::Signal) -> &'static str {
    match signal {
        oneiron::Signal::Vector => "vector",
        oneiron::Signal::Text => "text",
        oneiron::Signal::Phonetic => "phonetic",
        oneiron::Signal::Temporal => "temporal",
        oneiron::Signal::Ppr => "ppr",
        _ => "unknown",
    }
}

pub(crate) fn retrieval_signal_name(signal: oneiron::RetrievalSignal) -> &'static str {
    match signal {
        oneiron::RetrievalSignal::Vector => "vector",
        oneiron::RetrievalSignal::Text => "text",
        oneiron::RetrievalSignal::Phonetic => "phonetic",
        oneiron::RetrievalSignal::Temporal => "temporal",
        oneiron::RetrievalSignal::Ppr => "ppr",
        oneiron::RetrievalSignal::Recency => "recency",
        oneiron::RetrievalSignal::Salience => "salience",
        oneiron::RetrievalSignal::Confidence => "confidence",
        oneiron::RetrievalSignal::Gravity => "gravity",
        oneiron::RetrievalSignal::Rerank => "rerank",
        oneiron::RetrievalSignal::Hyde => "hyde",
        oneiron::RetrievalSignal::HydeRetry => "hyde_retry",
    }
}
