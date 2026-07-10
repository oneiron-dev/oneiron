use super::VadPayload;
use super::auth_bound_principal_ref;
use super::check_api_auth;
use super::core_engine_error;
use super::default_limit;
use super::hex_bytes;
use super::json_payload;
use super::non_empty_query;
use super::parse_entity_id_param;
use super::resume_caller;
use super::scoped_read_for_core_auth;
use super::scoped_read_for_legacy_api;
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
use axum::http::HeaderMap;
use axum::response::Json;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::sync::Mutex;
use utoipa::ToSchema;

pub(crate) const EIRI_SESSION_RAG_STATE_MAX_ENTRIES: usize = 1024;

pub(crate) const EIRI_SESSION_RAG_SESSION_ID_MAX_BYTES: usize = 256;

pub(crate) const EIRI_SESSION_RAG_LAST_RESULT_IDS_MAX: usize = 256;

pub(crate) const SHARED_EIRI_SESSION_SCOPE_IDS: &[&str] =
    &["bearer", "dev-bearer", "default", "legacy-shared-secret"];

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

pub(crate) static EIRI_SESSION_RAG_STATE: OnceLock<Mutex<EiriSessionRagStore>> = OnceLock::new();

#[derive(Default)]
pub(crate) struct EiriSessionRagStore {
    pub(crate) entries: BTreeMap<String, oneiron::EiriSessionRagState>,
    active_sessions: BTreeMap<String, String>,
    insertion_order: VecDeque<String>,
}

impl EiriSessionRagStore {
    pub(crate) fn current(
        &mut self,
        key: String,
        session_id: &str,
    ) -> oneiron::EiriSessionRagState {
        if let Some(state) = self.entries.get(&key) {
            return state.clone();
        }

        self.evict_if_full();
        let state = oneiron::EiriSessionRagState::new(session_id);
        self.entries.insert(key.clone(), state.clone());
        self.insertion_order.push_back(key);
        state
    }

    fn current_for_scope(
        &mut self,
        scope_key: String,
        default_key: String,
        default_session_id: &str,
    ) -> oneiron::EiriSessionRagState {
        if let Some(active_key) = self.active_sessions.get(&scope_key).cloned() {
            if let Some(state) = self.entries.get(&active_key) {
                return state.clone();
            }
            self.active_sessions.remove(&scope_key);
        }

        self.current(default_key, default_session_id)
    }

    pub(crate) fn advance(
        &mut self,
        scope_key: String,
        key: String,
        session_id: &str,
        pack: &oneiron::ContextPack,
        evidence: &CoreContextPackEvidence,
    ) -> oneiron::EiriSessionRagState {
        if !self.entries.contains_key(&key) {
            self.evict_if_full();
            self.entries
                .insert(key.clone(), oneiron::EiriSessionRagState::new(session_id));
            self.insertion_order.push_back(key.clone());
        }

        let state = self
            .entries
            .get_mut(&key)
            .expect("entry inserted before mutation");
        state.revision = state.revision.saturating_add(1);
        state.query_count = state.query_count.saturating_add(1);
        state.last_retrieval_run_id = evidence.retrieval_run_id.clone();
        state.last_result_ids = pack
            .results
            .iter()
            .take(EIRI_SESSION_RAG_LAST_RESULT_IDS_MAX)
            .map(|entity| entity.id.to_hex())
            .collect();
        let state = state.clone();
        self.active_sessions.insert(scope_key, key);
        state
    }

    fn evict_if_full(&mut self) {
        while self.entries.len() >= EIRI_SESSION_RAG_STATE_MAX_ENTRIES {
            let Some(key) = self.insertion_order.pop_front() else {
                self.entries.clear();
                self.active_sessions.clear();
                break;
            };
            if self.entries.remove(&key).is_some() {
                self.active_sessions
                    .retain(|_, active_key| active_key != &key);
                break;
            }
        }
    }
}

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

/// Eiri Context v4 memory-board per-slot row caps.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct EiriMemoryBoardSlotControls {
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
    pub(crate) companions: Option<usize>,
    #[serde(default)]
    #[schema(example = 1)]
    pub(crate) other: Option<usize>,
}

/// Eiri Context v4 memory-board controls.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct EiriMemoryBoardControls {
    /// Whether to emit the v4 memory board. Defaults to true when v4 is requested.
    #[serde(default)]
    #[schema(example = true)]
    pub(crate) enabled: Option<bool>,
    /// Exact per-slot row caps for the memory board.
    #[serde(default)]
    pub(crate) slots: Option<EiriMemoryBoardSlotControls>,
}

/// Eiri Context v4 session RAG controls.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct EiriSessionRagControls {
    /// Stable caller/session key used to carry RAG state across calls.
    #[serde(default, rename = "session_id", alias = "sessionId")]
    #[schema(example = "default")]
    session_id: Option<String>,
}

/// Companion context that influences Eiri Context v4 assembly.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct EiriCompanionControls {
    #[serde(default, rename = "person_ref", alias = "personRef")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    person_ref: Option<String>,
    #[serde(default, rename = "persona_ref", alias = "personaRef")]
    #[schema(example = "fedcba9876543210fedcba9876543210")]
    persona_ref: Option<String>,
    #[serde(default)]
    #[schema(example = "warm")]
    expression: Option<String>,
}

/// Interlocutor presence controls for context-pack assembly (OF-365 ILD-1).
///
/// The wire shape deliberately cannot express interlocutor class or presence
/// evidence: owner presence keys to the authenticated session, and every
/// supplied party resolves to a non-owner entry.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct CoreInterlocutorControls {
    /// Physical owner presence asserted by the embedder. May only be `true`
    /// on an owner-grade session (403 otherwise); `false` always narrows.
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

pub(crate) struct EiriContextV4Request {
    memory_board_budget: Option<oneiron::EiriMemoryBoardBudget>,
    session_scope_id: String,
    session_id: String,
    companion: Option<oneiron::EiriCompanionAssembly>,
}

pub(crate) struct EiriContextV4Identity<'a> {
    fallback_session_id: &'a str,
    companion_auth: Option<&'a CoreAuth>,
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
    /// Optional context format version. Use "v4" to request Eiri Context v4 fields.
    #[serde(default, rename = "context_version", alias = "contextVersion")]
    #[schema(example = "v4")]
    context_version: Option<String>,
    /// Optional Eiri Context v4 memory-board controls.
    #[serde(default, rename = "memory_board", alias = "memoryBoard")]
    memory_board: Option<EiriMemoryBoardControls>,
    /// Optional Eiri Context v4 session RAG controls.
    #[serde(default, rename = "session_rag", alias = "sessionRag")]
    session_rag: Option<EiriSessionRagControls>,
    /// Optional companion scope for Eiri Context v4 assembly.
    #[serde(default)]
    companion: Option<EiriCompanionControls>,
    /// Optional interlocutor presence controls (OF-365 ILD-1).
    #[serde(default)]
    interlocutors: Option<CoreInterlocutorControls>,
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

/// Stable Eiri Context v4 memory-board slot name.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoreEiriMemoryBoardSlot {
    Claims,
    Turns,
    Summaries,
    Facets,
    Companions,
    Other,
}

/// Source section for one Eiri Context v4 memory-board row.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoreEiriMemoryBoardSource {
    Result,
    Neighbor,
}

/// Per-slot row caps for an Eiri Context v4 memory board.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreEiriMemoryBoardBudget {
    /// Claim row cap.
    #[schema(example = 2)]
    claims: usize,
    /// Turn/message row cap.
    #[schema(example = 4)]
    turns: usize,
    /// Summary row cap.
    #[schema(example = 1)]
    summaries: usize,
    /// Facet row cap.
    #[schema(example = 1)]
    facets: usize,
    /// Companion-register row cap.
    #[schema(example = 0)]
    companions: usize,
    /// Row cap for all other entity types.
    #[schema(example = 2)]
    other: usize,
}

/// Companion assembly metadata echoed with an Eiri Context v4 memory board.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreEiriCompanionAssembly {
    /// Effective caller/session identity used for the v4 board.
    #[schema(example = "session-123")]
    caller: Option<String>,
    /// Effective companion scope selected from active companion records.
    #[schema(example = "personal")]
    scope: Option<String>,
    /// Active record class that selected the companion scope.
    #[serde(rename = "scope_source")]
    #[schema(example = "persona_and_relationship_records")]
    scope_source: Option<String>,
    /// Optional person entity id for companion-aware assembly metadata.
    #[serde(rename = "person_ref")]
    #[schema(example = "11111111111111111111111111111111")]
    person_ref: Option<String>,
    /// Optional persona entity id for companion-aware assembly metadata.
    #[serde(rename = "persona_ref")]
    #[schema(example = "22222222222222222222222222222222")]
    persona_ref: Option<String>,
    /// Effective expression register boundary.
    #[schema(example = "warm")]
    expression: Option<String>,
}

/// Stable row in an Eiri Context v4 memory board.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreEiriMemoryBoardRow {
    /// Zero-based index after stable sorting and slot-budget filtering.
    #[serde(rename = "row_index")]
    #[schema(example = 0)]
    row_index: usize,
    /// Budget slot that owns this row.
    slot: CoreEiriMemoryBoardSlot,
    /// Whether the row came from primary results or neighbors.
    source: CoreEiriMemoryBoardSource,
    /// Hex entity id.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: String,
    /// Short id used for compact display.
    #[serde(rename = "short_id")]
    #[schema(example = "tr_a1b2c3d4")]
    short_id: String,
    /// One-byte content hash as two lowercase hex digits.
    #[serde(rename = "content_hash")]
    #[schema(example = "a7")]
    content_hash: String,
    /// Numeric entity type byte.
    #[serde(rename = "entity_type")]
    #[schema(example = 1)]
    entity_type: u8,
    /// Short ref for ASSET and ASSET_TEXT rows. Consumers pass this to the core hydrate resolver.
    #[serde(rename = "asset_ref", skip_serializing_if = "Option::is_none")]
    #[schema(example = "tx123:a7")]
    asset_ref: Option<String>,
    /// Retrieval score.
    #[schema(example = 0.87)]
    score: f32,
}

/// Eiri Context v4 memory-board response envelope.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreEiriMemoryBoard {
    /// Context version for this memory-board envelope.
    #[schema(example = "v4")]
    version: String,
    /// Applied per-slot row budget.
    budget: CoreEiriMemoryBoardBudget,
    /// Stable memory-board rows.
    rows: Vec<CoreEiriMemoryBoardRow>,
    /// Companion assembly metadata when v4 companion controls are present.
    companion: Option<CoreEiriCompanionAssembly>,
}

/// Eiri Context v4 session RAG cursor response.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreEiriSessionRagState {
    /// Effective v4 session id.
    #[serde(rename = "session_id")]
    #[schema(example = "session-123")]
    session_id: String,
    /// Monotonic cursor revision for this session.
    #[schema(example = 2_u64)]
    revision: u64,
    /// Number of context-pack queries observed for this session.
    #[serde(rename = "query_count")]
    #[schema(example = 2_u64)]
    query_count: u64,
    /// Last persisted retrieval telemetry run id, when available.
    #[serde(rename = "last_retrieval_run_id")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    last_retrieval_run_id: Option<String>,
    /// Bounded list of most recent context-pack result ids for this session.
    #[serde(rename = "last_result_ids")]
    last_result_ids: Vec<String>,
}

/// Context-pack response envelope.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreContextPackResponse {
    /// Optional context format version for v4 response extensions.
    #[serde(rename = "context_version", skip_serializing_if = "Option::is_none")]
    #[schema(example = "v4")]
    context_version: Option<String>,
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
    /// Eiri Context v4 memory-board rows when requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<CoreEiriMemoryBoard>)]
    memory_board: Option<oneiron::EiriMemoryBoard>,
    /// Eiri Context v4 session RAG state when requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<CoreEiriSessionRagState>)]
    session_rag: Option<oneiron::EiriSessionRagState>,
    /// Resolved per-speaker interlocutor stamps when an interlocutors block
    /// was supplied or the auth is principal_ref-scoped (OF-365 ILD-1).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Vec<CoreInterlocutorStamp>>)]
    interlocutors: Option<Vec<oneiron::InterlocutorStamp>>,
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
    let interlocutors =
        resolve_core_interlocutor_set(&server.vault, &auth, req.interlocutors.as_ref())?;
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
    let projection = context_pack_json_projection_config(view, req.budget.as_ref(), 0);
    let scoped_read = scoped_read_for_core_auth(&server.vault, &auth)?;
    let candidate_limit = scoped_read
        .search_candidate_limit(req.limit, query.is_some(), req.query_vector.is_some())
        .map_err(|error| {
            tracing::error!(error = %error, "core context-pack scoped read setup failed");
            core_engine_error("core context-pack scoped read setup failed", error)
        })?;
    let fallback_session_id = auth.principal_ref().unwrap_or(auth.principal());
    let eiri_context = resolve_eiri_context_v4_request(
        &server.vault,
        req.context_version.as_deref(),
        req.memory_board.as_ref(),
        req.session_rag.as_ref(),
        req.companion.as_ref(),
        (req.limit, max_neighbors),
        EiriContextV4Identity {
            fallback_session_id,
            companion_auth: Some(&auth),
        },
    )?;

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
    let (builder, retrieval_budget) = apply_context_pack_budget(
        builder,
        req.budget.as_ref(),
        0,
        candidate_limit,
        req.limit,
        max_neighbors,
    )?;

    let mut response = run_context_pack_builder(
        &server.vault,
        &scoped_read,
        builder,
        projection,
        ContextPackResponseLimits {
            results: req.limit,
            neighbors: max_neighbors,
            retrieval: retrieval_budget,
        },
        "core context-pack failed",
        eiri_context,
    )
    .await?;
    response.interlocutors = interlocutors.as_ref().map(oneiron::InterlocutorSet::stamps);
    Ok(Json(response))
}

/// Resolves the effective interlocutor set for a core context-pack request
/// (OF-365 ILD-1, design §11).
///
/// Returns `None` exactly when no interlocutors block was supplied on an
/// owner-grade session: that request/response pair stays byte-identical to
/// pre-ILD behavior. In every other case the resolved set is echoed as
/// stamps on the response.
pub(crate) fn resolve_core_interlocutor_set(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    controls: Option<&CoreInterlocutorControls>,
) -> Result<Option<oneiron::InterlocutorSet>, ApiError> {
    if controls.is_none() && auth.is_owner_session() {
        return Ok(None);
    }

    let mut owner_present = None;
    let mut parties = Vec::new();
    let mut voice_session_ref = None;
    if let Some(controls) = controls {
        if controls.owner_present == Some(true) && !auth.is_owner_session() {
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

    let owner_session = owner_present.unwrap_or(auth.is_owner_session()) && auth.is_owner_session();
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
    top_level_max_item_tokens: usize,
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
    let max_item_tokens = budget
        .and_then(|budget| budget.max_item_tokens)
        .unwrap_or(top_level_max_item_tokens);
    if max_item_tokens > 0 {
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

pub(crate) fn resolve_eiri_context_v4_request(
    vault: &oneiron::Vault,
    context_version: Option<&str>,
    memory_board: Option<&EiriMemoryBoardControls>,
    session_rag: Option<&EiriSessionRagControls>,
    companion: Option<&EiriCompanionControls>,
    budget_shape: (usize, usize),
    identity: EiriContextV4Identity<'_>,
) -> Result<Option<EiriContextV4Request>, ApiError> {
    let requested = context_version.is_some()
        || memory_board.is_some()
        || session_rag.is_some()
        || companion.is_some();
    if !requested {
        return Ok(None);
    }

    let version = context_version.unwrap_or(oneiron::EIRI_CONTEXT_VERSION_V4);
    if version != oneiron::EIRI_CONTEXT_VERSION_V4 {
        return Err(ApiError::bad_request(
            "context_version must be v4",
            Some("context_version"),
        ));
    }

    let session_scope_id = identity.fallback_session_id.trim();
    validate_eiri_session_id(session_scope_id, "session_rag.scope")?;
    if is_shared_eiri_session_scope_id(session_scope_id) {
        return Err(ApiError::bad_request(
            "session_rag.session_id requires an isolated caller identity",
            Some("session_rag.session_id"),
        ));
    }

    let session_id = session_rag
        .and_then(|state| state.session_id.as_deref())
        .unwrap_or(session_scope_id)
        .trim();
    validate_eiri_session_id(session_id, "session_rag.session_id")?;

    let memory_board_budget = memory_board
        .and_then(|controls| controls.enabled)
        .unwrap_or(true)
        .then(|| eiri_memory_board_budget(memory_board, budget_shape.0, budget_shape.1));

    let companion =
        resolve_eiri_companion_assembly(vault, companion, session_id, identity.companion_auth)?;

    Ok(Some(EiriContextV4Request {
        memory_board_budget,
        session_scope_id: session_scope_id.to_owned(),
        session_id: session_id.to_owned(),
        companion: Some(companion),
    }))
}

pub(crate) fn resolve_eiri_companion_assembly(
    vault: &oneiron::Vault,
    companion: Option<&EiriCompanionControls>,
    session_id: &str,
    companion_auth: Option<&CoreAuth>,
) -> Result<oneiron::EiriCompanionAssembly, ApiError> {
    let (person_ref_wire, person_ref) = parse_companion_ref(
        companion.and_then(|controls| controls.person_ref.as_deref()),
        "companion.person_ref",
    )?;
    let (persona_ref_wire, persona_ref) = parse_companion_ref(
        companion.and_then(|controls| controls.persona_ref.as_deref()),
        "companion.persona_ref",
    )?;
    let requested_expression = companion
        .and_then(|controls| controls.expression.as_deref())
        .map(|value| {
            oneiron::CompanionExpression::parse(value).ok_or_else(|| {
                ApiError::bad_request(
                    "companion.expression must be professional, warm, or unrestricted",
                    Some("companion.expression"),
                )
            })
        })
        .transpose()?;
    let fallback_expression =
        requested_expression.unwrap_or(oneiron::CompanionExpression::Professional);
    if !companion_scope_resolution_authorized(vault, companion_auth, person_ref, persona_ref)? {
        return Ok(oneiron::EiriCompanionAssembly {
            caller: Some(session_id.to_owned()),
            scope: Some(companion_scope_wire(&oneiron::CompanionScope::neutral()).to_owned()),
            scope_source: Some(
                oneiron::CompanionScopeResolutionSource::NeutralDefault
                    .as_str()
                    .to_owned(),
            ),
            person_ref: person_ref_wire,
            persona_ref: persona_ref_wire,
            expression: Some(fallback_expression.as_str().to_owned()),
        });
    }
    let register = vault.companion_register().map_err(|error| {
        tracing::error!(error = %error, "companion scope resolution failed");
        core_engine_error("companion scope resolution failed", error)
    })?;
    let relationship_ref = person_ref.zip(persona_ref);
    let mut expressions = oneiron::CompanionExpressionRegister::new();
    let resolution = if let Some(expression) = requested_expression {
        let seed_resolution = register.resolve_companion_scope(
            &expressions,
            person_ref,
            persona_ref,
            relationship_ref,
        );
        if let Some(key) = seed_resolution
            .relationship_key
            .as_ref()
            .or(seed_resolution.persona_key.as_ref())
        {
            expressions
                .update(key.clone(), expression)
                .map_err(|error| {
                    tracing::error!(error = %error, "companion expression registration failed");
                    core_engine_error("companion expression registration failed", error)
                })?;
            register.resolve_companion_scope(
                &expressions,
                person_ref,
                persona_ref,
                relationship_ref,
            )
        } else {
            seed_resolution
        }
    } else {
        register.resolve_companion_scope(&expressions, person_ref, persona_ref, relationship_ref)
    };
    let expression = requested_expression.unwrap_or(resolution.expression);

    Ok(oneiron::EiriCompanionAssembly {
        caller: Some(session_id.to_owned()),
        scope: Some(companion_scope_wire(&resolution.scope).to_owned()),
        scope_source: Some(resolution.source.as_str().to_owned()),
        person_ref: person_ref_wire,
        persona_ref: persona_ref_wire,
        expression: Some(expression.as_str().to_owned()),
    })
}

pub(crate) fn companion_scope_resolution_authorized(
    vault: &oneiron::Vault,
    companion_auth: Option<&CoreAuth>,
    person_ref: Option<oneiron::EntityId>,
    persona_ref: Option<oneiron::EntityId>,
) -> Result<bool, ApiError> {
    let Some(auth) = companion_auth else {
        return Ok(true);
    };
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

pub(crate) fn parse_companion_ref(
    value: Option<&str>,
    field: &'static str,
) -> Result<(Option<String>, Option<oneiron::EntityId>), ApiError> {
    let Some(raw) = value else {
        return Ok((None, None));
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok((None, None));
    }
    if trimmed.len() == 32 && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        let id = parse_entity_id_param(trimmed, field)?;
        return Ok((Some(id.to_hex()), Some(id)));
    }
    Ok((Some(trimmed.to_owned()), None))
}

pub(crate) fn validate_eiri_session_id(
    session_id: &str,
    field: &'static str,
) -> Result<(), ApiError> {
    if session_id.trim().is_empty() {
        return Err(ApiError::bad_request(
            format!("{field} must be non-empty"),
            Some(field),
        ));
    }
    if session_id.len() > EIRI_SESSION_RAG_SESSION_ID_MAX_BYTES {
        return Err(ApiError::bad_request(
            format!("{field} must be at most {EIRI_SESSION_RAG_SESSION_ID_MAX_BYTES} bytes"),
            Some(field),
        ));
    }
    Ok(())
}

pub(crate) fn is_shared_eiri_session_scope_id(session_scope_id: &str) -> bool {
    SHARED_EIRI_SESSION_SCOPE_IDS.contains(&session_scope_id)
}

pub(crate) fn companion_scope_wire(scope: &oneiron::CompanionScope) -> &'static str {
    match scope {
        oneiron::CompanionScope::Neutral => "neutral",
        oneiron::CompanionScope::Personal { .. } => "personal",
        oneiron::CompanionScope::SharedVault { .. } => "shared_vault",
        _ => "unknown",
    }
}

pub(crate) fn eiri_memory_board_budget(
    controls: Option<&EiriMemoryBoardControls>,
    limit: usize,
    default_selected_edges: usize,
) -> oneiron::EiriMemoryBoardBudget {
    let retrieval_defaults = oneiron::ContextPackRetrievalBudget::from_limit(
        limit,
        oneiron::TokenAllocation::default(),
        default_selected_edges,
    );
    let defaults = oneiron::EiriMemoryBoardBudget::new(
        retrieval_defaults.claims,
        retrieval_defaults.turns,
        retrieval_defaults.summaries,
        retrieval_defaults.facets,
        0,
        retrieval_defaults.other,
    );
    let Some(slots) = controls.and_then(|controls| controls.slots.as_ref()) else {
        return defaults;
    };

    let companions = slots.companions.unwrap_or(defaults.companions);
    let other = slots
        .other
        .unwrap_or_else(|| retrieval_defaults.other.saturating_sub(companions));
    oneiron::EiriMemoryBoardBudget::new(
        slots.claims.unwrap_or(defaults.claims),
        slots.turns.unwrap_or(defaults.turns),
        slots.summaries.unwrap_or(defaults.summaries),
        slots.facets.unwrap_or(defaults.facets),
        companions,
        other,
    )
}

pub(crate) fn eiri_session_rag_store() -> &'static Mutex<EiriSessionRagStore> {
    EIRI_SESSION_RAG_STATE.get_or_init(|| Mutex::new(EiriSessionRagStore::default()))
}

pub(crate) fn eiri_session_rag_key(
    vault: &oneiron::Vault,
    scope_id: &str,
    session_id: &str,
) -> String {
    format!("{vault:p}:{scope_id}:{session_id}")
}

pub(crate) fn eiri_session_rag_scope_key(vault: &oneiron::Vault, scope_id: &str) -> String {
    format!("{vault:p}:{scope_id}")
}

pub(crate) async fn current_eiri_session_rag_state(
    vault: &oneiron::Vault,
    scope_id: &str,
) -> oneiron::EiriSessionRagState {
    let scope_key = eiri_session_rag_scope_key(vault, scope_id);
    let default_key = eiri_session_rag_key(vault, scope_id, scope_id);
    eiri_session_rag_store()
        .lock()
        .await
        .current_for_scope(scope_key, default_key, scope_id)
}

pub(crate) async fn advance_eiri_session_rag_state(
    vault: &oneiron::Vault,
    scope_id: &str,
    session_id: &str,
    pack: &oneiron::ContextPack,
    evidence: &CoreContextPackEvidence,
) -> oneiron::EiriSessionRagState {
    let scope_key = eiri_session_rag_scope_key(vault, scope_id);
    let key = eiri_session_rag_key(vault, scope_id, session_id);
    eiri_session_rag_store()
        .lock()
        .await
        .advance(scope_key, key, session_id, pack, evidence)
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
    error_context: &'static str,
    eiri_context: Option<EiriContextV4Request>,
) -> Result<CoreContextPackResponse, ApiError> {
    let mut pack = builder.run_unfinalized_with_telemetry().map_err(|error| {
        tracing::error!(error = %error, "{error_context}");
        core_engine_error(error_context, error)
    })?;
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
    let memory_board = eiri_context
        .as_ref()
        .and_then(|context| context.memory_board_budget)
        .map(|budget| {
            oneiron::context_pack::assemble_eiri_memory_board(
                &pack,
                budget,
                eiri_context
                    .as_ref()
                    .and_then(|context| context.companion.clone()),
            )
        });
    let session_rag = if let Some(context) = eiri_context.as_ref() {
        Some(
            advance_eiri_session_rag_state(
                vault,
                &context.session_scope_id,
                &context.session_id,
                &pack,
                &evidence,
            )
            .await,
        )
    } else {
        None
    };
    let context_version = eiri_context
        .as_ref()
        .map(|_| oneiron::EIRI_CONTEXT_VERSION_V4.to_owned());
    Ok(core_context_pack_response(
        pack,
        evidence,
        context_version,
        memory_board,
        session_rag,
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
    top_level_max_item_tokens: usize,
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
            .unwrap_or(top_level_max_item_tokens),
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
    context_version: Option<String>,
    memory_board: Option<oneiron::EiriMemoryBoard>,
    session_rag: Option<oneiron::EiriSessionRagState>,
) -> CoreContextPackResponse {
    let state = core_context_pack_state(pack.empty.as_ref());
    CoreContextPackResponse {
        context_version,
        results: pack.results.into_iter().map(core_context_entity).collect(),
        neighbors: pack
            .neighbors
            .into_iter()
            .map(core_context_entity)
            .collect(),
        stats: core_context_pack_stats(pack.stats),
        state,
        evidence,
        memory_board,
        session_rag,
        interlocutors: None,
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
    }
}

/// Request body for assembling a context pack from text and/or vector seeds.
#[derive(Deserialize, ToSchema)]
#[schema(example = json!({
    "query": "recent decisions about project alpha",
    "query_vector": [0.12, -0.04, 0.98],
    "limit": 10,
    "depth": { "edge_hop": 1, "max_neighbors": 50 },
    "policy": { "hydrate": true, "include_edges": true, "view": "full" },
    "time": { "since": 1782357600 },
    "budget": { "max_item_tokens": 512 }
}))]
pub(crate) struct ContextPackRequest {
    /// Optional text retrieval seed for context-pack assembly; omit when the caller only has an embedding vector.
    #[serde(default)]
    #[schema(example = "recent decisions about project alpha")]
    query: Option<String>,
    /// Optional embedding vector retrieval seed; omit when the caller only has text.
    #[serde(default, rename = "query_vector", alias = "queryVector")]
    #[schema(example = json!([0.12, -0.04, 0.98]))]
    query_vector: Option<Vec<f32>>,
    /// Maximum number of candidate entities to retrieve for the pack. Defaults to `10` when omitted.
    #[serde(default = "default_limit")]
    #[schema(default = default_limit, example = 10)]
    limit: usize,
    /// Per-item token cap for context-pack serialization; 0 disables it.
    #[serde(default, rename = "maxItemTokens", alias = "max_item_tokens")]
    max_item_tokens: usize,
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
    /// Whether to include stored vectors when present.
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
    /// Optional context format version. Use "v4" to request Eiri Context v4 fields.
    #[serde(default, rename = "context_version", alias = "contextVersion")]
    #[schema(example = "v4")]
    context_version: Option<String>,
    /// Optional Eiri Context v4 memory-board controls.
    #[serde(default, rename = "memory_board", alias = "memoryBoard")]
    memory_board: Option<EiriMemoryBoardControls>,
    /// Optional Eiri Context v4 session RAG controls.
    #[serde(default, rename = "session_rag", alias = "sessionRag")]
    session_rag: Option<EiriSessionRagControls>,
    /// Optional companion scope for Eiri Context v4 assembly.
    #[serde(default)]
    companion: Option<EiriCompanionControls>,
}

/// Context pack assembly.
#[utoipa::path(
    post,
    path = "/api/context-pack",
    request_body(
        content = ContextPackRequest,
        description = "Text and/or vector seed plus retrieval limits for context-pack assembly.",
        content_type = "application/json"
    ),
    responses(
        (
            status = 200,
            description = "Context pack assembled.",
            body = CoreContextPackResponse,
            content_type = "application/json",
            example = json!({
                "results": [],
                "neighbors": [],
                "stats": {
                    "candidates_considered": 0,
                    "signals_used": ["text"],
                    "query_time_us": 1000,
                    "entities_hydrated": 0,
                    "neighbors_hydrated": 0,
                    "cosine_ghosts_dampened": 0,
                    "claims_suppressed": 0,
                    "items_truncated": { "count": 0, "reason": "item_budget" },
                    "items_dropped": { "count": 0, "reason": "token_budget" }
                },
                "state": { "kind": "missing_data", "reason": "no_data", "total_in_scope": 0 },
                "evidence": { "telemetry_persisted": true, "retrieval_run_id": "018f0000000000000000000000000000", "result_ids": [], "scores": [] }
            })
        ),
        (
            status = 400,
            description = "Malformed context-pack request or controls.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid `x-oneiron-secret` header.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
pub(crate) async fn context_pack(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ContextPackRequest>, JsonRejection>,
) -> Result<Json<CoreContextPackResponse>, ApiError> {
    check_api_auth(&headers, &server.config)?;
    let caller = resume_caller(&headers);
    let req = json_payload(payload)?;
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
    let projection =
        context_pack_json_projection_config(view, req.budget.as_ref(), req.max_item_tokens);
    let scoped_read = scoped_read_for_legacy_api(&server.vault)?;
    let candidate_limit = scoped_read
        .search_candidate_limit(req.limit, query.is_some(), req.query_vector.is_some())
        .map_err(|error| {
            tracing::error!(error = %error, "context-pack scoped read setup failed");
            core_engine_error("context-pack scoped read setup failed", error)
        })?;
    let eiri_context = resolve_eiri_context_v4_request(
        &server.vault,
        req.context_version.as_deref(),
        req.memory_board.as_ref(),
        req.session_rag.as_ref(),
        req.companion.as_ref(),
        (req.limit, max_neighbors),
        EiriContextV4Identity {
            fallback_session_id: &caller,
            companion_auth: None,
        },
    )?;

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
    let (builder, retrieval_budget) = apply_context_pack_budget(
        builder,
        req.budget.as_ref(),
        req.max_item_tokens,
        candidate_limit,
        req.limit,
        max_neighbors,
    )?;

    Ok(Json(
        run_context_pack_builder(
            &server.vault,
            &scoped_read,
            builder,
            projection,
            ContextPackResponseLimits {
                results: req.limit,
                neighbors: max_neighbors,
                retrieval: retrieval_budget,
            },
            "context-pack failed",
            eiri_context,
        )
        .await?,
    ))
}
