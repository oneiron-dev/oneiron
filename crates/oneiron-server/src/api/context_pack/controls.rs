//! Request DTOs, control structs, and shared limit constants for context-pack assembly.

use super::super::default_limit;
use super::resolve::{default_context_neighbors, default_true, resolved_context_pack_depth};
use crate::projection::View;
use serde::Deserialize;
use serde::Serialize;
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
    pub(super) edge_hop: Option<u32>,
    /// Maximum neighbors to hydrate during edge expansion.
    #[serde(default, rename = "max_neighbors", alias = "maxNeighbors")]
    #[schema(example = 50)]
    pub(super) max_neighbors: Option<usize>,
}

/// Ranking and projection policy controls for context-pack assembly.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct ContextPackPolicyControls {
    /// Whether to include hydrated fields.
    #[serde(default)]
    #[schema(example = true)]
    pub(super) hydrate: Option<bool>,
    /// Whether to include edge records in hydrated entities.
    #[serde(default, rename = "include_edges", alias = "includeEdges")]
    #[schema(example = true)]
    pub(super) include_edges: Option<bool>,
    /// Whether to include stored vectors when present.
    #[serde(default, rename = "include_vectors", alias = "includeVectors")]
    #[schema(example = false)]
    pub(super) include_vectors: Option<bool>,
    /// Field profile for hydrated fields.
    #[serde(default)]
    #[schema(example = "standard")]
    pub(super) view: Option<View>,
    /// Apply recency boost with the supplied half-life in days.
    #[serde(default, rename = "boost_recency_days", alias = "boostRecencyDays")]
    #[schema(example = 7.0)]
    pub(super) boost_recency_days: Option<f32>,
    /// Apply salience boost.
    #[serde(default, rename = "boost_salience", alias = "boostSalience")]
    #[schema(example = true)]
    pub(super) boost_salience: Option<bool>,
    /// Apply confidence boost.
    #[serde(default, rename = "boost_confidence", alias = "boostConfidence")]
    #[schema(example = true)]
    pub(super) boost_confidence: Option<bool>,
    /// Apply contiguity boost.
    #[serde(default, rename = "boost_contiguity", alias = "boostContiguity")]
    #[schema(example = true)]
    pub(super) boost_contiguity: Option<bool>,
}

/// Time-window controls for context-pack assembly.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct ContextPackTimeControls {
    /// Keep entities learned at or after this Unix timestamp.
    #[serde(default)]
    #[schema(example = 1_782_357_600_u64)]
    pub(super) since: Option<u64>,
    /// Occurrence window start, inclusive.
    #[serde(default, rename = "occurred_start", alias = "occurredStart")]
    #[schema(example = 1_782_357_600_u64)]
    pub(super) occurred_start: Option<u64>,
    /// Occurrence window end, inclusive.
    #[serde(default, rename = "occurred_end", alias = "occurredEnd")]
    #[schema(example = 1_782_357_900_u64)]
    pub(super) occurred_end: Option<u64>,
    /// Learned-at window start, inclusive.
    #[serde(default, rename = "learned_start", alias = "learnedStart")]
    #[schema(example = 1_782_357_600_u64)]
    pub(super) learned_start: Option<u64>,
    /// Learned-at window end, inclusive.
    #[serde(default, rename = "learned_end", alias = "learnedEnd")]
    #[schema(example = 1_782_357_900_u64)]
    pub(super) learned_end: Option<u64>,
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
    pub(super) token_budget: Option<usize>,
    /// Per-item token cap for context-pack serialization; 0 disables it.
    #[serde(default, rename = "max_item_tokens", alias = "maxItemTokens")]
    #[schema(example = 512)]
    pub(super) max_item_tokens: Option<usize>,
    /// Maximum field characters before serialization truncation.
    #[serde(default, rename = "max_field_chars", alias = "maxFieldChars")]
    #[schema(example = 500)]
    pub(super) max_field_chars: Option<usize>,
    /// Per-kind retrieval item budgets before final result truncation.
    #[serde(default)]
    pub(super) retrieval: Option<ContextPackRetrievalBudgetControls>,
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
    pub(super) owner_present: Option<bool>,
    /// Third-party conversation participants.
    #[serde(default, rename = "third_parties", alias = "thirdParties")]
    pub(super) third_parties: Vec<CoreInterlocutorParty>,
    /// Voice session roster reference. Accepted now; the roster merge lands
    /// with ILD-3 (ONE-1518).
    #[serde(default, rename = "voice_session_ref", alias = "voiceSessionRef")]
    #[schema(example = "call-123")]
    pub(super) voice_session_ref: Option<String>,
}

/// One third-party interlocutor. Exactly one of `contact_ref`,
/// `channel_identity_ref`+`counterparty`, or `label` must be supplied.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct CoreInterlocutorParty {
    /// Hex CounterpartyContact entity id.
    #[serde(default, rename = "contact_ref", alias = "contactRef")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    pub(super) contact_ref: Option<String>,
    /// Hex ChannelIdentity entity id; requires `counterparty`.
    #[serde(default, rename = "channel_identity_ref", alias = "channelIdentityRef")]
    #[schema(example = "fedcba9876543210fedcba9876543210")]
    pub(super) channel_identity_ref: Option<String>,
    /// Provider-native counterparty key; requires `channel_identity_ref`.
    #[serde(default)]
    #[schema(example = "kenji@example.com")]
    pub(super) counterparty: Option<String>,
    /// Display label for an untyped party.
    #[serde(default)]
    #[schema(example = "unknown speaker 2")]
    pub(super) label: Option<String>,
    /// Label-only owner claim carried on the stamp; never authority.
    #[serde(default, rename = "claimed_owner", alias = "claimedOwner")]
    #[schema(example = false)]
    pub(super) claimed_owner: Option<bool>,
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
    pub(super) query: Option<String>,
    /// Optional vector query.
    #[serde(default, rename = "query_vector", alias = "queryVector")]
    #[schema(example = json!([0.1, 0.2, 0.3, 0.4]))]
    pub(super) query_vector: Option<Vec<f32>>,
    /// Maximum primary candidates to retrieve.
    #[serde(default = "default_limit")]
    #[schema(default = default_limit, example = 10)]
    pub(super) limit: usize,
    /// Whether to include hydrated fields. Defaults to true.
    #[serde(default = "default_true")]
    #[schema(default = default_true, example = true)]
    pub(super) hydrate: bool,
    /// Whether to include edge records in hydrated entities.
    #[serde(default, rename = "include_edges", alias = "includeEdges")]
    #[schema(example = true)]
    pub(super) include_edges: bool,
    /// Edge expansion depth for neighbor hydration.
    #[serde(default, rename = "edge_hop", alias = "edgeHop")]
    #[schema(example = 1)]
    pub(super) edge_hop: u32,
    /// Maximum neighbors to hydrate during edge expansion.
    #[serde(
        default = "default_context_neighbors",
        rename = "max_neighbors",
        alias = "maxNeighbors"
    )]
    #[schema(default = default_context_neighbors, example = 50)]
    pub(super) max_neighbors: usize,
    /// Whether to include vectors in hydrated entities.
    #[serde(default, rename = "include_vectors", alias = "includeVectors")]
    #[schema(example = false)]
    pub(super) include_vectors: bool,
    /// Field profile for hydrated fields. Defaults to standard.
    #[serde(default)]
    #[schema(example = "standard")]
    pub(super) view: Option<View>,
    /// Optional nested depth controls. Overrides top-level edge_hop/max_neighbors when set.
    #[serde(default)]
    pub(super) depth: Option<ContextPackDepthControls>,
    /// Optional nested ranking/projection policy controls.
    #[serde(default)]
    pub(super) policy: Option<ContextPackPolicyControls>,
    /// Optional time-window filters.
    #[serde(default)]
    pub(super) time: Option<ContextPackTimeControls>,
    /// Optional retrieval and serialization budget controls.
    #[serde(default)]
    pub(super) budget: Option<ContextPackBudgetControls>,
    /// Optional interlocutor presence controls (OF-365 ILD-1).
    #[serde(default)]
    pub(super) interlocutors: Option<CoreInterlocutorControls>,
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
