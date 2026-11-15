//! Moved from `crates/oneiron/src/verbs/embedding_space.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::embedding_vocabulary::InputKind;
use serde::Deserialize;
use serde::Serialize;

/// `vault.embedding_spaces.bind`'s input: one kind slot and its space.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingSpaceBindRequest {
    /// `text`, `image` or `audio`.
    #[schemars(with = "String")]
    pub kind: InputKind,
    /// The declared space; absent returns the slot to its default.
    #[serde(default)]
    pub space: Option<String>,
}

/// One declared space, by id: `vault.embedding_spaces.one_space` and
/// `.retire`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingSpaceRequest {
    pub space: String,
}

/// `vault.embedding_spaces.move`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingSpaceMoveRequest {
    pub candidate: String,
    /// A declared space id, or absent for the vault's text index.
    #[serde(default)]
    pub incumbent: Option<String>,
    /// A tolerance stricter than the measured retest noise.
    #[serde(default)]
    pub margin: Option<f32>,
}

/// One move, by its candidate: `vault.embedding_spaces.move_check`,
/// `.move_approve`, `.move_undo` and `.move_abandon`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingSpaceCandidateRequest {
    pub candidate: String,
}

/// What a move's check did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddingSpaceMoveOutcome {
    /// The candidate still lacks a vector of some moving document; no probe
    /// ran.
    Filling,
    /// Every kind read not worse: the candidate serves now.
    SwappedIn,
    /// A kind read worse: the incumbent keeps serving and the move is closed.
    Kept,
    /// A kind read unknown: the incumbent keeps serving and the move stays
    /// open.
    Undecided,
}

/// `vault.embedding_spaces.probes.put`'s input: one probe the owner, or
/// another model, wrote.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingSpaceProbePutRequest {
    /// `text`, `image` or `audio`: the kind of the documents it finds.
    #[schemars(with = "String")]
    pub kind: InputKind,
    /// A text query; beside `query_media`, what it asks in words, which may be empty.
    pub query: String,
    /// A stored image or audio ASSET whose bytes are the query, as 32 hex; absent for a text
    /// query. Never one of its targets.
    #[serde(default)]
    pub query_media: Option<EntityId>,
    /// The document the query was written from, as 32 hex.
    pub family: EntityId,
    /// Every document that answers it, as 32 hex; the family's when absent.
    #[serde(default)]
    pub targets: Vec<EntityId>,
    /// Every other stored row the query was written from, as 32 hex (FIX 9829): erasing any
    /// of them, the family or the media query erases the probe. Empty when absent.
    #[serde(default)]
    pub source_refs: Vec<EntityId>,
    /// Who wrote the query.
    pub author: String,
}

/// `vault.embedding_spaces.probes.delete`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingSpaceProbeDeleteRequest {
    /// The probe's id, 32 hex.
    pub id: String,
}

/// `vault.embedding_spaces.probes.delete`'s answer: whether a probe went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EmbeddingSpaceProbeDeleted {
    pub ok: bool,
}
