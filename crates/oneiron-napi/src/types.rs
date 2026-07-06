use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Edge information returned from graph queries.
#[napi(object)]
pub struct NapiEdgeInfo {
    /// Source entity ID (16 bytes).
    pub src: Buffer,
    /// Edge kind discriminant (0-19).
    pub kind: u32,
    /// Target entity ID (16 bytes).
    pub tgt: Buffer,
    /// Edge weight (0.0-1.0).
    pub weight: f64,
    /// Creation timestamp (UNIX seconds).
    pub created_at: i64,
    /// VAD valence (-1.0 to 1.0), absent for structural edges.
    pub valence: Option<f64>,
    /// VAD arousal (0.0 to 1.0), absent for structural edges.
    pub arousal: Option<f64>,
    /// VAD dominance (0.0 to 1.0), absent for structural edges.
    pub dominance: Option<f64>,
}

/// A scored entity result from search operations.
#[napi(object)]
pub struct NapiScoredEntity {
    /// Entity ID (16 bytes).
    pub id: Buffer,
    /// Ranking score.
    pub score: f64,
}

/// A subtree entry with entity ID and depth.
#[napi(object)]
pub struct NapiSubtreeEntry {
    /// Entity ID (16 bytes).
    pub id: Buffer,
    /// Depth from root (1 = direct child).
    pub depth: u32,
}

/// An entity to write in a batch operation.
#[napi(object)]
pub struct NapiBatchEntity {
    /// Entity ID (16 bytes).
    pub id: Buffer,
    /// Entity type discriminant.
    pub entity_type: u32,
    /// Occurred range start (UNIX seconds).
    pub occurred_start: i64,
    /// Occurred range end (UNIX seconds).
    pub occurred_end: i64,
    /// Learned-at timestamp (UNIX seconds).
    pub learned_at: i64,
    /// Entity data payload (msgpack-encoded).
    pub data: Buffer,
}

/// One file entry in a codebase snapshot manifest.
#[napi(object)]
pub struct NapiCodebaseFileEntry {
    /// Repository-relative normalized file path.
    pub path: String,
    /// 32-byte content hash.
    pub content_hash: Buffer,
    /// File size in bytes.
    pub size_bytes: i64,
}

/// Codebase snapshot metadata attached to a CODE_ARTIFACT entity.
#[napi(object)]
pub struct NapiCodebaseSnapshot {
    /// Stable project identity used for retrieval filters.
    pub project_id: String,
    /// Canonical or parseable repo_ref string.
    pub repo_ref: String,
    /// 40-hex commit hash, required for GitHub-at-commit repo_refs.
    pub commit_hash: Option<String>,
    /// Deterministic manifest hash computed by core. Optional on input.
    pub fork_hash: Option<Buffer>,
    /// Deterministic repository scope key computed by core. Optional on input.
    pub scope_key: Option<Buffer>,
    /// Deterministic file manifest.
    pub files: Vec<NapiCodebaseFileEntry>,
}

/// Configuration for deterministic dev-safe email identity addresses.
#[napi(object)]
pub struct NapiEmailIdentityAdapterConfig {
    /// Exact product domain that owns agent email identities.
    pub domain: String,
    /// Secret used to sign deterministic local-parts. Never returned by bindings.
    pub signing_secret: String,
    /// Optional local-part prefix. Defaults to `agent`.
    pub local_part_prefix: Option<String>,
}

/// Provider-normalized inbound email webhook data.
#[napi(object)]
pub struct NapiEmailInboundEvent {
    /// Provider event id for idempotent host handling.
    pub provider_event_id: String,
    /// Raw envelope recipient address.
    pub envelope_to: String,
    /// Raw envelope sender address.
    pub envelope_from: String,
    /// Optional provider payload/body reference.
    pub payload_ref: Option<String>,
    /// Received-at timestamp (UNIX seconds).
    pub received_at: i64,
}
