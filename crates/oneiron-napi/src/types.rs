use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Edge information returned from graph queries.
#[napi(object)]
pub struct NapiEdgeInfo {
    /// Source entity ID (16 bytes).
    pub src: Buffer,
    /// Edge kind discriminant (0-17).
    pub kind: u32,
    /// Target entity ID (16 bytes).
    pub tgt: Buffer,
    /// Edge weight (0.0-1.0).
    pub weight: f64,
    /// Creation timestamp (UNIX seconds).
    pub created_at: i64,
    /// VAD valence (-1.0 to 1.0).
    pub valence: f64,
    /// VAD arousal (0.0 to 1.0).
    pub arousal: f64,
    /// VAD dominance (0.0 to 1.0).
    pub dominance: f64,
}

/// A scored entity result from search operations.
#[napi(object)]
pub struct NapiScoredEntity {
    /// Entity ID (16 bytes).
    pub id: Buffer,
    /// Ranking score.
    pub score: f64,
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
