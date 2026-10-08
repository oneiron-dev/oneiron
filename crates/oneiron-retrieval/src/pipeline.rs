//! Value types the retrieval pipeline's kernels share. The pipeline itself (builder,
//! channels, trace) still lives in `oneiron`, which re-exports these at
//! `oneiron::pipeline`.

use oneiron_contracts::entity_id::EntityId;

/// A scored entity result.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScoredEntity {
    /// Entity identifier.
    pub id: EntityId,
    /// Ranking score.
    pub score: f32,
}
