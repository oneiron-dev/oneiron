//! Moved from `crates/oneiron/src/embed/home_vectors.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::embedding_vocabulary::EmbeddingProvenance;
use serde::Deserialize;
use serde::Serialize;

/// One settled default CLAIM vector and the complete source image it embeds.
/// A transport receipt, not a read grant or canonical claim history.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HomeClaimVector {
    pub entity_id: EntityId,
    pub source: Vec<u8>,
    /// Source identities retained for the socket's final destination judgment.
    pub release_rows: Vec<EntityId>,
    pub model_id: String,
    pub transform: Option<String>,
    pub route: String,
    /// 1 is OwnerServer; 2 is ThirdParty. OnDevice never travels.
    pub locality: u8,
    pub provenance: EmbeddingProvenance,
    /// The exact persisted EMB-3 f16 row.
    pub row: Vec<u8>,
}
