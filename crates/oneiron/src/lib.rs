use std::time::{SystemTime, UNIX_EPOCH};

pub mod analyzer;
pub mod batch;
pub(crate) mod bm25;
pub mod claim;
pub mod context_pack;
pub mod deletion;
pub(crate) mod distance;
pub mod error;
pub(crate) mod fusion;
pub(crate) mod hnsw;
pub(crate) mod identity;
pub(crate) mod limits;
pub mod maintain;
pub mod pipeline;
pub(crate) mod ppr;
pub mod provenance;
pub mod serialize;
pub mod store;
pub(crate) mod sweep;
#[cfg(feature = "sync")]
pub mod sync;
pub mod types;
mod vault;

pub use crate::analyzer::{
    ANALYZER_VERSION, AnalyzerAssetManifest, AnalyzerChannel, AnalyzerContext, AnalyzerManifest,
    AnalyzerMode, LangPolicy, LanguageHint, NormalizationPolicy, Token, TokenKind,
};
pub use crate::batch::{BatchBuilder, TxnBatchBuilder};
pub use crate::bm25::Bm25Formula;
pub use crate::claim::{
    CLAIM_BODY_KEYS, ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource,
    ClaimSubject, MAX_PREDICATE_BYTES, RESERVED_PREDICATE_NAMESPACE,
};
pub use crate::context_pack::ContextPackBuilder;
pub use crate::deletion::{
    DecodedTombstoneValue, DeleteEntityOutcome, DeleteReason, TOMBSTONE_VALUE_LEGACY_LEN,
    TOMBSTONE_VALUE_V2_LEN, TombstoneReason, TombstoneValueV2, decode_tombstone_value,
};
pub use crate::error::{Error, ErrorKind, Result};
pub use crate::maintain::{MaintenanceBuilder, MaintenanceReport};
pub use crate::pipeline::{DEFAULT_RECENCY_HALF_LIFE_DAYS, FacetMode, PipelineBuilder, WorldScope};
pub use crate::provenance::{
    EDGE_PROVENANCE_BODY_KEYS, EDGE_REF_LEN, EdgeProvenanceClaimBody, EdgeRef,
    MODEL_SUBSTRATE_FIELD_MAX_BYTES, PREDICATE_EDGE_PROVENANCE, REASONING_EFFORT_MAX_BYTES,
    SupersessionStatus, decode_edge_provenance_body, derive_confirmation_status,
    validate_actor_class,
};
pub use crate::types::{
    Bm25RankProfile, ContextEntity, ContextPack, DecodedEdgeValue, EdgeActorClass,
    EdgeConfirmationStatus, EdgeInfo, EdgeKind, EdgeProvenanceFlags, EdgeValueLayout, EmptyContext,
    EmptyReason, EntityId, FieldProfile, HnswConfig, PackFormat, PackStats, ScoredEntity, Signal,
    TemporalAnchorMode, TemporalGranularity, TextAnalyzerConfig, TextIndexOptions, TimeRange,
    TokenAllocation, Vad, VadComponent, VaultConfig,
};
pub use crate::vault::{
    ActorBound, TextIndexStatus, Vault, VaultDoctorDbManifestReport, VaultDoctorHnswRecordState,
    VaultDoctorHnswReport, VaultDoctorReport,
};

pub(crate) fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

pub(crate) fn le_bytes_to_f32_vec(bytes: &[u8]) -> Result<Vec<f32>> {
    if !bytes.len().is_multiple_of(4) {
        return Err(Error::InvalidKey);
    }

    let (chunks, rem) = bytes.as_chunks::<4>();
    debug_assert!(rem.is_empty());
    Ok(chunks
        .iter()
        .map(|bytes| f32::from_le_bytes(*bytes))
        .collect())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod tests_bug;

#[cfg(test)]
pub(crate) mod test_util {
    //! Shared test helpers. Centralized to avoid drift between per-module
    //! copies of `open_test_vault`. Each module keeps its own `test_config()`
    //! because configs diverge (map sizes, dimensions, embedding model).
    use crate::types::VaultConfig;
    use crate::vault::Vault;

    /// Opens a temporary vault with the supplied config. Returns the
    /// `TempDir` so callers keep the directory alive for the vault's lifetime.
    pub(crate) fn open_test_vault_with(cfg: VaultConfig) -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), cfg).expect("open vault");
        (dir, vault)
    }
}
