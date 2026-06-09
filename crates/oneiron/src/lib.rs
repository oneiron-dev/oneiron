use std::time::{SystemTime, UNIX_EPOCH};

pub mod analyzer;
pub mod batch;
pub(crate) mod bm25;
pub mod context_pack;
pub mod deletion;
pub(crate) mod distance;
pub mod error;
pub(crate) mod fusion;
pub(crate) mod hnsw;
pub(crate) mod limits;
pub mod maintain;
pub mod pipeline;
pub(crate) mod ppr;
pub mod serialize;
pub mod store;
#[cfg(feature = "sync")]
pub mod sync;
pub mod types;
mod vault;

pub use crate::analyzer::{
    ANALYZER_VERSION, AnalyzerAssetManifest, AnalyzerChannel, AnalyzerContext, AnalyzerManifest,
    AnalyzerMode, LangPolicy, LanguageHint, NormalizationPolicy, Token, TokenKind,
};
pub use crate::batch::{BatchBuilder, TxnBatchBuilder};
pub use crate::context_pack::ContextPackBuilder;
pub use crate::deletion::{DeleteEntityOutcome, DeleteReason};
pub use crate::error::{Error, ErrorKind, Result};
pub use crate::maintain::{MaintenanceBuilder, MaintenanceReport};
pub use crate::pipeline::PipelineBuilder;
pub use crate::types::{
    ContextEntity, ContextPack, DecodedEdgeValue, EdgeActorClass, EdgeConfirmationStatus, EdgeInfo,
    EdgeKind, EdgeProvenanceFlags, EdgeValueLayout, EntityId, FieldProfile, HnswConfig, PackFormat,
    PackStats, ScoredEntity, Signal, TemporalAnchorMode, TemporalGranularity, TextAnalyzerConfig,
    TextIndexOptions, TimeRange, TokenAllocation, Vad, VadComponent, VaultConfig,
};
pub use crate::vault::{TextIndexStatus, Vault};

pub(crate) fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

pub(crate) fn le_bytes_to_f32_vec(bytes: &[u8]) -> Result<Vec<f32>> {
    if !bytes.len().is_multiple_of(4) {
        return Err(Error::InvalidKey);
    }

    Ok(bytes
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes(c.try_into().unwrap()))
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
