use std::time::{SystemTime, UNIX_EPOCH};

pub mod analyzer;
pub mod batch;
pub(crate) mod bm25;
pub mod context_pack;
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
pub use crate::error::{Error, Result};
pub use crate::maintain::{MaintenanceBuilder, MaintenanceReport};
pub use crate::pipeline::PipelineBuilder;
pub use crate::types::{
    ContextEntity, ContextPack, EdgeInfo, EdgeKind, EntityId, FieldProfile, HnswConfig, PackFormat,
    PackStats, ScoredEntity, Signal, TemporalAnchorMode, TemporalGranularity, TextAnalyzerConfig,
    TextIndexOptions, TimeRange, TokenAllocation, Vad, VaultConfig,
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
