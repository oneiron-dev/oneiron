//! Retrieval quality report vocabulary. Defined in `oneiron-contracts`; every
//! `oneiron::retrieval_quality` path is unchanged.

pub use oneiron_contracts::retrieval_quality::{
    CONFIDENCE_ADJUSTMENT_SCALE, ConfidenceAdjustment, PprCacheOutcome, RetrievalDegradation,
    RetrievalDiagnostics, RetrievalQuality, RetrievalQualityReport, classify_retrieval_quality,
};
