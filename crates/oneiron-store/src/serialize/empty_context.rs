//! Empty context-pack response metadata.

use oneiron_base::retrieval_quality::RetrievalQualityReport;

/// Machine-readable reason an otherwise successful context-pack query surfaced
/// no entities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmptyReason {
    FilterMatchedNone,
    NoData,
    AllActivated,
    BelowThreshold,
    /// The reader's profile takes no optional memory for this task, so no
    /// retrieval ran (ARCH-0004 #reader-budget). It says nothing about rows.
    SkippedByProfile,
}

/// Structured context for an empty context-pack response.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmptyContext {
    #[serde(default)]
    pub retrieval_quality: RetrievalQualityReport,
    pub reason: EmptyReason,
    pub total_in_scope: usize,
    pub hint: String,
}
