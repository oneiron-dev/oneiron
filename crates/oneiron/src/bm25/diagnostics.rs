//! Per-vault BM25 integrity diagnostics (counters, snapshot, record).
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use super::BM25_DIAGNOSTIC_COUNTER_COUNT;

/// One vault's BM25 integrity counters.
///
/// Owned by that vault's store handle (`StoreCore::diagnostics`), so a second
/// vault open in the same process counts separately and a reader's delta is
/// exactly what its own vault recorded.
pub(crate) struct Bm25Diagnostics {
    counters: [AtomicU64; BM25_DIAGNOSTIC_COUNTER_COUNT],
}

impl Default for Bm25Diagnostics {
    fn default() -> Self {
        Self {
            counters: [const { AtomicU64::new(0) }; BM25_DIAGNOSTIC_COUNTER_COUNT],
        }
    }
}

impl Bm25Diagnostics {
    /// Returns this vault's BM25 integrity diagnostic counters.
    #[must_use]
    pub(crate) fn snapshot(&self) -> Bm25DiagnosticsSnapshot {
        Bm25DiagnosticsSnapshot {
            counters: Bm25DiagnosticKind::metric_values().map(|kind| Bm25DiagnosticCounter {
                kind,
                count: self.counters[kind.metric_index()].load(AtomicOrdering::Relaxed),
            }),
        }
    }

    pub(super) fn record(&self, kind: Bm25DiagnosticKind) {
        self.counters[kind.metric_index()].fetch_add(1, AtomicOrdering::Relaxed);
    }
}

/// Content-free BM25 integrity diagnostic class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm25DiagnosticKind {
    MalformedPostingAlignment,
    MissingScoredDocumentMetadata,
    DeindexSelfHealedMissingPostingRow,
    DeindexSelfHealedMissingPostingEntity,
}

impl Bm25DiagnosticKind {
    /// Stable, privacy-preserving label for metrics and diagnostic surfaces.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedPostingAlignment => "malformed_posting_alignment",
            Self::MissingScoredDocumentMetadata => "missing_scored_document_metadata",
            Self::DeindexSelfHealedMissingPostingRow => "deindex_self_healed_missing_posting_row",
            Self::DeindexSelfHealedMissingPostingEntity => {
                "deindex_self_healed_missing_posting_entity"
            }
        }
    }

    const fn metric_index(self) -> usize {
        match self {
            Self::MalformedPostingAlignment => 0,
            Self::MissingScoredDocumentMetadata => 1,
            Self::DeindexSelfHealedMissingPostingRow => 2,
            Self::DeindexSelfHealedMissingPostingEntity => 3,
        }
    }

    const fn metric_values() -> [Self; BM25_DIAGNOSTIC_COUNTER_COUNT] {
        [
            Self::MalformedPostingAlignment,
            Self::MissingScoredDocumentMetadata,
            Self::DeindexSelfHealedMissingPostingRow,
            Self::DeindexSelfHealedMissingPostingEntity,
        ]
    }
}

/// Count for one BM25 integrity diagnostic class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm25DiagnosticCounter {
    pub kind: Bm25DiagnosticKind,
    pub count: u64,
}

/// One vault's BM25 integrity diagnostics with stable, content-free labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm25DiagnosticsSnapshot {
    pub counters: [Bm25DiagnosticCounter; BM25_DIAGNOSTIC_COUNTER_COUNT],
}

impl Bm25DiagnosticsSnapshot {
    #[must_use]
    pub fn count(&self, kind: Bm25DiagnosticKind) -> u64 {
        self.counters[kind.metric_index()].count
    }
}
