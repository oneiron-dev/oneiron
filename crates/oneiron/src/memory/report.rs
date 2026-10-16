//! A report files evidence, not authority. Even a read-only visiting actor may report.
use super::{Memory, MemoryError, MemoryResult, RoomTurnHandle};
use crate::feedback::intake::FeedbackDedup;
use crate::feedback::{ReportReceipt, ReportRequest};

/// The same T2 cosine threshold for every report entry point. Exact identity
/// never depends on it, on the note, or on an available embedding model.
const REPORT_DEDUP_MIN_SIMILARITY: f32 = 0.92;

impl Memory<'_> {
    pub fn report(&self, request: ReportRequest) -> MemoryResult<ReportReceipt> {
        self.report_with_embedding(request, None)
    }

    /// An optional host-produced vector, never a reporter-supplied assertion.
    /// With no embedder the report still lands and exact retries count once.
    pub fn report_with_embedding(
        &self,
        request: ReportRequest,
        embedding: Option<&[f32]>,
    ) -> MemoryResult<ReportReceipt> {
        self.verified_actor_class()?;
        self.vault()
            .submit_report(
                self.actor(),
                request,
                embedding,
                FeedbackDedup::new(REPORT_DEDUP_MIN_SIMILARITY).map_err(MemoryError::from)?,
            )
            .map_err(MemoryError::from)
    }
}

impl RoomTurnHandle<'_> {
    pub fn report(&self, request: ReportRequest) -> MemoryResult<ReportReceipt> {
        self.memory.report(request)
    }

    pub fn report_with_embedding(
        &self,
        request: ReportRequest,
        embedding: Option<&[f32]>,
    ) -> MemoryResult<ReportReceipt> {
        self.memory.report_with_embedding(request, embedding)
    }
}
