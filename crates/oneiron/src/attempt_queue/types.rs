//! Durable wire, verb-input, and outcome types for the attempt queue.
//!
//! Storage mechanics live in [`super::encoding`], input validation in
//! [`super::validate`], and the queue handle itself in [`super::engine`]. The
//! ONE-1896 graceful-cancel rows and verbs are their own concern and live in
//! [`super::cancel`].

use super::cancel::{
    AttemptCancelPressure, AttemptCancelReceipt, AttemptCancellation, AttemptLanding,
    AttemptLandingReserve, AttemptResumePoint,
};

mod cleanup;
mod exhaust;
mod hold;
pub use cleanup::{
    AttemptQueueCleanupReport, AttemptQueueRetryReason, AttemptQueueRetryReasonCount,
    CleanupAttemptLeases,
};
pub use exhaust::AttemptTerminalExhaust;
pub(crate) use hold::AttemptPause;

pub(crate) use crate::store::attempt_record::ATTEMPT_RECORD_VERSION;
pub(super) const MAX_ATTEMPT_EVENTS_PER_RECORD: usize = 256;
pub(super) use crate::store::attempt_cleanup::ATTEMPT_QUEUE_RETRY_REASON_COUNT;

pub use crate::store::attempt_id::AttemptId;

pub use crate::store::attempt_result::AttemptResultRef;

pub use crate::store::attempt_state::AttemptState;

pub use crate::store::attempt_inputs::{AttemptEvent, AttemptInterventionKind};

pub use crate::store::attempt_manifest::{ManifestEntry, ManifestKind};

pub use crate::store::attempt_outcomes::{
    AbandonAttempt, AbandonOutcome, ClaimOutcome, CompleteOutcome, EnqueueOutcome, FailOutcome,
    InterveneAttempt, InterveneOutcome, RetryOutcome,
};
pub use crate::store::attempt_record::{
    AttemptPlacement, AttemptRecord, PlannedBinding, PlannedExactness,
};

impl AttemptRecord {
    pub(crate) fn accepts_worker(&self, worker: &str) -> bool {
        self.placement
            .as_ref()
            .and_then(|p| p.worker.as_deref())
            .is_none_or(|assigned| assigned == worker)
    }

    /// The attempt's accumulated pack manifest, in append order.
    #[must_use]
    pub fn manifest(&self) -> &[ManifestEntry] {
        &self.manifest
    }

    /// The append-only graceful-cancel evidence, in append order.
    #[must_use]
    pub fn cancel_receipts(&self) -> &[AttemptCancelReceipt] {
        &self.cancel_state.receipts
    }

    /// The artifact version this try's durable output lives in, once one
    /// exists.
    #[must_use]
    pub const fn result_ref(&self) -> Option<&AttemptResultRef> {
        self.result_ref.as_ref()
    }

    /// The durable landing record, present while landing and preserved on a
    /// row that landed.
    #[must_use]
    pub const fn landing(&self) -> Option<&AttemptLanding> {
        self.cancel_state.landing.as_ref()
    }

    /// The exact point a successor resumes from, once recorded.
    #[must_use]
    pub const fn resume_point(&self) -> Option<&AttemptResumePoint> {
        self.cancel_state.resume_point.as_ref()
    }

    /// The terminal cancellation receipt, when this row was cancelled.
    #[must_use]
    pub const fn cancellation(&self) -> Option<&AttemptCancellation> {
        self.cancel_state.cancellation.as_ref()
    }

    /// This attempt's landing reserve accounting.
    #[must_use]
    pub const fn landing_reserve(&self) -> AttemptLandingReserve {
        self.cancel_state.reserve
    }

    /// The limit an ordinary execution meter for this attempt must use: the
    /// dialed budget MINUS the landing reserve.
    #[must_use]
    pub const fn ordinary_budget_limit_units(&self) -> u64 {
        self.cancel_state.reserve.ordinary_limit_units()
    }

    /// Soft-request pressure counters.
    #[must_use]
    pub const fn cancel_pressure(&self) -> AttemptCancelPressure {
        self.cancel_state.pressure
    }

    /// True once repeated refusal of soft requests is an observable pathology.
    #[must_use]
    pub const fn soft_cancel_pathology(&self) -> bool {
        self.cancel_state.pressure.is_pathological()
    }
}

pub use crate::store::attempt_inputs::EnqueueAttempt;

pub use crate::store::attempt_inputs::ClaimAttempt;

pub use crate::store::attempt_inputs::CompleteAttempt;

pub use crate::store::attempt_inputs::FailAttempt;

pub use crate::store::attempt_inputs::SetAttemptResult;

pub use crate::store::attempt_inputs::RetryAttempt;

pub use crate::store::attempt_inputs::AttemptInterventionEffect;

pub(crate) use crate::store::attempt_record::attempt_record_order;
