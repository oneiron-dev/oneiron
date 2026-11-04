//! Lease-cleanup input and report vocabulary retained at the store layer.

pub use crate::store::attempt_cleanup::{
    AttemptQueueCleanupReport, AttemptQueueRetryReason, AttemptQueueRetryReasonCount,
    CleanupAttemptLeases,
};
