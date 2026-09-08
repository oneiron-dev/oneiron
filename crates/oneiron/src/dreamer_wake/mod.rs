//! Dreamer wake-pass driver (ONE-1288, DREAM-001 residual).
//!
//! One wake pass = one bounded work cycle on one node (a Dreamer wake-pass,
//! never a process wake). The driver composes the LANDED primitives only —
//! atomic admission (`admit_next_consolidation`), reserve-then-spend budget
//! settlement, park rows, milestones-as-claims, and the ephemeral progress
//! lane — and adds the LOOP: admit → execute → settle/complete or park,
//! until a stop condition. The engine owns no timer or cron: hosts call
//! [`request_wake`] to ENQUEUE and [`DreamerWakeDriver::run_wake_pass`] to
//! RUN the pass — two separate host calls. Idle = nothing runs.
mod deadline;
mod driver;
mod legibility;
mod scheduling;
mod settlement;
mod types;

pub use self::deadline::*;
pub use self::driver::*;
pub use self::legibility::*;
pub use self::scheduling::*;
pub use self::types::*;

// `settlement` is impl-only: it re-opens `impl DreamerWakeDriver` and owns no
// name the rest of the crate reaches for, so it needs no re-export.

#[cfg(test)]
mod tests;
#[cfg(test)]
use crate::attempt_queue::{
    AttemptCancelReceiptKind, AttemptId, AttemptResumePoint, LandingTrigger,
};
#[cfg(test)]
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerConsolidationScope, DreamerMilestoneKind,
    DreamerRunnerStore, EnqueueDreamerAttemptOutcome, EnqueueDreamerConsolidationAttempt,
    ParkDreamerAttempt,
};
#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use crate::write_envelope::WriteEnvelope;
#[cfg(test)]
use rmpv::Value;
