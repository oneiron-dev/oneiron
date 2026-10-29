//! The wake-pass supervisor (ONE-1683): the loop that pumps
//! [`DreamerWakeDriver::run_wake_pass`] — the starter motor the engine
//! deliberately does not own. This file declares the supervisor's modules and
//! re-exports its API; the loop is `loop.rs`, its one arbitration point
//! `arbiter.rs`, the owed-pass debt and backoff `retry.rs`, and the wave
//! quanta `wave_lane.rs`.
//!
//! Shape (all acceptance-pinned):
//!
//! * ONE arbiter composes the loop (`arbiter::next_supervisor_event`):
//!   shutdown beats everything, then fresh source ticks, due owed retries
//!   and wave quanta take turns in a fixed rotation, so no lane pins another.
//!   The tick source resolves deadline-vs-push order itself (see
//!   [`HybridTick`](crate::HybridTick)).
//! * A `tokio::sync::Semaphore(1)` serializes passes: a second tick arriving
//!   mid-pass can never start a second pass (share the gate across
//!   supervisors over one vault via [`WakeSupervisor::with_pass_gate`]).
//! * Panic containment is layered: the ENGINE contains an `exec.execute`
//!   panic at the attempt boundary (the attempt is parked, its reservation
//!   refunded, and the pass fails cleanly), and a panic anywhere else in a
//!   pass is caught HERE as the backstop — either way the supervisor
//!   restarts with backoff, never crashes.
//! * Shutdown mid-pass is COOPERATIVE (H-S5/R2): the supervisor raises the
//!   pass's [`WakeCancellation`] flag and KEEPS AWAITING the pass future —
//!   it is never dropped mid-await, so an in-flight gated write or
//!   off-record close is never aborted. The pass stops itself at its
//!   attempt-boundary checkpoints, parking + refunding anything it had admitted.
//! * Budget admission stays entirely INSIDE `run_wake_pass`: this crate
//!   never calls `admit_next_consolidation` / `settle_budget` /
//!   `abort_budget_reservation`.
//! * No actor framework, no attempt-worker crate, no heartbeat: the loop only
//!   ever wakes for a [`Tick`] (an attempt-queue deadline read or an
//!   authenticated push), an owed retry coming due, or wave work. A pass that
//!   fails or admits nothing leaves its tick owed, due again after that
//!   tick's own capped backoff (`retry`), while fresh ticks and wave work
//!   keep their turns.

mod arbiter;
mod attachment;
mod budget_ids;
mod config;
mod factory;
mod inference;
mod inference_device;
mod inference_worker;
mod pass;
mod program_factory;
mod retry;
#[path = "loop.rs"]
mod run;
mod shutdown;
mod supervised_pass;
mod wave_lane;

pub use self::attachment::{
    AttachedPassFuture, LinkedShutdown, PassAttachment, PassAttachmentSource, WakePassFuture,
};
pub use self::config::{NowSeconds, RestartBackoffConfig, WakeSupervisorConfig};
pub use self::factory::{
    ConsolidationExecutorFactory, PassExecutorFactory, SkillOptimizerLoan, WaveReadyDispatcher,
};
pub use self::inference::{WorkerProbe, WorkerProbeFuture, WorkerSpec};
pub use self::inference_device::{
    DeclaredEnvelope, DeviceLedger, DeviceRow, DeviceSnapshot, ResidentReport, ResidentSource,
};
pub use self::inference_worker::{
    DEFAULT_WORKER_IDLE_STOP, InferenceWorker, LaunchFailure, LauncherFuture, RunningWorker,
    WORKER_ACTIVITY_POLL, WORKER_CRASH_BACKOFF_SECS, WORKER_LIVENESS_POLL, WORKER_STOP_GRACE,
    WorkerActivity, WorkerExit, WorkerLauncher, WorkerLease, WorkerPolicy, WorkerUnavailable,
};
pub use self::program_factory::ProgramExecutorFactory;
pub use self::run::{WakeSupervisor, WakeSupervisorReport};
pub use self::shutdown::ShutdownHandle;

#[cfg(test)]
mod budget_tests;
#[cfg(test)]
mod factory_tests;
#[cfg(test)]
mod loop_tests;
#[cfg(test)]
mod tests;

#[cfg(test)]
use self::{budget_ids::*, config::*, pass::*, tests::*};
