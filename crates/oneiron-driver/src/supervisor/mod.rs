//! The wake-pass supervisor (ONE-1683): a plain `tokio::select!` loop that
//! pumps [`DreamerWakeDriver::run_wake_pass`] — the starter motor the engine
//! deliberately does not own.
//!
//! Shape (all acceptance-pinned):
//!
//! * ONE biased select composes the loop: shutdown beats a ready tick, and
//!   the tick source itself resolves deadline-vs-push priority (deadline
//!   wins — see [`HybridTick`](crate::HybridTick)).
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
//!   authenticated push) — plus a bounded one-shot delay after a FAILED
//!   pass, which defers consuming the next already-signalled tick rather
//!   than generating wakeups of its own.

mod budget_ids;
mod config;
mod factory;
mod pass;
#[path = "loop.rs"]
mod run;
mod shutdown;

pub use self::config::{
    MAX_PASS_BUDGET_BASE_LEN, NowSeconds, RestartBackoffConfig, WakeSupervisorConfig,
};
pub use self::factory::{ConsolidationExecutorFactory, PassExecutorFactory};
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
