//! oneiron-driver — the in-process starter motor (ONE-1683 / ONE-1684, M8
//! agent runtime RT-01/RT-02).
//!
//! The engine owns no timer, no cron, and no scheduler (ARCH-0026 /
//! CROSS-ARCH-0022 / ARCH-0046): hosts enqueue work and something must pump
//! [`DreamerWakeDriver::run_wake_pass`](oneiron::DreamerWakeDriver). This
//! crate is that something — a plain `tokio::select!` supervisor
//! ([`WakeSupervisor`]) fed by a [`TickSource`]:
//!
//! * [`TimerTick`] — the wake-on-next-commitment-deadline timer lane, read
//!   from the job queue (never a poll, never a heartbeat). Deliberately
//!   NOT a standalone [`TickSource`]: a quiet timer lane is not source
//!   exhaustion, so it only ships composed into [`HybridTick`],
//! * [`PushTick`] — one bounded coalescing push mailbox whose producer
//!   handles are typed by role ([`WakePusher`] vs [`HintPusher`], H-S4),
//! * [`HybridTick`] — a biased select over both, deadline priority, burst
//!   coalescing that can never drop a distinct missed deadline.
//!
//! It is deliberately NOT an actor framework and NOT a job-worker crate —
//! the queue lives in `oneiron::job_queue` and stays there. Budget
//! admission stays inside `run_wake_pass`; this crate constructs the
//! [`LlmBackend`](oneiron::LlmBackend) (local adapter by default — no
//! egress unless a host injects a remote one) and the per-pass budget
//! machinery, and never touches runner-store rows itself.

mod supervisor;
mod tick;

pub use supervisor::{
    ConsolidationExecutorFactory, MAX_PASS_BUDGET_BASE_LEN, NowSeconds, PassExecutorFactory,
    RestartBackoffConfig, ShutdownHandle, WakeSupervisor, WakeSupervisorConfig,
    WakeSupervisorReport,
};
pub use tick::{
    CommitmentDeadline, DeadlineSource, HintPusher, HintSignal, HybridTick, JobQueueDeadlines,
    NowMillis, PushTick, Tick, TickPushError, TickSource, TimerTick, WakePusher, WakeSignal,
};
