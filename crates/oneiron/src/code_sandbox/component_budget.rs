//! Per-step ceilings of a Wasmtime component run. The runtime that spends them
//! lives in `oneiron-agent-runtime`; core keeps the type, because the hook
//! sandbox (`runtime_hooks::sandbox`) runs on the same ceilings.

use std::time::Duration;

/// Per-step ceilings, and one advisory threshold (`host_calls`). Zero
/// ceilings are never interpreted as unlimited.
#[derive(Debug, Clone, Copy)]
pub struct ComponentBudget {
    pub fuel: u64,
    pub memory_bytes: usize,
    /// The step's time allowance for guest execution and new host calls, not
    /// cancellation of host code. An admitted synchronous host callback runs to
    /// completion, and its elapsed time counts. Once the allowance is spent the
    /// step stops at its next safe point (before another host call or output, or
    /// at the guest's epoch check) and answers the typed `step_deadline` stop: not
    /// done, not failed, its finished host calls kept (FIX 7665). Its host takes
    /// the stop as a typed fact and may run the same program again from those
    /// calls (FIX 7703). This is not a hard end-to-end RPC timeout.
    pub wall_time: Duration,
    /// An advisory observation threshold, never a ceiling (FIX 8676): each
    /// step counts its host calls, and a count past it only marks the
    /// step's tracing observation. No count refuses a call or ends a step.
    /// Zero turns the marker off.
    pub host_calls: u32,
    pub message_bytes: usize,
    pub foreign_budget: super::microvm::ExecutionBudget,
}

impl Default for ComponentBudget {
    fn default() -> Self {
        Self {
            // The QuickJS factory's readiness probe alone burns 12,684,552 fuel
            // on the pinned first-party artifact; the default must admit it.
            // A streamed result costs the guest a few instructions a byte to
            // encode, so a step may emit hundreds of megabytes before its
            // fuel, not its wall time, ends it.
            fuel: 2_000_000_000,
            memory_bytes: 64 * 1024 * 1024,
            wall_time: Duration::from_secs(5),
            host_calls: 256,
            message_bytes: 1024 * 1024,
            foreign_budget: super::microvm::ExecutionBudget::default(),
        }
    }
}
