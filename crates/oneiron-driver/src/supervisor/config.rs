//! Static config, restart backoff, and budget-id length ceilings.
use std::sync::Arc;
use std::time::Duration;

use oneiron::{
    BudgetExhaustionPolicy, DEFAULT_DREAMER_CHILD_RESERVE_UNITS, DREAMER_GRACEFUL_WRAP_WINDOW_MS,
    DREAMER_WAKE_PASS_WALL_CLOCK_CEILING_MS, Result, WakeMilestoneAuthor,
};

/// Second-resolution wall-clock read for [`RunWakePass::now`], injectable
/// for tests.
pub type NowSeconds = Arc<dyn Fn() -> u64 + Send + Sync>;

pub(super) fn system_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Restart-backoff shape for failed/panicked passes: exponential from
/// `initial`, doubling to `max`. Reset by every completed pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartBackoffConfig {
    pub initial: Duration,
    pub max: Duration,
}

impl Default for RestartBackoffConfig {
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(500),
            max: Duration::from_secs(60),
        }
    }
}

#[derive(Debug)]
pub(super) struct RestartBackoff {
    config: RestartBackoffConfig,
    next: Option<Duration>,
}

impl RestartBackoff {
    pub(super) fn new(config: RestartBackoffConfig) -> Self {
        Self { config, next: None }
    }

    pub(super) fn advance(&mut self) -> Duration {
        let delay = self
            .next
            .unwrap_or(self.config.initial)
            .min(self.config.max);
        self.next = Some(delay.saturating_mul(2).min(self.config.max));
        delay
    }

    pub(super) fn reset(&mut self) {
        self.next = None;
    }
}

/// Dense-scan window for the one-shot startup probe of the next free
/// per-pass budget index (see [`next_pass_budget_index`]). Every index in
/// `[0, bound)` is probed once (at most 65_536 point-reads via
/// [`DreamerRunnerStore::budget`]). When the window is full, a galloping
/// probe continues past the bound until a free suffix is found (binary
/// search between the last occupied and first free), so restart never
/// clamps onto an already-occupied `{base}:p{bound}`. Finite work, no
/// rescan per pass, no hot-loop; cost is paid once per [`WakeSupervisor::run`].
pub(super) const PASS_BUDGET_INDEX_SCAN_BOUND: u64 = 65_536;

/// Mirror of the runner store's private budget-id ceiling
/// (`MAX_DREAMER_BUDGET_ID_LEN` in `oneiron::dreamer_runner`). Pinned by a
/// real-store validation test below, so drift breaks the build here.
pub(super) const MAX_RUNNER_BUDGET_ID_LEN: usize = 128;

/// Mirror of `attempt_queue`'s private `MAX_LEASE_OWNER_LEN` (admission stamps
/// `lease_owner` through the runner into the attempt queue, which rejects empty
/// and over-long owners before mutating rows). Pinned by a real-queue
/// validation test below.
pub(super) const MAX_RUNNER_LEASE_OWNER_LEN: usize = 128;

/// Bytes reserved for the derived per-pass suffix: `":p"` plus the widest
/// `u64` decimal rendering (20 digits).
const PASS_BUDGET_SUFFIX_RESERVE: usize = 22;

/// Longest base [`WakeSupervisorConfig::budget_id`] whose derived
/// `{base}:p{n}` id stays within the runner store's ceiling for every
/// possible pass index.
pub const MAX_PASS_BUDGET_BASE_LEN: usize = MAX_RUNNER_BUDGET_ID_LEN - PASS_BUDGET_SUFFIX_RESERVE;

/// Static supervisor configuration. One base wake budget id + lease owner
/// per supervisor; every pass gets a fresh wall-clock deadline, a fresh
/// in-memory wake-budget counter, and a **per-pass durable runner-store
/// budget row** derived from [`Self::budget_id`] (see
/// `durable_pass_budget_id`).
///
/// On each [`WakeSupervisor::run`] the supervisor probes the runner store
/// once for existing `{budget_id}:p{n}` rows and resumes at
/// highest-occupied + 1 (dense-scanning `[0, bound)` then galloping past
/// the bound when full) so process restarts do not re-mint spent rows or
/// land in a hole that later collides with a still-occupied higher
/// suffix. Concurrent supervisors sharing one base id remain out of
/// scope (single-supervisor model; share the pass gate when co-located).
#[derive(Clone)]
pub struct WakeSupervisorConfig {
    /// Base durable runner-store budget id. Each pass appends a monotonic
    /// pass index (`{budget_id}:p{n}`) so a long-lived supervisor never
    /// reuses a spent budget row across passes. Note: each pass therefore
    /// leaves one budget row in the runner store; this crate does not GC
    /// them. Restart-safe: [`WakeSupervisor::run`] skip-scans existing
    /// `:p{n}` rows before minting.
    pub budget_id: String,
    /// Lease owner stamped on admissions and parks.
    pub lease_owner: String,
    /// This node's id (macro-scope admission verifies it against the vault
    /// identity; must be nonzero — zero is rejected by [`Self::validate`]).
    pub local_node_id: u64,
    /// Total budget units granted to each pass.
    pub budget_total_units: u64,
    /// Units reserved per admitted child attempt.
    pub reserve_units: u64,
    /// Per-pass wall-clock ceiling in milliseconds. Must exceed
    /// [`DREAMER_GRACEFUL_WRAP_WINDOW_MS`] so a pass is not born already
    /// inside the finalize/hard-cut window (see [`Self::validate`]).
    pub pass_ceiling_ms: u64,
    /// Counter behavior at exhaustion. `Suspend` (fail-closed) by default.
    pub exhaustion_policy: BudgetExhaustionPolicy,
    /// Durable Started/Done milestone authorship, if the host wants it.
    pub milestones: Option<WakeMilestoneAuthor>,
    /// Restart-backoff shape for failed/panicked passes and for
    /// zero-progress [`WakePassStop::BudgetExhausted`] /
    /// [`WakePassStop::DeadlineHardCut`] (admitted == 0), which would
    /// otherwise hot-loop under HybridTick deadline redelivery.
    pub backoff: RestartBackoffConfig,
}

impl WakeSupervisorConfig {
    #[must_use]
    pub fn new(
        budget_id: impl Into<String>,
        lease_owner: impl Into<String>,
        local_node_id: u64,
        budget_total_units: u64,
    ) -> Self {
        Self {
            budget_id: budget_id.into(),
            lease_owner: lease_owner.into(),
            local_node_id,
            budget_total_units,
            reserve_units: DEFAULT_DREAMER_CHILD_RESERVE_UNITS,
            pass_ceiling_ms: DREAMER_WAKE_PASS_WALL_CLOCK_CEILING_MS,
            exhaustion_policy: BudgetExhaustionPolicy::Suspend,
            milestones: None,
            backoff: RestartBackoffConfig::default(),
        }
    }

    /// Rejects configs that would make every pass fail or hard-cut without
    /// durable progress (fail-fast before the tick loop):
    ///
    /// * a base [`Self::budget_id`] whose derived `{base}:p{n}` id could
    ///   exceed the runner store's budget-id ceiling (startup scan would
    ///   treat validation errors as "occupied" and spin);
    /// * `local_node_id == 0` (admission rejects zero before mutating any
    ///   attempt row, so every pass would empty-fail under HybridTick);
    /// * `pass_ceiling_ms <= DREAMER_GRACEFUL_WRAP_WINDOW_MS` (the pass is
    ///   born already in the finalize/hard-cut window and never admits);
    /// * `reserve_units == 0` (runner admission rejects zero reserve before
    ///   mutating rows — every pass would surface as Failed);
    /// * empty or over-long [`Self::lease_owner`] (attempt-queue lease-owner
    ///   ceiling is `MAX_RUNNER_LEASE_OWNER_LEN`; empty/over-long fails
    ///   admission the same way).
    pub fn validate(&self) -> Result<()> {
        if self.budget_id.len() > MAX_PASS_BUDGET_BASE_LEN {
            return Err(oneiron::Error::InvalidConfig(format!(
                "wake supervisor budget_id is {} bytes; max {} so derived \
                 per-pass ids fit the runner-store ceiling",
                self.budget_id.len(),
                MAX_PASS_BUDGET_BASE_LEN
            )));
        }
        if self.local_node_id == 0 {
            return Err(oneiron::Error::InvalidConfig(
                "wake supervisor local_node_id must be nonzero \
                 (admission rejects zero before mutating any attempt)"
                    .into(),
            ));
        }
        if self.pass_ceiling_ms <= DREAMER_GRACEFUL_WRAP_WINDOW_MS {
            return Err(oneiron::Error::InvalidConfig(format!(
                "wake supervisor pass_ceiling_ms is {}; must exceed the \
                 graceful wrap window ({DREAMER_GRACEFUL_WRAP_WINDOW_MS} ms) \
                 so a pass is not born already in the finalize window",
                self.pass_ceiling_ms,
            )));
        }
        if self.reserve_units == 0 {
            return Err(oneiron::Error::InvalidConfig(
                "wake supervisor reserve_units must be > 0 \
                 (admission rejects zero reserve before mutating any attempt)"
                    .into(),
            ));
        }
        if self.lease_owner.is_empty() {
            return Err(oneiron::Error::InvalidConfig(
                "wake supervisor lease_owner must be non-empty \
                 (admission rejects empty lease owners before mutating any attempt)"
                    .into(),
            ));
        }
        if self.lease_owner.len() > MAX_RUNNER_LEASE_OWNER_LEN {
            return Err(oneiron::Error::InvalidConfig(format!(
                "wake supervisor lease_owner is {} bytes; max {} \
                 (attempt-queue lease-owner ceiling)",
                self.lease_owner.len(),
                MAX_RUNNER_LEASE_OWNER_LEN
            )));
        }
        Ok(())
    }
}
