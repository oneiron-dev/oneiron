//! Timer lane: attempt-queue deadline reads, commitment reconcile and fire, deadline timer, and due sleep.

use std::sync::Arc;
use std::time::Duration;

use oneiron::attempt_queue::{AttemptQueue, AttemptState};
use oneiron::{
    DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND, DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND,
    DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND, DreamerConsolidationScope, DreamerRunnerStore, Vault,
};
use oneiron::{commitment_schedule, commitment_wake};

use super::{CommitmentDeadline, DeadlineSource, NowMillis, system_now_ms};

/// [`DeadlineSource`] over the vault's advisory attempt table: the earliest due
/// queued Dreamer consolidation attempt THIS NODE could admit. A queued attempt
/// with no retry backoff is due at its enqueue stamp; a backoff-delayed attempt
/// is due when the backoff clears. Attempt stamps are stored in seconds and
/// surfaced here in milliseconds.
///
/// MACRO attempts are gated at admission by the full local-admissibility
/// predicate (`admit_next_consolidation`): `local_node_id` must match both
/// the vault's stable client identity (`load_or_mint_client_id` via
/// [`DreamerRunnerStore::local_home_node_candidate`]) and the elected home
/// designation. Surfacing a due macro when either check would refuse leaves
/// the queued row unmutated and — deadlines having priority over pushes —
/// busy-spins the supervisor on the same overdue deadline, starving push
/// lanes. Both checks are re-read every cycle; an unreadable vault identity
/// is treated as not-admissible (macro suppressed, other lanes still flow).
pub struct AttemptQueueDeadlines<'v> {
    vault: &'v Vault,
    local_node_id: u64,
    commitment_now: Option<NowMillis>,
}

impl<'v> AttemptQueueDeadlines<'v> {
    /// `local_node_id` is the same node identity the host passes to
    /// admission (`WakeSupervisorConfig::local_node_id`).
    #[must_use]
    pub fn new(vault: &'v Vault, local_node_id: u64) -> Self {
        Self {
            vault,
            local_node_id,
            commitment_now: None,
        }
    }

    /// [`Self::new`] with an injected clock for the commitment-due lane.
    ///
    /// Only the commitment lane reads a clock: the attempt lane's stamps are
    /// durable and need none. Tests that must place "now" relative to a stored
    /// due instant use this instead of sleeping.
    #[must_use]
    pub fn with_commitment_clock(vault: &'v Vault, local_node_id: u64, now: NowMillis) -> Self {
        Self {
            vault,
            local_node_id,
            commitment_now: Some(now),
        }
    }

    /// Mirrors macro admission: home designation AND vault client identity
    /// both equal `local_node_id`. Designation read errors propagate (timer
    /// goes quiet). Identity read errors suppress macro only — same fail-
    /// closed stance as "not admissible", without starving micro/meso.
    fn macro_locally_admissible(&self) -> oneiron::Result<bool> {
        let store = DreamerRunnerStore::new(self.vault);
        let Some(designation) = store.home_node_designation()? else {
            return Ok(false);
        };
        if designation.node_id != self.local_node_id {
            return Ok(false);
        }
        // Same stable client id admission loads via load_or_mint_client_id
        // (exposed here through local_home_node_candidate).
        let vault_node_id = match store.local_home_node_candidate(false, false, false) {
            Ok(candidate) => candidate.node_id,
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "vault client identity unreadable; suppressing macro deadlines"
                );
                return Ok(false);
            }
        };
        Ok(vault_node_id == self.local_node_id)
    }
}

impl DeadlineSource for AttemptQueueDeadlines<'_> {
    fn next_deadline(&mut self) -> oneiron::Result<Option<CommitmentDeadline>> {
        // The commitment lane runs FIRST (CMT-3, ONE-1540). Consuming a due
        // phase COMMITS a Dreamer attempt, so reading the attempt queue after
        // it is what makes that brand-new attempt visible in the same caller
        // read — without relocating this merge into the commitment source.
        let commitment = match &self.commitment_now {
            Some(clock) => CommitmentDueDeadlines::with_clock(self.vault, Arc::clone(clock)),
            None => CommitmentDueDeadlines::new(self.vault),
        }
        .next_deadline()?;
        let queue = AttemptQueue::new(self.vault);
        let macro_admissible = self.macro_locally_admissible()?;
        let mut next: Option<CommitmentDeadline> = None;
        for attempt in queue.list()? {
            if attempt.state != AttemptState::Queued {
                continue;
            }
            let Some(scope) = scope_for_attempt_kind(&attempt.kind) else {
                continue;
            };
            if scope == DreamerConsolidationScope::Macro && !macro_admissible {
                continue;
            }
            let due_secs = attempt.backoff_until.unwrap_or(attempt.created_at);
            let due_at_ms = due_secs.saturating_mul(1_000);
            if next.is_none_or(|current| due_at_ms < current.due_at_ms) {
                next = Some(CommitmentDeadline { due_at_ms, scope });
            }
        }
        // The two lanes are independent durable sources; the earlier one arms
        // the timer. A TIE keeps the attempt deadline, so wiring the commitment
        // lane in can never displace a deadline this source already surfaced.
        Ok(match (next, commitment) {
            (Some(attempt), Some(due)) if due.due_at_ms < attempt.due_at_ms => Some(due),
            (Some(attempt), _) => Some(attempt),
            (None, commitment) => commitment,
        })
    }
}

/// The three phases that may arm the timer.
///
/// `LifecycleDue` is absent BY CONSTRUCTION, not by a filter: it is a lapse
/// marker (an unmet obligation is a fact to notice on the next pass, never a
/// reason to wake the machine) and it is ONE-1541's caller-driven sweep input.
/// Naming the phase set at the call site is what keeps it out of the wake feed.
const COMMITMENT_TIMER_PHASES: [commitment_schedule::CommitmentDuePhase; 3] = [
    commitment_schedule::CommitmentDuePhase::Project,
    commitment_schedule::CommitmentDuePhase::Lead,
    commitment_schedule::CommitmentDuePhase::Due,
];

/// [`DeadlineSource`] over the commitment due index (CMT-2, ONE-1539 +
/// CMT-3, ONE-1540).
///
/// Reads three phases — `Project`, `Lead`, and `Due`. `LifecycleDue` is a
/// lapse marker and ONE-1541's input: it remains visible through
/// `next_due_at()` but structurally cannot reach the timer feed from here.
///
/// This is also the SOLE production caller of
/// [`Vault::reconcile_commitment_schedule`], and — since ONE-1540 — of
/// [`fire_due_commitment_wake`](oneiron::commitment_wake::fire_due_commitment_wake).
/// Both run inside the deadline read, the one moment the driver is already
/// awake and about to arm a timer, rather than on a period. That is what keeps
/// ARCH-0026's no-poll rule intact with no scheduler anywhere.
///
/// This source NEVER touches the attempt queue. A due phase's Dreamer attempt
/// surfaces through the existing [`AttemptQueueDeadlines`] merge, so the
/// supervisor still sees an ordinary [`Tick::Deadline`] and no new tick variant
/// exists: the Event-vs-Timer distinction belongs to the enqueued attempt, not
/// to supervisor control flow.
///
/// A read, projection, or fire failure propagates as `Err`. Mapping it to
/// `Ok(None)` would tell the supervisor "no obligations exist" on a corrupt
/// index, which is the one answer a commitment engine must never give; the
/// unconsumed row simply stays for the next read.
pub struct CommitmentDueDeadlines<'v> {
    vault: &'v Vault,
    now: NowMillis,
}

impl<'v> CommitmentDueDeadlines<'v> {
    /// Reads wall-clock time from the system.
    #[must_use]
    pub fn new(vault: &'v Vault) -> Self {
        Self::with_clock(vault, Arc::new(system_now_ms))
    }

    /// [`Self::new`] with an injected millisecond clock.
    #[must_use]
    pub fn with_clock(vault: &'v Vault, now: NowMillis) -> Self {
        Self { vault, now }
    }

    /// ONE-1539's Project-consume body, unchanged: a Project row that has come
    /// due is work to DO, not a deadline to arm on. Materialize it first so the
    /// timer arms on what the projection left behind instead of on the row it
    /// just consumed.
    fn reconcile_due_projects(&self, now_secs: u64) -> oneiron::Result<()> {
        let project = [commitment_schedule::CommitmentDuePhase::Project];
        if let Some(at) = self
            .vault
            .commitment_due_index_snapshot()?
            .next_timer_at(&project)
            && at <= now_secs
        {
            self.vault.reconcile_commitment_schedule(now_secs)?;
        }
        Ok(())
    }

    /// Drains every actionable `Lead`/`Due` phase at or before `now_secs`
    /// through the fire-once door.
    ///
    /// `Enqueued`, `Existing`, `MissingInstance`, `ClosedInstance`,
    /// `StatedIntention`, and `Decision` all consumed the exact phase
    /// transactionally, so the loop simply re-reads and an honest backlog
    /// terminates. `Raced` consumed nothing but is convergent: the equality
    /// miss MEANS a competing writer already changed the minimum and owns that
    /// progress, so re-reading is the right next move.
    ///
    /// A typed error propagates as `Err`, leaving the unconsumed row for the
    /// next read.
    fn fire_due_wake_phases(&self, now_secs: u64) -> oneiron::Result<()> {
        loop {
            let Some(entry) = self.vault.next_actionable_wake_phase()? else {
                return Ok(());
            };
            let Some(due) = commitment_wake::CommitmentWakeDue::from_due_entry(&entry)? else {
                return Ok(());
            };
            if due.fire_at > now_secs {
                return Ok(());
            }
            commitment_wake::fire_due_commitment_wake(self.vault, due, now_secs)?;
        }
    }
}

impl DeadlineSource for CommitmentDueDeadlines<'_> {
    fn next_deadline(&mut self) -> oneiron::Result<Option<CommitmentDeadline>> {
        // The index stores seconds; the tick lane speaks milliseconds.
        let now_secs = (self.now)() / 1_000;
        self.reconcile_due_projects(now_secs)?;
        self.fire_due_wake_phases(now_secs)?;
        Ok(self
            .vault
            .commitment_due_index_snapshot()?
            .next_timer_at(&COMMITMENT_TIMER_PHASES)
            .map(|due_secs| CommitmentDeadline {
                due_at_ms: due_secs.saturating_mul(1_000),
                scope: DreamerConsolidationScope::Micro,
            }))
    }
}

fn scope_for_attempt_kind(kind: &str) -> Option<DreamerConsolidationScope> {
    if kind == DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND {
        Some(DreamerConsolidationScope::Micro)
    } else if kind == DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND {
        Some(DreamerConsolidationScope::Meso)
    } else if kind == DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND {
        Some(DreamerConsolidationScope::Macro)
    } else {
        None
    }
}

/// Wake-on-deadline timer LANE: reads the next commitment deadline from
/// its [`DeadlineSource`] and sleeps until exactly that instant. There is
/// no interval and no heartbeat — with no timed work (or on a deadline
/// read error) the lane goes quiet instead of polling.
///
/// Deliberately NOT a [`TickSource`]: a quiet timer lane is not source
/// exhaustion — timed work can appear later, and under the no-poll
/// architecture (ARCH-0026) the lane has no way to learn of it on its own.
/// Wired bare into the supervisor it would either stop the loop permanently
/// (`None` on an empty queue) or have to poll; both are wrong, so that
/// wiring is unrepresentable. Compose it into a [`HybridTick`], whose push
/// lane both carries the "new work arrived" notification and owns the one
/// true exhaustion signal (every producer handle dropped).
pub struct TimerTick<D> {
    source: D,
    pub(super) now_ms: NowMillis,
}

impl<D: DeadlineSource> TimerTick<D> {
    /// Timer over the system wall clock.
    #[must_use]
    pub fn new(source: D) -> Self {
        Self::with_clock(source, Arc::new(system_now_ms))
    }

    /// Timer over an injected clock (tests).
    #[must_use]
    pub fn with_clock(source: D, now_ms: NowMillis) -> Self {
        Self { source, now_ms }
    }

    /// One deadline read. A read error is logged and treated as "no timed
    /// work": the lane goes quiet (fail-stop) instead of spinning against a
    /// broken store.
    pub(super) fn read_deadline(&mut self) -> Option<CommitmentDeadline> {
        match self.source.next_deadline() {
            Ok(deadline) => deadline,
            Err(error) => {
                tracing::error!(?error, "commitment-deadline read failed; timer lane quiet");
                None
            }
        }
    }

    pub(super) fn now(&self) -> u64 {
        (self.now_ms)()
    }
}

/// Sleeps until `due_at_ms` on the given clock; returns immediately for a
/// deadline already in the past (a missed deadline fires, never drops).
pub(crate) async fn sleep_until_due(now_ms: &NowMillis, due_at_ms: u64) {
    let now = (*now_ms)();
    if due_at_ms > now {
        tokio::time::sleep(Duration::from_millis(due_at_ms - now)).await;
    }
}
