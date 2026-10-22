//! Timer lane: attempt-queue deadline reads, commitment reconcile and fire, deadline timer, and due sleep.

use std::sync::Arc;
use std::time::Duration;

use oneiron::attempt_queue::{AttemptQueue, AttemptState};
use oneiron::sync::residence::FreeTimeArming;
use oneiron::{
    DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND, DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND,
    DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND, DreamerConsolidationScope, DreamerRunnerStore, Vault,
};
use oneiron::{commitment_schedule, commitment_wake};

use super::{CommitmentDeadline, DeadlineSource, IdleSample, NowMillis, system_now_ms};

/// [`DeadlineSource`] over the vault's advisory attempt table: the earliest due
/// pending Dreamer consolidation attempt THIS NODE could admit. A queued attempt
/// with no retry backoff is due at its enqueue stamp; a backoff-delayed attempt
/// is due when the backoff clears, and a scheduled retry at its scheduled
/// instant. A Checkpoint park whose cutting pass ended, which this node's
/// next pass resumes, is due at once (DOOR-144); a Retry park is due its
/// retry delay after it parked. Attempt stamps are stored
/// in seconds and surfaced here in milliseconds.
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
/// For the same reason an attempt an operator placed on another worker is
/// never this node's deadline: the claim refuses it.
pub struct AttemptQueueDeadlines<'v> {
    vault: &'v Vault,
    local_node_id: u64,
    lease_owner: Option<String>,
    commitment_now: Option<NowMillis>,
    /// The host's liveness, read only for the Arc deadline (FIX 7509 P8).
    idle: Option<IdleSample>,
}

impl<'v> AttemptQueueDeadlines<'v> {
    /// `local_node_id` is the same node identity the host passes to
    /// admission (`WakeSupervisorConfig::local_node_id`).
    #[must_use]
    pub fn new(vault: &'v Vault, local_node_id: u64) -> Self {
        Self {
            vault,
            local_node_id,
            lease_owner: None,
            commitment_now: None,
            idle: None,
        }
    }

    /// The supervisor's lease owner (`WakeSupervisorConfig::lease_owner`), so
    /// an attempt placed on this worker still arms the timer.
    #[must_use]
    pub fn for_worker(mut self, lease_owner: impl Into<String>) -> Self {
        self.lease_owner = Some(lease_owner.into());
        self
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
            lease_owner: None,
            commitment_now: Some(now),
            idle: None,
        }
    }

    /// The host's liveness sample, lent to the Arc deadline alone (FIX 7509
    /// P8): an owed Arc arms none while a turn runs, background work is
    /// live or compute is away, and none before the wake policy's idle
    /// window after the last inbound. Every other deadline is unchanged.
    #[must_use]
    pub fn with_idle(mut self, idle: IdleSample) -> Self {
        self.idle = Some(idle);
        self
    }

    /// The earliest owed Arc's due instant (Unix seconds), once the host is
    /// settled when its liveness is lent. The host's own pushes read it
    /// again when live work ends.
    fn arc_due_at(&self) -> oneiron::Result<Option<u64>> {
        let Some(at) = self.vault.next_arc_due_at()? else {
            return Ok(None);
        };
        let Some(idle) = &self.idle else {
            return Ok(Some(at));
        };
        let state = idle();
        if !state.compute_available || state.running_turns || state.live_background_work {
            return Ok(None);
        }
        let idle_secs = self.vault.dreamer_wake_policy()?.idle_secs;
        Ok(Some(
            at.max(state.last_inbound_at.saturating_add(idle_secs)),
        ))
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
    fn subscribe_changes(&self) -> Option<tokio::sync::watch::Receiver<u64>> {
        Some(self.vault.subscribe_proactivity_changes())
    }

    fn next_deadline(&mut self) -> oneiron::Result<Option<CommitmentDeadline>> {
        // FIX 5661 C2b (FIX 6211): a new home adopts the handoff its move
        // carried, or records that none came, before this read arms any
        // free-time cadence. Best effort: a failure is logged and the read
        // goes on with today's opening.
        if let Err(error) = oneiron::sync::residence::prepare_home_handoff(self.vault) {
            tracing::warn!(
                kind = ?error.kind(),
                "home handoff not prepared before the deadline read"
            );
        }
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
        let macro_ready = DreamerRunnerStore::new(self.vault).macro_schedulable_attempts()?;
        let free_time = free_time_arming(self.vault);
        let mut macro_admissible = None;
        let mut macro_error = None;
        let mut next: Option<CommitmentDeadline> = None;
        for attempt in queue.list()? {
            if !matches!(
                attempt.state,
                AttemptState::Queued | AttemptState::Scheduled
            ) {
                continue;
            }
            let placed_elsewhere = attempt
                .placement
                .as_ref()
                .and_then(|placement| placement.worker.as_deref())
                .is_some_and(|worker| self.lease_owner.as_deref() != Some(worker));
            if placed_elsewhere {
                continue;
            }
            let Some(scope) = scope_for_attempt_kind(&attempt.kind) else {
                continue;
            };
            // A turn program its runtime holds parked arms nothing: only a
            // ready one is due (DOOR-141 PR2). Program rows alone are read.
            if attempt.kind == oneiron::dreamer_runner::DREAMER_TURN_PROGRAM_ATTEMPT_KIND
                && program_held(self.vault, &attempt)
            {
                continue;
            }
            // FIX 5661 C2b (FIX 6212): a started free-time try the old home
            // drains arms without the home gate, so it settles here.
            if scope == DreamerConsolidationScope::Macro && !free_time.drain.contains(&attempt.id) {
                let eligible = match macro_admissible {
                    Some(value) => value,
                    None => match self.macro_locally_admissible() {
                        Ok(value) => {
                            macro_admissible = Some(value);
                            value
                        }
                        Err(error) => {
                            macro_error = Some(error);
                            macro_admissible = Some(false);
                            continue;
                        }
                    },
                };
                // The bucket rule is MACRO consolidation's alone (FIX 6576):
                // cleanup, the NOTE review and a resident's nightly dreaming
                // arm on the home gate. A free-time try admission takes here
                // never reads it, on any node; one admission does not take
                // here (a fenced home) stays unarmed, of either kind.
                let held = !free_time.tries.contains(&attempt.id)
                    && if attempt.kind == DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND {
                        !macro_ready.contains(&attempt.id)
                    } else {
                        attempt.kind
                            == oneiron::dreamer_runner::DREAMER_FREE_TIME_FOR_HUMAN_ATTEMPT_KIND
                            || oneiron::dreamer_runner::is_free_time_try(&attempt)
                    };
                if !eligible || held {
                    continue;
                }
            }
            // The same readiness instant the claim reads.
            let due_secs = attempt
                .scheduled_at
                .or(attempt.backoff_until)
                .unwrap_or(attempt.created_at);
            let due_at_ms = due_secs.saturating_mul(1_000);
            if next.is_none_or(|current| due_at_ms < current.due_at_ms) {
                next = Some(CommitmentDeadline { due_at_ms, scope });
            }
        }
        // A Checkpoint park whose cutting pass ended is due at once, a Retry
        // park its retry delay later (Engine 10-21): the next pass of its
        // scope resumes it as the same try (DOOR-144). Read-only and
        // best-effort: an unreadable projection arms and silences nothing.
        match DreamerRunnerStore::new(self.vault).checkpoint_resumes_due() {
            Ok(due) => {
                for park in due {
                    let attempt = &park.attempt;
                    let placed_elsewhere = attempt
                        .placement
                        .as_ref()
                        .and_then(|placement| placement.worker.as_deref())
                        .is_some_and(|worker| self.lease_owner.as_deref() != Some(worker));
                    let Some(scope) = scope_for_attempt_kind(&attempt.kind) else {
                        continue;
                    };
                    if placed_elsewhere {
                        continue;
                    }
                    if scope == DreamerConsolidationScope::Macro
                        && !free_time.drain.contains(&attempt.id)
                    {
                        let eligible = match macro_admissible {
                            Some(value) => value,
                            None => match self.macro_locally_admissible() {
                                Ok(value) => {
                                    macro_admissible = Some(value);
                                    value
                                }
                                Err(error) => {
                                    macro_error = Some(error);
                                    macro_admissible = Some(false);
                                    continue;
                                }
                            },
                        };
                        if !eligible {
                            continue;
                        }
                    }
                    let due_at_ms = park.due_at.saturating_mul(1_000);
                    if next.is_none_or(|current| due_at_ms < current.due_at_ms) {
                        next = Some(CommitmentDeadline { due_at_ms, scope });
                    }
                }
            }
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "checkpoint resume deadline unavailable; keeping independent deadlines"
            ),
        }
        // A digest is per vault, so only the elected home node arms its
        // cadence. Macro admission's local-home check is also the digest's
        // home check, even when no Macro attempt is queued.
        let digest_home = match macro_admissible {
            Some(eligible) => eligible,
            None => match self.macro_locally_admissible() {
                Ok(eligible) => eligible,
                Err(error) => {
                    macro_error = Some(error);
                    false
                }
            },
        };
        if digest_home {
            // A broken digest index is observable, but cannot silence a
            // separately valid attempt or commitment deadline.
            let digest = match self.vault.next_proactivity_digest_at() {
                Ok(digest) => digest,
                Err(error) if next.is_some() || commitment.is_some() => {
                    tracing::warn!(
                        ?error,
                        "digest deadline unavailable; keeping independent deadline"
                    );
                    None
                }
                Err(error) => return Err(error),
            };
            if let Some(at) = digest {
                let due = CommitmentDeadline {
                    due_at_ms: at.saturating_mul(1_000),
                    scope: DreamerConsolidationScope::Micro,
                };
                if next.is_none_or(|current| due.due_at_ms < current.due_at_ms) {
                    next = Some(due);
                }
            }
            // Each reader's weave digest schedule (OF-499) arms the same
            // home-only cadence, and is as independent of the rest.
            let weave = match self.vault.next_weave_digest_at() {
                Ok(weave) => weave,
                Err(error) if next.is_some() || commitment.is_some() => {
                    tracing::warn!(
                        ?error,
                        "weave digest deadline unavailable; keeping independent deadline"
                    );
                    None
                }
                Err(error) => return Err(error),
            };
            if let Some(at) = weave {
                let due = CommitmentDeadline {
                    due_at_ms: at.saturating_mul(1_000),
                    scope: DreamerConsolidationScope::Micro,
                };
                if next.is_none_or(|current| due.due_at_ms < current.due_at_ms) {
                    next = Some(due);
                }
            }
            // Each agent's next owner-set free-time boundary (FIX 4453) arms
            // a Macro pass on the home alone, whose Timer begin opens the
            // cycle; it is as independent of the rest.
            let free_time = match self.vault.next_free_time_due_at() {
                Ok(free_time) => free_time,
                Err(error) if next.is_some() || commitment.is_some() => {
                    tracing::warn!(
                        ?error,
                        "free-time deadline unavailable; keeping independent deadline"
                    );
                    None
                }
                Err(error) => return Err(error),
            };
            if let Some(at) = free_time {
                let due = CommitmentDeadline {
                    due_at_ms: at.saturating_mul(1_000),
                    scope: DreamerConsolidationScope::Macro,
                };
                if next.is_none_or(|current| due.due_at_ms < current.due_at_ms) {
                    next = Some(due);
                }
            }
            // Each standing question's refresh (OF-506) and each held
            // artifact answer's wake (ARCH-0075 §4) arm the same home-only
            // cadence; the Deadline pass runs the host's pump for both.
            let question = match self.vault.next_question_refresh_at().and_then(|question| {
                let wake = self.vault.next_answer_wake_at()?;
                Ok(question.into_iter().chain(wake).min())
            }) {
                Ok(question) => question,
                Err(error) if next.is_some() || commitment.is_some() => {
                    tracing::warn!(
                        ?error,
                        "question refresh deadline unavailable; keeping independent deadline"
                    );
                    None
                }
                Err(error) => return Err(error),
            };
            if let Some(at) = question {
                let due = CommitmentDeadline {
                    due_at_ms: at.saturating_mul(1_000),
                    scope: DreamerConsolidationScope::Micro,
                };
                if next.is_none_or(|current| due.due_at_ms < current.due_at_ms) {
                    next = Some(due);
                }
            }
            // Each owed Arc (FIX 7509 P8) arms a Macro pass on the home
            // alone, whose Timer begin sweeps it; as independent of the rest.
            let arc = match self.arc_due_at() {
                Ok(arc) => arc,
                Err(error) if next.is_some() || commitment.is_some() => {
                    tracing::warn!(
                        kind = ?error.kind(),
                        "arc deadline unavailable; keeping independent deadline"
                    );
                    None
                }
                Err(error) => return Err(error),
            };
            if let Some(at) = arc {
                let due = CommitmentDeadline {
                    due_at_ms: at.saturating_mul(1_000),
                    scope: DreamerConsolidationScope::Macro,
                };
                if next.is_none_or(|current| due.due_at_ms < current.due_at_ms) {
                    next = Some(due);
                }
            }
        }
        // An unreadable home designation refuses Macro and digest, but
        // independent Micro/Meso/maintenance or commitment work continues.
        if next.is_none()
            && commitment.is_none()
            && let Some(error) = macro_error
        {
            return Err(error);
        }
        // The lanes are independent durable sources; the earlier one arms
        // the timer. A tie keeps the attempt deadline.
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
/// supervisor still sees an ordinary [`Tick::Deadline`](crate::Tick::Deadline) and no new tick variant
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

/// FIX 5661 C2b (FIX 6212): the free-time tries this node's admission takes
/// now, which the timer arms by the claim's own readiness, and the started
/// ones the old home drains, which the host's own pass runs to their end
/// without the home gate so the node can freeze its state for the move.
/// Read-only and best-effort: an unreadable set arms nothing for it.
fn free_time_arming(vault: &Vault) -> FreeTimeArming {
    oneiron::sync::residence::free_time_arming(vault).unwrap_or_else(|error| {
        tracing::warn!(
            kind = ?error.kind(),
            "free-time arming unavailable; keeping independent deadlines"
        );
        FreeTimeArming::default()
    })
}

/// Whether a queued turn program holds a park, so no pass is due for it.
/// Read-only and best-effort: an unreadable park arms nothing for it.
fn program_held(vault: &Vault, attempt: &oneiron::attempt_queue::AttemptRecord) -> bool {
    match DreamerRunnerStore::new(vault).parked_attempt(attempt.id) {
        Ok(park) => park.is_some(),
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "a turn program's park was unreadable; its deadline is not armed"
            );
            true
        }
    }
}

fn scope_for_attempt_kind(kind: &str) -> Option<DreamerConsolidationScope> {
    if kind == DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND
        || kind == oneiron::dreamer_runner::maintenance::MAINTENANCE_QUEUE_KIND
        || kind == oneiron::dreamer_runner::DREAMER_RECIPE_WAKE_ATTEMPT_KIND
        || kind == oneiron::dreamer_runner::connector_event::CONNECTOR_EVENT_QUEUE_KIND
        || kind == oneiron::dreamer_runner::DREAMER_TASK_REALIZE_ATTEMPT_KIND
        || kind == oneiron::dreamer_runner::DREAMER_WEAVE_LENS_ATTEMPT_KIND
        || kind == oneiron::dreamer_runner::DREAMER_TURN_PROGRAM_ATTEMPT_KIND
        || kind == oneiron::dreamer_runner::DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND
    {
        // Maintenance, the wake policy's recipe receipts, connector wakes
        // (OF-218), a Dreamer-lane TASK's realization, a weave lens render,
        // a turn-woken program (DOOR-141 PR2) and a SKILL-OPT job the
        // Dreamer driver admits on any pass (FIX 6939), queued or reclaimed,
        // are vault-local and do not need Macro home election.
        Some(DreamerConsolidationScope::Micro)
    } else if kind == DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND {
        Some(DreamerConsolidationScope::Meso)
    } else if kind == DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND
        || kind == oneiron::dreamer_runner::DREAMER_VAULT_CLEANUP_ATTEMPT_KIND
        || kind == oneiron::dreamer_runner::DREAMER_NOTE_REVIEW_ATTEMPT_KIND
        || kind == oneiron::dreamer_runner::DREAMER_RESIDENT_DREAM_ATTEMPT_KIND
        || kind == oneiron::dreamer_runner::DREAMER_FREE_TIME_FOR_HUMAN_ATTEMPT_KIND
    {
        // Cleanup admits only on a Timer pass at Macro scope, so its
        // deadline arms one, on the elected home alone.
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
/// Deliberately NOT a [`TickSource`](crate::TickSource): a quiet timer lane is not source
/// exhaustion — timed work can appear later, and under the no-poll
/// architecture (ARCH-0026) the lane has no way to learn of it on its own.
/// Wired bare into the supervisor it would either stop the loop permanently
/// (`None` on an empty queue) or have to poll; both are wrong, so that
/// wiring is unrepresentable. Compose it into a [`HybridTick`](crate::HybridTick), whose push
/// lane both carries the "new work arrived" notification and owns the one
/// true exhaustion signal (every producer handle dropped).
pub struct TimerTick<D> {
    source: D,
    pub(super) now_ms: NowMillis,
}

impl<D: DeadlineSource> TimerTick<D> {
    pub(super) fn subscribe_changes(&self) -> Option<tokio::sync::watch::Receiver<u64>> {
        self.source.subscribe_changes()
    }

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
                tracing::error!(kind = ?error.kind(), "commitment-deadline read failed; timer lane quiet");
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
