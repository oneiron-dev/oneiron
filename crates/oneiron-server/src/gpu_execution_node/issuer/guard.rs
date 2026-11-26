//! The issuer's half of the drain guard (pass 33 row R4, 7.9): how each confirmed end and each
//! dispatch the machine never answered counts for `MACHINE_JOB_GUARD`, and the refusal a drained
//! machine gets before anything is sent or held there.
//!
//! It mirrors the node's own count (the GPU slot table's), from what the issuer observes: a lost
//! box, a refused launch, an unconfirmed release, an end inside `jobs.drain.fast_exit_secs`, and
//! a node figure above the issuer's bracket count; a run past the window resets; a caller's
//! stop, a revoke, a withdrawn key and a refusal the node wrote down for the request neither
//! count nor reset. Door 12 clears the issuer's drain, as `machines.drain.clear_by` allows. Under
//! `after_readiness_check` (the default), a passed readiness check that the node ran after the
//! issuer read the drain clears it as well ([`ReadinessReads`], CG-2 row 9).
//!
//! [`ReadinessReads`] is how the issuer reads a node's readiness fact from the `Node` answer. A
//! passed check clears the issuer's drain. A run of failed checks reaches the owner as one ask per
//! run once the run is long enough (pass 34, 7.3 and 16, practice 6; row Q4). Two callers read
//! that answer:
//! - the job worker's work-order pass, for the candidate machines of open orders. A placement
//!   preview and the order door's own pass only read the answer;
//! - the job worker's scheduled read, beside its passes, of every machine the vault's grants
//!   admit on the job protocol that the worker has not asked within that machine's
//!   `jobs.readiness.every_secs`, so that an idle machine is observed too (FIX
//!   CG2-ROW9-UNDEMANDED-MACHINES-UNOBSERVED).
//!
//! The node's own drain belongs to the node: `resume` at the box clears only that one.

use std::collections::{HashMap, HashSet};

use oneiron::gpu_job::MeterVerdict;
use oneiron::job_dispatch::machine_records::{MachineDrain, MachineJobGuard, MachineJobOutcome};
use oneiron::machine_readiness::ReadinessEscalation;
use oneiron::{EntityId, Vault};

use crate::gpu_execution_node::wire::{
    DeviceRelease, JobEnd, JobReceipt, NodeReadiness, ReadinessState,
};

/// How the terminal receipt `ended`, billed with `meter`, counts for its machine.
#[must_use]
pub fn machine_job_outcome(
    ended: &JobReceipt,
    meter: &MeterVerdict,
    fast_exit_secs: u64,
) -> MachineJobOutcome {
    let failure = |why: String| MachineJobOutcome::MachineFailure { why };
    match &ended.end {
        // A session slice's paid end (row W1) is no end of the machine's run.
        Some(
            JobEnd::Stopped
            | JobEnd::Revoked
            | JobEnd::Withdrawn
            | JobEnd::Refused { .. }
            | JobEnd::Continued,
        ) => {
            return MachineJobOutcome::NotTheMachines;
        }
        Some(JobEnd::Lost { reason, .. }) => return failure(format!("lost: {reason}")),
        Some(JobEnd::LaunchRefused { reason }) => {
            return failure(format!("launch_refused: {reason}"));
        }
        _ => {}
    }
    if let DeviceRelease::Unconfirmed { why } = &ended.release {
        return failure(format!("release_unconfirmed: {why}"));
    }
    if matches!(meter, MeterVerdict::Bracketed { .. }) {
        return failure("measured_above_bracket".to_owned());
    }
    // A renewed session's later slice (row W1) began only after the run went
    // past a whole paid chunk: its run is past the window, however few of
    // the slice's own seconds it used.
    if ended.slice.as_ref().is_some_and(|slice| slice.renewal > 0) {
        return MachineJobOutcome::RanPastFastExit;
    }
    match ended.measured_secs {
        Some(secs) if secs > fast_exit_secs => MachineJobOutcome::RanPastFastExit,
        _ => failure(format!("ended_within_{fast_exit_secs}_s")),
    }
}

/// Counts `outcome` for `machine` at `now_ms`. A store failure is logged: the guard is a
/// brake, and a count that did not land is counted again by the node's own guard.
pub fn count_outcome(vault: &Vault, machine: EntityId, outcome: &MachineJobOutcome, now_ms: u64) {
    match vault.count_machine_job_outcome(machine, outcome, now_ms) {
        Ok(guard) => {
            if let Some(drained) = &guard.drained
                && drained.at_ms == now_ms
            {
                tracing::warn!(machine = %machine.to_hex(), why = %drained.why, "vault_machine: the issuer drained a machine");
            }
        }
        Err(error) => {
            tracing::warn!(machine = %machine.to_hex(), %error, "vault_machine: the machine's job guard not counted");
        }
    }
}

/// The refusal a start or a dispatch on `machine` gets while the issuer has drained it, before
/// any reservation or network call: the code `machine_drained`. The drain's cause names what
/// the machine's runs ended with, so it stays in `MACHINE_JOB_GUARD` for door 12 and the
/// machine views, never in a job's reason (section 6, as #10414's review round 1 ruled for the
/// node's own refusals). A guard the store cannot read refuses too, as
/// `machine_guard_unreadable`: the brake fails closed. `None` while the machine is not drained.
#[must_use]
pub fn machine_job_guard_refusal(vault: &Vault, machine: EntityId) -> Option<String> {
    match vault.machine_job_drained(machine) {
        Ok(drained) => drained.map(|_| "machine_drained".to_owned()),
        Err(error) => {
            tracing::warn!(machine = %machine.to_hex(), %error, "vault_machine: the machine's job guard not read; the dispatch is refused");
            Some("machine_guard_unreadable".to_owned())
        }
    }
}

/// What the issuer did with one reading of a machine's readiness fact.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReadinessObserved {
    /// The issuer's drain that a passed check cleared.
    pub cleared: Option<MachineDrain>,
    /// What a run of failed checks raised. `None` while the last check passed, and before any
    /// check ran.
    pub escalation: Option<ReadinessEscalation>,
    /// A store read or write failed. The reading is acted on again at the next answer.
    pub store_failed: bool,
}

/// What one reading is matched on: the node's check, its run of failures, its own drain, and
/// the issuer's guard row as read before the request. An answer that repeats the last sample is
/// not acted on again.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReadinessSample {
    checked_at_ms: Option<u64>,
    failed_in_a_row: u32,
    node_drained: bool,
    guard: Option<MachineJobGuard>,
}

/// The checks that a drained machine's clear counts from, all on the node's own clock, so the
/// two machines' clocks are never compared.
/// - `checked_at_ms` is the node's newest check in the first answer to a `Node` request sent
///   after the issuer read `guard`. That answer reports the newest check the node had settled.
/// - `settled_after_ms` is the first check the node dates later. It settled after that answer,
///   but it may have started, and run its probes, before the issuer drained the machine: the
///   node can pause between its probes and settling them (REVIEW-10518 round 2 P1). So it
///   clears nothing.
///
/// The node runs one check at a time. A check it dates later still started after that one
/// settled, so after the answer, the request and every write `guard` holds. Only such a check
/// clears.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ClearBaseline {
    guard: MachineJobGuard,
    checked_at_ms: Option<u64>,
    settled_after_ms: Option<u64>,
}

/// What one reading does to a drained machine's clear.
enum ClearStep {
    /// The reading is the baseline's first answer.
    Baseline,
    /// The reading shows the first check settled after the baseline's answer.
    SettledAfter(Option<u64>),
    /// The reading shows a passed check that started after that one settled.
    Clear,
    /// Nothing to do.
    Wait,
}

/// One machine's entry in [`ReadinessReads`].
#[derive(Debug)]
struct MachineReads {
    /// The sample last acted on. `None` after a store failure, so that the next answer is acted
    /// on again.
    sample: Option<ReadinessSample>,
    baseline: Option<ClearBaseline>,
    /// When the issuer last read this machine, on its own clock.
    read_at_ms: u64,
}

/// The issuer's readings of its machines' readiness facts, held by the job worker. Each machine
/// has its last sample and its clear baseline. Every machine read in the last [`Self::IDLE_MS`]
/// is kept, however many the worker reads in a pass, so another machine's read never evicts a
/// baseline (REVIEW-10518 round 2 P1). So is every machine the vault's grants admit, as the
/// scheduled read last listed them ([`Self::keep_granted`]), however long its period, so a
/// machine read less than once a day still reaches its clear (REVIEW-10544 round 2 P1). Any
/// other machine not read for a day is dropped. The worker reads only the vault's own machines,
/// so the entries stay as many as those. A dropped entry, or one lost to a restart, only delays
/// a clear: the next answer becomes the new baseline.
///
/// Apart from those entries it keeps when the worker last sent each machine a `Node` request,
/// which the scheduled read counts each machine's period from ([`Self::due`]), for as long as
/// the grants admit the machine (REVIEW-10544 round 1 P1).
#[derive(Debug, Default)]
pub struct ReadinessReads {
    machines: HashMap<EntityId, MachineReads>,
    /// When the worker last sent each machine a `Node` request, on the issuer's clock, whatever
    /// came back.
    asked_at: HashMap<EntityId, u64>,
    /// The machines the vault's grants admitted at the scheduled read's last listing.
    granted: HashSet<EntityId>,
}

impl ReadinessReads {
    /// How long a machine stays kept with no read: a day.
    pub const IDLE_MS: u64 = 86_400_000;

    /// How many machines are kept.
    #[must_use]
    pub fn len(&self) -> usize {
        self.machines.len()
    }

    /// Whether no machine is kept.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.machines.is_empty()
    }

    /// Records that the worker sends `machine` a `Node` request at `asked_at_ms`, before it is
    /// sent, whatever comes back: an answer, another answer than `Node`, or none. The scheduled
    /// read counts the machine's period from it, and asks no machine a request is already out to
    /// (REVIEW-10544 round 2 P1).
    pub fn asked(&mut self, machine: EntityId, asked_at_ms: u64) {
        self.asked_at.insert(machine, asked_at_ms);
    }

    /// Whether `machine` is due the scheduled read that follows the worker's pass begun at
    /// `pass_at_ms`, at `now_ms`, with the period `every_ms`:
    /// - never asked: due;
    /// - last asked after `now_ms` (the issuer's clock stepped back past it): due;
    /// - asked since `pass_at_ms`, by that pass, by a later one or by this read: not due, so one
    ///   pass and its read never ask a machine twice, whatever the period;
    /// - otherwise due once its last ask is at least `every_ms` old.
    #[must_use]
    pub fn due(&self, machine: EntityId, now_ms: u64, every_ms: u64, pass_at_ms: u64) -> bool {
        let Some(&asked_at_ms) = self.asked_at.get(&machine) else {
            return true;
        };
        let Some(age) = now_ms.checked_sub(asked_at_ms) else {
            return true;
        };
        asked_at_ms < pass_at_ms && age >= every_ms
    }

    /// Whether `machine` is due ([`Self::due`]), and if so records the scheduled read's ask of it
    /// at `now_ms` ([`Self::asked`]), in one step, so no ask out to it meanwhile is repeated.
    pub fn claim(
        &mut self,
        machine: EntityId,
        now_ms: u64,
        every_ms: u64,
        pass_at_ms: u64,
    ) -> bool {
        let due = self.due(machine, now_ms, every_ms, pass_at_ms);
        if due {
            self.asked(machine, now_ms);
        }
        due
    }

    /// Records `machines` as the machines the vault's grants admit now: their readings are kept
    /// past the one-day drop, and every other machine's last ask is dropped.
    pub fn keep_granted(&mut self, machines: &[EntityId]) {
        self.granted = machines.iter().copied().collect();
        let granted = &self.granted;
        self.asked_at.retain(|machine, _| granted.contains(machine));
    }

    /// Reads `machine`'s readiness fact from one `Node` answer the issuer read at `now_ms`. The
    /// node's own drain comes from the same answer (`node_drained`). `guard_before` is the
    /// issuer's guard row as read before that request was sent (`Vault::machine_job_guard`).
    /// Returns `None`, and does nothing, when the answer repeats the last sample.
    /// - A passed check clears the issuer's drain when all of these hold:
    ///   `machines.drain.clear_by` is `after_readiness_check`; the same answer shows the node's
    ///   own drain cleared; the node dates the check later than the baseline (see
    ///   `ClearBaseline`); and the guard row is still the one the baseline was read with
    ///   (`Vault::clear_machine_job_drain_after_check`, which compares the row in its write).
    ///   A failure counted after that read changes the row, so the next answer becomes a new
    ///   baseline and a later check clears.
    /// - A run of failed checks raises the owner's one ask for the run once it reaches
    ///   `machines.readiness.escalate_after` (`Vault::raise_machine_readiness_ask`). A later
    ///   reading of the same run raises nothing more.
    ///
    /// A node wall clock that steps back delays a clear until it passes the baseline again. It
    /// never brings a clear forward.
    pub fn observe(
        &mut self,
        vault: &Vault,
        machine: EntityId,
        guard_before: Option<&MachineJobGuard>,
        node_drained: Option<&str>,
        readiness: &NodeReadiness,
        now_ms: u64,
    ) -> Option<ReadinessObserved> {
        let sample = ReadinessSample {
            checked_at_ms: readiness.checked_at_ms,
            failed_in_a_row: readiness.failed_in_a_row,
            node_drained: node_drained.is_some(),
            guard: guard_before.cloned(),
        };
        if !self.machines.contains_key(&machine) {
            self.drop_idle(now_ms);
        }
        let reads = self.machines.entry(machine).or_insert(MachineReads {
            sample: None,
            baseline: None,
            read_at_ms: now_ms,
        });
        reads.read_at_ms = now_ms;
        if reads.sample.as_ref() == Some(&sample) {
            return None;
        }
        let observed = observe_node_readiness(
            vault,
            machine,
            guard_before,
            &mut reads.baseline,
            node_drained,
            readiness,
            now_ms,
        );
        reads.sample = (!observed.store_failed).then_some(sample);
        Some(observed)
    }

    /// Drops every machine idle for [`Self::IDLE_MS`] that the grants no longer admit.
    fn drop_idle(&mut self, now_ms: u64) {
        let granted = &self.granted;
        self.machines.retain(|machine, reads| {
            granted.contains(machine) || now_ms.saturating_sub(reads.read_at_ms) < Self::IDLE_MS
        });
    }
}

/// One reading of `machine`'s readiness fact against its clear `baseline`, as
/// [`ReadinessReads::observe`] describes. A store failure is logged, changes nothing and is
/// reported.
fn observe_node_readiness(
    vault: &Vault,
    machine: EntityId,
    guard_before: Option<&MachineJobGuard>,
    baseline: &mut Option<ClearBaseline>,
    node_drained: Option<&str>,
    readiness: &NodeReadiness,
    now_ms: u64,
) -> ReadinessObserved {
    let mut observed = ReadinessObserved::default();
    match guard_before.filter(|guard| guard.drained.is_some()) {
        None => *baseline = None,
        Some(guard) => {
            let step = match baseline.as_ref().filter(|base| base.guard == *guard) {
                None => ClearStep::Baseline,
                Some(base) => match base.settled_after_ms {
                    None if readiness.checked_at_ms > base.checked_at_ms => {
                        ClearStep::SettledAfter(readiness.checked_at_ms)
                    }
                    Some(settled)
                        if matches!(readiness.state, ReadinessState::Ready)
                            && node_drained.is_none()
                            && readiness.checked_at_ms > Some(settled) =>
                    {
                        ClearStep::Clear
                    }
                    _ => ClearStep::Wait,
                },
            };
            match step {
                ClearStep::Baseline => {
                    *baseline = Some(ClearBaseline {
                        guard: guard.clone(),
                        checked_at_ms: readiness.checked_at_ms,
                        settled_after_ms: None,
                    });
                }
                ClearStep::SettledAfter(settled) => {
                    if let Some(base) = baseline.as_mut() {
                        base.settled_after_ms = settled;
                    }
                }
                ClearStep::Clear => {
                    match vault.clear_machine_job_drain_after_check(machine, guard, now_ms) {
                        Ok(Some(drain)) => {
                            tracing::info!(machine = %machine.to_hex(), was = %drain.why, checked_at_ms = ?readiness.checked_at_ms, "vault_machine: a passed readiness check cleared the issuer's drain");
                            observed.cleared = Some(drain);
                            *baseline = None;
                        }
                        Ok(None) => {}
                        Err(error) => {
                            tracing::warn!(machine = %machine.to_hex(), %error, "vault_machine: the issuer's drain not cleared after a passed readiness check");
                            observed.store_failed = true;
                        }
                    }
                }
                ClearStep::Wait => {}
            }
        }
    }
    if let Some(streak) = readiness.streak(machine) {
        match vault.raise_machine_readiness_ask(&streak) {
            Ok(escalation) => {
                if let ReadinessEscalation::Asked {
                    seq,
                    queued_now: true,
                } = escalation
                {
                    tracing::warn!(machine = %machine.to_hex(), seq, failed_in_a_row = streak.failed_in_a_row, "vault_machine: a machine keeps failing its readiness check; the owner is asked");
                }
                observed.escalation = Some(escalation);
            }
            Err(error) => {
                tracing::warn!(machine = %machine.to_hex(), %error, "vault_machine: the readiness ask not raised");
                observed.store_failed = true;
            }
        }
    }
    observed
}
