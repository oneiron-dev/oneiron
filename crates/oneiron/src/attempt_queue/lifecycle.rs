//! The run lifecycle (untangle slice 5.0c, S5-3): ONE transition table for an
//! attempt row's state and pause, the shared engine-hold write, and the
//! [`RunState`] a run reports, derived from its row.
//!
//! Each run writer that interrupts, pauses, holds, resumes, cancels, reclaims
//! or releases a row asks [`RunLifecycle::step`] what the event does in the
//! row's current state, then writes that answer. The writer keeps its own
//! guards (the lease fence, input validation, the reserved hold actors) and
//! its side writes (the ready and annotation-hold indexes, dedupe, pack
//! receipts, settlement, notifications). The writers that consult it:
//! - the interventions, `apply_intervention_in_txn` (interrupt, pause,
//!   resume, cancel). Every hold's release resumes its row through `Resume`:
//!   the budget, fan-out, hook and annotation releases;
//! - the engine holds, budget, fan-out and hook, through
//!   [`AttemptQueue::hold_in_txn`]. The annotation hold pauses through the
//!   pause intervention under its reserved actor;
//! - the parks: lease reclaim (`cleanup_leases_except`, whose held set is the
//!   parked rows; boot recovery calls it too) and the lease release a parked
//!   run resumes by (`release_lease_in_txn`).
//!
//! The table encodes today's transitions; no stored byte changes. Two of
//! today's cells are known gaps, kept here as they are:
//! - `Resume` on an engine hold clears the pause and leaves the hold's own
//!   record (the plan hold, the launch, the verb ask, the annotation
//!   attachment) as it was (FIX RUN-HOLD changes that cell).
//! - `Reclaim` keeps a parked lease only when its caller names it held, and
//!   a lease warning reads no park (FIX RUN-LEASE).

use super::AttemptQueue;
use super::AttemptResumePoint;
use super::encoding::decode_record;
use super::run_tree_view::RunTreeStatus;
use super::telemetry::invalid_transition;
use super::types::{AttemptId, AttemptInterventionKind, AttemptPause, AttemptRecord, AttemptState};
use super::validate::{
    append_attempt_event, validate_lease_owner, validate_resume_point, validate_transition_lease,
};
use crate::entity_id::EntityId;
use crate::error::Result;

/// The facts of an attempt row the table reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RunRow {
    pub(crate) state: AttemptState,
    pub(crate) pause: Option<AttemptPause>,
    /// Whether the row keeps a scheduled instant, which a resume restores.
    pub(crate) scheduled: bool,
    /// The row's lease generation.
    pub(crate) attempt_count: u32,
}

impl RunRow {
    pub(crate) fn of(record: &AttemptRecord) -> Self {
        Self {
            state: record.state,
            pause: record.active_pause,
            scheduled: record.scheduled_at.is_some(),
            attempt_count: record.attempt_count,
        }
    }
}

/// An engine hold a lease holder puts its own running row under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EngineHold {
    /// OF-541: the run reached its spend cap. A landing row is held too.
    Budget,
    /// OF-393: the cut waits on its launch approval.
    Fanout { launch_ref: EntityId },
    /// FIX 7114: the run waits on this verb-hook invocation, at this lease
    /// generation.
    Hook {
        invocation: [u8; 16],
        attempt_count: u32,
    },
}

impl EngineHold {
    /// The pause the held row sits under.
    pub(crate) const fn pause(self) -> AttemptPause {
        match self {
            Self::Budget => AttemptPause::Budget,
            Self::Fanout { launch_ref } => AttemptPause::Fanout { launch_ref },
            Self::Hook { invocation, .. } => AttemptPause::Hook { invocation },
        }
    }

    /// The action a refusal of this hold names.
    pub(crate) const fn action(self) -> &'static str {
        match self {
            Self::Budget => "budget_hold",
            Self::Fanout { .. } => "fanout_hold",
            Self::Hook { .. } => "hook_hold",
        }
    }

    /// Whether a row already under this hold is this hold's own: a hook hold
    /// is its invocation's at one lease generation only.
    const fn holds_generation(self, attempt_count: u32) -> bool {
        match self {
            Self::Budget | Self::Fanout { .. } => true,
            Self::Hook {
                attempt_count: held,
                ..
            } => held == attempt_count,
        }
    }
}

/// An event that may move a run's attempt row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunEvent {
    /// An operator note; claimability does not change.
    Interrupt,
    /// A pause intervention asking to hold the row under `pause`.
    /// `by_hold_actor` when the annotation hold's reserved actor asks: its
    /// pause never takes over another hold.
    Pause {
        pause: AttemptPause,
        by_hold_actor: bool,
    },
    /// A resume intervention; every hold's release resumes through it.
    Resume,
    /// A cancel intervention.
    Cancel,
    /// A lease holder holds its own running row.
    Hold(EngineHold),
    /// Lease cleanup: `expired` when the lease outlived its timeout, `held`
    /// when the caller keeps the lease (a parked row).
    Reclaim { expired: bool, held: bool },
    /// The lease holder returns its row to the queue as the same try (a
    /// parked run's resume). `lease_holder` when the caller holds the lease.
    Release { lease_holder: bool },
}

/// What an event does to a row in its current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunStep {
    /// The row moves to `to`, held under `pause`.
    Move {
        to: AttemptState,
        pause: Option<AttemptPause>,
    },
    /// The row keeps its state and pause and records the event; `clock`
    /// when `updated_at` moves with it.
    Note { clock: bool },
    /// The event already holds on the row: nothing new is recorded.
    Replay,
    /// The row stays as it is; the writer reports no change.
    Keep,
    /// The event is refused in this state.
    Refuse,
}

/// The owner of the run lifecycle's one transition table.
pub(crate) struct RunLifecycle;

impl RunLifecycle {
    /// The table: what `event` does to a row with these facts.
    pub(crate) fn step(row: RunRow, event: RunEvent) -> RunStep {
        use AttemptState as S;
        match event {
            RunEvent::Interrupt => match row.state {
                // A landing row is still live work, so it can still be handed
                // an operator note. It has one bounded lease window, which a
                // note must not extend as a hidden heartbeat: only accepting
                // the landing starts it.
                S::Queued | S::Leased | S::Paused | S::Scheduled | S::Landing => RunStep::Note {
                    clock: !matches!(row.state, S::Landing),
                },
                S::Completed | S::Failed | S::Cancelled | S::Abandoned => RunStep::Refuse,
            },
            RunEvent::Pause {
                pause,
                by_hold_actor,
            } => match row.state {
                // A person's pause takes over any engine hold (FIX 9579), so
                // no hold's release resumes the row: only a resume does.
                S::Paused
                    if !by_hold_actor && row.pause.is_some_and(AttemptPause::is_engine_hold) =>
                {
                    RunStep::Move {
                        to: S::Paused,
                        pause: Some(AttemptPause::Person),
                    }
                }
                S::Paused => RunStep::Replay,
                S::Queued | S::Scheduled => RunStep::Move {
                    to: S::Paused,
                    pause: Some(pause),
                },
                S::Leased | S::Landing | S::Completed | S::Failed | S::Cancelled | S::Abandoned => {
                    RunStep::Refuse
                }
            },
            RunEvent::Resume => match row.state {
                // Restoring a still-deferred row as Queued would render it as
                // runnable now on every read surface; it goes back Scheduled.
                S::Paused => RunStep::Move {
                    to: if row.scheduled {
                        S::Scheduled
                    } else {
                        S::Queued
                    },
                    pause: None,
                },
                S::Queued | S::Leased | S::Scheduled => RunStep::Replay,
                S::Landing | S::Completed | S::Failed | S::Cancelled | S::Abandoned => {
                    RunStep::Refuse
                }
            },
            RunEvent::Cancel => match row.state {
                S::Cancelled => RunStep::Replay,
                S::Queued | S::Paused | S::Scheduled => RunStep::Move {
                    to: S::Cancelled,
                    pause: None,
                },
                S::Leased | S::Landing | S::Completed | S::Failed | S::Abandoned => RunStep::Refuse,
            },
            RunEvent::Hold(hold) => {
                if row.state == S::Paused
                    && row.pause == Some(hold.pause())
                    && hold.holds_generation(row.attempt_count)
                {
                    return RunStep::Replay;
                }
                match (hold, row.state) {
                    // A hold is not a landing: a landing row at its spend cap
                    // leaves Landing for Paused and keeps its checkpoint.
                    (EngineHold::Budget, S::Leased | S::Landing)
                    | (EngineHold::Fanout { .. } | EngineHold::Hook { .. }, S::Leased) => {
                        RunStep::Move {
                            to: S::Paused,
                            pause: Some(hold.pause()),
                        }
                    }
                    _ => RunStep::Refuse,
                }
            }
            RunEvent::Reclaim { expired, held } => match row.state {
                // A reclaimed lease resumes the SAME try (FIX 9932).
                S::Leased if expired && !held => RunStep::Move {
                    to: S::Queued,
                    pause: row.pause,
                },
                // An expired landing is mid-flight, not pre-flight: it settles
                // as the hard rung's force cancellation, which keeps the pause.
                S::Landing if expired && !held => RunStep::Move {
                    to: S::Cancelled,
                    pause: row.pause,
                },
                _ => RunStep::Keep,
            },
            RunEvent::Release { lease_holder } => match row.state {
                S::Leased if lease_holder => RunStep::Move {
                    to: S::Queued,
                    pause: row.pause,
                },
                _ => RunStep::Keep,
            },
        }
    }
}

/// One engine hold's write, as its door asks for it.
pub(in crate::attempt_queue) struct HoldWrite {
    pub(in crate::attempt_queue) id: AttemptId,
    pub(in crate::attempt_queue) lease_owner: String,
    pub(in crate::attempt_queue) attempt_count: u32,
    /// Where the same work picks up on resume.
    pub(in crate::attempt_queue) resume_point: AttemptResumePoint,
    pub(in crate::attempt_queue) hold: EngineHold,
    /// The pause event's actor: the hold's reserved actor, or the runtime's.
    pub(in crate::attempt_queue) actor: &'static str,
    /// The pause event's note. It names the hold alone: the checkpoint lives
    /// in the resume point, so no note repeats it (FIX 9580).
    pub(in crate::attempt_queue) note: String,
    pub(in crate::attempt_queue) now: u64,
}

impl AttemptQueue<'_> {
    /// The engine holds' one write. Lease-fenced like complete and fail, it
    /// moves the holder's running row to `Paused` under the hold with the
    /// checkpoint it resumes from, and releases the lease. Idempotent for a
    /// row already under the same hold. The caller retains any side record
    /// (the plan hold, the launch, the transcript) in this same writer.
    ///
    /// # Errors
    ///
    /// A missing row, a row the hold does not admit, a stale lease or an
    /// invalid resume point; storage errors.
    pub(in crate::attempt_queue) fn hold_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: HoldWrite,
    ) -> Result<AttemptRecord> {
        let action = input.hold.action();
        validate_lease_owner(&input.lease_owner)?;
        validate_resume_point(&input.resume_point)?;
        let Some(raw_record) = self.store.attempt_records.get(wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition(action, "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        let (to, pause) = match RunLifecycle::step(RunRow::of(&record), RunEvent::Hold(input.hold))
        {
            RunStep::Replay => return Ok(record),
            RunStep::Move { to, pause } => (to, pause),
            RunStep::Note { .. } | RunStep::Keep | RunStep::Refuse => {
                return Err(invalid_transition(action, record.state.as_str()));
            }
        };
        validate_transition_lease(&record, &input.lease_owner, input.attempt_count, action)?;
        // A held row is not claimable; resume restores its readiness.
        self.delete_ready_entry_for_record(wtxn, &record)?;
        // A hold owes no outstanding stop request an answer, and is not a
        // landing.
        record.cancel_state.landing = None;
        record.cancel_state.pressure.pending = 0;
        record.cancel_state.resume_point = Some(input.resume_point);
        append_attempt_event(
            &mut record,
            AttemptInterventionKind::Pause,
            input.actor.to_owned(),
            Some(input.note),
            input.now,
        )?;
        record.state = to;
        record.active_pause = pause;
        record.lease_owner = None;
        record.updated_at = input.now;
        let encoded = self.encode_in_txn(wtxn, &mut record)?;
        self.store
            .attempt_records
            .put(wtxn, record.id.as_bytes(), &encoded)?;
        Ok(record)
    }
}

/// Who holds a paused run, and so what releases it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseKind {
    /// A person paused it; only a resume releases it.
    Person,
    /// OF-368: it answers a comment thread that is unattached; reattaching
    /// the thread releases it.
    Annotation,
    /// OF-541: it reached its spend cap; the owner's resume releases it.
    Budget,
    /// OF-393: its cut waits on the launch approval.
    Fanout,
    /// FIX 7114: it waits on a verb hook's answer.
    Hook,
}

impl PauseKind {
    pub(crate) const fn of(pause: AttemptPause) -> Self {
        match pause {
            AttemptPause::Person => Self::Person,
            AttemptPause::Annotation { .. } => Self::Annotation,
            AttemptPause::Budget => Self::Budget,
            AttemptPause::Fanout { .. } => Self::Fanout,
            AttemptPause::Hook { .. } => Self::Hook,
        }
    }
}

/// The state a run reports, derived from its attempt row and, when the caller
/// read one, its park row. It stores nothing: each state is a rule over
/// today's rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    /// Waiting for a worker, runnable now.
    Ready,
    /// Waiting for a worker at a later instant: scheduled, or backing off
    /// (a row from before ONE-1795 keeps only its backoff instant).
    Deferred,
    /// A worker holds its lease.
    Running,
    /// A worker holds its lease and the run waits on a signal: its park row
    /// stands.
    Parked,
    /// A worker finishes its bounded landing.
    Landing,
    /// Paused; the kind names who holds it and what releases it. A paused row
    /// that names no pause was paused by a person.
    Paused(PauseKind),
    Completed,
    Failed,
    Cancelled,
    /// The executor stopped without delivering and without being stopped.
    Abandoned,
}

impl RunState {
    /// The run's state from its attempt row alone. A leased row reads
    /// [`Self::Running`]; [`Self::with_park`] adds what its park row says.
    #[must_use]
    pub fn of(record: &AttemptRecord) -> Self {
        match record.state {
            AttemptState::Queued if record.scheduled_at.or(record.backoff_until).is_some() => {
                Self::Deferred
            }
            AttemptState::Queued => Self::Ready,
            AttemptState::Scheduled => Self::Deferred,
            AttemptState::Leased => Self::Running,
            AttemptState::Landing => Self::Landing,
            AttemptState::Paused => {
                Self::Paused(record.active_pause.map_or(PauseKind::Person, PauseKind::of))
            }
            AttemptState::Completed => Self::Completed,
            AttemptState::Failed => Self::Failed,
            AttemptState::Cancelled => Self::Cancelled,
            AttemptState::Abandoned => Self::Abandoned,
        }
    }

    /// A running run whose park row stands is parked.
    #[must_use]
    pub const fn with_park(self, parked: bool) -> Self {
        match self {
            Self::Running if parked => Self::Parked,
            state => state,
        }
    }

    /// The run tree's status token. A deferred run reads `Paused`, not
    /// eligible to run now, which the Context Board projects as Scheduled; a
    /// parked or landing run is still running.
    #[must_use]
    pub const fn tree_status(self) -> RunTreeStatus {
        match self {
            Self::Ready => RunTreeStatus::Queued,
            Self::Deferred | Self::Paused(_) => RunTreeStatus::Paused,
            Self::Running | Self::Parked | Self::Landing => RunTreeStatus::Running,
            Self::Completed => RunTreeStatus::Completed,
            Self::Failed => RunTreeStatus::Failed,
            Self::Cancelled => RunTreeStatus::Cancelled,
            Self::Abandoned => RunTreeStatus::Abandoned,
        }
    }
}
