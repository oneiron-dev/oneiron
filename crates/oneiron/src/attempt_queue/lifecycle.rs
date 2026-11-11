//! The run lifecycle (untangle slice 5.0c, S5-3): ONE transition table for an
//! attempt row's state and pause, the shared engine-hold write, and the
//! [`RunState`] a run reports, derived from its row.
//!
//! Each production writer of the row's seven lifecycle fields (`state`,
//! `active_pause`, `lease_owner`, `scheduled_at`, `settled_at`, `cancel_state`,
//! `attempt_count`) goes through the write functions of [`RunLifecycle`] below.
//! State-moving writers ask [`RunLifecycle::step`] what the event does in the
//! row's current state; fresh rows, cancel receipt appends and pressure counts
//! also live here. The store codec's secret mask (`encode_admitted_record`)
//! replaces a row by a decode of its own serialized members, not a lifecycle
//! write. The writer keeps its own
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
//!   run resumes by (`release_lease_in_txn`);
//! - the retry source, `retry_storage_in_txn`, through `Retry`; its fresh
//!   successor is built by [`RunLifecycle::successor_row`];
//! - landing acceptance, `accept_landing_in_txn`, through `AcceptLanding`;
//! - landing finish, `finish_landing_in_txn`, through `FinishLanding`;
//! - hard cancellation, `force_cancel_in_txn` and `force_cancel_record`,
//!   through `ForceCancel` (lease cleanup also calls the latter);
//! - ready-row claims, `lease_claimed_record`, through `Claim`;
//! - completion, `complete_storage_in_txn`, through `Complete`;
//! - failure, `fail_storage_in_txn`, through `Fail`;
//! - abandonment, `abandon_in_txn`, through `Abandon`;
//! - placement changes, `redirect`, through `Redirect`;
//! - same-try requeue, `requeue_with_history_in_txn`, through `Requeue`;
//! - fresh-row deferral, `defer_enqueued_in_txn`, through `Defer`;
//! - retry acceleration, `advance_waiting_retry_in_txn`, through `AdvanceRetry`;
//! - checkpoint lease reset, `unlease_attempt`, through `Unlease`.
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
use super::types::{
    AttemptEvent, AttemptId, AttemptInterventionKind, AttemptLeaseExpiry, AttemptPause,
    AttemptPlacement, AttemptRecord, AttemptResultRef, AttemptState, AttemptTerminalExhaust,
    ManifestEntry, PlannedBinding,
};
use super::validate::{
    CancelReceiptDraft, append_attempt_event, validate_lease_owner, validate_resume_point,
    validate_transition_lease,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::limit_ask::{EngineLimit, LimitWatch};
use crate::store::attempt_cancel::{
    AttemptCancelReceipt, AttemptCancelReceiptKind, AttemptCancelState, AttemptCancellation,
    AttemptLanding, AttemptLandingReserve,
};
use crate::store::attempt_record::{AttemptReadSet, RequeuedFailure};
use crate::store::attempt_record_codec::cancel_validators::validate_cancel_receipt_fields;
use crate::store::attempt_run_signal::{RunAsk, RunBranchSignal, SignalIntent};

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

/// The non-lifecycle parts of a fresh attempt: sites provide their payload
/// and provenance, while lifecycle.rs alone builds the row's lifecycle fields.
pub(crate) struct NewAttempt {
    pub(crate) id: AttemptId,
    pub(crate) kind: String,
    pub(crate) payload: Vec<u8>,
    pub(crate) lease_expirations: Vec<AttemptLeaseExpiry>,
    pub(crate) claimed_at: Option<u64>,
    pub(crate) retry_of: Option<AttemptId>,
    pub(crate) folded_retries: u32,
    pub(crate) backoff_until: Option<u64>,
    pub(crate) last_error: Option<String>,
    pub(crate) task_ref: Option<String>,
    pub(crate) run_id: Option<String>,
    pub(crate) dedupe_key: Option<String>,
    pub(crate) dedupe_actor_ref: Option<String>,
    pub(crate) created_at: u64,
    pub(crate) updated_at: u64,
    pub(crate) events: Vec<AttemptEvent>,
    pub(crate) manifest: Vec<ManifestEntry>,
    pub(crate) executor_model: Option<String>,
    pub(crate) executor_seat: Option<String>,
    pub(crate) executor_role: Option<oneiron_model::model_binding::ModelRole>,
    pub(crate) planned_binding: Option<PlannedBinding>,
    pub(crate) read_set: Option<AttemptReadSet>,
    pub(crate) result_ref: Option<AttemptResultRef>,
    pub(crate) signals: Vec<RunBranchSignal>,
    pub(crate) asks: Vec<RunAsk>,
    pub(crate) placement: Option<AttemptPlacement>,
    pub(crate) history: Vec<RequeuedFailure>,
    pub(crate) terminal_exhaust: Option<AttemptTerminalExhaust>,
    pub(crate) signal_intents: Vec<SignalIntent>,
}

/// Builds a fresh row with its ready state and cancel lifecycle supplied here.
fn row(
    parts: NewAttempt,
    scheduled_at: Option<u64>,
    cancel_state: AttemptCancelState,
) -> AttemptRecord {
    AttemptRecord {
        id: parts.id,
        kind: parts.kind,
        payload: parts.payload,
        state: if scheduled_at.is_some() {
            AttemptState::Scheduled
        } else {
            AttemptState::Queued
        },
        lease_owner: None,
        attempt_count: 0,
        lease_expirations: parts.lease_expirations,
        claimed_at: parts.claimed_at,
        scheduled_at,
        retry_of: parts.retry_of,
        folded_retries: parts.folded_retries,
        backoff_until: parts.backoff_until,
        last_error: parts.last_error,
        task_ref: parts.task_ref,
        run_id: parts.run_id,
        dedupe_key: parts.dedupe_key,
        dedupe_actor_ref: parts.dedupe_actor_ref,
        created_at: parts.created_at,
        updated_at: parts.updated_at,
        settled_at: None,
        events: parts.events,
        manifest: parts.manifest,
        executor_model: parts.executor_model,
        executor_seat: parts.executor_seat,
        executor_role: parts.executor_role,
        planned_binding: parts.planned_binding,
        read_set: parts.read_set,
        cancel_state,
        result_ref: parts.result_ref,
        signals: parts.signals,
        asks: parts.asks,
        placement: parts.placement,
        history: parts.history,
        active_pause: None,
        terminal_exhaust: parts.terminal_exhaust,
        signal_intents: parts.signal_intents,
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
    /// The lease holder's try failed and a successor row carries the next try:
    /// this row settles as failed.
    Retry,
    /// Landing acceptance by `accept_landing_in_txn`.
    AcceptLanding,
    /// Landing completion by `finish_landing_in_txn`.
    FinishLanding,
    /// Hard cancellation by `force_cancel_record` and `force_cancel_in_txn`.
    ForceCancel,
    /// Ready-row leasing by `lease_claimed_record`.
    Claim,
    /// Completion by `complete_storage_in_txn`.
    Complete,
    /// Failure by `fail_storage_in_txn`.
    Fail,
    /// Abandonment by `abandon_in_txn`.
    Abandon,
    /// Placement changes by `redirect`, fencing a lease when its worker moves.
    Redirect { worker_moved: bool },
    /// Same-try requeue by `requeue_with_history_in_txn`.
    Requeue,
    /// Fresh-row deferral by `defer_enqueued_in_txn`.
    Defer,
    /// Retry acceleration by `advance_waiting_retry_in_txn`.
    AdvanceRetry,
    /// Checkpoint lease reset by `unlease_attempt`.
    Unlease,
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
            RunEvent::Retry => match row.state {
                S::Leased => RunStep::Move {
                    to: S::Failed,
                    pause: row.pause,
                },
                S::Queued
                | S::Paused
                | S::Scheduled
                | S::Landing
                | S::Completed
                | S::Failed
                | S::Cancelled
                | S::Abandoned => RunStep::Refuse,
            },
            RunEvent::AcceptLanding => match row.state {
                S::Leased => RunStep::Move {
                    to: S::Landing,
                    pause: row.pause,
                },
                S::Landing => RunStep::Replay,
                S::Queued
                | S::Paused
                | S::Scheduled
                | S::Completed
                | S::Failed
                | S::Cancelled
                | S::Abandoned => RunStep::Refuse,
            },
            RunEvent::FinishLanding => match row.state {
                S::Landing => RunStep::Move {
                    to: S::Cancelled,
                    pause: row.pause,
                },
                S::Queued
                | S::Leased
                | S::Paused
                | S::Scheduled
                | S::Completed
                | S::Failed
                | S::Cancelled
                | S::Abandoned => RunStep::Refuse,
            },
            RunEvent::ForceCancel => match row.state {
                S::Queued | S::Leased | S::Paused | S::Scheduled | S::Landing => RunStep::Move {
                    to: S::Cancelled,
                    pause: row.pause,
                },
                S::Cancelled => RunStep::Replay,
                S::Completed | S::Failed | S::Abandoned => RunStep::Keep,
            },
            RunEvent::Claim => match row.state {
                S::Queued | S::Scheduled => RunStep::Move {
                    to: S::Leased,
                    pause: row.pause,
                },
                S::Leased
                | S::Paused
                | S::Landing
                | S::Completed
                | S::Failed
                | S::Cancelled
                | S::Abandoned => RunStep::Refuse,
            },
            RunEvent::Complete => match row.state {
                S::Leased => RunStep::Move {
                    to: S::Completed,
                    pause: row.pause,
                },
                S::Completed => RunStep::Replay,
                S::Queued
                | S::Paused
                | S::Scheduled
                | S::Landing
                | S::Failed
                | S::Cancelled
                | S::Abandoned => RunStep::Refuse,
            },
            RunEvent::Fail => match row.state {
                S::Leased => RunStep::Move {
                    to: S::Failed,
                    pause: row.pause,
                },
                S::Failed => RunStep::Replay,
                S::Queued
                | S::Paused
                | S::Scheduled
                | S::Landing
                | S::Completed
                | S::Cancelled
                | S::Abandoned => RunStep::Refuse,
            },
            RunEvent::Abandon => match row.state {
                S::Leased | S::Landing => RunStep::Move {
                    to: S::Abandoned,
                    pause: row.pause,
                },
                S::Abandoned => RunStep::Replay,
                S::Queued | S::Paused | S::Scheduled | S::Completed | S::Failed | S::Cancelled => {
                    RunStep::Refuse
                }
            },
            RunEvent::Requeue => match row.state {
                S::Leased => RunStep::Move {
                    to: S::Scheduled,
                    pause: row.pause,
                },
                S::Queued
                | S::Paused
                | S::Scheduled
                | S::Landing
                | S::Completed
                | S::Failed
                | S::Cancelled
                | S::Abandoned => RunStep::Refuse,
            },
            RunEvent::Defer => match row.state {
                S::Queued => RunStep::Move {
                    to: S::Scheduled,
                    pause: row.pause,
                },
                S::Leased
                | S::Paused
                | S::Scheduled
                | S::Landing
                | S::Completed
                | S::Failed
                | S::Cancelled
                | S::Abandoned => RunStep::Keep,
            },
            RunEvent::AdvanceRetry => match row.state {
                S::Scheduled => RunStep::Move {
                    to: S::Scheduled,
                    pause: row.pause,
                },
                S::Queued
                | S::Leased
                | S::Paused
                | S::Landing
                | S::Completed
                | S::Failed
                | S::Cancelled
                | S::Abandoned => RunStep::Keep,
            },
            RunEvent::Redirect { worker_moved } => match row.state {
                S::Leased if worker_moved => RunStep::Move {
                    to: S::Queued,
                    pause: row.pause,
                },
                S::Queued | S::Scheduled | S::Leased => RunStep::Note { clock: false },
                S::Paused | S::Landing | S::Completed | S::Failed | S::Cancelled | S::Abandoned => {
                    RunStep::Refuse
                }
            },
            RunEvent::Unlease => match row.state {
                S::Leased => RunStep::Move {
                    to: S::Queued,
                    pause: row.pause,
                },
                S::Queued
                | S::Paused
                | S::Scheduled
                | S::Completed
                | S::Failed
                | S::Cancelled
                | S::Abandoned => RunStep::Keep,
                S::Landing => RunStep::Refuse,
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

    /// Applies `Complete`, writing state, active_pause, lease_owner and
    /// settled_at. The site keeps lease guards, backoff_until, last_error,
    /// updated_at, indexes, receipts, projection and notifications.
    pub(crate) fn complete(record: &mut AttemptRecord, now: u64) -> RunStep {
        let step = Self::step(RunRow::of(record), RunEvent::Complete);
        if let RunStep::Move { to, pause } = step {
            record.state = to;
            record.active_pause = pause;
            record.lease_owner = None;
            record.settled_at = Some(now);
        }
        step
    }

    /// Applies `Fail`, writing state, active_pause, lease_owner and settled_at.
    /// The site keeps lease and reason guards, backoff_until, last_error,
    /// updated_at, indexes, receipts and notifications.
    pub(crate) fn fail(record: &mut AttemptRecord, now: u64) -> RunStep {
        let step = Self::step(RunRow::of(record), RunEvent::Fail);
        if let RunStep::Move { to, pause } = step {
            record.state = to;
            record.active_pause = pause;
            record.lease_owner = None;
            record.settled_at = Some(now);
        }
        step
    }

    /// Applies `Abandon`, writing state, active_pause, cancel_state.landing,
    /// lease_owner, scheduled_at and settled_at. The site keeps lease, reason
    /// and result guards, backoff_until, last_error, result_ref, updated_at,
    /// indexes, receipts and settlement.
    ///
    /// The landing was answered-but-unfinished advisory state; an abandoned
    /// row settles by reason + result_ref, and the placement rule forbids a
    /// landing record outside landing/cancelled.
    pub(crate) fn abandon(record: &mut AttemptRecord, now: u64) -> RunStep {
        let step = Self::step(RunRow::of(record), RunEvent::Abandon);
        if let RunStep::Move { to, pause } = step {
            record.state = to;
            record.active_pause = pause;
            record.cancel_state.landing = None;
            record.lease_owner = None;
            record.scheduled_at = None;
            record.settled_at = Some(now);
        }
        step
    }

    /// Applies `Reclaim`, writing state, active_pause, lease_owner and
    /// scheduled_at only for a previously Leased row. A Landing move is
    /// returned unwritten for force_cancel_record. The site keeps expiry
    /// history, backoff_until, last_error, updated_at, indexes and persistence.
    pub(crate) fn reclaim(record: &mut AttemptRecord, expired: bool, held: bool) -> RunStep {
        let row = RunRow::of(record);
        let step = Self::step(row, RunEvent::Reclaim { expired, held });
        if row.state == AttemptState::Leased
            && let RunStep::Move { to, pause } = step
        {
            record.state = to;
            record.active_pause = pause;
            record.lease_owner = None;
            record.scheduled_at = None;
        }
        step
    }

    /// Applies `Redirect`, checking the next attempt_count before writing
    /// state, active_pause, lease_owner, scheduled_at and attempt_count. The
    /// site keeps placement guards, backoff_until, updated_at, indexes, events,
    /// persistence and stopping the fenced executor.
    pub(crate) fn redirect(record: &mut AttemptRecord, worker_moved: bool) -> Result<RunStep> {
        let step = Self::step(RunRow::of(record), RunEvent::Redirect { worker_moved });
        if let RunStep::Move { to, pause } = step {
            // Fence the former worker immediately, even if a new worker uses
            // the same owner string before claiming.
            let attempt_count = record
                .attempt_count
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("redirect lease generation"))?;
            record.state = to;
            record.active_pause = pause;
            record.lease_owner = None;
            record.scheduled_at = None;
            record.attempt_count = attempt_count;
        }
        Ok(step)
    }

    /// Applies `Requeue`, writing state, active_pause, lease_owner and
    /// scheduled_at. The site keeps lease and reason guards, history,
    /// last_error, backoff_until, updated_at, indexes and persistence.
    pub(crate) fn requeue(record: &mut AttemptRecord, due_at: u64) -> RunStep {
        let step = Self::step(RunRow::of(record), RunEvent::Requeue);
        if let RunStep::Move { to, pause } = step {
            record.state = to;
            record.active_pause = pause;
            record.lease_owner = None;
            record.scheduled_at = Some(due_at);
        }
        step
    }

    /// Applies `Defer`, writing state, active_pause and scheduled_at. The site
    /// keeps readiness and due guards, indexes and persistence.
    pub(crate) fn defer(record: &mut AttemptRecord, due: u64) -> RunStep {
        let step = Self::step(RunRow::of(record), RunEvent::Defer);
        if let RunStep::Move { to, pause } = step {
            record.state = to;
            record.active_pause = pause;
            record.scheduled_at = Some(due);
        }
        step
    }

    /// Applies `AdvanceRetry`, writing state and active_pause unchanged, and
    /// scheduled_at. The site keeps retry guards, backoff_until, indexes and
    /// persistence.
    pub(crate) fn advance_retry(record: &mut AttemptRecord, now: u64) -> RunStep {
        let step = Self::step(RunRow::of(record), RunEvent::AdvanceRetry);
        if let RunStep::Move { to, pause } = step {
            record.state = to;
            record.active_pause = pause;
            record.scheduled_at = Some(now);
        }
        step
    }

    /// Applies `Unlease`, writing state, active_pause and lease_owner. The
    /// site keeps the landing refusal, claimed_at and checkpoint serialization.
    pub(crate) fn unlease(record: &mut AttemptRecord) -> RunStep {
        let step = Self::step(RunRow::of(record), RunEvent::Unlease);
        if let RunStep::Move { to, pause } = step {
            record.state = to;
            record.active_pause = pause;
            record.lease_owner = None;
        }
        step
    }

    /// Builds a fresh row with no state move: row writes state, active_pause,
    /// lease_owner, scheduled_at, settled_at, cancel_state and attempt_count.
    /// The site keeps payload, provenance, guards, indexes and persistence.
    pub(crate) fn new_row(parts: NewAttempt) -> AttemptRecord {
        row(parts, None, AttemptCancelState::default())
    }

    /// Applies `Pause`, writing state and active_pause; clears lease_owner only
    /// if the row was not Paused. The site keeps guards, indexes, updated_at,
    /// backoff_until, last_error and events.
    pub(crate) fn pause(
        record: &mut AttemptRecord,
        pause: AttemptPause,
        by_hold_actor: bool,
    ) -> RunStep {
        let row = RunRow::of(record);
        let step = Self::step(
            row,
            RunEvent::Pause {
                pause,
                by_hold_actor,
            },
        );
        if let RunStep::Move { to, pause } = step {
            record.state = to;
            record.active_pause = pause;
            if row.state != AttemptState::Paused {
                record.lease_owner = None;
            }
        }
        step
    }

    /// Applies `Resume`, writing state, active_pause and lease_owner. The site
    /// keeps guards, indexes, updated_at, backoff_until, last_error and events.
    pub(crate) fn resume(record: &mut AttemptRecord) -> RunStep {
        let step = Self::step(RunRow::of(record), RunEvent::Resume);
        if let RunStep::Move { to, pause } = step {
            record.state = to;
            record.active_pause = pause;
            record.lease_owner = None;
        }
        step
    }

    /// Applies `Cancel`, writing state, active_pause, lease_owner, scheduled_at
    /// and settled_at. The site keeps guards, indexes, updated_at,
    /// backoff_until, last_error and events.
    pub(crate) fn cancel(record: &mut AttemptRecord, now: u64) -> RunStep {
        let step = Self::step(RunRow::of(record), RunEvent::Cancel);
        if let RunStep::Move { to, pause } = step {
            record.state = to;
            record.active_pause = pause;
            record.lease_owner = None;
            record.scheduled_at = None;
            record.settled_at = Some(now);
        }
        step
    }

    /// Applies `Release`, writing state, active_pause, lease_owner and
    /// scheduled_at. The site keeps guards, indexes, updated_at, backoff_until,
    /// last_error and events.
    pub(crate) fn release(record: &mut AttemptRecord, lease_owner: &str) -> RunStep {
        let lease_holder = record.lease_owner.as_deref() == Some(lease_owner);
        let step = Self::step(RunRow::of(record), RunEvent::Release { lease_holder });
        if let RunStep::Move { to, pause } = step {
            record.state = to;
            record.active_pause = pause;
            record.lease_owner = None;
            record.scheduled_at = None;
        }
        step
    }

    /// Applies `Retry`, writing state, active_pause (unchanged), lease_owner,
    /// scheduled_at and settled_at. The site keeps guards, indexes, updated_at,
    /// backoff_until, last_error and events.
    pub(crate) fn retry(source: &mut AttemptRecord, now: u64) -> RunStep {
        let step = Self::step(RunRow::of(source), RunEvent::Retry);
        if let RunStep::Move { to, pause } = step {
            source.state = to;
            source.active_pause = pause;
            source.lease_owner = None;
            source.scheduled_at = None;
            source.settled_at = Some(now);
        }
        step
    }

    /// Applies `AcceptLanding`, writing cancel_state.landing, an optional
    /// cancel_state.resume_point, cancel_state.pressure.pending, state and
    /// active_pause. The site keeps guards, provenance, receipts and updated_at.
    pub(crate) fn accept_landing(
        record: &mut AttemptRecord,
        landing: AttemptLanding,
        resume_point: Option<AttemptResumePoint>,
    ) -> RunStep {
        let step = Self::step(RunRow::of(record), RunEvent::AcceptLanding);
        if let RunStep::Move { to, pause } = step {
            record.cancel_state.landing = Some(landing);
            if let Some(resume_point) = resume_point {
                record.cancel_state.resume_point = Some(resume_point);
            }
            // Landing satisfies every outstanding ask — they all wanted the worker
            // to stop, and it is stopping — so no request stays owed an answer.
            // The receipt still names the ONE request this landing answers, so the
            // trigger and the requester on it are the real ones.
            record.cancel_state.pressure.pending = 0;
            record.state = to;
            record.active_pause = pause;
        }
        step
    }

    /// Applies `FinishLanding`, writing state, active_pause, lease_owner,
    /// scheduled_at, settled_at and cancel_state.cancellation. The site keeps
    /// guards, the successor, receipts, indexes, backoff_until, last_error and
    /// updated_at.
    pub(crate) fn finish_landing(
        record: &mut AttemptRecord,
        now: u64,
        cancellation: AttemptCancellation,
    ) -> RunStep {
        let step = Self::step(RunRow::of(record), RunEvent::FinishLanding);
        if let RunStep::Move { to, pause } = step {
            record.state = to;
            record.active_pause = pause;
            record.lease_owner = None;
            record.scheduled_at = None;
            record.settled_at = Some(now);
            record.cancel_state.cancellation = Some(cancellation);
        }
        step
    }

    /// Applies `ForceCancel`, writing state, active_pause, lease_owner,
    /// scheduled_at, settled_at, cancel_state.pressure.pending and
    /// cancel_state.cancellation. The site keeps authority, receipts, indexes,
    /// backoff_until, last_error and updated_at.
    pub(crate) fn force_cancel(
        record: &mut AttemptRecord,
        now: u64,
        cancellation: AttemptCancellation,
    ) -> RunStep {
        let step = Self::step(RunRow::of(record), RunEvent::ForceCancel);
        if let RunStep::Move { to, pause } = step {
            record.state = to;
            record.active_pause = pause;
            record.lease_owner = None;
            record.scheduled_at = None;
            record.settled_at = Some(now);
            record.cancel_state.pressure.pending = 0;
            record.cancel_state.cancellation = Some(cancellation);
        }
        step
    }

    /// Applies `Claim`, checking the next attempt_count before writing state,
    /// active_pause, lease_owner, attempt_count and scheduled_at. The site keeps
    /// admission, claimed_at, backoff_until, updated_at and indexes.
    pub(crate) fn claim(record: &mut AttemptRecord, lease_owner: &str) -> Result<RunStep> {
        let step = Self::step(RunRow::of(record), RunEvent::Claim);
        if let RunStep::Move { to, pause } = step {
            let attempt_count = record
                .attempt_count
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("attempt lease count"))?;
            record.state = to;
            record.active_pause = pause;
            record.lease_owner = Some(lease_owner.to_owned());
            record.attempt_count = attempt_count;
            record.scheduled_at = None;
        }
        Ok(step)
    }

    /// Builds a fresh landing successor with no state move: row writes state,
    /// lease_owner, attempt_count, scheduled_at, settled_at, active_pause and
    /// cancel_state, retaining the checkpoint and fresh reserve dial values.
    /// The site keeps the id, payload, provenance, indexes and persistence.
    pub(crate) fn landing_successor_row(
        parts: NewAttempt,
        scheduled_at: Option<u64>,
        source: &AttemptRecord,
    ) -> AttemptRecord {
        row(
            parts,
            scheduled_at,
            AttemptCancelState {
                // The whole point of a designed landing: the successor starts from
                // the exact recorded point, with a fresh reserve on the same dial.
                resume_point: source.cancel_state.resume_point.clone(),
                reserve: AttemptLandingReserve {
                    spent_units: 0,
                    // A NEW row inherits the dial's VALUES as its starting
                    // accounting but not its one-shot mark: the successor's own
                    // admission dials it against the successor's own generation,
                    // and until then nothing has been told what it may spend.
                    dial_generation: None,
                    ..source.cancel_state.reserve
                },
                ..AttemptCancelState::default()
            },
        )
    }

    /// Moves no state; writes cancel_state.resume_point. The site keeps the
    /// landing and lease guards, receipt, clock and persistence.
    pub(crate) fn record_landing_checkpoint(
        record: &mut AttemptRecord,
        resume_point: AttemptResumePoint,
    ) {
        record.cancel_state.resume_point = Some(resume_point);
    }

    /// Moves no state; writes cancel_state.reserve. The site keeps the state
    /// and generation guards, reserve arithmetic and persistence.
    pub(crate) fn dial_landing_reserve(record: &mut AttemptRecord, reserve: AttemptLandingReserve) {
        record.cancel_state.reserve = reserve;
    }

    /// Moves no state; writes cancel_state.reserve.spent_units after the
    /// checked addition. The site keeps state, lease and remaining-unit guards,
    /// the receipt, clock and persistence.
    pub(crate) fn spend_landing_reserve(record: &mut AttemptRecord, units: u64) -> Result<()> {
        record.cancel_state.reserve.spent_units = record
            .cancel_state
            .reserve
            .spent_units
            .checked_add(units)
            .ok_or(Error::ArithmeticOverflow("landing reserve spend"))?;
        Ok(())
    }

    /// Moves no state; writes cancel_state.receipts. The site keeps guards,
    /// pressure accounting, clocks and persistence.
    ///
    /// Appends one protocol row. Never drains and never refuses on a count, so
    /// `Landed` / `ForceCancelled` — including the runtime's lease-expiry cleanup
    /// — always have room: landing finish and the hard rung settle atomically and
    /// never silently omit their evidence.
    ///
    /// Past the `[limits]` `attempt_cancel_receipts` row the append asks through
    /// `watch` whether everything is okay and lands (Rule 5); only storage
    /// capacity (LMDB's value ceiling, a full map) refuses the record write.
    pub(in crate::attempt_queue) fn append_cancel_receipt(
        watch: &LimitWatch,
        record: &mut AttemptRecord,
        kind: AttemptCancelReceiptKind,
        actor: String,
        draft: CancelReceiptDraft,
        now: u64,
    ) -> Result<()> {
        let sequence = match record.cancel_state.receipts.last() {
            Some(receipt) => receipt
                .sequence
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("attempt cancel receipt sequence"))?,
            None => 1,
        };
        let receipt = AttemptCancelReceipt {
            sequence,
            at: now,
            actor,
            kind,
            standing: draft.standing,
            trigger: draft.trigger,
            grounds: draft.grounds,
            status: draft.status,
            reason: draft.reason,
            resume_point: draft.resume_point,
            reserve_units: draft.reserve_units,
            request_sequence: draft.request_sequence,
        };
        // The SAME per-kind contract `decode_record` enforces, applied before the
        // row exists: a writer cannot persist a shape the reader would then refuse,
        // and a malformed draft leaves the record — and storage — untouched.
        validate_cancel_receipt_fields(&receipt)?;
        record.cancel_state.receipts.push(receipt);
        watch.measure(
            EngineLimit::AttemptCancelReceipts,
            record.cancel_state.receipts.len() as u64,
        );
        Ok(())
    }

    /// Moves no state; writes cancel_state.pressure.rejections and pending. The
    /// site keeps the refusal guards, receipt, clocks and persistence.
    ///
    /// Counts one refused soft request. Saturating: the pathology signal is "many",
    /// and an overflow must not reset it to "none". One refusal answers one
    /// outstanding request; duplicate asks remain pending until answered.
    pub(in crate::attempt_queue) fn count_cancel_rejection(record: &mut AttemptRecord) {
        let pressure = &mut record.cancel_state.pressure;
        pressure.rejections = pressure.rejections.saturating_add(1);
        pressure.pending = pressure.pending.saturating_sub(1);
    }

    /// Moves no state; writes cancel_state.pressure.requests and pending. The
    /// site keeps request provenance, receipts, clocks and persistence.
    pub(in crate::attempt_queue) fn count_cancel_request(record: &mut AttemptRecord) {
        let pressure = &mut record.cancel_state.pressure;
        pressure.requests = pressure.requests.saturating_add(1);
        pressure.pending = pressure.pending.saturating_add(1);
    }

    /// Builds a fresh successor, retaining the source's reserve dial values,
    /// but none of its spent units, generation mark or other cancel history.
    pub(crate) fn successor_row(
        parts: NewAttempt,
        scheduled_at: Option<u64>,
        source: &AttemptRecord,
    ) -> AttemptRecord {
        row(
            parts,
            scheduled_at,
            AttemptCancelState {
                reserve: AttemptLandingReserve {
                    spent_units: 0,
                    dial_generation: None,
                    ..source.cancel_state.reserve
                },
                ..AttemptCancelState::default()
            },
        )
    }
}

/// What a held row waits on: the signal that releases it for a caller that
/// is not the vault owner (Fable 5.2 item 2, lead 06:5x: the table is keyed
/// on hold kind x caller class; the matching signal wakes the wait). A
/// refused Pause or Resume names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HoldSignal {
    /// OF-541: the vault owner resumes the run's budget hold once its lease
    /// has room (`vault.budgets.hold.resume`).
    BudgetResume,
    /// OF-393: the launch's approval ruling (`vault.fanout.resume`, or
    /// `vault.fanout.resume_as` by a holder of its decision role).
    FanoutApproval { launch_ref: EntityId },
    /// FIX 7114: the verb hook's ask is answered (`tasks.answer` by one of
    /// its members); the runtime then resumes the row.
    HookAnswer,
    /// OF-368: the comment thread reattaches at its exact words.
    AnnotationReattach {
        artifact_id: EntityId,
        thread_id: EntityId,
    },
    /// A person's pause: the caller that paused the row resumes it, or the
    /// vault owner does.
    Pauser,
}

impl HoldSignal {
    /// The refusal's reason code.
    pub(crate) const fn reason_code(self) -> &'static str {
        match self {
            Self::BudgetResume => "awaits:budget_resume",
            Self::FanoutApproval { .. } => "awaits:fanout_approval",
            Self::HookAnswer => "awaits:hook_answer",
            Self::AnnotationReattach { .. } => "awaits:annotation_reattach",
            Self::Pauser => "awaits:pauser",
        }
    }

    /// The signal a row under `pause` waits on.
    const fn of(pause: AttemptPause) -> Self {
        match pause {
            AttemptPause::Person => Self::Pauser,
            AttemptPause::Budget => Self::BudgetResume,
            AttemptPause::Fanout { launch_ref } => Self::FanoutApproval { launch_ref },
            AttemptPause::Hook { .. } => Self::HookAnswer,
            AttemptPause::Annotation {
                artifact_id,
                thread_id,
            } => Self::AnnotationReattach {
                artifact_id,
                thread_id,
            },
        }
    }
}

impl RunLifecycle {
    /// The table's caller-class column: whether a caller that is not the
    /// vault owner may run `event` on `row`. It releases a person's pause it
    /// placed itself (`placed`) and no other: no engine hold, and no other
    /// caller's pause; nor does its Pause take an engine hold over, so it
    /// cannot pause a held row and then resume its own pause. `None` admits
    /// the event, which the table then steps as for anyone; `Some` refuses
    /// it and names what the row waits on. The vault owner overrides any
    /// hold and never asks this; a hold's own release door is the signal.
    /// A paused row that names no pause was paused by a person.
    pub(crate) fn caller_hold(row: RunRow, event: RunEvent, placed: bool) -> Option<HoldSignal> {
        if row.state != AttemptState::Paused {
            return None;
        }
        let pause = row.pause.unwrap_or(AttemptPause::Person);
        match (event, pause) {
            (RunEvent::Resume, AttemptPause::Person) if placed => None,
            (RunEvent::Resume, pause) => Some(HoldSignal::of(pause)),
            // A pause over a person's pause replays; over an engine hold it
            // would take the hold over.
            (RunEvent::Pause { .. }, AttemptPause::Person) => None,
            (RunEvent::Pause { .. }, pause) => Some(HoldSignal::of(pause)),
            _ => None,
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
