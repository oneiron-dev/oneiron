//! Landing completion, the hard cancel rung, and the runtime's warning doors.
//!
//! Everything here either SETTLES an attempt (finishing a landing, forcing a
//! stop) or is the runtime's own soft ask that a worker land before a budget
//! or a lease runs out. RUNG 1 and the reserve dial live in [`super::ops`].

use crate::attempt_queue::encoding::{
    DedupeIndexKeys, decode_record, lease_expired, ready_at, ready_key,
};
use crate::attempt_queue::engine::AttemptQueue;
use crate::attempt_queue::lifecycle::{
    NewAttempt, PackReceiptActor, RunEvent, RunLifecycle, RunRow, RunStep, TerminalCommit,
};
use crate::attempt_queue::telemetry::invalid_transition;
use crate::attempt_queue::types::{AttemptId, AttemptRecord, AttemptState};
use crate::attempt_queue::validate::{
    CancelReceiptDraft, ERR_HANDOFF_WITHOUT_RESUME_POINT, ERR_LEASE_TIMEOUT_ZERO,
    validate_cancel_actor, validate_intervention_actor, validate_lease_owner,
    validate_optional_failure_reason, validate_transition_lease,
};
use crate::error::{Error, Result};
use crate::limit_ask::LimitWatch;

use super::ops::SoftRequestAuthorship;
use super::types::{
    ATTEMPT_RUNTIME_ACTOR, AttemptCancelReceiptKind, AttemptCancellation, CancelMode,
    ForceCancelAuthority, ForceCancelGrounds, LEASE_LANDING_WARNING_PERCENT, LandingTrigger,
};
use super::verbs::{
    AttemptLeaseWarningReport, FinishAttemptLanding, FinishLandingOutcome, ForceAttemptCancel,
    ForceCancelOutcome, LandingWarningOutcome, LeaseWarningOutcome, WarnAttemptBudgetPressure,
    WarnAttemptLeaseExpiry, WarnExpiringAttemptLeases,
};
use crate::error::ArtifactError;

impl AttemptQueue<'_> {
    /// Finishes a landing: the row becomes terminally cancelled in
    /// [`CancelMode::Landed`], optionally handing off to a successor that
    /// carries the exact resume point.
    ///
    /// Never `Completed`: a landing is an honest stop. The landed row is
    /// finalized and its advisory dedupe entry moves to the successor, exactly
    /// as a retry moves it, so the pair can never both be completed.
    pub fn finish_landing(&self, input: FinishAttemptLanding) -> Result<FinishLandingOutcome> {
        let mut wtxn = self.store.env.write_txn()?;
        let outcome = self.finish_landing_in_txn(&mut wtxn, input)?;
        wtxn.commit()?;
        self.store.notify_attempt_observers();
        // FIX 11482: a landed row's job notice commits here, outside any
        // owner scope, so this door sends the signal itself.
        if matches!(outcome, FinishLandingOutcome::Landed(_)) {
            self.store.notify_notification_updates();
        }
        Ok(outcome)
    }

    /// Transaction-composable [`Self::finish_landing`], including cancellation receipts.
    pub(crate) fn finish_landing_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: FinishAttemptLanding,
    ) -> Result<FinishLandingOutcome> {
        validate_lease_owner(&input.lease_owner)?;

        let Some(raw_record) = self.store.attempt_records.get(wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("finish_landing", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        if !matches!(
            RunLifecycle::step(RunRow::of(&record), RunEvent::FinishLanding),
            RunStep::Move { .. }
        ) {
            return Err(invalid_transition("finish_landing", record.state.as_str()));
        }
        let lease_owner = input.lease_owner.clone();
        validate_transition_lease(&record, &lease_owner, input.attempt_count, "finish_landing")?;
        if input.hand_off && record.cancel_state.resume_point.is_none() {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_HANDOFF_WITHOUT_RESUME_POINT,
            )));
        }

        let successor = if input.hand_off {
            Some(landing_successor(
                &record,
                AttemptId::from_bytes(&self.store.clock.ulid()?)?,
                input.scheduled_at,
                input.now,
            ))
        } else {
            None
        };

        let trigger = record.cancel_state.landing.as_ref().map(|l| l.trigger);
        let cancellation = AttemptCancellation {
            mode: CancelMode::Landed,
            grounds: None,
            actor: lease_owner.clone(),
            at: input.now,
            reason: None,
            trigger,
            reserve_units: record.cancel_state.reserve.reserve_units,
            reserve_spent_units: record.cancel_state.reserve.spent_units,
        };
        let _ = RunLifecycle::finish_landing(&mut record, input.now, cancellation);
        let landed_resume_point = record.cancel_state.resume_point.clone();
        let landed_reserve_spent = record.cancel_state.reserve.spent_units;
        RunLifecycle::append_cancel_receipt(
            &self.store.limit_watch,
            &mut record,
            AttemptCancelReceiptKind::Landed,
            lease_owner,
            CancelReceiptDraft {
                trigger,
                resume_point: landed_resume_point,
                reserve_units: landed_reserve_spent,
                ..CancelReceiptDraft::default()
            },
            input.now,
        )?;

        // Landing is a terminal attempt door too: preserve the existing PACK
        // receipt invariant when the live attempt accumulated a manifest.
        self.commit_terminal_in_txn(
            wtxn,
            &mut record,
            TerminalCommit {
                last_error: None,
                now: input.now,
                receipt_actor: PackReceiptActor::StoredCancellation,
            },
        )?;

        // A landing that hands off is not the end of the work: its successor
        // surfaces when it settles.
        let Some(mut successor) = successor else {
            self.notify_settled_in_txn(wtxn, &record)?;
            return Ok(FinishLandingOutcome::Landed(record));
        };

        // A minted successor never lies in the owner-retained range, so an
        // owner-retained kind, whose owner derives its rows' ids, is not
        // handed off here.
        crate::attempt_queue::check_owner_retained_range(&successor.kind, &successor.id)?;
        if self
            .store
            .attempt_records
            .get(wtxn, successor.id.as_bytes())?
            .is_some()
        {
            return Err(Error::InvariantViolation("attempt id collision"));
        }
        crate::ports::recorded_at_in_txn(self.store, wtxn)?;
        let encoded_successor = self.encode_in_txn(wtxn, &mut successor)?;
        self.store
            .attempt_records
            .put(wtxn, successor.id.as_bytes(), &encoded_successor)?;
        let ready_key = ready_key(ready_at(&successor), successor.id);
        self.store
            .attempt_ready
            .put(wtxn, &ready_key, successor.id.as_bytes())?;
        self.store.put_attempt_run_index_in_txn(
            wtxn,
            successor.run_id.as_deref(),
            successor.id.as_bytes(),
        )?;
        crate::attempt_queue::index::put_created_in_txn(self.store, wtxn, &successor)?;
        // Same rule a retry uses, so a landed handoff cannot invent a second
        // scoping scheme: the successor's entry comes from the scope it copied.
        if let Some(dedupe_key) = successor.dedupe_key.as_deref() {
            let keys = DedupeIndexKeys::new(
                &successor.kind,
                successor.dedupe_actor_ref.as_deref(),
                dedupe_key,
            );
            self.store
                .attempt_dedupe
                .put(wtxn, &keys.primary[..], successor.id.as_bytes())?;
        }
        Ok(FinishLandingOutcome::HandedOff {
            landed: record,
            successor,
        })
    }

    /// RUNG 2 (hard): terminates an attempt, unrefusably.
    ///
    /// Authorization IS the [`ForceCancelAuthority`] token, which only the
    /// owner path or a runtime ground can mint; there is no actor string here
    /// for a worker to supply, so the terminal receipt cannot be forged.
    /// Terminal already means terminal: a settled attempt is reported, never
    /// re-killed.
    pub fn force_cancel(&self, input: ForceAttemptCancel) -> Result<ForceCancelOutcome> {
        validate_optional_failure_reason(input.reason.as_deref())?;

        let mut wtxn = self.store.env.write_txn()?;
        let outcome = self.force_cancel_in_txn(&mut wtxn, input)?;
        wtxn.commit()?;
        self.store.notify_attempt_observers();
        // FIX 11482: a cancelled row's job notice commits here, outside
        // any owner scope, so this door sends the signal itself.
        if matches!(outcome, ForceCancelOutcome::Cancelled(_)) {
            self.store.notify_notification_updates();
        }
        // Committed: the step its lease was running stops (FIX 600).
        if let ForceCancelOutcome::Cancelled(record) = &outcome {
            crate::engine_executor::stop_attempt_step(self.vault, record.id, record.attempt_count);
        }
        Ok(outcome)
    }

    /// Publishes only actual native cancellations retained by a committed
    /// erase/restore writer. A cancelled ledger row is not a stopped process.
    pub(crate) fn erased_payload_cancellations_committed(&self, cancelled: &[(AttemptId, u32)]) {
        if cancelled.is_empty() {
            return;
        }
        self.store.notify_attempt_observers();
        self.store.notify_notification_updates();
        for &(id, attempt_count) in cancelled {
            crate::engine_executor::stop_attempt_step(self.vault, id, attempt_count);
        }
    }

    /// Transaction-composable [`Self::force_cancel`].
    pub(crate) fn force_cancel_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: ForceAttemptCancel,
    ) -> Result<ForceCancelOutcome> {
        validate_optional_failure_reason(input.reason.as_deref())?;
        // The authority's actor becomes the terminal receipt's actor, so it is
        // validated BEFORE any durable state changes: an owner-verified but
        // malformed identity (empty, oversized, or claiming the runtime's own
        // name) must fail at the door rather than terminalize the attempt and
        // leave behind a cancellation row that `decode_record` then refuses.
        validate_force_authority(&input.authority)?;

        let Some(raw_record) = self.store.attempt_records.get(wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("cancel_force", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        match RunLifecycle::step(RunRow::of(&record), RunEvent::ForceCancel) {
            RunStep::Replay => return Ok(ForceCancelOutcome::AlreadyCancelled(record)),
            RunStep::Keep => return Ok(ForceCancelOutcome::AlreadySettled(record)),
            RunStep::Move { .. } => {}
            RunStep::Note { .. } | RunStep::Refuse => {
                return Err(invalid_transition("cancel_force", record.state.as_str()));
            }
        }

        if record.state.is_ready_indexed() {
            self.delete_ready_entry_for_record(wtxn, &record)?;
        }
        force_cancel_record(
            &self.store.limit_watch,
            &mut record,
            input.authority.grounds(),
            input.authority.actor().to_owned(),
            input.reason,
            input.now,
        )?;
        // The cleared pause takes its annotation-hold mark with it, as the
        // operator's Cancel does.
        crate::attempt_queue::index::delete_annotation_hold_in_txn(self.store, wtxn, record.id)?;
        // A hard cancellation is a terminal queue door, so a PACK loaded by
        // the attempt still receives the same atomic receipt as complete/fail.
        self.commit_terminal_in_txn(
            wtxn,
            &mut record,
            TerminalCommit {
                last_error: None,
                now: input.now,
                receipt_actor: PackReceiptActor::Caller(input.authority.actor()),
            },
        )?;
        self.notify_settled_in_txn(wtxn, &record)?;
        // FIX 900: a force-cancelled child settles its spend lease in the
        // same write (OF-532); idempotent, a no-op when unmetered.
        if let Some(vault) = self.vault {
            crate::agent_dispatch::AgentDispatcher::new(vault)
                .settle_child_in_txn(wtxn, &record.id, input.now)?;
        }
        Ok(ForceCancelOutcome::Cancelled(record))
    }

    /// Runtime QUOTA/BUDGET warning — the `budget.land.95` rung's queue door.
    ///
    /// The runtime, not an actor, authors it: a worker whose wake counter is
    /// nearly spent is asked to LAND while there is still budget to land WITH,
    /// which is the whole point of holding a reserve back. Idempotent per
    /// outstanding ask, so a loop that observes pressure on every iteration
    /// records one row and does not inflate the refusal pressure counters.
    pub fn warn_budget_pressure(
        &self,
        input: WarnAttemptBudgetPressure,
    ) -> Result<LandingWarningOutcome> {
        let mut wtxn = self.store.env.write_txn()?;
        let outcome = self.warn_budget_pressure_in_txn(&mut wtxn, input)?;
        wtxn.commit()?;
        self.store.notify_attempt_observers();
        Ok(outcome)
    }

    /// Transaction-composable [`Self::warn_budget_pressure`].
    fn warn_budget_pressure_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: WarnAttemptBudgetPressure,
    ) -> Result<LandingWarningOutcome> {
        let Some(raw_record) = self.store.attempt_records.get(wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("budget_warning", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        match record.state {
            AttemptState::Leased => {}
            AttemptState::Landing => return Ok(LandingWarningOutcome::AlreadyRequested(record)),
            _ => return Ok(LandingWarningOutcome::NotRunning(record)),
        }
        if record.cancel_state.pressure.pending > 0 {
            return Ok(LandingWarningOutcome::AlreadyRequested(record));
        }

        self.record_soft_request(
            wtxn,
            &mut record,
            runtime_landing_request(LandingTrigger::BudgetWarning),
            input.now,
        )?;
        Ok(LandingWarningOutcome::LandingRequested(record))
    }

    /// Sweeps live leases and WARNS the ones inside the expiry window.
    ///
    /// The lane that reclaims expired leases (`cleanup_leases`) is the one lane
    /// that already knows the lease timeout, so the warning rung lives beside
    /// it and stays strictly distinct from it: this door never terminalizes,
    /// never requeues, and never touches a row whose lease has ALREADY expired
    /// — that row belongs to cleanup's hard rung. Per-row it applies exactly
    /// [`Self::warn_lease_expiry`]'s rule, through the same private
    /// `lease_warning_step` decision, so the sweep and the single-row door
    /// cannot drift. A run parked on its signal keeps its lease and has no
    /// work to land, so it is counted, never warned (FIX RUN-LEASE).
    pub fn warn_expiring_leases(
        &self,
        input: WarnExpiringAttemptLeases,
    ) -> Result<AttemptLeaseWarningReport> {
        if input.lease_timeout_secs == 0 {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_LEASE_TIMEOUT_ZERO,
            )));
        }

        let mut candidates = Vec::new();
        {
            let rtxn = self.store.env.read_txn()?;
            for row in self.store.attempt_records.iter(&rtxn)? {
                let (key, raw_record) = row?;
                let id = AttemptId::from_bytes(&key)?;
                let record = decode_record(&raw_record, id)?;
                if record.state == AttemptState::Leased {
                    candidates.push(id);
                }
            }
        }

        let mut report = AttemptLeaseWarningReport::default();
        if candidates.is_empty() {
            return Ok(report);
        }

        let mut wtxn = self.store.env.write_txn()?;
        for id in candidates {
            let Some(raw_record) = self.store.attempt_records.get(&wtxn, id.as_bytes())? else {
                continue;
            };
            let mut record = decode_record(&raw_record, id)?;
            if record.state != AttemptState::Leased {
                continue;
            }
            report.scanned += 1;
            let parked = self.parked_in_txn(&wtxn, id)?;
            match lease_warning_step(&record, parked, input.now, input.lease_timeout_secs) {
                LeaseWarningStep::Parked => report.parked += 1,
                LeaseWarningStep::Expired => report.expired += 1,
                LeaseWarningStep::NotDue => report.not_due += 1,
                LeaseWarningStep::AlreadyRequested => report.already_requested += 1,
                LeaseWarningStep::Warn => {
                    self.record_soft_request(
                        &mut wtxn,
                        &mut record,
                        runtime_landing_request(LandingTrigger::LeaseWarning),
                        input.now,
                    )?;
                    report.warned += 1;
                }
            }
        }
        wtxn.commit()?;
        self.store.notify_attempt_observers();
        Ok(report)
    }

    /// Runtime lease-expiry WARNING for ONE attempt — the soft rung, not the
    /// reclaim.
    ///
    /// Inside the warning window the runtime asks the worker to land, which is
    /// the whole point of the distinction: expiry can only reclaim or force,
    /// and by then the worker's unlanded work is already lost. The request is
    /// idempotent per outstanding ask, so repeated polling records one row.
    /// A run parked on its signal is answered [`LeaseWarningOutcome::Parked`]
    /// and nothing is recorded (FIX RUN-LEASE).
    pub fn warn_lease_expiry(&self, input: WarnAttemptLeaseExpiry) -> Result<LeaseWarningOutcome> {
        if input.lease_timeout_secs == 0 {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_LEASE_TIMEOUT_ZERO,
            )));
        }

        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw_record) = self.store.attempt_records.get(&wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("lease_warning", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        match record.state {
            AttemptState::Landing => return Ok(LeaseWarningOutcome::AlreadyRequested(record)),
            AttemptState::Leased => {}
            state => return Err(invalid_transition("lease_warning", state.as_str())),
        }
        let parked = self.parked_in_txn(&wtxn, input.id)?;
        match lease_warning_step(&record, parked, input.now, input.lease_timeout_secs) {
            LeaseWarningStep::Parked => return Ok(LeaseWarningOutcome::Parked(record)),
            LeaseWarningStep::Expired => return Ok(LeaseWarningOutcome::Expired(record)),
            LeaseWarningStep::NotDue => return Ok(LeaseWarningOutcome::NotDue(record)),
            LeaseWarningStep::AlreadyRequested => {
                return Ok(LeaseWarningOutcome::AlreadyRequested(record));
            }
            LeaseWarningStep::Warn => {}
        }

        self.record_soft_request(
            &mut wtxn,
            &mut record,
            runtime_landing_request(LandingTrigger::LeaseWarning),
            input.now,
        )?;
        wtxn.commit()?;
        self.store.notify_attempt_observers();
        Ok(LeaseWarningOutcome::LandingRequested(record))
    }
}

/// The runtime's OWN ask, carrying no standing token: standing is a claim an
/// ACTOR makes, and only these runtime doors may author the row.
fn runtime_landing_request(trigger: LandingTrigger) -> SoftRequestAuthorship {
    SoftRequestAuthorship {
        actor: ATTEMPT_RUNTIME_ACTOR.to_owned(),
        standing: None,
        trigger,
        reason: None,
    }
}

/// What the lease-warning rung should do with ONE leased row. Shared by the
/// sweep and the single-attempt door so both rungs read the same clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeaseWarningStep {
    /// The run is parked on its signal: it keeps its lease, which cleanup
    /// never reclaims, and has no work to land.
    Parked,
    /// Already past expiry: cleanup's hard rung owns it, never a warning.
    Expired,
    /// Inside the lease and before the warning window.
    NotDue,
    /// An ask is already outstanding; warning again only inflates pressure.
    AlreadyRequested,
    /// Record one runtime-authored landing request.
    Warn,
}

fn lease_warning_step(
    record: &AttemptRecord,
    parked: bool,
    now: u64,
    lease_timeout_secs: u64,
) -> LeaseWarningStep {
    if parked {
        return LeaseWarningStep::Parked;
    }
    if lease_expired(record, now, lease_timeout_secs) {
        return LeaseWarningStep::Expired;
    }
    if now.saturating_sub(record.updated_at) < lease_warning_after_secs(lease_timeout_secs) {
        return LeaseWarningStep::NotDue;
    }
    if record.cancel_state.pressure.pending > 0 {
        return LeaseWarningStep::AlreadyRequested;
    }
    LeaseWarningStep::Warn
}

/// Instant, as an age against the lease clock, at which the runtime may warn.
fn lease_warning_after_secs(lease_timeout_secs: u64) -> u64 {
    let warn_after =
        ((u128::from(lease_timeout_secs) * u128::from(LEASE_LANDING_WARNING_PERCENT)) / 100) as u64;
    // A one-second timeout must still leave a window where warning is possible
    // and expiry has not happened; without the clamp the warning instant and
    // the expiry instant coincide and the warning rung is unreachable.
    warn_after.min(lease_timeout_secs.saturating_sub(1))
}

/// Validates the identity a hard cancellation would author its terminal
/// receipt with, by the grounds it rests on.
///
/// An OWNER is an ordinary actor and is held to the ordinary actor rules,
/// including the refusal to claim the reserved runtime name. The RUNTIME
/// grounds legitimately carry [`ATTEMPT_RUNTIME_ACTOR`], so they are validated
/// as a plain actor name.
pub(in crate::attempt_queue) fn validate_force_authority(
    authority: &ForceCancelAuthority,
) -> Result<()> {
    match authority.grounds() {
        ForceCancelGrounds::Owner => validate_cancel_actor(authority.actor()),
        ForceCancelGrounds::LeaseExpiry
        | ForceCancelGrounds::Criticality
        | ForceCancelGrounds::ErasedPayload => validate_intervention_actor(authority.actor()),
    }
}

/// Applies a terminal, runtime-authored hard cancellation in place.
///
/// `actor` comes from the [`ForceCancelAuthority`], never from request text,
/// and the reason rides the cancellation receipt rather than `last_error` — a
/// cancelled row is not a failed one. `watch` is the store's, which the
/// receipt append measures against its `[limits]` row. Each caller then ends
/// through [`AttemptQueue::commit_terminal_in_txn`] with no error text, which
/// writes the row's backoff, error and settle instant.
pub(in crate::attempt_queue) fn force_cancel_record(
    watch: &LimitWatch,
    record: &mut AttemptRecord,
    grounds: ForceCancelGrounds,
    actor: String,
    reason: Option<String>,
    now: u64,
) -> Result<()> {
    let trigger = record.cancel_state.landing.as_ref().map(|l| l.trigger);
    let cancellation = AttemptCancellation {
        mode: CancelMode::Forced,
        grounds: Some(grounds),
        actor: actor.clone(),
        at: now,
        reason: reason.clone(),
        trigger,
        reserve_units: record.cancel_state.reserve.reserve_units,
        reserve_spent_units: record.cancel_state.reserve.spent_units,
    };
    if !matches!(
        RunLifecycle::force_cancel(record, now, cancellation),
        RunStep::Move { .. }
    ) {
        return Err(invalid_transition("cancel_force", record.state.as_str()));
    }
    let resume_point = record.cancel_state.resume_point.clone();
    let reserve_spent_units = record.cancel_state.reserve.spent_units;
    RunLifecycle::append_cancel_receipt(
        watch,
        record,
        AttemptCancelReceiptKind::ForceCancelled,
        actor,
        CancelReceiptDraft {
            trigger,
            grounds: Some(grounds),
            reason,
            resume_point,
            reserve_units: reserve_spent_units,
            ..CancelReceiptDraft::default()
        },
        now,
    )
}

/// Mints the successor row a landing hands off to.
///
/// It is linked by `retry_of`, the same explicit row link a retry uses, so
/// every existing surface that reduces a chain to its live HEAD — run-tree
/// parenting, `cancel` membership, terminal-status folding — treats the
/// landed row as superseded history without a second lineage concept.
fn landing_successor(
    source: &AttemptRecord,
    id: AttemptId,
    scheduled_at: Option<u64>,
    now: u64,
) -> AttemptRecord {
    RunLifecycle::landing_successor_row(
        NewAttempt {
            id,
            kind: source.kind.clone(),
            payload: source.payload.clone(),
            lease_expirations: Vec::new(),
            claimed_at: None,
            retry_of: Some(source.id),
            folded_retries: 0,
            backoff_until: None,
            last_error: None,
            task_ref: source.task_ref.clone(),
            run_id: source.run_id.clone(),
            dedupe_key: source.dedupe_key.clone(),
            dedupe_actor_ref: source.dedupe_actor_ref.clone(),
            created_at: now,
            updated_at: now,
            events: Vec::new(),
            manifest: Vec::new(),
            executor_model: None,
            executor_seat: None,
            executor_role: None,
            planned_binding: None,
            read_set: None,
            signals: Vec::new(),
            asks: Vec::new(),
            placement: source.placement.as_ref().map(|placement| {
                crate::attempt_queue::AttemptPlacement {
                    worker: placement.worker.clone(),
                    // Keep the new try below its predecessor, not beside it. A later
                    // explicit redirect can still select another effective parent.
                    parent: Some(source.id),
                }
            }),
            result_ref: None,
            history: Vec::new(),
            terminal_exhaust: None,
            signal_intents: Vec::new(),
        },
        scheduled_at,
        source,
    )
}
