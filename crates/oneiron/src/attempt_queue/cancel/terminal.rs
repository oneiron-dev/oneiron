//! Landing completion, the hard cancel rung, and the runtime's warning doors.
//!
//! Everything here either SETTLES an attempt (finishing a landing, forcing a
//! stop) or is the runtime's own soft ask that a worker land before a budget
//! or a lease runs out. RUNG 1 and the reserve dial live in [`super::ops`].

use crate::attempt_queue::encoding::{
    DedupeIndexKeys, decode_record, encode_record, lease_expired, ready_at, ready_key,
};
use crate::attempt_queue::engine::AttemptQueue;
use crate::attempt_queue::telemetry::invalid_transition;
use crate::attempt_queue::types::{AttemptId, AttemptRecord, AttemptState};
use crate::attempt_queue::validate::{
    CancelReceiptDraft, ERR_HANDOFF_WITHOUT_RESUME_POINT, ERR_LEASE_TIMEOUT_ZERO,
    append_cancel_receipt, validate_cancel_actor, validate_intervention_actor,
    validate_lease_owner, validate_optional_failure_reason, validate_transition_lease,
};
use crate::error::{Error, Result};

use super::ops::SoftRequestAuthorship;
use super::types::{
    ATTEMPT_RUNTIME_ACTOR, AttemptCancelReceiptKind, AttemptCancelState, AttemptCancellation,
    AttemptLandingReserve, CancelMode, ForceCancelAuthority, ForceCancelGrounds,
    LEASE_LANDING_WARNING_PERCENT, LandingTrigger,
};
use super::verbs::{
    AttemptLeaseWarningReport, FinishAttemptLanding, FinishLandingOutcome, ForceAttemptCancel,
    ForceCancelOutcome, LandingWarningOutcome, LeaseWarningOutcome, WarnAttemptBudgetPressure,
    WarnAttemptLeaseExpiry, WarnExpiringAttemptLeases,
};

impl AttemptQueue<'_> {
    /// Finishes a landing: the row becomes terminally cancelled in
    /// [`CancelMode::Landed`], optionally handing off to a successor that
    /// carries the exact resume point.
    ///
    /// Never `Completed`: a landing is an honest stop. The landed row is
    /// finalized and its advisory dedupe entry moves to the successor, exactly
    /// as a retry moves it, so the pair can never both be completed.
    pub fn finish_landing(&self, input: FinishAttemptLanding) -> Result<FinishLandingOutcome> {
        validate_lease_owner(&input.lease_owner)?;

        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw_record) = self.store.attempt_records.get(&wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("finish_landing", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        if record.state != AttemptState::Landing {
            return Err(invalid_transition("finish_landing", record.state.as_str()));
        }
        let lease_owner = input.lease_owner.clone();
        validate_transition_lease(&record, &lease_owner, input.attempt_count, "finish_landing")?;
        if input.hand_off && record.cancel_state.resume_point.is_none() {
            return Err(Error::InvalidAttemptQueueRecord(
                ERR_HANDOFF_WITHOUT_RESUME_POINT,
            ));
        }

        let successor = if input.hand_off {
            Some(landing_successor(&record, input.scheduled_at, input.now))
        } else {
            None
        };

        let trigger = record.cancel_state.landing.as_ref().map(|l| l.trigger);
        record.state = AttemptState::Cancelled;
        record.lease_owner = None;
        record.scheduled_at = None;
        record.backoff_until = None;
        record.last_error = None;
        record.updated_at = input.now;
        record.cancel_state.cancellation = Some(AttemptCancellation {
            mode: CancelMode::Landed,
            grounds: None,
            actor: lease_owner.clone(),
            at: input.now,
            reason: None,
            trigger,
            reserve_units: record.cancel_state.reserve.reserve_units,
            reserve_spent_units: record.cancel_state.reserve.spent_units,
        });
        let landed_resume_point = record.cancel_state.resume_point.clone();
        let landed_reserve_spent = record.cancel_state.reserve.spent_units;
        append_cancel_receipt(
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

        let encoded = encode_record(&record)?;
        self.store
            .attempt_records
            .put(&mut wtxn, record.id.as_bytes(), &encoded)?;
        // Landing is a terminal attempt door too: preserve the existing PACK
        // receipt invariant when the live attempt accumulated a manifest.
        crate::receipt::stamp_attempt_pack_receipt_in_txn(
            self.store,
            &mut wtxn,
            &record,
            record
                .cancel_state
                .cancellation
                .as_ref()
                .map_or(ATTEMPT_RUNTIME_ACTOR, |cancellation| {
                    cancellation.actor.as_str()
                }),
        )?;
        self.delete_dedupe_entry_for_record(&mut wtxn, &record)?;

        let Some(successor) = successor else {
            wtxn.commit()?;
            return Ok(FinishLandingOutcome::Landed(record));
        };

        let encoded_successor = encode_record(&successor)?;
        self.store
            .attempt_records
            .put(&mut wtxn, successor.id.as_bytes(), &encoded_successor)?;
        let ready_key = ready_key(ready_at(&successor), successor.id);
        self.store
            .attempt_ready
            .put(&mut wtxn, &ready_key, successor.id.as_bytes())?;
        self.store.put_attempt_run_index_in_txn(
            &mut wtxn,
            successor.run_id.as_deref(),
            successor.id.as_bytes(),
        )?;
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
                .put(&mut wtxn, &keys.primary[..], successor.id.as_bytes())?;
        }
        wtxn.commit()?;
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
        Ok(outcome)
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
        match record.state {
            AttemptState::Cancelled => return Ok(ForceCancelOutcome::AlreadyCancelled(record)),
            AttemptState::Completed | AttemptState::Failed => {
                return Ok(ForceCancelOutcome::AlreadySettled(record));
            }
            _ => {}
        }

        if record.state.is_ready_indexed() {
            self.delete_ready_entry_for_record(wtxn, &record)?;
        }
        force_cancel_record(
            &mut record,
            input.authority.grounds(),
            input.authority.actor().to_owned(),
            input.reason,
            input.now,
        )?;
        let encoded = encode_record(&record)?;
        self.store
            .attempt_records
            .put(wtxn, record.id.as_bytes(), &encoded)?;
        // A hard cancellation is a terminal queue door, so a PACK loaded by
        // the attempt still receives the same atomic receipt as complete/fail.
        crate::receipt::stamp_attempt_pack_receipt_in_txn(
            self.store,
            wtxn,
            &record,
            input.authority.actor(),
        )?;
        self.delete_dedupe_entry_for_record(wtxn, &record)?;
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
        Ok(outcome)
    }

    /// Transaction-composable [`Self::warn_budget_pressure`].
    pub(crate) fn warn_budget_pressure_in_txn(
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
    /// cannot drift.
    pub fn warn_expiring_leases(
        &self,
        input: WarnExpiringAttemptLeases,
    ) -> Result<AttemptLeaseWarningReport> {
        if input.lease_timeout_secs == 0 {
            return Err(Error::InvalidAttemptQueueRecord(ERR_LEASE_TIMEOUT_ZERO));
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
            match lease_warning_step(&record, input.now, input.lease_timeout_secs) {
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
        Ok(report)
    }

    /// Runtime lease-expiry WARNING for ONE attempt — the soft rung, not the
    /// reclaim.
    ///
    /// Inside the warning window the runtime asks the worker to land, which is
    /// the whole point of the distinction: expiry can only reclaim or force,
    /// and by then the worker's unlanded work is already lost. The request is
    /// idempotent per outstanding ask, so repeated polling records one row.
    pub fn warn_lease_expiry(&self, input: WarnAttemptLeaseExpiry) -> Result<LeaseWarningOutcome> {
        if input.lease_timeout_secs == 0 {
            return Err(Error::InvalidAttemptQueueRecord(ERR_LEASE_TIMEOUT_ZERO));
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
        match lease_warning_step(&record, input.now, input.lease_timeout_secs) {
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
    now: u64,
    lease_timeout_secs: u64,
) -> LeaseWarningStep {
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
/// including the refusal to claim the reserved runtime name. The two RUNTIME
/// grounds legitimately carry [`ATTEMPT_RUNTIME_ACTOR`], so they are validated
/// as a plain actor name.
pub(in crate::attempt_queue) fn validate_force_authority(
    authority: &ForceCancelAuthority,
) -> Result<()> {
    match authority.grounds() {
        ForceCancelGrounds::Owner => validate_cancel_actor(authority.actor()),
        ForceCancelGrounds::LeaseExpiry | ForceCancelGrounds::Criticality => {
            validate_intervention_actor(authority.actor())
        }
    }
}

/// Applies a terminal, runtime-authored hard cancellation in place.
///
/// `actor` comes from the [`ForceCancelAuthority`], never from request text,
/// and the reason rides the cancellation receipt rather than `last_error` — a
/// cancelled row is not a failed one.
pub(in crate::attempt_queue) fn force_cancel_record(
    record: &mut AttemptRecord,
    grounds: ForceCancelGrounds,
    actor: String,
    reason: Option<String>,
    now: u64,
) -> Result<()> {
    let trigger = record.cancel_state.landing.as_ref().map(|l| l.trigger);
    record.state = AttemptState::Cancelled;
    record.lease_owner = None;
    record.scheduled_at = None;
    record.backoff_until = None;
    record.last_error = None;
    record.updated_at = now;
    record.cancel_state.pressure.pending = 0;
    record.cancel_state.cancellation = Some(AttemptCancellation {
        mode: CancelMode::Forced,
        grounds: Some(grounds),
        actor: actor.clone(),
        at: now,
        reason: reason.clone(),
        trigger,
        reserve_units: record.cancel_state.reserve.reserve_units,
        reserve_spent_units: record.cancel_state.reserve.spent_units,
    });
    let resume_point = record.cancel_state.resume_point.clone();
    let reserve_spent_units = record.cancel_state.reserve.spent_units;
    append_cancel_receipt(
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
/// parenting, `tasks.cancel` membership, terminal-status folding — treats the
/// landed row as superseded history without a second lineage concept.
fn landing_successor(source: &AttemptRecord, scheduled_at: Option<u64>, now: u64) -> AttemptRecord {
    AttemptRecord {
        id: AttemptId::now(),
        kind: source.kind.clone(),
        payload: source.payload.clone(),
        state: if scheduled_at.is_some() {
            AttemptState::Scheduled
        } else {
            AttemptState::Queued
        },
        lease_owner: None,
        attempt_count: 0,
        claimed_at: None,
        scheduled_at,
        retry_of: Some(source.id),
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
        cancel_state: AttemptCancelState {
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
    }
}
