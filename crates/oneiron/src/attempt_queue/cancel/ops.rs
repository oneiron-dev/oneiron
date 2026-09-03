//! RUNG 1 of the graceful-cancel protocol plus the landing reserve dial.
//!
//! Asking, answering (land or refuse), recording where a successor resumes,
//! and the integer reserve accounting a landing spends from. The terminal
//! rungs — finishing a landing, the hard force, and the runtime's warnings —
//! live in [`super::terminal`].

use std::collections::HashSet;

use crate::attempt_queue::encoding::{decode_record, encode_record};
use crate::attempt_queue::engine::AttemptQueue;
use crate::attempt_queue::telemetry::invalid_transition;
use crate::attempt_queue::types::{AttemptRecord, AttemptState};
use crate::attempt_queue::validate::{
    CancelReceiptDraft, ERR_RESERVE_SPEND_ZERO, append_cancel_receipt, count_cancel_rejection,
    count_cancel_request, validate_cancel_actor, validate_cancel_standing, validate_failure_reason,
    validate_lease_owner, validate_optional_cancel_status, validate_optional_failure_reason,
    validate_optional_resume_point, validate_reserve_percent, validate_resume_point,
    validate_transition_lease,
};
use crate::error::{Error, Result};

use super::types::{
    AttemptCancelReceipt, AttemptCancelReceiptKind, AttemptLanding, AttemptLandingReserve,
    CancelStanding, LANDING_RESERVE_PERCENT, LandingTrigger,
};
use super::verbs::{
    AcceptAttemptLanding, CancelRejectionOutcome, CancelRequestOutcome, DialLandingReserve,
    LandingOutcome, LandingReserveSpendOutcome, RecordAttemptResumePoint, RejectAttemptCancel,
    RequestAttemptCancel, SpendAttemptLandingReserve,
};

/// Who authored one soft-request row, and why.
#[derive(Debug)]
pub(super) struct SoftRequestAuthorship {
    pub(super) actor: String,
    /// `None` for a runtime-authored warning: standing is a claim an ACTOR
    /// makes, and the runtime is not one of them.
    pub(super) standing: Option<CancelStanding>,
    pub(super) trigger: LandingTrigger,
    pub(super) reason: Option<String>,
}

impl AttemptQueue<'_> {
    /// RUNG 1 (soft): asks a running attempt to stop.
    ///
    /// This NEVER mutates a running attempt to terminal cancelled. It records a
    /// durable, typed request and leaves the worker to answer by landing
    /// ([`Self::accept_landing`]) or refusing ([`Self::reject_cancel`]). A
    /// caller that could not establish standing passes
    /// [`CancelStanding::None`] and gets [`CancelRequestOutcome::NoStanding`]
    /// with the row untouched.
    ///
    /// Asking again is legitimate and additive: every ask is its own append-only
    /// receipt, so a worker that refuses repeatedly accumulates the evidence
    /// that says so.
    pub fn request_cancel(&self, input: RequestAttemptCancel) -> Result<CancelRequestOutcome> {
        let mut wtxn = self.store.env.write_txn()?;
        let outcome = self.request_cancel_in_txn(&mut wtxn, input)?;
        wtxn.commit()?;
        Ok(outcome)
    }

    /// Transaction-composable [`Self::request_cancel`], so an adapter can
    /// co-commit the request with its own gate/proposal state.
    pub(crate) fn request_cancel_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: RequestAttemptCancel,
    ) -> Result<CancelRequestOutcome> {
        validate_cancel_actor(&input.actor)?;
        validate_optional_failure_reason(input.reason.as_deref())?;

        let Some(raw_record) = self.store.attempt_records.get(wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("cancel_request", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        if !input.standing.may_request() {
            return Ok(CancelRequestOutcome::NoStanding(record));
        }
        validate_cancel_standing(input.standing)?;
        match record.state {
            AttemptState::Landing => return Ok(CancelRequestOutcome::AlreadyLanding(record)),
            AttemptState::Completed | AttemptState::Failed | AttemptState::Cancelled => {
                return Ok(CancelRequestOutcome::AlreadySettled(record));
            }
            // Only a CLAIMED, leased realization has a worker who can answer.
            // Recording a pending ask against a queued/paused/scheduled row
            // would create an obligation nobody holds: `accept_landing` and
            // `reject_cancel` both require the lease, so the ask could never be
            // discharged, and its permanent `pending` would read as a worker
            // that will not answer. Pre-lease work is stopped, not asked.
            AttemptState::Leased => {}
            AttemptState::Queued | AttemptState::Paused | AttemptState::Scheduled => {
                return Ok(CancelRequestOutcome::NotRunning(record));
            }
        }

        self.record_soft_request(
            wtxn,
            &mut record,
            SoftRequestAuthorship {
                actor: input.actor,
                standing: Some(input.standing),
                trigger: input.trigger,
                reason: input.reason,
            },
            input.now,
        )?;
        let pressure = record.cancel_state.pressure;
        Ok(CancelRequestOutcome::Requested { record, pressure })
    }

    /// Appends one soft-request receipt and persists the row. `updated_at` is
    /// deliberately NOT bumped: it is the lease-expiry clock, and letting a
    /// requester restart it would let repeated asking keep a stalled worker's
    /// lease alive forever.
    pub(super) fn record_soft_request(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        record: &mut AttemptRecord,
        authorship: SoftRequestAuthorship,
        now: u64,
    ) -> Result<()> {
        append_cancel_receipt(
            record,
            AttemptCancelReceiptKind::SoftRequested,
            authorship.actor,
            CancelReceiptDraft {
                standing: authorship.standing,
                trigger: Some(authorship.trigger),
                reason: authorship.reason,
                ..CancelReceiptDraft::default()
            },
            now,
        )?;
        count_cancel_request(&mut record.cancel_state.pressure);
        let encoded = encode_record(record)?;
        self.store
            .attempt_records
            .put(wtxn, record.id.as_bytes(), &encoded)?;
        Ok(())
    }

    /// The worker ACCEPTS a stop and enters [`AttemptState::Landing`].
    ///
    /// The lease fence is the same one `complete`/`fail` use, so a stale
    /// generation or a wrong owner cannot land someone else's attempt. The row
    /// keeps its lease: landing is bounded work, not a release.
    ///
    /// This is the one cancel door that DOES restart the lease clock, and only
    /// once: accepting buys the worker a fresh, bounded window to finish in.
    /// Landing work itself — resume points, reserve spends — deliberately does
    /// not touch `updated_at`, so a worker cannot land forever by continuing to
    /// look busy; when that window runs out, cleanup force-cancels.
    pub fn accept_landing(&self, input: AcceptAttemptLanding) -> Result<LandingOutcome> {
        validate_lease_owner(&input.lease_owner)?;
        validate_optional_cancel_status(input.status.as_deref())?;
        validate_optional_resume_point(input.resume_point.as_ref())?;

        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw_record) = self.store.attempt_records.get(&wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("accept_landing", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        match record.state {
            AttemptState::Landing => {
                validate_transition_lease(
                    &record,
                    &input.lease_owner,
                    input.attempt_count,
                    "accept_landing",
                )?;
                return Ok(LandingOutcome::AlreadyLanding(record));
            }
            AttemptState::Leased => {}
            state => return Err(invalid_transition("accept_landing", state.as_str())),
        }
        validate_transition_lease(
            &record,
            &input.lease_owner,
            input.attempt_count,
            "accept_landing",
        )?;

        // The ANSWERED request is the source of truth for trigger provenance;
        // the worker cannot relabel a lease warning as an unrelated cancel
        // request while answering it. A self-triggered landing has no pending
        // request and uses the typed trigger supplied by the worker.
        //
        // Which request is answered is chosen by identity, never by recency:
        // with a peer ask and a runtime warning both outstanding, the landing
        // must name the one it actually answers.
        let answered = select_pending_request(&record, input.request_sequence, "accept_landing")?;
        let answered_sequence = answered.map(|request| request.sequence);
        let trigger = answered
            .and_then(|request| request.trigger)
            .unwrap_or(input.trigger);
        let requested_by = answered
            .map(|request| request.actor.clone())
            .unwrap_or(input.lease_owner.clone());
        record.cancel_state.landing = Some(AttemptLanding {
            trigger,
            requested_by,
            entered_at: input.now,
            status: input.status.clone(),
        });
        if let Some(resume_point) = input.resume_point.clone() {
            record.cancel_state.resume_point = Some(resume_point);
        }
        // Landing satisfies every outstanding ask — they all wanted the worker
        // to stop, and it is stopping — so no request stays owed an answer.
        // The receipt still names the ONE request this landing answers, so the
        // trigger and the requester on it are the real ones.
        record.cancel_state.pressure.pending = 0;
        record.state = AttemptState::Landing;
        record.updated_at = input.now;
        let recorded_resume_point = record.cancel_state.resume_point.clone();
        append_cancel_receipt(
            &mut record,
            AttemptCancelReceiptKind::LandingAccepted,
            input.lease_owner,
            CancelReceiptDraft {
                trigger: Some(trigger),
                status: input.status,
                resume_point: recorded_resume_point,
                request_sequence: answered_sequence,
                ..CancelReceiptDraft::default()
            },
            input.now,
        )?;
        let encoded = encode_record(&record)?;
        self.store
            .attempt_records
            .put(&mut wtxn, record.id.as_bytes(), &encoded)?;
        wtxn.commit()?;
        Ok(LandingOutcome::Landing(record))
    }

    /// The worker REFUSES a soft request and stays at work.
    ///
    /// The refusal is append-only evidence and the refusal count is the
    /// pathology signal. Nothing here terminates anything: only the hard rung
    /// can stop a worker that will not land.
    pub fn reject_cancel(&self, input: RejectAttemptCancel) -> Result<CancelRejectionOutcome> {
        validate_lease_owner(&input.lease_owner)?;
        validate_failure_reason(&input.reason)?;
        validate_optional_cancel_status(input.status.as_deref())?;

        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw_record) = self.store.attempt_records.get(&wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("cancel_reject", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        if record.state != AttemptState::Leased {
            return Err(invalid_transition("cancel_reject", record.state.as_str()));
        }
        validate_transition_lease(
            &record,
            &input.lease_owner,
            input.attempt_count,
            "cancel_reject",
        )?;
        // Preserve the trigger on the request being answered. The worker's
        // refusal reason is new evidence, but it must not erase whether the
        // ask came from a peer, a quota warning, or lease expiry — and with
        // several asks outstanding it must name the one it refused, or the
        // remaining requesters inherit an answer nobody gave them.
        let Some(answered) =
            select_pending_request(&record, input.request_sequence, "cancel_reject")?
        else {
            return Err(invalid_transition("cancel_reject", "no_request"));
        };
        let trigger = answered.trigger;
        let answered_request_sequence = answered.sequence;

        count_cancel_rejection(&mut record.cancel_state.pressure);
        append_cancel_receipt(
            &mut record,
            AttemptCancelReceiptKind::SoftRejected,
            input.lease_owner,
            CancelReceiptDraft {
                trigger,
                reason: Some(input.reason),
                status: input.status,
                request_sequence: Some(answered_request_sequence),
                ..CancelReceiptDraft::default()
            },
            input.now,
        )?;
        let encoded = encode_record(&record)?;
        self.store
            .attempt_records
            .put(&mut wtxn, record.id.as_bytes(), &encoded)?;
        wtxn.commit()?;

        let pressure = record.cancel_state.pressure;
        Ok(CancelRejectionOutcome {
            record,
            pressure,
            pathology: pressure.is_pathological(),
            answered_request_sequence,
        })
    }

    /// Records the exact resume point a successor picks up from.
    ///
    /// Landing-only: a resume point recorded by a still-running attempt would
    /// name a position the worker is about to move past.
    pub fn record_resume_point(&self, input: RecordAttemptResumePoint) -> Result<AttemptRecord> {
        validate_lease_owner(&input.lease_owner)?;
        validate_resume_point(&input.resume_point)?;

        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw_record) = self.store.attempt_records.get(&wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("record_resume_point", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        if record.state != AttemptState::Landing {
            return Err(invalid_transition(
                "record_resume_point",
                record.state.as_str(),
            ));
        }
        validate_transition_lease(
            &record,
            &input.lease_owner,
            input.attempt_count,
            "record_resume_point",
        )?;

        record.cancel_state.resume_point = Some(input.resume_point.clone());
        let trigger = record.cancel_state.landing.as_ref().map(|l| l.trigger);
        append_cancel_receipt(
            &mut record,
            AttemptCancelReceiptKind::ResumePointRecorded,
            input.lease_owner,
            CancelReceiptDraft {
                trigger,
                resume_point: Some(input.resume_point),
                ..CancelReceiptDraft::default()
            },
            input.now,
        )?;
        let encoded = encode_record(&record)?;
        self.store
            .attempt_records
            .put(&mut wtxn, record.id.as_bytes(), &encoded)?;
        wtxn.commit()?;
        Ok(record)
    }

    /// Dials the attempt's budget and carves its landing reserve out of it.
    ///
    /// ONE-SHOT per admitted generation: see
    /// [`Self::dial_landing_reserve_in_txn`], which this door commits.
    pub fn dial_landing_reserve(&self, input: DialLandingReserve) -> Result<AttemptRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let record = self.dial_landing_reserve_in_txn(&mut wtxn, input)?;
        wtxn.commit()?;
        Ok(record)
    }

    /// Transaction-composable [`Self::dial_landing_reserve`], so an admission
    /// path can co-commit the dial with the lease it just took: the units a
    /// runner reserved for an attempt and the attempt's own landing slice are
    /// one fact, and a crash between them would leave a leased attempt with a
    /// budget but no way to land inside it.
    ///
    /// Two fences, both refusing with a typed transition error and leaving
    /// every unit of accounting untouched:
    ///
    /// * a landing or terminal row is never dialed — re-dialing mid-landing
    ///   would let a worker mint the very reserve it is spending;
    /// * the dial is applied at most ONCE per lease generation
    ///   ([`AttemptLandingReserve::dial_generation`]). Ordinary execution is
    ///   already metered with
    ///   [`AttemptRecord::ordinary_budget_limit_units`](crate::attempt_queue::AttemptRecord::ordinary_budget_limit_units)
    ///   — this dial MINUS the reserve — so a second dial against the running
    ///   generation would enlarge a reserve the live meter was never sized
    ///   against. A fresh claim advances the generation, so the next admission
    ///   dials its own row honestly.
    pub(crate) fn dial_landing_reserve_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: DialLandingReserve,
    ) -> Result<AttemptRecord> {
        let reserve_percent = input.reserve_percent.unwrap_or(LANDING_RESERVE_PERCENT);
        validate_reserve_percent(reserve_percent)?;

        let Some(raw_record) = self.store.attempt_records.get(wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("dial_landing_reserve", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        match record.state {
            AttemptState::Queued
            | AttemptState::Leased
            | AttemptState::Paused
            | AttemptState::Scheduled => {}
            state => {
                return Err(invalid_transition("dial_landing_reserve", state.as_str()));
            }
        }
        if record.cancel_state.reserve.dial_generation == Some(record.attempt_count) {
            return Err(invalid_transition("dial_landing_reserve", "already_dialed"));
        }
        record.cancel_state.reserve = AttemptLandingReserve::dialed_at_generation(
            input.limit_units,
            reserve_percent,
            record.attempt_count,
        );
        let encoded = encode_record(&record)?;
        self.store
            .attempt_records
            .put(wtxn, record.id.as_bytes(), &encoded)?;
        Ok(record)
    }

    /// Spends landing reserve units.
    ///
    /// Fails closed on both axes: out of landing mode is a typed transition
    /// refusal, and a request larger than what remains spends NOTHING and
    /// reports [`LandingReserveSpendOutcome::Exhausted`]. There is no partial
    /// spend, so the terminal receipt's accounting is exact.
    pub fn spend_landing_reserve(
        &self,
        input: SpendAttemptLandingReserve,
    ) -> Result<LandingReserveSpendOutcome> {
        validate_lease_owner(&input.lease_owner)?;
        if input.units == 0 {
            return Err(Error::InvalidAttemptQueueRecord(ERR_RESERVE_SPEND_ZERO));
        }

        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw_record) = self.store.attempt_records.get(&wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("spend_landing_reserve", "missing"));
        };
        let mut record = decode_record(&raw_record, input.id)?;
        if record.state != AttemptState::Landing {
            return Err(invalid_transition(
                "spend_landing_reserve",
                record.state.as_str(),
            ));
        }
        validate_transition_lease(
            &record,
            &input.lease_owner,
            input.attempt_count,
            "spend_landing_reserve",
        )?;

        let remaining_units = record.cancel_state.reserve.remaining_units();
        if input.units > remaining_units {
            return Ok(LandingReserveSpendOutcome::Exhausted {
                record,
                requested_units: input.units,
                remaining_units,
            });
        }
        record.cancel_state.reserve.spent_units = record
            .cancel_state
            .reserve
            .spent_units
            .checked_add(input.units)
            .ok_or(Error::ArithmeticOverflow("landing reserve spend"))?;
        let trigger = record.cancel_state.landing.as_ref().map(|l| l.trigger);
        append_cancel_receipt(
            &mut record,
            AttemptCancelReceiptKind::ReserveSpent,
            input.lease_owner,
            CancelReceiptDraft {
                trigger,
                reserve_units: input.units,
                ..CancelReceiptDraft::default()
            },
            input.now,
        )?;
        let encoded = encode_record(&record)?;
        self.store
            .attempt_records
            .put(&mut wtxn, record.id.as_bytes(), &encoded)?;
        wtxn.commit()?;

        let remaining_units = record.cancel_state.reserve.remaining_units();
        Ok(LandingReserveSpendOutcome::Spent {
            record,
            remaining_units,
        })
    }
}

/// Every soft request still owed an answer, OLDEST FIRST.
///
/// A request's identity is its own receipt `sequence`, and an answer names the
/// request it consumed, so "still pending" is the set difference — not a guess
/// from recency. Gated on the pending counter so an already-answered round
/// (or a terminal row, whose asks are moot) yields nothing.
fn pending_soft_requests(record: &AttemptRecord) -> Vec<&AttemptCancelReceipt> {
    if record.cancel_state.pressure.pending == 0 {
        return Vec::new();
    }
    let answered: HashSet<u64> = record
        .cancel_state
        .receipts
        .iter()
        .filter(|receipt| receipt.kind.answers_request())
        .filter_map(|receipt| receipt.request_sequence)
        .collect();
    record
        .cancel_state
        .receipts
        .iter()
        .filter(|receipt| {
            receipt.kind == AttemptCancelReceiptKind::SoftRequested
                && !answered.contains(&receipt.sequence)
        })
        .collect()
}

/// Resolves WHICH outstanding request a worker's answer consumes.
///
/// `None` selects the oldest outstanding ask — the only recency rule that is
/// stable under repeated asking. An explicit sequence must name a request that
/// is actually outstanding: answering an unknown or already-answered one is a
/// typed refusal, never a silent re-answer of some other requester's ask.
fn select_pending_request<'r>(
    record: &'r AttemptRecord,
    request_sequence: Option<u64>,
    action: &'static str,
) -> Result<Option<&'r AttemptCancelReceipt>> {
    let pending = pending_soft_requests(record);
    match request_sequence {
        None => Ok(pending.first().copied()),
        Some(sequence) => pending
            .into_iter()
            .find(|receipt| receipt.sequence == sequence)
            .map(Some)
            .ok_or_else(|| invalid_transition(action, "unknown_request")),
    }
}
