//! Per-sequence answers, receipt-cap settlement, reserve dial math, and projections.

use super::*;
use crate::error::ArtifactError;

/// Proof 9: with several asks outstanding, each answer consumes exactly the
/// request it names — not the newest one.
#[test]
fn each_answer_consumes_the_request_it_names_not_the_newest() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let leased = leased_attempt(&queue, "turn:two-asks")?;

    let CancelRequestOutcome::Requested {
        record: after_first,
        ..
    } = queue.request_cancel(RequestAttemptCancel {
        id: leased.id,
        actor: "peer-1".to_owned(),
        standing: CancelStanding::PeerAgent,
        trigger: LandingTrigger::CancelRequest,
        reason: Some("the spawner wants the slot back".to_owned()),
        now: 12,
    })?
    else {
        panic!("a peer with standing may ask");
    };
    let first_sequence = after_first
        .cancel_receipts()
        .last()
        .expect("request receipt")
        .sequence;

    let CancelRequestOutcome::Requested {
        record: after_second,
        pressure,
    } = queue.request_cancel(RequestAttemptCancel {
        id: leased.id,
        actor: "healer-1".to_owned(),
        standing: CancelStanding::Healer,
        trigger: LandingTrigger::BudgetWarning,
        reason: Some("quota nearly spent".to_owned()),
        now: 13,
    })?
    else {
        panic!("a second actor may ask too");
    };
    let second_sequence = after_second
        .cancel_receipts()
        .last()
        .expect("request receipt")
        .sequence;
    assert_eq!(pressure.pending, 2, "two asks are outstanding");
    assert_ne!(first_sequence, second_sequence);

    // Refuse the SECOND ask by name. Recency-pairing consumed the newest row
    // no matter which was answered, so it could not tell these two apart.
    let rejection = queue.reject_cancel(RejectAttemptCancel {
        id: leased.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: leased.attempt_count,
        reason: "budget is fine; the peer's slot is not my problem".to_owned(),
        status: Some("amber + unpushed".to_owned()),
        request_sequence: Some(second_sequence),
        now: 14,
    })?;
    assert_eq!(rejection.answered_request_sequence, second_sequence);
    assert_eq!(
        rejection.pressure.pending, 1,
        "one refusal answers exactly one request"
    );
    assert_eq!(rejection.pressure.rejections, 1);
    assert_eq!(rejection.pressure.requests, 2);
    let refusal = rejection
        .record
        .cancel_receipts()
        .last()
        .expect("refusal receipt");
    assert_eq!(
        refusal.trigger,
        Some(LandingTrigger::BudgetWarning),
        "the refusal carries the trigger of the ask it answered"
    );
    assert_eq!(refusal.request_sequence, Some(second_sequence));

    // The peer's ask is still owed an answer, so the landing answers THAT one:
    // its actor and its trigger, not the refused warning's.
    let landing = accept_landing_at(&queue, &leased, LandingTrigger::LeaseWarning, 15)?;
    let record = landing.landing().expect("landing record");
    assert_eq!(record.requested_by, "peer-1");
    assert_eq!(
        record.trigger,
        LandingTrigger::CancelRequest,
        "the answered request owns the provenance, not the worker's label"
    );
    let accepted = landing.cancel_receipts().last().expect("landing receipt");
    assert_eq!(accepted.request_sequence, Some(first_sequence));
    assert_eq!(
        landing.cancel_pressure().pending,
        0,
        "landing satisfies every outstanding ask"
    );

    // Answering a request that is not outstanding is typed, never a silent
    // re-answer of somebody else's ask.
    let other = leased_attempt(&queue, "turn:unknown-ask")?;
    queue.request_cancel(soft_request(other.id, "peer-2", CancelStanding::PeerAgent))?;
    assert_invalid_transition(
        queue
            .reject_cancel(RejectAttemptCancel {
                id: other.id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: other.attempt_count,
                reason: "refusing an ask that was never made".to_owned(),
                status: None,
                request_sequence: Some(9_999),
                now: 16,
            })
            .expect_err("an unknown request cannot be answered"),
        "cancel_reject",
        "unknown_request",
    );
    Ok(())
}

/// Proof 10: a full history bounds the EVIDENCE, never the settlement.
///
/// The reserved last slot is why: without it a worker could refuse its way to
/// the cap and become permanently unsettleable — no landing finish, no hard
/// force, and no lease-expiry cleanup.
#[test]
fn a_full_receipt_history_still_settles_every_terminal_door() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    assert_eq!(
        MAX_NONTERMINAL_ATTEMPT_CANCEL_RECEIPTS + TERMINAL_CANCEL_RECEIPT_RESERVE,
        MAX_ATTEMPT_CANCEL_RECEIPTS
    );

    // 1. Landing finish at the cap.
    let landing = landing_at_receipt_cap(&queue, "turn:cap-landed")?;
    // Non-terminal evidence refuses at the cap rather than dropping a row.
    assert!(matches!(
        queue
            .record_resume_point(RecordAttemptResumePoint {
                id: landing.id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: landing.attempt_count,
                resume_point: AttemptResumePoint::new("one-too-many", 15),
                now: 15,
            })
            .expect_err("a full history refuses non-terminal rows"),
        Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(reason)) if reason == ERR_CANCEL_RECEIPTS_FULL
    ));
    let FinishLandingOutcome::Landed(landed) = queue.finish_landing(FinishAttemptLanding {
        id: landing.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: landing.attempt_count,
        hand_off: false,
        scheduled_at: None,
        now: 16,
    })?
    else {
        panic!("a landing at the cap still finishes");
    };
    assert_eq!(landed.state, AttemptState::Cancelled);
    assert_eq!(landed.cancel_receipts().len(), MAX_ATTEMPT_CANCEL_RECEIPTS);
    let terminal = landed.cancel_receipts().last().expect("terminal receipt");
    assert_eq!(terminal.kind, AttemptCancelReceiptKind::Landed);
    assert!(terminal.kind.is_terminal());
    assert_eq!(
        landed.cancellation().expect("cancellation").mode,
        CancelMode::Landed
    );
    // Prior evidence was preserved, not overwritten.
    assert_eq!(
        landed.cancel_receipts()[0].kind,
        AttemptCancelReceiptKind::SoftRequested
    );
    assert_eq!(queue.get(landed.id)?.expect("row"), landed);

    // 2. Hard force at the cap.
    let forced_landing = landing_at_receipt_cap(&queue, "turn:cap-forced")?;
    let ForceCancelOutcome::Cancelled(forced) = queue.force_cancel(ForceAttemptCancel {
        id: forced_landing.id,
        authority: ForceCancelAuthority::owner("owner-1").expect("verified owner"),
        reason: Some("owner reclaimed the machine".to_owned()),
        now: 17,
    })?
    else {
        panic!("the hard rung is never blocked by a full history");
    };
    assert_eq!(forced.cancel_receipts().len(), MAX_ATTEMPT_CANCEL_RECEIPTS);
    assert_eq!(
        forced
            .cancel_receipts()
            .last()
            .expect("terminal receipt")
            .kind,
        AttemptCancelReceiptKind::ForceCancelled
    );
    assert_eq!(
        forced.cancellation().expect("cancellation").actor,
        "owner-1"
    );
    assert_eq!(queue.get(forced.id)?.expect("row"), forced);

    // 3. Lease-expiry cleanup at the cap.
    let expiring = landing_at_receipt_cap(&queue, "turn:cap-expired")?;
    let report = queue.cleanup_leases(CleanupAttemptLeases {
        now: 10_000,
        lease_timeout_secs: 60,
    })?;
    assert_eq!(report.landing_force_cancelled, 1);
    let reclaimed = queue.get(expiring.id)?.expect("row");
    assert_eq!(reclaimed.state, AttemptState::Cancelled);
    assert_eq!(
        reclaimed.cancel_receipts().len(),
        MAX_ATTEMPT_CANCEL_RECEIPTS
    );
    let terminal = reclaimed
        .cancel_receipts()
        .last()
        .expect("terminal receipt");
    assert_eq!(terminal.kind, AttemptCancelReceiptKind::ForceCancelled);
    assert_eq!(terminal.grounds, Some(ForceCancelGrounds::LeaseExpiry));
    assert_eq!(
        reclaimed.cancellation().expect("cancellation").actor,
        ATTEMPT_RUNTIME_ACTOR
    );
    Ok(())
}

/// Proof 11: the dialed reserve is real accounting at every budget size —
/// including the sizes where there is nothing to reserve.
#[test]
fn the_landing_reserve_dial_is_exact_and_fails_closed_when_spent() -> Result<()> {
    // Integer percent, rounded DOWN, so the reserve can never exceed the
    // budget it is carved from.
    assert_eq!(
        AttemptLandingReserve::dialed(0, LANDING_RESERVE_PERCENT),
        AttemptLandingReserve::default()
    );
    let short = AttemptLandingReserve::dialed(9, LANDING_RESERVE_PERCENT);
    assert_eq!(short.reserve_units, 0, "9 units cannot carve a 10% slice");
    assert_eq!(short.ordinary_limit_units(), 9);
    assert!(short.is_exhausted());
    let dialed = AttemptLandingReserve::dialed(100, LANDING_RESERVE_PERCENT);
    assert_eq!(dialed.reserve_units, 10);
    assert_eq!(
        dialed.ordinary_limit_units(),
        90,
        "the ordinary meter is built WITHOUT the reserve"
    );

    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    // A budget too small to reserve from: landing work fails closed instead of
    // overdrawing the ordinary limit.
    let tiny = leased_attempt(&queue, "turn:reserve-tiny")?;
    let tiny = queue.dial_landing_reserve(DialLandingReserve {
        id: tiny.id,
        limit_units: 9,
        reserve_percent: None,
        now: 12,
    })?;
    assert_eq!(tiny.ordinary_budget_limit_units(), 9);
    queue.request_cancel(soft_request(tiny.id, "peer-1", CancelStanding::PeerAgent))?;
    let tiny_landing = accept_landing_at(&queue, &tiny, LandingTrigger::CancelRequest, 13)?;
    let LandingReserveSpendOutcome::Exhausted {
        record,
        requested_units,
        remaining_units,
    } = queue.spend_landing_reserve(SpendAttemptLandingReserve {
        id: tiny_landing.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: tiny_landing.attempt_count,
        units: 1,
        now: 14,
    })?
    else {
        panic!("an undialed reserve has nothing to spend");
    };
    assert_eq!(requested_units, 1);
    assert_eq!(remaining_units, 0);
    assert_eq!(record.landing_reserve().spent_units, 0, "nothing was spent");

    // A dialed budget: ordinary work is metered on 90, landing spends the 10.
    let full = leased_attempt(&queue, "turn:reserve-full")?;
    let full = queue.dial_landing_reserve(DialLandingReserve {
        id: full.id,
        limit_units: 100,
        reserve_percent: None,
        now: 15,
    })?;
    assert_eq!(full.ordinary_budget_limit_units(), 90);
    queue.request_cancel(soft_request(full.id, "peer-1", CancelStanding::PeerAgent))?;
    let full_landing = accept_landing_at(&queue, &full, LandingTrigger::CancelRequest, 16)?;
    let LandingReserveSpendOutcome::Spent {
        remaining_units, ..
    } = queue.spend_landing_reserve(SpendAttemptLandingReserve {
        id: full_landing.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: full_landing.attempt_count,
        units: 10,
        now: 17,
    })?
    else {
        panic!("landing work spends the reserve it was given");
    };
    assert_eq!(remaining_units, 0);
    let LandingReserveSpendOutcome::Exhausted { record, .. } =
        queue.spend_landing_reserve(SpendAttemptLandingReserve {
            id: full_landing.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: full_landing.attempt_count,
            units: 1,
            now: 18,
        })?
    else {
        panic!("the reserve is a ceiling, not a suggestion");
    };
    assert_eq!(record.landing_reserve().spent_units, 10);

    let FinishLandingOutcome::Landed(landed) = queue.finish_landing(FinishAttemptLanding {
        id: full_landing.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: full_landing.attempt_count,
        hand_off: false,
        scheduled_at: None,
        now: 19,
    })?
    else {
        panic!("the landing finishes");
    };
    let cancellation = landed.cancellation().expect("cancellation");
    assert_eq!(cancellation.reserve_units, 10);
    assert_eq!(
        cancellation.reserve_spent_units, 10,
        "the terminal receipt reports the settled reserve accounting"
    );
    Ok(())
}

/// Proof 12: both runtime warning rungs are runtime-authored, idempotent per
/// outstanding ask, and strictly separate from expiry's hard rung.
#[test]
fn runtime_warnings_ask_and_never_take_the_lease_away() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    // Budget/quota rung.
    let running = leased_attempt(&queue, "turn:budget-warning")?;
    let LandingWarningOutcome::LandingRequested(warned) =
        queue.warn_budget_pressure(WarnAttemptBudgetPressure {
            id: running.id,
            now: 12,
        })?
    else {
        panic!("a leased worker can be warned");
    };
    assert_eq!(warned.state, AttemptState::Leased, "a warning never stops");
    let receipt = warned.cancel_receipts().last().expect("warning receipt");
    assert_eq!(receipt.kind, AttemptCancelReceiptKind::SoftRequested);
    assert_eq!(receipt.actor, ATTEMPT_RUNTIME_ACTOR);
    assert_eq!(receipt.trigger, Some(LandingTrigger::BudgetWarning));
    assert_eq!(
        receipt.standing, None,
        "the runtime is not an actor claiming standing"
    );
    assert_eq!(warned.cancel_pressure().pending, 1);
    assert!(matches!(
        queue.warn_budget_pressure(WarnAttemptBudgetPressure {
            id: running.id,
            now: 13,
        })?,
        LandingWarningOutcome::AlreadyRequested(_)
    ));
    assert_eq!(
        queue
            .get(running.id)?
            .expect("row")
            .cancel_pressure()
            .requests,
        1,
        "polling pressure records one ask, not a pathology-inflating stream"
    );

    // A pre-lease row has nobody to warn.
    let EnqueueOutcome::Enqueued(queued) =
        queue.enqueue(enqueue("sync", Some("turn:warn-queued"), 14))?
    else {
        panic!("enqueue");
    };
    assert!(matches!(
        queue.warn_budget_pressure(WarnAttemptBudgetPressure {
            id: queued.id,
            now: 15,
        })?,
        LandingWarningOutcome::NotRunning(_)
    ));

    // Lease rung: the sweep warns inside the window and leaves the already
    // expired lease to cleanup's hard rung.
    let (_dir_b, vault_b) = open_queue();
    let queue_b = AttemptQueue::new(&vault_b);
    let inside = leased_attempt(&queue_b, "turn:lease-warning")?;
    let not_due = queue_b.warn_expiring_leases(WarnExpiringAttemptLeases {
        now: 12,
        lease_timeout_secs: 100,
    })?;
    assert_eq!(not_due.scanned, 1);
    assert_eq!(not_due.warned, 0);
    assert_eq!(not_due.not_due, 1);

    let warned = queue_b.warn_expiring_leases(WarnExpiringAttemptLeases {
        now: 100,
        lease_timeout_secs: 100,
    })?;
    assert_eq!(warned.warned, 1);
    let row = queue_b.get(inside.id)?.expect("row");
    assert_eq!(
        row.state,
        AttemptState::Leased,
        "a warning is not a reclaim"
    );
    assert_eq!(
        row.cancel_receipts().last().expect("receipt").trigger,
        Some(LandingTrigger::LeaseWarning)
    );
    let repeated = queue_b.warn_expiring_leases(WarnExpiringAttemptLeases {
        now: 101,
        lease_timeout_secs: 100,
    })?;
    assert_eq!(repeated.warned, 0);
    assert_eq!(repeated.already_requested, 1);

    let expired = queue_b.warn_expiring_leases(WarnExpiringAttemptLeases {
        now: 10_000,
        lease_timeout_secs: 100,
    })?;
    assert_eq!(expired.warned, 0);
    assert_eq!(
        expired.expired, 1,
        "an expired lease belongs to cleanup, not to the warning rung"
    );
    // And cleanup still owns stale-lease recovery, unchanged.
    let cleanup = queue_b.cleanup_leases(CleanupAttemptLeases {
        now: 10_000,
        lease_timeout_secs: 100,
    })?;
    assert_eq!(cleanup.stale_requeued, 1);
    assert_eq!(
        queue_b.get(inside.id)?.expect("row").state,
        AttemptState::Queued
    );
    Ok(())
}

/// Proof 12 (ONE-1896 §4): the landing reserve is dialed ONCE per admitted
/// generation, and a second dial against the running generation is a typed
/// refusal that moves nothing.
///
/// The one-shot mark is durable, so a row dialed honestly to a ZERO reserve —
/// a budget too small to carve a slice from — stays distinguishable from a row
/// nothing has dialed yet, and neither can be enlarged underneath the ordinary
/// meter that was already built from it.
#[test]
fn the_landing_reserve_dial_is_one_shot_per_admitted_generation() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let leased = leased_attempt(&queue, "turn:one-shot")?;
    assert!(
        !leased.landing_reserve().is_dialed(),
        "an admitted row starts undialed, not dialed to zero"
    );

    let dialed = queue.dial_landing_reserve(DialLandingReserve {
        id: leased.id,
        limit_units: 1_000,
        reserve_percent: None,
        now: 12,
    })?;
    assert!(dialed.landing_reserve().is_dialed());
    assert_eq!(dialed.landing_reserve().reserve_units, 100);
    assert_eq!(
        dialed.ordinary_budget_limit_units(),
        900,
        "ordinary execution is metered on the dial MINUS the reserve"
    );
    assert_eq!(
        dialed.landing_reserve().dial_generation,
        Some(leased.attempt_count),
        "the dial is fenced to the generation it was applied at"
    );

    assert_invalid_transition(
        queue
            .dial_landing_reserve(DialLandingReserve {
                id: leased.id,
                limit_units: 1_000_000,
                reserve_percent: Some(MAX_LANDING_RESERVE_PERCENT),
                now: 13,
            })
            .expect_err("an already admitted generation is not re-dialed"),
        "dial_landing_reserve",
        "already_dialed",
    );
    let unchanged = queue.get(leased.id)?.expect("row");
    assert_eq!(
        unchanged.landing_reserve(),
        dialed.landing_reserve(),
        "a refused re-dial leaves every unit of accounting untouched"
    );

    // A budget too small to carve a slice from dials to a zero reserve, and
    // that is still a DIAL: it is refused a second time exactly like a rich one.
    let short = leased_attempt(&queue, "turn:one-shot-short")?;
    let short = queue.dial_landing_reserve(DialLandingReserve {
        id: short.id,
        limit_units: 9,
        reserve_percent: None,
        now: 14,
    })?;
    assert_eq!(short.landing_reserve().reserve_units, 0);
    assert!(short.landing_reserve().is_dialed());
    assert_eq!(short.ordinary_budget_limit_units(), 9);
    assert_invalid_transition(
        queue
            .dial_landing_reserve(DialLandingReserve {
                id: short.id,
                limit_units: 100,
                reserve_percent: None,
                now: 15,
            })
            .expect_err("a zero reserve is a dial, not an absence"),
        "dial_landing_reserve",
        "already_dialed",
    );

    // Landing spend stays bounded on the dialed reserve: an over-ask spends
    // NOTHING, and a landing row is not dialed at all.
    queue.request_cancel(soft_request(leased.id, "peer-1", CancelStanding::PeerAgent))?;
    let landing = accept_landing_at(&queue, &leased, LandingTrigger::CancelRequest, 16)?;
    let LandingReserveSpendOutcome::Exhausted {
        record,
        requested_units,
        remaining_units,
    } = queue.spend_landing_reserve(SpendAttemptLandingReserve {
        id: landing.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: landing.attempt_count,
        units: 101,
        now: 17,
    })?
    else {
        panic!("an over-ask spends nothing");
    };
    assert_eq!(requested_units, 101);
    assert_eq!(remaining_units, 100);
    assert_eq!(record.landing_reserve().spent_units, 0);
    assert_invalid_transition(
        queue
            .dial_landing_reserve(DialLandingReserve {
                id: landing.id,
                limit_units: 10,
                reserve_percent: None,
                now: 18,
            })
            .expect_err("a landing row would be minting the reserve it spends"),
        "dial_landing_reserve",
        "landing",
    );
    Ok(())
}

/// Proof 13 (ONE-1896 §6): a persisted cancel receipt must agree with its own
/// KIND, and the same contract guards the write door.
///
/// Contradictory rows are not a cosmetic problem: a refusal with no reason is
/// indistinguishable from a worker that ignored the ask, and a projection that
/// faithfully renders one is reporting a fact nobody established.
#[test]
fn a_persisted_cancel_receipt_must_agree_with_its_own_kind() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let leased = leased_attempt(&queue, "turn:receipt-kinds")?;
    queue.request_cancel(soft_request(leased.id, "peer-1", CancelStanding::PeerAgent))?;
    let refused = queue.reject_cancel(RejectAttemptCancel {
        id: leased.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: leased.attempt_count,
        reason: "mid-write".to_owned(),
        status: None,
        request_sequence: None,
        now: 13,
    })?;
    let record = refused.record;
    assert_eq!(record.cancel_receipts().len(), 2);

    let refuse_decode = |mutate: &dyn Fn(&mut AttemptRecord), expected: &'static str| {
        let mut malformed = record.clone();
        mutate(&mut malformed);
        let encoded = rmp_serde::to_vec_named(&malformed).expect("encode");
        let mut raw = vec![super::types::ATTEMPT_RECORD_VERSION];
        raw.extend(encoded);
        let err = decode_record(&raw, malformed.id).expect_err("a contradictory row fails closed");
        assert!(
            matches!(&err, Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(reason)) if *reason == expected),
            "expected {expected}, got {err:?}"
        );
    };

    // The ASK: it must name its trigger, may not rest on force grounds, moves
    // no reserve units, and cannot record the "no standing" refusal verdict as
    // if it were standing.
    refuse_decode(
        &|row| row.cancel_state.receipts[0].trigger = None,
        ERR_CANCEL_RECEIPT_MISSING_TRIGGER,
    );
    refuse_decode(
        &|row| row.cancel_state.receipts[0].grounds = Some(ForceCancelGrounds::Owner),
        ERR_CANCEL_RECEIPT_FIELD_FORBIDDEN,
    );
    refuse_decode(
        &|row| row.cancel_state.receipts[0].reserve_units = 5,
        ERR_CANCEL_RECEIPT_RESERVE_UNITS,
    );
    refuse_decode(
        &|row| row.cancel_state.receipts[0].standing = Some(CancelStanding::None),
        ERR_CANCEL_NO_STANDING,
    );

    // The REFUSAL: the reason is the evidence, and the request reference is
    // what keeps the other requesters still owed an answer.
    refuse_decode(
        &|row| row.cancel_state.receipts[1].reason = None,
        ERR_CANCEL_RECEIPT_MISSING_REASON,
    );
    refuse_decode(
        &|row| row.cancel_state.receipts[1].request_sequence = None,
        ERR_CANCEL_RECEIPT_MISSING_REQUEST_REF,
    );

    // A resume-point row with no point, a reserve spend of zero units, and a
    // force with no grounds are all the same failure: a kind that claims
    // something the row does not carry.
    refuse_decode(
        &|row| {
            let receipt = &mut row.cancel_state.receipts[0];
            receipt.kind = AttemptCancelReceiptKind::ResumePointRecorded;
            receipt.standing = None;
            receipt.reason = None;
        },
        ERR_CANCEL_RECEIPT_MISSING_RESUME_POINT,
    );
    refuse_decode(
        &|row| {
            let receipt = &mut row.cancel_state.receipts[0];
            receipt.kind = AttemptCancelReceiptKind::ReserveSpent;
            receipt.standing = None;
            receipt.reason = None;
        },
        ERR_CANCEL_RECEIPT_RESERVE_UNITS,
    );
    refuse_decode(
        &|row| {
            let receipt = &mut row.cancel_state.receipts[1];
            receipt.kind = AttemptCancelReceiptKind::ForceCancelled;
            receipt.request_sequence = None;
        },
        ERR_CANCEL_RECEIPT_MISSING_GROUNDS,
    );

    // The WRITE door holds the same contract, so a malformed draft can never
    // reach storage in the first place: the row is refused and the append-only
    // history is exactly as long as it was.
    let mut draft_target = record.clone();
    let before = draft_target.cancel_state.receipts.len();
    let err = append_cancel_receipt(
        &mut draft_target,
        AttemptCancelReceiptKind::SoftRejected,
        "worker-a".to_owned(),
        CancelReceiptDraft {
            request_sequence: Some(1),
            ..CancelReceiptDraft::default()
        },
        14,
    )
    .expect_err("a refusal without a reason is refused at the door");
    assert!(matches!(
        err,
        Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(reason)) if reason == ERR_CANCEL_RECEIPT_MISSING_REASON
    ));
    assert_eq!(
        draft_target.cancel_state.receipts.len(),
        before,
        "a refused append leaves the record untouched"
    );

    // The live row on disk is still the well-formed one every mutation copied.
    let stored = queue.get(leased.id)?.expect("row");
    assert_eq!(stored.cancel_receipts().len(), 2);
    assert_eq!(stored.state, AttemptState::Leased);
    Ok(())
}

/// Proof 14 (ONE-1896 §5): the A2A projection exports the WHOLE durable resume
/// point, artifact reference included.
///
/// A successor handed only the cursor has lost the identity of the work
/// already produced and would redo it; the reference is a typed ref, never a
/// payload body.
#[test]
fn the_a2a_projection_carries_the_whole_durable_resume_point() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let leased = leased_attempt(&queue, "turn:a2a-resume")?;

    let ordinary = crate::run_tree::project_attempt_to_a2a(&leased);
    assert!(ordinary.extensions.resume_point.is_none());
    assert!(
        ordinary.extensions.resume_artifact_ref.is_none(),
        "an ordinary row carries neither half of a resume point"
    );

    queue.request_cancel(soft_request(leased.id, "peer-1", CancelStanding::PeerAgent))?;
    let landing = accept_landing_at(&queue, &leased, LandingTrigger::CancelRequest, 13)?;
    let recorded = queue.record_resume_point(RecordAttemptResumePoint {
        id: landing.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: landing.attempt_count,
        resume_point: AttemptResumePoint::new("step-7/of-12", 14).with_artifact_ref("receipt:9f2c"),
        now: 14,
    })?;
    let a2a = crate::run_tree::project_attempt_to_a2a(&recorded);
    assert_eq!(a2a.extensions.resume_point.as_deref(), Some("step-7/of-12"));
    assert_eq!(
        a2a.extensions.resume_artifact_ref.as_deref(),
        Some("receipt:9f2c"),
        "the artifact identity is exported, not silently dropped"
    );

    let FinishLandingOutcome::HandedOff { successor, .. } =
        queue.finish_landing(FinishAttemptLanding {
            id: landing.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: landing.attempt_count,
            hand_off: true,
            scheduled_at: None,
            now: 15,
        })?
    else {
        panic!("a recorded resume point may hand off");
    };
    let handed_off = crate::run_tree::project_attempt_to_a2a(&successor);
    assert_eq!(
        handed_off.extensions.resume_point.as_deref(),
        Some("step-7/of-12")
    );
    assert_eq!(
        handed_off.extensions.resume_artifact_ref.as_deref(),
        Some("receipt:9f2c"),
        "the successor carries the whole point across the handoff"
    );
    Ok(())
}
