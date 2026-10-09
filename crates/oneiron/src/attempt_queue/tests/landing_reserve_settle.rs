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
