//! Abandon gates and terminal idempotence, write-once set_result, and result refs.

use super::*;
use crate::error::ArtifactError;

#[test]
fn abandon_requires_a_lease_a_reason_and_a_result_reference() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let claim = claimed(&queue, "byoa", "worker-a")?;

    // The lease fence is the same one complete/fail use: a stranger and a
    // stale generation are both refused, and neither writes anything.
    assert_invalid_transition(
        queue
            .abandon(AbandonAttempt {
                id: claim.id,
                lease_owner: "worker-b".to_owned(),
                attempt_count: claim.attempt_count,
                result_ref: result_ref("blob-artifact:aa@1"),
                reason: "stopped".to_owned(),
                now: 12,
            })
            .expect_err("another worker may not abandon this row"),
        "abandon",
        "leased_by_other",
    );
    assert_invalid_transition(
        queue
            .abandon(AbandonAttempt {
                id: claim.id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: claim.attempt_count + 1,
                result_ref: result_ref("blob-artifact:aa@1"),
                reason: "stopped".to_owned(),
                now: 12,
            })
            .expect_err("a stale lease generation may not abandon this row"),
        "abandon",
        "stale_attempt",
    );

    // An empty reason is refused at the door, and an empty reference cannot
    // even be constructed.
    let err = queue
        .abandon(AbandonAttempt {
            id: claim.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: claim.attempt_count,
            result_ref: result_ref("blob-artifact:aa@1"),
            reason: String::new(),
            now: 12,
        })
        .expect_err("an abandonment must say why it stopped");
    assert!(matches!(
        err,
        Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_FAILURE_REASON_EMPTY
        ))
    ));
    assert!(
        AttemptResultRef::new("").is_err(),
        "an empty result reference names nothing and must not exist"
    );

    // Nothing above moved the row.
    assert_eq!(
        queue.get(claim.id)?.expect("row").state,
        AttemptState::Leased
    );
    Ok(())
}

/// Abandoning a landing row must clear the landing record it leaves behind:
/// the placement rule refuses a landing record on a terminal row, so a row
/// written otherwise would be undecodable on the very next read.
#[test]
fn abandon_from_landing_clears_landing_and_round_trips() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let leased = leased_attempt(&queue, "turn:landing-abandon")?;
    queue.request_cancel(soft_request(leased.id, "peer-1", CancelStanding::PeerAgent))?;
    let landing = accept_landing_at(&queue, &leased, LandingTrigger::CancelRequest, 13)?;
    assert!(landing.landing().is_some(), "the landing row carries one");

    let AbandonOutcome::Abandoned(abandoned) = queue.abandon(AbandonAttempt {
        id: leased.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: landing.attempt_count,
        result_ref: result_ref("blob-artifact:aa@1"),
        reason: "executor stopped without delivering".to_owned(),
        now: 14,
    })?
    else {
        panic!("a landing row that stopped without delivering is abandonable");
    };
    assert_eq!(abandoned.state, AttemptState::Abandoned);
    assert!(
        abandoned.landing().is_none(),
        "a settled row keeps no live landing pointer"
    );

    // The persisted row decodes, and decodes the SAME way twice: the codec is
    // the door every later read and every cleanup scan goes through.
    let reread = queue.get(leased.id)?.expect("abandoned row");
    assert_eq!(reread.state, AttemptState::Abandoned);
    assert!(reread.landing().is_none());
    assert_eq!(reread, abandoned);
    assert_eq!(queue.get(leased.id)?.expect("abandoned row"), reread);

    // The landing itself is not lost: its receipt still names what happened.
    assert!(
        reread
            .cancel_receipts()
            .iter()
            .any(|receipt| receipt.kind == AttemptCancelReceiptKind::LandingAccepted),
        "the receipt history still records the landing"
    );
    Ok(())
}

#[test]
fn a_settled_row_refuses_every_further_transition() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let claim = claimed(&queue, "byoa", "worker-a")?;
    let AbandonOutcome::Abandoned(abandoned) = queue.abandon(AbandonAttempt {
        id: claim.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: claim.attempt_count,
        result_ref: result_ref("blob-artifact:aa@1"),
        reason: "stopped".to_owned(),
        now: 12,
    })?
    else {
        panic!("expected a fresh abandonment");
    };

    assert_invalid_transition(
        queue
            .complete(CompleteAttempt {
                id: abandoned.id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: abandoned.attempt_count,
                now: 13,
            })
            .expect_err("an abandoned row never completes"),
        "complete",
        "abandoned",
    );
    assert_invalid_transition(
        queue
            .fail(FailAttempt {
                id: abandoned.id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: abandoned.attempt_count,
                reason: "late".to_owned(),
                now: 13,
            })
            .expect_err("an abandoned row never fails"),
        "fail",
        "abandoned",
    );
    assert_invalid_transition(
        queue
            .retry(RetryAttempt {
                id: abandoned.id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: abandoned.attempt_count,
                backoff_until: 30,
                last_error: None,
                now: 13,
            })
            .expect_err("an abandoned row never retries"),
        "retry",
        "abandoned",
    );
    assert_invalid_transition(
        queue
            .intervene(InterveneAttempt {
                id: abandoned.id,
                kind: AttemptInterventionKind::Cancel,
                actor: "dashboard".to_owned(),
                note: None,
                now: 13,
            })
            .expect_err("an abandoned row cannot be cancelled after the fact"),
        "cancel",
        "abandoned",
    );

    // The soft-cancel rung reports it as settled rather than as pre-lease
    // work: something WAS carrying this row, and it stopped.
    let CancelRequestOutcome::AlreadySettled(settled) =
        queue.request_cancel(RequestAttemptCancel {
            id: abandoned.id,
            actor: "owner".to_owned(),
            standing: CancelStanding::Authority,
            trigger: LandingTrigger::CancelRequest,
            reason: None,
            now: 13,
        })?
    else {
        panic!("a cancel request against a settled row is settled");
    };
    assert_eq!(settled.state, AttemptState::Abandoned);
    Ok(())
}

#[test]
fn set_result_is_fenced_write_once_and_idempotent() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let claim = claimed(&queue, "byoa", "worker-a")?;

    assert_invalid_transition(
        queue
            .set_result(SetAttemptResult {
                id: claim.id,
                lease_owner: "worker-b".to_owned(),
                attempt_count: claim.attempt_count,
                result_ref: result_ref("blob-artifact:aa@1"),
                now: 12,
            })
            .expect_err("another worker may not speak for this row"),
        "set_result",
        "leased_by_other",
    );

    let attached = queue.set_result(SetAttemptResult {
        id: claim.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: claim.attempt_count,
        result_ref: result_ref("blob-artifact:aa@1"),
        now: 12,
    })?;
    assert_eq!(
        attached.result_ref().map(AttemptResultRef::as_str),
        Some("blob-artifact:aa@1")
    );
    assert_eq!(
        attached.state,
        AttemptState::Leased,
        "naming a result does not settle the row"
    );

    // Idempotent for the same reference.
    let again = queue.set_result(SetAttemptResult {
        id: claim.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: claim.attempt_count,
        result_ref: result_ref("blob-artifact:aa@1"),
        now: 13,
    })?;
    assert_eq!(again.result_ref, attached.result_ref);

    // Write-once for a different one: a published artifact is never silently
    // repointed at another.
    let err = queue
        .set_result(SetAttemptResult {
            id: claim.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: claim.attempt_count,
            result_ref: result_ref("blob-artifact:bb@1"),
            now: 14,
        })
        .expect_err("a result reference is write-once");
    assert!(matches!(
        err,
        Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_RESULT_REF_REBOUND
        ))
    ));

    // The reference survives settling, so a completed row still names its
    // output.
    let CompleteOutcome::Completed(completed) = queue.complete(CompleteAttempt {
        id: claim.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: claim.attempt_count,
        now: 15,
    })?
    else {
        panic!("expected a fresh completion");
    };
    assert_eq!(
        completed.result_ref().map(AttemptResultRef::as_str),
        Some("blob-artifact:aa@1")
    );
    Ok(())
}

#[test]
fn abandoned_state_index_is_appended_and_old_rows_still_decode() -> Result<()> {
    // T6a: the wire index of every pre-existing state is unchanged, so a row
    // written before `Abandoned` existed reads back as the same state.
    let states = [
        (AttemptState::Queued, "queued"),
        (AttemptState::Leased, "leased"),
        (AttemptState::Paused, "paused"),
        (AttemptState::Completed, "completed"),
        (AttemptState::Failed, "failed"),
        (AttemptState::Cancelled, "cancelled"),
        (AttemptState::Scheduled, "scheduled"),
        (AttemptState::Landing, "landing"),
        (AttemptState::Abandoned, "abandoned"),
    ];
    for (index, (state, label)) in states.iter().enumerate() {
        let encoded = rmp_serde::to_vec_named(state).expect("encode state");
        let decoded: AttemptState = rmp_serde::from_slice(&encoded).expect("decode state");
        assert_eq!(decoded, *state);
        assert_eq!(state.as_str(), *label);
        // Abandoned is LAST, so it cannot have taken an index an older row
        // already wrote.
        if *state == AttemptState::Abandoned {
            assert_eq!(index, states.len() - 1);
        }
    }

    // T6b: a row written without the `result_ref` key decodes as `None`,
    // through the real decode door with all its validators.
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let EnqueueOutcome::Enqueued(row) = queue.enqueue(enqueue("legacy", None, 10))? else {
        panic!("expected an enqueue");
    };
    let stored = queue.get(row.id)?.expect("row");
    assert_eq!(stored.result_ref, None);

    // T6c: a round trip through the real encoder preserves an attached
    // reference exactly.
    let mut with_result = stored;
    with_result.result_ref = Some(result_ref("blob-artifact:cc@9"));
    let encoded = encode_record(&with_result)?;
    let decoded = decode_record(&encoded, with_result.id)?;
    assert_eq!(decoded, with_result);
    Ok(())
}

#[test]
fn a_malformed_abandoned_row_fails_closed_on_decode() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let EnqueueOutcome::Enqueued(row) = queue.enqueue(enqueue("byoa", None, 10))? else {
        panic!("expected an enqueue");
    };
    let mut record = queue.get(row.id)?.expect("row");
    record.state = AttemptState::Abandoned;
    record.last_error = Some("stopped".to_owned());

    // No result reference: the stop would not be auditable.
    let encoded = encode_record(&record)?;
    let err = decode_record(&encoded, record.id).expect_err("an abandonment needs its artifact");
    assert!(matches!(
        err,
        Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_ABANDONED_WITHOUT_RESULT
        ))
    ));

    // No reason: the stop would not be explainable.
    record.result_ref = Some(result_ref("blob-artifact:dd@1"));
    record.last_error = None;
    let encoded = encode_record(&record)?;
    let err = decode_record(&encoded, record.id).expect_err("an abandonment needs its reason");
    assert!(matches!(
        err,
        Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_ABANDONED_WITHOUT_REASON
        ))
    ));

    // A lease owner: a settled row holds no lease.
    record.last_error = Some("stopped".to_owned());
    record.lease_owner = Some("worker-a".to_owned());
    let encoded = encode_record(&record)?;
    assert!(
        decode_record(&encoded, record.id).is_err(),
        "a terminal row must not carry a lease owner"
    );
    Ok(())
}
