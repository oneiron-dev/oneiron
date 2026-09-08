//! Claim semantics and index hygiene, plus complete/fail transition guards.

use super::*;

#[test]
fn attempt_queue_claim_is_atomic_and_returns_typed_states() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    assert_eq!(
        queue.claim(ClaimAttempt {
            lease_owner: "worker-a".to_owned(),
            now: 10,
        })?,
        ClaimOutcome::Empty
    );

    let EnqueueOutcome::Enqueued(first) = queue.enqueue(enqueue("first", None, 10))? else {
        panic!("expected first enqueue");
    };
    let EnqueueOutcome::Enqueued(second) = queue.enqueue(enqueue("second", None, 20))? else {
        panic!("expected second enqueue");
    };

    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".to_owned(),
        now: 30,
    })?
    else {
        panic!("expected claimed attempt");
    };
    assert_eq!(claimed.id, first.id);
    assert_eq!(claimed.state, AttemptState::Leased);
    assert_eq!(claimed.lease_owner.as_deref(), Some("worker-a"));
    assert_eq!(claimed.attempt_count, 1);
    assert_eq!(claimed.updated_at, 30);

    let persisted = queue.get(first.id)?.expect("claimed attempt persisted");
    assert_eq!(persisted, claimed);

    let ClaimOutcome::Claimed(next) = queue.claim(ClaimAttempt {
        lease_owner: "worker-b".to_owned(),
        now: 40,
    })?
    else {
        panic!("expected second claimed attempt");
    };
    assert_eq!(next.id, second.id);

    assert_eq!(
        queue.claim(ClaimAttempt {
            lease_owner: "worker-c".to_owned(),
            now: 50,
        })?,
        ClaimOutcome::Empty
    );

    Ok(())
}

#[test]
fn attempt_queue_claim_kind_skips_other_ready_attempts_without_leasing_them() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(other) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:other"), 10))?
    else {
        panic!("expected other attempt enqueue");
    };
    let EnqueueOutcome::Enqueued(companion) =
        queue.enqueue(enqueue("companion_task", Some("companion:task"), 11))?
    else {
        panic!("expected companion attempt enqueue");
    };

    let ClaimOutcome::Claimed(claimed_companion) = queue.claim_kind(
        "companion_task",
        ClaimAttempt {
            lease_owner: "companion-worker".to_owned(),
            now: 20,
        },
    )?
    else {
        panic!("expected companion attempt claim");
    };
    assert_eq!(claimed_companion.id, companion.id);
    assert_eq!(claimed_companion.kind, "companion_task");
    assert_eq!(
        claimed_companion.lease_owner.as_deref(),
        Some("companion-worker")
    );

    let persisted_other = queue.get(other.id)?.expect("other attempt persisted");
    assert_eq!(persisted_other.state, AttemptState::Queued);
    assert_eq!(persisted_other.lease_owner, None);

    let ClaimOutcome::Claimed(claimed_other) = queue.claim(ClaimAttempt {
        lease_owner: "generic-worker".to_owned(),
        now: 21,
    })?
    else {
        panic!("expected generic claim");
    };
    assert_eq!(claimed_other.id, other.id);
    assert_eq!(claimed_other.kind, "claim_extraction");
    assert_eq!(claimed_other.lease_owner.as_deref(), Some("generic-worker"));

    Ok(())
}

#[test]
fn attempt_queue_claim_kind_preserves_stale_ready_index_for_skipped_kind() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(other) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:stale-skip"), 10))?
    else {
        panic!("expected other attempt enqueue");
    };
    {
        let mut stale_record = other.clone();
        stale_record.backoff_until = Some(5);
        stale_record.updated_at = 11;
        let encoded = encode_record(&stale_record)?;
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .attempt_records
            .put(&mut wtxn, other.id.as_bytes(), &encoded)?;
        wtxn.commit()?;
    }

    assert_eq!(
        queue.claim_kind(
            "companion_task",
            ClaimAttempt {
                lease_owner: "companion-worker".to_owned(),
                now: 20,
            },
        )?,
        ClaimOutcome::Empty
    );

    let ClaimOutcome::Claimed(claimed_other) = queue.claim(ClaimAttempt {
        lease_owner: "generic-worker".to_owned(),
        now: 21,
    })?
    else {
        panic!("expected skipped stale-ready attempt to remain claimable");
    };
    assert_eq!(claimed_other.id, other.id);
    assert_eq!(claimed_other.kind, "claim_extraction");
    assert_eq!(claimed_other.backoff_until, None);
    assert_eq!(claimed_other.lease_owner.as_deref(), Some("generic-worker"));

    Ok(())
}

#[test]
fn attempt_queue_claim_treats_non_backoff_attempts_as_immediately_ready() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(attempt) =
        queue.enqueue(enqueue("future-created", None, 1_000))?
    else {
        panic!("expected enqueue");
    };

    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".to_owned(),
        now: 1,
    })?
    else {
        panic!("expected future-created attempt without backoff to be claimable");
    };
    assert_eq!(claimed.id, attempt.id);
    assert_eq!(claimed.created_at, 1_000);
    assert_eq!(claimed.backoff_until, None);
    assert_eq!(claimed.attempt_count, 1);

    Ok(())
}

#[test]
fn attempt_queue_claim_cleans_ready_key_id_mismatch_and_continues() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(enqueue("first", None, 10))? else {
        panic!("expected enqueue");
    };
    let stale_ready_key = ready_key(0, AttemptId { bytes: [0; 16] });
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .attempt_ready
            .put(&mut wtxn, &stale_ready_key, attempt.id.as_bytes())?;
        wtxn.commit()?;
    }

    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claim past stale ready row");
    };
    assert_eq!(claimed.id, attempt.id);

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .attempt_ready
            .get(&rtxn, &stale_ready_key)?
            .is_none()
    );

    Ok(())
}

#[test]
fn attempt_queue_claim_cleans_malformed_ready_rows_and_continues() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(enqueue("first", None, 10))? else {
        panic!("expected enqueue");
    };
    let malformed_key = vec![0];
    let malformed_value_key = ready_key(0, AttemptId { bytes: [0; 16] });
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .attempt_ready
            .put(&mut wtxn, &malformed_key, attempt.id.as_bytes())?;
        vault
            .store
            .attempt_ready
            .put(&mut wtxn, &malformed_value_key, b"bad")?;
        wtxn.commit()?;
    }

    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claim past malformed ready rows");
    };
    assert_eq!(claimed.id, attempt.id);

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .attempt_ready
            .get(&rtxn, &malformed_key)?
            .is_none()
    );
    assert!(
        vault
            .store
            .attempt_ready
            .get(&rtxn, &malformed_value_key)?
            .is_none()
    );

    Ok(())
}

#[test]
fn attempt_queue_transitions_complete_is_idempotent_and_rejects_invalid_states() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(attempt) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:complete"), 10))?
    else {
        panic!("expected enqueue");
    };

    let queued_complete = queue
        .complete(CompleteAttempt {
            id: attempt.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: 0,
            now: 11,
        })
        .unwrap_err();
    assert_invalid_transition(queued_complete, "complete", "queued");

    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claimed attempt");
    };
    assert_eq!(claimed.id, attempt.id);

    let wrong_owner_complete = queue
        .complete(CompleteAttempt {
            id: attempt.id,
            lease_owner: "worker-b".to_owned(),
            attempt_count: claimed.attempt_count,
            now: 25,
        })
        .unwrap_err();
    assert_invalid_transition(wrong_owner_complete, "complete", "leased_by_other");

    let CompleteOutcome::Completed(completed) = queue.complete(CompleteAttempt {
        id: attempt.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: claimed.attempt_count,
        now: 30,
    })?
    else {
        panic!("expected complete");
    };
    assert_eq!(completed.state, AttemptState::Completed);
    assert_eq!(completed.lease_owner, None);
    assert_eq!(completed.backoff_until, None);
    assert_eq!(completed.last_error, None);
    assert_eq!(completed.payload, b"payload-10");
    assert_eq!(completed.run_id.as_deref(), Some("run-10"));
    assert_eq!(completed.dedupe_key.as_deref(), Some("turn:complete"));
    assert_eq!(completed.updated_at, 30);

    let CompleteOutcome::AlreadyCompleted(again) = queue.complete(CompleteAttempt {
        id: attempt.id,
        lease_owner: String::new(),
        attempt_count: 0,
        now: 40,
    })?
    else {
        panic!("expected idempotent complete");
    };
    assert_eq!(again.updated_at, 30);

    let completed_fail = queue
        .fail(FailAttempt {
            id: attempt.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: 0,
            reason: "boom".to_owned(),
            now: 50,
        })
        .unwrap_err();
    assert_invalid_transition(completed_fail, "fail", "completed");

    let completed_retry = queue
        .retry(RetryAttempt {
            id: attempt.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: 0,
            backoff_until: 60,
            last_error: Some("retryable".to_owned()),
            now: 50,
        })
        .unwrap_err();
    assert_invalid_transition(completed_retry, "retry", "completed");

    let EnqueueOutcome::Enqueued(replacement) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:complete"), 60))?
    else {
        panic!("terminal dedupe key should be reusable");
    };
    assert_ne!(replacement.id, attempt.id);

    Ok(())
}

#[test]
fn attempt_queue_transitions_fail_is_idempotent_and_rejects_invalid_states() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(attempt) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:fail"), 10))?
    else {
        panic!("expected enqueue");
    };

    let queued_fail = queue
        .fail(FailAttempt {
            id: attempt.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: 0,
            reason: "boom".to_owned(),
            now: 11,
        })
        .unwrap_err();
    assert_invalid_transition(queued_fail, "fail", "queued");

    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claimed attempt");
    };
    assert_eq!(claimed.id, attempt.id);

    let wrong_owner_fail = queue
        .fail(FailAttempt {
            id: attempt.id,
            lease_owner: "worker-b".to_owned(),
            attempt_count: claimed.attempt_count,
            reason: "fatal".to_owned(),
            now: 25,
        })
        .unwrap_err();
    assert_invalid_transition(wrong_owner_fail, "fail", "leased_by_other");

    let FailOutcome::Failed(failed) = queue.fail(FailAttempt {
        id: attempt.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: claimed.attempt_count,
        reason: "fatal".to_owned(),
        now: 30,
    })?
    else {
        panic!("expected fail");
    };
    assert_eq!(failed.state, AttemptState::Failed);
    assert_eq!(failed.lease_owner, None);
    assert_eq!(failed.backoff_until, None);
    assert_eq!(failed.last_error.as_deref(), Some("fatal"));
    assert_eq!(failed.payload, b"payload-10");
    assert_eq!(failed.run_id.as_deref(), Some("run-10"));
    assert_eq!(failed.dedupe_key.as_deref(), Some("turn:fail"));

    let FailOutcome::AlreadyFailed(again) = queue.fail(FailAttempt {
        id: attempt.id,
        lease_owner: String::new(),
        attempt_count: 0,
        reason: "x".repeat(MAX_FAILURE_REASON_LEN + 1),
        now: 40,
    })?
    else {
        panic!("expected idempotent fail");
    };
    assert_eq!(again.updated_at, 30);
    assert_eq!(again.last_error.as_deref(), Some("fatal"));

    let failed_complete = queue
        .complete(CompleteAttempt {
            id: attempt.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: 0,
            now: 50,
        })
        .unwrap_err();
    assert_invalid_transition(failed_complete, "complete", "failed");

    let EnqueueOutcome::Enqueued(replacement) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:fail"), 60))?
    else {
        panic!("terminal dedupe key should be reusable");
    };
    assert_ne!(replacement.id, attempt.id);

    Ok(())
}

#[test]
fn attempt_queue_transitions_reject_stale_attempt_tokens() -> Result<()> {
    fn lease_second_attempt(queue: &AttemptQueue<'_>, dedupe_key: &str) -> Result<AttemptRecord> {
        let EnqueueOutcome::Enqueued(attempt) =
            queue.enqueue(enqueue("claim_extraction", Some(dedupe_key), 10))?
        else {
            panic!("expected enqueue");
        };
        let ClaimOutcome::Claimed(first_attempt) = queue.claim(ClaimAttempt {
            lease_owner: "worker-a".to_owned(),
            now: 20,
        })?
        else {
            panic!("expected first attempt");
        };
        assert_eq!(first_attempt.id, attempt.id);

        // The retry is a fresh row, so the second lease restarts that row's own
        // generation fence at 1 rather than continuing the source's count.
        let RetryOutcome::Retried(scheduled) = queue.retry(RetryAttempt {
            id: attempt.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: first_attempt.attempt_count,
            backoff_until: 30,
            last_error: Some("retryable".to_owned()),
            now: 25,
        })?;

        let ClaimOutcome::Claimed(second_attempt) = queue.claim(ClaimAttempt {
            lease_owner: "worker-a".to_owned(),
            now: 30,
        })?
        else {
            panic!("expected second attempt");
        };
        assert_eq!(second_attempt.id, scheduled.id);
        assert_ne!(second_attempt.id, attempt.id);
        assert_eq!(second_attempt.attempt_count, 1);
        Ok(second_attempt)
    }

    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let complete_attempt = lease_second_attempt(&queue, "stale-complete")?;
    let stale_complete = queue
        .complete(CompleteAttempt {
            id: complete_attempt.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: complete_attempt.attempt_count - 1,
            now: 40,
        })
        .unwrap_err();
    assert_invalid_transition(stale_complete, "complete", "stale_attempt");

    let fail_attempt = lease_second_attempt(&queue, "stale-fail")?;
    let stale_fail = queue
        .fail(FailAttempt {
            id: fail_attempt.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: fail_attempt.attempt_count - 1,
            reason: "fatal".to_owned(),
            now: 40,
        })
        .unwrap_err();
    assert_invalid_transition(stale_fail, "fail", "stale_attempt");

    let retry_attempt = lease_second_attempt(&queue, "stale-retry")?;
    let stale_retry = queue
        .retry(RetryAttempt {
            id: retry_attempt.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: retry_attempt.attempt_count - 1,
            backoff_until: 60,
            last_error: Some("retryable".to_owned()),
            now: 40,
        })
        .unwrap_err();
    assert_invalid_transition(stale_retry, "retry", "stale_attempt");

    Ok(())
}

#[test]
fn attempt_queue_transitions_reject_empty_failure_reasons() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(attempt) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:empty-fail"), 10))?
    else {
        panic!("expected enqueue");
    };
    let ClaimOutcome::Claimed(mut claimed) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claim");
    };

    let err = queue
        .fail(FailAttempt {
            id: attempt.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: claimed.attempt_count,
            reason: String::new(),
            now: 30,
        })
        .unwrap_err();
    assert!(matches!(
        err,
        Error::InvalidAttemptQueueRecord(ERR_FAILURE_REASON_EMPTY)
    ));

    claimed.state = AttemptState::Failed;
    claimed.lease_owner = None;
    claimed.last_error = Some(String::new());
    let encoded = encode_record(&claimed)?;
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .attempt_records
            .put(&mut wtxn, claimed.id.as_bytes(), &encoded)?;
        wtxn.commit()?;
    }

    let err = queue.get(claimed.id).unwrap_err();
    assert!(matches!(
        err,
        Error::InvalidAttemptQueueRecord(ERR_FAILURE_REASON_EMPTY)
    ));

    Ok(())
}
