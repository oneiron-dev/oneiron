//! Stale-lease cleanup and recovery, decode-fails-closed guards, and the ready-key codec.

use super::*;
use crate::error::ArtifactError;

#[test]
fn attempt_queue_claim_cleans_missing_record_ready_and_dedupe() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(first) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:missing"), 10))?
    else {
        panic!("expected enqueue");
    };
    let EnqueueOutcome::Enqueued(second) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:missing-too"), 11))?
    else {
        panic!("expected enqueue");
    };
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .attempt_records
            .delete(&mut wtxn, first.id.as_bytes())?;
        vault
            .store
            .attempt_records
            .delete(&mut wtxn, second.id.as_bytes())?;
        wtxn.commit()?;
    }

    assert!(matches!(
        queue.claim(ClaimAttempt {
            lease_owner: "worker-a".to_owned(),
            now: 20,
        })?,
        ClaimOutcome::Empty
    ));

    let EnqueueOutcome::Enqueued(replacement) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:missing"), 30))?
    else {
        panic!("expected stale dedupe key to be reusable");
    };
    assert_ne!(replacement.id, first.id);
    let EnqueueOutcome::Enqueued(second_replacement) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:missing-too"), 31))?
    else {
        panic!("expected second stale dedupe key to be reusable");
    };
    assert_ne!(second_replacement.id, second.id);

    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".to_owned(),
        now: 40,
    })?
    else {
        panic!("expected replacement claim");
    };
    let ClaimOutcome::Claimed(second_claimed) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".to_owned(),
        now: 40,
    })?
    else {
        panic!("expected second replacement claim");
    };
    assert!(
        (claimed.id == replacement.id && second_claimed.id == second_replacement.id)
            || (claimed.id == second_replacement.id && second_claimed.id == replacement.id)
    );
    assert!(matches!(
        queue.claim(ClaimAttempt {
            lease_owner: "worker-a".to_owned(),
            now: 40,
        })?,
        ClaimOutcome::Empty
    ));

    Ok(())
}

#[test]
fn attempt_queue_decode_fails_closed_on_record_key_id_mismatch() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(enqueue("claim_extraction", None, 10))?
    else {
        panic!("expected enqueue");
    };
    let mut corrupt = attempt.clone();
    corrupt.id = AttemptId::now();
    let encoded = encode_record(&corrupt)?;
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .attempt_records
            .put(&mut wtxn, attempt.id.as_bytes(), &encoded)?;
        wtxn.commit()?;
    }

    let err = queue
        .claim(ClaimAttempt {
            lease_owner: "worker-a".to_owned(),
            now: 20,
        })
        .unwrap_err();
    assert!(matches!(
        err,
        Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(_))
    ));

    Ok(())
}

#[test]
fn attempt_queue_decode_fails_closed_on_lease_owner_state_mismatch() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(enqueue("claim_extraction", None, 10))?
    else {
        panic!("expected enqueue");
    };
    let mut corrupt = attempt.clone();
    corrupt.state = AttemptState::Leased;
    corrupt.lease_owner = None;
    let encoded = encode_record(&corrupt)?;
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .attempt_records
            .put(&mut wtxn, attempt.id.as_bytes(), &encoded)?;
        wtxn.commit()?;
    }

    let err = queue.get(attempt.id).unwrap_err();
    assert!(matches!(
        err,
        Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(_))
    ));

    Ok(())
}

#[test]
fn attempt_queue_cleanup_recovers_stale_leases_through_claim() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(attempt) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:stale"), 10))?
    else {
        panic!("expected enqueue");
    };
    let ClaimOutcome::Claimed(first_attempt) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected first claim");
    };

    let report = queue.cleanup_leases(CleanupAttemptLeases {
        now: 40,
        lease_timeout_secs: 10,
    })?;
    assert_eq!(report.pending, 1);
    assert_eq!(report.running, 0);
    assert_eq!(report.stale_requeued, 1);
    assert_eq!(
        report.retry_reason_count(AttemptQueueRetryReason::LeaseTimeout),
        1
    );

    let requeued = queue.get(attempt.id)?.expect("requeued attempt");
    assert_eq!(requeued.state, AttemptState::Queued);
    assert_eq!(requeued.lease_owner, None);
    assert_eq!(requeued.attempt_count, first_attempt.attempt_count);
    assert_eq!(requeued.last_error.as_deref(), Some("lease_timeout"));
    assert_eq!(requeued.updated_at, 40);

    let stale_complete = queue
        .complete(CompleteAttempt {
            id: attempt.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: first_attempt.attempt_count,
            now: 41,
        })
        .unwrap_err();
    assert_invalid_transition(stale_complete, "complete", "queued");

    let ClaimOutcome::Claimed(second_attempt) = queue.claim(ClaimAttempt {
        lease_owner: "worker-b".to_owned(),
        now: 42,
    })?
    else {
        panic!("expected reclaim through claim");
    };
    assert_eq!(second_attempt.id, attempt.id);
    assert_eq!(second_attempt.lease_owner.as_deref(), Some("worker-b"));
    assert_eq!(
        second_attempt.attempt_count,
        first_attempt.attempt_count + 1
    );

    Ok(())
}

#[test]
fn attempt_queue_cleanup_rejects_zero_timeout_without_requeuing() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(attempt) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:zero"), 10))?
    else {
        panic!("expected enqueue");
    };
    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claim");
    };

    let err = queue
        .cleanup_leases(CleanupAttemptLeases {
            now: 20,
            lease_timeout_secs: 0,
        })
        .unwrap_err();
    assert!(matches!(
        err,
        Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_LEASE_TIMEOUT_ZERO
        ))
    ));

    let persisted = queue.get(attempt.id)?.expect("leased attempt");
    assert_eq!(persisted.state, AttemptState::Leased);
    assert_eq!(persisted.lease_owner.as_deref(), Some("worker-a"));
    assert_eq!(
        queue.claim(ClaimAttempt {
            lease_owner: "worker-b".to_owned(),
            now: 21,
        })?,
        ClaimOutcome::Empty
    );
    assert!(matches!(
        queue.complete(CompleteAttempt {
            id: attempt.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: claimed.attempt_count,
            now: 22,
        })?,
        CompleteOutcome::Completed(_)
    ));

    Ok(())
}

#[test]
fn attempt_queue_cleanup_does_not_duplicate_completed_attempts() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(attempt) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:done"), 10))?
    else {
        panic!("expected enqueue");
    };
    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claim");
    };
    let CompleteOutcome::Completed(_) = queue.complete(CompleteAttempt {
        id: attempt.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: claimed.attempt_count,
        now: 30,
    })?
    else {
        panic!("expected complete");
    };

    let report = queue.cleanup_leases(CleanupAttemptLeases {
        now: 1_000,
        lease_timeout_secs: 1,
    })?;
    assert_eq!(report.done, 1);
    assert_eq!(report.pending, 0);
    assert_eq!(report.running, 0);
    assert_eq!(report.stale_requeued, 0);
    assert_eq!(
        queue.claim(ClaimAttempt {
            lease_owner: "worker-b".to_owned(),
            now: 1_001,
        })?,
        ClaimOutcome::Empty
    );

    Ok(())
}

#[test]
fn attempt_queue_cleanup_reports_counts_and_retry_reasons() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(backoff_attempt) =
        queue.enqueue(enqueue("backoff", Some("turn:backoff"), 10))?
    else {
        panic!("expected enqueue");
    };
    let ClaimOutcome::Claimed(backoff_claim) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".to_owned(),
        now: 11,
    })?
    else {
        panic!("expected claim");
    };
    // Retrying finalizes `backoff_attempt` as a failed try and mints the
    // scheduled row that carries the backoff; the pause lands on that new row.
    let RetryOutcome::Retried(backoff_retry) = queue.retry(RetryAttempt {
        id: backoff_attempt.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: backoff_claim.attempt_count,
        backoff_until: 80,
        last_error: Some("provider said secret text".to_owned()),
        now: 12,
    })?;
    let InterveneOutcome {
        effect: AttemptInterventionEffect::Paused,
        ..
    } = queue.intervene(InterveneAttempt {
        id: backoff_retry.id,
        kind: AttemptInterventionKind::Pause,
        actor: "cleanup-test".to_owned(),
        note: None,
        now: 13,
    })?
    else {
        panic!("expected pause");
    };

    let EnqueueOutcome::Enqueued(stale_attempt) =
        queue.enqueue(enqueue("stale", Some("turn:stale"), 13))?
    else {
        panic!("expected enqueue");
    };
    let ClaimOutcome::Claimed(stale_claim) = queue.claim(ClaimAttempt {
        lease_owner: "worker-stale".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected stale claim");
    };
    assert_eq!(stale_claim.id, stale_attempt.id);

    let EnqueueOutcome::Enqueued(live_attempt) =
        queue.enqueue(enqueue("live", Some("turn:live"), 21))?
    else {
        panic!("expected enqueue");
    };
    let ClaimOutcome::Claimed(live_claim) = queue.claim(ClaimAttempt {
        lease_owner: "worker-live".to_owned(),
        now: 30,
    })?
    else {
        panic!("expected live claim");
    };
    assert_eq!(live_claim.id, live_attempt.id);

    let EnqueueOutcome::Enqueued(done_attempt) =
        queue.enqueue(enqueue("done", Some("turn:done"), 31))?
    else {
        panic!("expected enqueue");
    };
    let ClaimOutcome::Claimed(done_claim) = queue.claim(ClaimAttempt {
        lease_owner: "worker-done".to_owned(),
        now: 32,
    })?
    else {
        panic!("expected done claim");
    };
    assert_eq!(done_claim.id, done_attempt.id);
    let CompleteOutcome::Completed(_) = queue.complete(CompleteAttempt {
        id: done_attempt.id,
        lease_owner: "worker-done".to_owned(),
        attempt_count: done_claim.attempt_count,
        now: 33,
    })?
    else {
        panic!("expected complete");
    };

    let EnqueueOutcome::Enqueued(failed_attempt) =
        queue.enqueue(enqueue("failed", Some("turn:failed"), 34))?
    else {
        panic!("expected enqueue");
    };
    let ClaimOutcome::Claimed(failed_claim) = queue.claim(ClaimAttempt {
        lease_owner: "worker-failed".to_owned(),
        now: 35,
    })?
    else {
        panic!("expected failed claim");
    };
    assert_eq!(failed_claim.id, failed_attempt.id);
    let FailOutcome::Failed(_) = queue.fail(FailAttempt {
        id: failed_attempt.id,
        lease_owner: "worker-failed".to_owned(),
        attempt_count: failed_claim.attempt_count,
        reason: "fatal".to_owned(),
        now: 36,
    })?
    else {
        panic!("expected fail");
    };

    let EnqueueOutcome::Enqueued(queued_attempt) =
        queue.enqueue(enqueue("queued", Some("turn:queued"), 37))?
    else {
        panic!("expected enqueue");
    };

    let report = queue.cleanup_leases(CleanupAttemptLeases {
        now: 39,
        lease_timeout_secs: 10,
    })?;
    assert_eq!(report.pending, 3);
    assert_eq!(report.running, 1);
    // Two failed rows: the terminal `failed_attempt` plus the retried try that
    // `backoff_attempt` became.
    assert_eq!(report.failed, 2);
    assert_eq!(report.done, 1);
    assert_eq!(report.stale_requeued, 1);
    assert_eq!(
        report.retry_reason_count(AttemptQueueRetryReason::LeaseTimeout),
        1
    );
    assert_eq!(
        report.retry_reason_count(AttemptQueueRetryReason::RetryBackoff),
        1
    );

    let retried_source = queue
        .get(backoff_attempt.id)?
        .expect("retried source persisted");
    assert_eq!(retried_source.state, AttemptState::Failed);
    let paused_retry = queue.get(backoff_retry.id)?.expect("retry row persisted");
    assert_eq!(paused_retry.state, AttemptState::Paused);
    assert_eq!(paused_retry.scheduled_at, Some(80));

    let requeued = queue
        .get(stale_attempt.id)?
        .expect("stale attempt persisted");
    assert_eq!(requeued.state, AttemptState::Queued);
    assert_eq!(requeued.lease_owner, None);
    assert_eq!(
        queue.get(live_attempt.id)?.expect("live attempt").state,
        AttemptState::Leased
    );
    assert_eq!(
        queue.get(done_attempt.id)?.expect("done attempt").state,
        AttemptState::Completed
    );
    assert_eq!(
        queue.get(failed_attempt.id)?.expect("failed attempt").state,
        AttemptState::Failed
    );
    assert_eq!(
        queue.get(queued_attempt.id)?.expect("queued attempt").state,
        AttemptState::Queued
    );

    Ok(())
}

#[test]
fn attempt_queue_cleanup_metrics_have_stable_privacy_preserving_labels() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let (_untouched_dir, untouched_vault) = open_queue();
    let before = vault.diagnostics().attempt_queue_cleanup_snapshot();

    let EnqueueOutcome::Enqueued(attempt) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:metrics"), 10))?
    else {
        panic!("expected enqueue");
    };
    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "worker-secret-owner".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claim");
    };
    assert_eq!(claimed.id, attempt.id);

    queue.cleanup_leases(CleanupAttemptLeases {
        now: 40,
        lease_timeout_secs: 10,
    })?;

    let after = vault.diagnostics().attempt_queue_cleanup_snapshot();
    // The counters belong to this vault, so the delta is exactly this run's.
    assert_eq!(after.runs, before.runs + 1);
    assert_eq!(after.stale_requeued, before.stale_requeued + 1);
    assert!(
        after
            .retry_reasons
            .iter()
            .all(|counter| matches!(counter.reason.as_str(), "lease_timeout" | "retry_backoff"))
    );
    for label in ["lease_timeout", "retry_backoff"] {
        assert_eq!(
            after
                .retry_reasons
                .iter()
                .filter(|counter| counter.reason.as_str() == label)
                .count(),
            1,
        );
    }
    let before_timeout = before
        .retry_reasons
        .iter()
        .find(|counter| counter.reason.as_str() == "lease_timeout")
        .expect("expected exported lease timeout counter");
    let after_timeout = after
        .retry_reasons
        .iter()
        .find(|counter| counter.reason.as_str() == "lease_timeout")
        .expect("expected exported lease timeout counter");
    assert_eq!(after_timeout.count, before_timeout.count + 1);

    // A vault that cleaned nothing keeps its own zeros: a cleanup run on one
    // vault cannot move the number a reader of another vault sees.
    let untouched = untouched_vault
        .diagnostics()
        .attempt_queue_cleanup_snapshot();
    assert_eq!(untouched.runs, 0);
    assert_eq!(untouched.stale_requeued, 0);

    Ok(())
}

#[test]
fn attempt_queue_cleanup_log_span_has_stable_privacy_preserving_fields() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let capture = TelemetryCapture::default();

    let EnqueueOutcome::Enqueued(attempt) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:logs"), 10))?
    else {
        panic!("expected enqueue");
    };
    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "worker-secret-owner".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claim");
    };
    assert_eq!(claimed.id, attempt.id);

    tracing::subscriber::with_default(capture.clone(), || {
        // `tracing` caches one `Interest` per callsite for the whole process, but
        // `with_default` installs a subscriber on THIS thread only. The first
        // thread to reach a callsite is the one that computes that cache, and it
        // computes it from its own thread-local subscriber
        // (`DefaultCallsite::register` -> `Rebuilder::JustOne` ->
        // `dispatcher::get_default`). Several other tests call `cleanup_leases`
        // concurrently with no subscriber attached, so whichever of them wins the
        // race pins these callsites to `Interest::never()` for the rest of the
        // process and nothing below is ever recorded. Emitting once forces the
        // callsites REGISTERED whoever wins, and rebuilding the cache then
        // recomputes them against this thread's subscriber; registration is
        // one-shot, so they cannot be re-poisoned while the assertions run.
        emit_attempt_queue_cleanup_span(
            &CleanupAttemptLeases {
                now: 0,
                lease_timeout_secs: 0,
            },
            &AttemptQueueCleanupReport::default(),
        );
        tracing::callsite::rebuild_interest_cache();
        capture.records.lock().unwrap().clear();

        queue.cleanup_leases(CleanupAttemptLeases {
            now: 40,
            lease_timeout_secs: 10,
        })
    })?;

    let records = capture.records.lock().unwrap();
    let span = records
        .iter()
        .find(|record| record.kind == "span" && record.name == "attempt_queue_cleanup")
        .unwrap_or_else(|| panic!("cleanup span records={records:?}"));
    assert!(span.fields.contains_key("pending"));
    assert!(span.fields.contains_key("running"));
    assert!(span.fields.contains_key("failed"));
    assert!(span.fields.contains_key("done"));
    assert!(span.fields.contains_key("stale_requeued"));
    assert!(span.fields.contains_key("retry_lease_timeout"));
    assert!(span.fields.contains_key("retry_backoff"));

    let captured = records
        .iter()
        .flat_map(|record| {
            std::iter::once(record.name.as_str())
                .chain(record.fields.keys().map(String::as_str))
                .chain(record.fields.values().map(String::as_str))
        })
        .collect::<Vec<_>>()
        .join(" ");
    assert!(!captured.contains("worker-secret-owner"));
    assert!(!captured.contains("payload-10"));
    assert!(!captured.contains("run-10"));
    assert!(!captured.contains("turn:logs"));
    assert!(!captured.contains("claim_extraction"));

    Ok(())
}

#[test]
fn ready_key_round_trips() -> Result<()> {
    let id = AttemptId::from_bytes(&[
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe,
        0x0f,
    ])?;
    let fixtures = [
        (
            42,
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65,
                0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
            ],
        ),
        (
            0x0102_0304_0506_0708,
            [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65,
                0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
            ],
        ),
    ];

    for (ready_at, bytes) in fixtures {
        let (decoded_ready_at, decoded_id) = decode_ready_key(&bytes)?;
        assert_eq!(decoded_ready_at, ready_at);
        assert_eq!(decoded_id, id);
        assert_eq!(ready_key(ready_at, id), bytes);
    }

    Ok(())
}
