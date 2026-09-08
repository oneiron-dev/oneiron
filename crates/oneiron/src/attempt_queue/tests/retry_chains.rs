//! Retry minting, retry_of lineage queryability, and bounded depth counting.

use super::*;

#[test]
fn attempt_queue_retry_mints_a_new_row_and_leaves_the_source_terminal() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(attempt) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:retry"), 10))?
    else {
        panic!("expected enqueue");
    };

    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claimed attempt");
    };
    assert_eq!(claimed.id, attempt.id);
    assert_eq!(claimed.attempt_count, 1);

    let wrong_owner_retry = queue
        .retry(RetryAttempt {
            id: attempt.id,
            lease_owner: "worker-b".to_owned(),
            attempt_count: claimed.attempt_count,
            backoff_until: 100,
            last_error: Some("rate limited".to_owned()),
            now: 25,
        })
        .unwrap_err();
    assert_invalid_transition(wrong_owner_retry, "retry", "leased_by_other");

    let RetryOutcome::Retried(retried) = queue.retry(RetryAttempt {
        id: attempt.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: claimed.attempt_count,
        backoff_until: 100,
        last_error: Some("rate limited".to_owned()),
        now: 30,
    })?;

    // The retry is a DIFFERENT row that carries the immutable payload and
    // provenance forward, links back to the try it replaces, and restarts the
    // per-row lease fence.
    assert_ne!(retried.id, attempt.id);
    assert_eq!(retried.retry_of, Some(attempt.id));
    assert_eq!(retried.state, AttemptState::Scheduled);
    assert_eq!(retried.lease_owner, None);
    assert_eq!(retried.attempt_count, 0);
    assert_eq!(retried.scheduled_at, Some(100));
    assert_eq!(retried.backoff_until, None);
    assert_eq!(retried.last_error, None);
    assert_eq!(retried.claimed_at, None);
    assert_eq!(retried.created_at, 30);
    assert_eq!(retried.updated_at, 30);
    assert_eq!(retried.payload, b"payload-10");
    assert_eq!(retried.run_id.as_deref(), Some("run-10"));
    assert_eq!(retried.dedupe_key.as_deref(), Some("turn:retry"));

    // The source stays queryable as the failed try and can never be reclaimed.
    let source = queue.get(attempt.id)?.expect("source stays point-readable");
    assert_eq!(source.state, AttemptState::Failed);
    assert_eq!(source.last_error.as_deref(), Some("rate limited"));
    assert_eq!(source.lease_owner, None);
    assert_eq!(source.scheduled_at, None);
    assert_eq!(source.backoff_until, None);
    assert_eq!(source.retry_of, None);
    assert_eq!(source.updated_at, 30);
    assert_eq!(source.attempt_count, 1);

    // The advisory dedupe index followed the newest pending member.
    let EnqueueOutcome::Existing(duplicate_pending) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:retry"), 40))?
    else {
        panic!("pending dedupe key should coalesce onto the scheduled retry");
    };
    assert_eq!(duplicate_pending.id, retried.id);

    // Claimable exactly at `scheduled_at`, never one second early.
    assert_eq!(
        queue.claim(ClaimAttempt {
            lease_owner: "worker-b".to_owned(),
            now: 99,
        })?,
        ClaimOutcome::Empty
    );

    let ClaimOutcome::Claimed(second_attempt) = queue.claim(ClaimAttempt {
        lease_owner: "worker-b".to_owned(),
        now: 100,
    })?
    else {
        panic!("expected claim at the scheduled instant");
    };
    assert_eq!(second_attempt.id, retried.id);
    assert_eq!(second_attempt.attempt_count, 1);
    assert_eq!(second_attempt.scheduled_at, None);
    assert_eq!(second_attempt.backoff_until, None);
    assert_eq!(second_attempt.retry_of, Some(attempt.id));
    assert_eq!(second_attempt.payload, b"payload-10");
    assert_eq!(second_attempt.run_id.as_deref(), Some("run-10"));
    assert_eq!(second_attempt.dedupe_key.as_deref(), Some("turn:retry"));

    // The terminal source never re-enters the ready index behind the retry.
    assert_eq!(
        queue.claim(ClaimAttempt {
            lease_owner: "worker-c".to_owned(),
            now: 1_000,
        })?,
        ClaimOutcome::Empty
    );

    Ok(())
}

#[test]
fn attempt_queue_retry_chain_keeps_every_try_independently_queryable() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(root) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:chain"), 10))?
    else {
        panic!("expected enqueue");
    };

    let mut chain = vec![root.id];
    let mut now = 20;
    for _ in 0..3 {
        let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
            lease_owner: "worker-a".to_owned(),
            now,
        })?
        else {
            panic!("expected claim at {now}");
        };
        assert_eq!(claimed.id, *chain.last().expect("chain is never empty"));
        let RetryOutcome::Retried(next) = queue.retry(RetryAttempt {
            id: claimed.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: claimed.attempt_count,
            backoff_until: now + 10,
            last_error: Some(format!("retryable at {now}")),
            now: now + 1,
        })?;
        chain.push(next.id);
        now += 10;
    }

    // Three retries produce four distinct rows in an unambiguous parent chain.
    assert_eq!(chain.len(), 4);
    let unique: std::collections::HashSet<_> = chain.iter().collect();
    assert_eq!(unique.len(), 4);

    for (index, id) in chain.iter().enumerate() {
        let record = queue.get(*id)?.expect("every try stays queryable");
        assert_eq!(
            record.retry_of,
            index.checked_sub(1).map(|prev| chain[prev])
        );
        assert_eq!(record.payload, b"payload-10");
        assert_eq!(record.run_id.as_deref(), Some("run-10"));
        if index + 1 == chain.len() {
            assert_eq!(record.state, AttemptState::Scheduled);
        } else {
            assert_eq!(record.state, AttemptState::Failed);
            assert!(record.last_error.is_some());
        }
    }

    // Every try is attached to the one run, so the run index tracked each mint.
    let run = queue.list_run("run-10")?;
    assert_eq!(run.len(), 4);
    assert_eq!(
        run.iter().map(|record| record.id).collect::<Vec<_>>(),
        chain
    );

    Ok(())
}

#[test]
fn attempt_queue_retry_chain_depth_counts_the_lineage_not_the_lease() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(root) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:depth"), 10))?
    else {
        panic!("expected enqueue");
    };
    // A first try is depth 0: nothing precedes it.
    assert_eq!(queue.retry_chain_depth(root.id)?, 0);

    let mut chain = vec![root.id];
    let mut now = 20;
    for expected_depth in 1..4_u32 {
        let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
            lease_owner: "worker-a".to_owned(),
            now,
        })?
        else {
            panic!("expected claim at {now}");
        };
        let RetryOutcome::Retried(next) = queue.retry(RetryAttempt {
            id: claimed.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: claimed.attempt_count,
            backoff_until: now + 10,
            last_error: Some("retryable".to_owned()),
            now: now + 1,
        })?;
        // The fresh row restarts the lease fence at zero while the lineage
        // keeps counting: that gap is exactly why depth is read from
        // `retry_of` and never from `attempt_count`.
        assert_eq!(claimed.attempt_count, 1);
        assert_eq!(next.attempt_count, 0);
        assert_eq!(queue.retry_chain_depth(next.id)?, expected_depth);
        chain.push(next.id);
        now += 10;
    }

    // Each ancestor keeps its own depth — the walk is per row, not per chain.
    for (index, id) in chain.iter().enumerate() {
        let expected = u32::try_from(index).expect("a four-row chain fits");
        assert_eq!(queue.retry_chain_depth(*id)?, expected);
    }

    Ok(())
}

#[test]
fn attempt_queue_retry_chain_depth_saturates_at_the_bounded_limit() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(root) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:bound"), 10))?
    else {
        panic!("expected enqueue");
    };

    // A lineage longer than any backoff curve could ever read. The walk stops
    // spending point reads at the limit and reports it, rather than growing
    // with the row set — a bound, not an error.
    let mut rows = Vec::new();
    let mut template = root.clone();
    let mut parent = root.id;
    for index in 0..RETRY_CHAIN_DEPTH_LIMIT + 6 {
        template.id = synthetic_attempt_id(index);
        template.retry_of = Some(parent);
        parent = template.id;
        rows.push(template.clone());
    }
    put_raw_attempts(&vault, &rows)?;

    assert_eq!(queue.retry_chain_depth(parent)?, RETRY_CHAIN_DEPTH_LIMIT);
    // A short lineage inside that same store is still counted exactly.
    assert_eq!(queue.retry_chain_depth(synthetic_attempt_id(0))?, 1);
    assert_eq!(queue.retry_chain_depth(synthetic_attempt_id(3))?, 4);

    Ok(())
}

#[test]
fn attempt_queue_retry_chain_depth_fails_closed_on_a_corrupt_lineage() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(root) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:corrupt"), 10))?
    else {
        panic!("expected enqueue");
    };

    // A link naming a row this queue does not hold. Counting it as the end of
    // the chain would silently restart a caller's backoff at its first rung.
    let orphan_id = synthetic_attempt_id(1);
    let mut orphan = root.clone();
    orphan.id = orphan_id;
    orphan.retry_of = Some(synthetic_attempt_id(404));
    put_raw_attempts(&vault, &[orphan])?;
    assert!(matches!(
        queue.retry_chain_depth(orphan_id).unwrap_err(),
        Error::InvalidAttemptQueueRecord(ERR_RETRY_CHAIN_MISSING_ROW)
    ));
    // An id this queue never held at all is that same broken read.
    assert!(matches!(
        queue
            .retry_chain_depth(synthetic_attempt_id(404))
            .unwrap_err(),
        Error::InvalidAttemptQueueRecord(ERR_RETRY_CHAIN_MISSING_ROW)
    ));

    // A lineage that returns to a row already on the walk.
    let first_id = synthetic_attempt_id(2);
    let second_id = synthetic_attempt_id(3);
    let mut first = root.clone();
    first.id = first_id;
    first.retry_of = Some(second_id);
    let mut second = root.clone();
    second.id = second_id;
    second.retry_of = Some(first_id);
    put_raw_attempts(&vault, &[first, second])?;
    assert!(matches!(
        queue.retry_chain_depth(first_id).unwrap_err(),
        Error::InvalidAttemptQueueRecord(ERR_RETRY_CHAIN_CYCLE)
    ));

    // A row naming ITSELF is the shortest cycle there is.
    let selfish_id = synthetic_attempt_id(4);
    let mut selfish = root.clone();
    selfish.id = selfish_id;
    selfish.retry_of = Some(selfish_id);
    put_raw_attempts(&vault, &[selfish])?;
    assert!(matches!(
        queue.retry_chain_depth(selfish_id).unwrap_err(),
        Error::InvalidAttemptQueueRecord(ERR_RETRY_CHAIN_CYCLE)
    ));

    // None of it reached the honest row beside them.
    assert_eq!(queue.retry_chain_depth(root.id)?, 0);

    Ok(())
}

#[test]
fn attempt_queue_retry_chain_depth_fails_closed_on_a_cross_chain_link() -> Result<()> {
    type AttemptMutation = fn(&mut AttemptRecord);
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(root) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:cross"), 10))?
    else {
        panic!("expected enqueue");
    };

    // One case per field both `retry_of` writers copy verbatim from a source
    // row to the row superseding it. Each parent is otherwise a perfect clone
    // of its child, so the single mutated field is the only thing the walk can
    // be rejecting — a link naming an EXISTING but unrelated attempt.
    let cases: [(&str, AttemptMutation); 6] = [
        ("kind", |record| record.kind = "dreamer_runner".to_owned()),
        ("payload", |record| {
            record.payload = b"payload-of-another-attempt".to_vec();
        }),
        ("task_ref", |record| {
            record.task_ref = Some("task:other".to_owned());
        }),
        ("run_id", |record| {
            record.run_id = Some("run-other".to_owned());
        }),
        ("dedupe_key", |record| {
            record.dedupe_key = Some("turn:other".to_owned());
        }),
        // Same dedupe key, different scope: two actors sharing one client key
        // hold disjoint attempts, so a link across them is no lineage either.
        ("dedupe_actor_ref", |record| {
            record.dedupe_actor_ref = Some("actor:other".to_owned());
        }),
    ];

    for (index, (field, mutate)) in cases.into_iter().enumerate() {
        let step = u32::try_from(index).expect("six cases fit") * 2;
        let mut parent = root.clone();
        parent.id = synthetic_attempt_id(step + 10);
        mutate(&mut parent);
        let child_id = synthetic_attempt_id(step + 11);
        let mut child = root.clone();
        child.id = child_id;
        child.retry_of = Some(parent.id);
        put_raw_attempts(&vault, &[parent, child])?;

        // Counting this hop would hand the caller a backoff rung measured on
        // somebody else's history, so it is corruption, not a short chain.
        let err = queue.retry_chain_depth(child_id).expect_err(field);
        assert!(
            matches!(
                err,
                Error::InvalidAttemptQueueRecord(ERR_RETRY_CHAIN_MISMATCH)
            ),
            "a differing {field} must fail closed, got {err:?}"
        );
    }

    // None of it reached the honest row beside them.
    assert_eq!(queue.retry_chain_depth(root.id)?, 0);

    Ok(())
}

#[test]
fn attempt_queue_retry_chain_depth_counts_real_successors_but_not_a_deep_cross_link() -> Result<()>
{
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(root) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:deep"), 10))?
    else {
        panic!("expected enqueue");
    };

    // ANTI-OVER-MATCH: a genuine successor differs from its source on state,
    // lease owner, lease counter, timestamps and the stamped failure reason.
    // The identity check must ignore every one of those and still count.
    let mut now = 20;
    let mut head = root.id;
    for expected_depth in 1..4_u32 {
        let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
            lease_owner: "worker-a".to_owned(),
            now,
        })?
        else {
            panic!("expected claim at {now}");
        };
        let RetryOutcome::Retried(next) = queue.retry(RetryAttempt {
            id: claimed.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: claimed.attempt_count,
            backoff_until: now + 10,
            last_error: Some("retryable".to_owned()),
            now: now + 1,
        })?;
        assert_eq!(queue.retry_chain_depth(next.id)?, expected_depth);
        head = next.id;
        now += 10;
    }
    assert_eq!(queue.retry_chain_depth(head)?, 3);

    // A cross-chain link buried DEEP in an otherwise honest lineage: three
    // truthful hops, then one that leaves the attempt entirely. Validating
    // only the first hop would have counted the whole chain.
    let foreign_id = synthetic_attempt_id(20);
    let mut foreign = root.clone();
    foreign.id = foreign_id;
    foreign.run_id = Some("run-foreign".to_owned());
    let mut rows = vec![foreign];
    let mut parent = foreign_id;
    for index in 0..4_u32 {
        let mut row = root.clone();
        row.id = synthetic_attempt_id(21 + index);
        row.retry_of = Some(parent);
        parent = row.id;
        rows.push(row);
    }
    put_raw_attempts(&vault, &rows)?;

    assert!(matches!(
        queue.retry_chain_depth(parent).unwrap_err(),
        Error::InvalidAttemptQueueRecord(ERR_RETRY_CHAIN_MISMATCH)
    ));
    // The honest lineage beside it still counts exactly.
    assert_eq!(queue.retry_chain_depth(head)?, 3);

    Ok(())
}

#[test]
fn attempt_queue_retry_omitting_a_reason_stamps_a_stable_token() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(attempt) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:no-reason"), 10))?
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

    let RetryOutcome::Retried(retried) = queue.retry(RetryAttempt {
        id: attempt.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: claimed.attempt_count,
        backoff_until: 40,
        last_error: None,
        now: 30,
    })?;
    assert_eq!(retried.state, AttemptState::Scheduled);

    // A `Failed` row must carry a reason; the source is finalized either way.
    let source = queue.get(attempt.id)?.expect("source stays readable");
    assert_eq!(source.state, AttemptState::Failed);
    assert_eq!(source.last_error.as_deref(), Some(RETRY_REASON_UNSPECIFIED));

    Ok(())
}

#[test]
fn attempt_queue_retry_of_a_missing_lease_writes_nothing() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(attempt) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:atomic"), 10))?
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

    // A rejected retry must leave neither a half-finalized source nor an
    // orphan retry row: the whole transition is one transaction.
    let stale = queue
        .retry(RetryAttempt {
            id: attempt.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: claimed.attempt_count + 1,
            backoff_until: 40,
            last_error: Some("retryable".to_owned()),
            now: 30,
        })
        .unwrap_err();
    assert_invalid_transition(stale, "retry", "stale_attempt");

    let records = queue.list()?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id, attempt.id);
    assert_eq!(records[0].state, AttemptState::Leased);
    assert_eq!(records[0].updated_at, 20);

    Ok(())
}
