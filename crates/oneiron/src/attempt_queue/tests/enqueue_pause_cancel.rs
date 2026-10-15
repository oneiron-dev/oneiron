//! Enqueue persistence, run index, dedupe keys, and pause/resume/cancel/interrupt lifecycle.

use super::*;

#[test]
fn list_run_rejects_a_dangling_run_index_row() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(enqueue("indexed-worker", None, 10))?
    else {
        panic!("expected indexed attempt");
    };

    // This bypasses the index-maintaining removal seam to model actual index
    // corruption. `list_run` must fail closed rather than silently dropping
    // the dangling row.
    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .attempt_records
        .delete(&mut wtxn, attempt.id.as_bytes())?;
    wtxn.commit()?;

    assert!(matches!(
        queue.list_run("run-10"),
        Err(Error::CorruptedIndex("attempt run index"))
    ));
    Ok(())
}

#[test]
fn attempt_queue_pause_and_cancel_reject_leased_attempts() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let EnqueueOutcome::Enqueued(attempt) =
        queue.enqueue(enqueue("claim_extraction", Some("leased"), 10))?
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

    let pause = queue
        .intervene(InterveneAttempt {
            id: attempt.id,
            kind: AttemptInterventionKind::Pause,
            actor: "dashboard".to_owned(),
            note: None,
            now: 30,
        })
        .unwrap_err();
    assert_invalid_transition(pause, "pause", "leased");

    let cancel = queue
        .intervene(InterveneAttempt {
            id: attempt.id,
            kind: AttemptInterventionKind::Cancel,
            actor: "dashboard".to_owned(),
            note: None,
            now: 31,
        })
        .unwrap_err();
    assert_invalid_transition(cancel, "cancel", "leased");

    let CompleteOutcome::Completed(completed) = queue.complete(CompleteAttempt {
        id: attempt.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: claimed.attempt_count,
        now: 40,
    })?
    else {
        panic!("expected leased attempt to remain completable");
    };
    assert_eq!(completed.state, AttemptState::Completed);
    assert!(completed.events.is_empty());

    Ok(())
}

#[test]
fn attempt_queue_cancel_is_terminal_and_clears_dedupe() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let EnqueueOutcome::Enqueued(attempt) =
        queue.enqueue(enqueue("claim_extraction", Some("same"), 10))?
    else {
        panic!("expected enqueue");
    };

    let cancelled = queue.intervene(InterveneAttempt {
        id: attempt.id,
        kind: AttemptInterventionKind::Cancel,
        actor: "dashboard".to_owned(),
        note: Some("stop branch".to_owned()),
        now: 20,
    })?;

    assert_eq!(cancelled.effect, AttemptInterventionEffect::Cancelled);
    assert_eq!(cancelled.record.state, AttemptState::Cancelled);
    assert_eq!(cancelled.record.events.len(), 1);
    assert_eq!(
        cancelled.record.events[0].kind,
        AttemptInterventionKind::Cancel
    );
    assert!(matches!(
        queue.claim(ClaimAttempt {
            lease_owner: "worker-a".to_owned(),
            now: 21,
        })?,
        ClaimOutcome::Empty
    ));
    let EnqueueOutcome::Enqueued(replacement) =
        queue.enqueue(enqueue("claim_extraction", Some("same"), 22))?
    else {
        panic!("expected replacement enqueue after cancelled dedupe");
    };
    assert_ne!(replacement.id, attempt.id);

    let repeated_cancel = queue.intervene(InterveneAttempt {
        id: attempt.id,
        kind: AttemptInterventionKind::Cancel,
        actor: "dashboard".to_owned(),
        note: None,
        now: 23,
    })?;
    assert_eq!(
        repeated_cancel.effect,
        AttemptInterventionEffect::AlreadyCancelled
    );
    assert_eq!(repeated_cancel.record.events.len(), 1);
    assert_eq!(repeated_cancel.record.updated_at, 20);

    Ok(())
}

#[test]
fn attempt_queue_enqueue_uses_blake3_advisory_dedupe_key() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(attempt) =
        queue.enqueue(enqueue("claim_extraction", Some("same"), 10))?
    else {
        panic!("expected enqueue");
    };

    assert_eq!(
        dedupe_index_key("claim_extraction", "same"),
        DEDUPE_KEY_V1_CLAIM_EXTRACTION_SAME,
        "the v1 dedupe key is an on-disk LMDB key: a new derivation orphans every live row"
    );
    assert_ne!(
        DEDUPE_KEY_V1_CLAIM_EXTRACTION_SAME.as_slice(),
        LEGACY_DEDUPE_KEY_CLAIM_EXTRACTION_SAME
    );

    let rtxn = vault.store.env.read_txn()?;
    let stored_id = vault
        .store
        .attempt_dedupe
        .get(&rtxn, &DEDUPE_KEY_V1_CLAIM_EXTRACTION_SAME)?
        .expect("dedupe row");
    assert_eq!(AttemptId::from_bytes(&stored_id)?, attempt.id);

    Ok(())
}

#[test]
fn attempt_queue_dedupe_key_is_scoped_by_kind() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(first) =
        queue.enqueue(enqueue("claim_extraction", Some("same"), 10))?
    else {
        panic!("expected first enqueue");
    };
    let EnqueueOutcome::Enqueued(second) =
        queue.enqueue(enqueue("signal_extraction", Some("same"), 20))?
    else {
        panic!("expected separate kind-scoped enqueue");
    };
    let EnqueueOutcome::Existing(third) =
        queue.enqueue(enqueue("claim_extraction", Some("same"), 30))?
    else {
        panic!("expected existing enqueue for matching kind");
    };

    assert_ne!(second.id, first.id);
    assert_eq!(third.id, first.id);
    assert_eq!(third.kind, "claim_extraction");

    Ok(())
}
