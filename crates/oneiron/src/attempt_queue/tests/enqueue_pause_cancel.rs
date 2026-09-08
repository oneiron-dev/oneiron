//! Enqueue persistence, run index, dedupe keys, and pause/resume/cancel/interrupt lifecycle.

use super::*;

#[test]
fn attempt_queue_enqueue_persists_required_fields() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(attempt) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:1"), 10))?
    else {
        panic!("expected new attempt");
    };

    let persisted = queue.get(attempt.id)?.expect("persisted attempt");
    assert_eq!(persisted.kind, "claim_extraction");
    assert_eq!(persisted.payload, b"payload-10");
    assert_eq!(persisted.state, AttemptState::Queued);
    assert_eq!(persisted.lease_owner, None);
    assert_eq!(persisted.attempt_count, 0);
    assert_eq!(persisted.backoff_until, None);
    assert_eq!(persisted.last_error, None);
    assert_eq!(persisted.run_id.as_deref(), Some("run-10"));
    assert_eq!(persisted.dedupe_key.as_deref(), Some("turn:1"));
    assert_eq!(persisted.created_at, 10);
    assert_eq!(persisted.updated_at, 10);
    assert!(persisted.events.is_empty());

    Ok(())
}

#[test]
fn run_index_scopes_list_run_and_run_tree_without_returning_other_runs() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let mut later_input = enqueue("indexed-worker", None, 30);
    later_input.run_id = Some("run-indexed".to_owned());
    let EnqueueOutcome::Enqueued(later) = queue.enqueue(later_input)? else {
        panic!("expected later indexed attempt");
    };
    let other = queue.enqueue(enqueue("other-worker", None, 5))?;
    let mut earlier_input = enqueue("indexed-worker", None, 20);
    earlier_input.run_id = Some("run-indexed".to_owned());
    let EnqueueOutcome::Enqueued(earlier) = queue.enqueue(earlier_input)? else {
        panic!("expected earlier indexed attempt");
    };
    assert!(matches!(other, EnqueueOutcome::Enqueued(_)));

    let indexed = queue.list_run("run-indexed")?;
    let baseline: Vec<AttemptRecord> = queue
        .list()?
        .into_iter()
        .filter(|record| record.run_id.as_deref() == Some("run-indexed"))
        .collect();
    assert_eq!(indexed, baseline);
    assert_eq!(
        indexed.iter().map(|record| record.id).collect::<Vec<_>>(),
        vec![earlier.id, later.id]
    );

    let tree = crate::RunTreeAdapter::new(&vault).read_run("run-indexed")?;
    assert!(tree.repairs.is_empty());
    assert_eq!(
        tree.roots
            .iter()
            .map(|root| root.attempt_id.clone())
            .collect::<Vec<_>>(),
        vec![
            crate::entity_id::bytes_to_hex_lower(earlier.id.as_bytes()),
            crate::entity_id::bytes_to_hex_lower(later.id.as_bytes()),
        ]
    );
    Ok(())
}

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
fn attempt_queue_enqueue_is_idempotent_for_dedupe_key() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(first) =
        queue.enqueue(enqueue("claim_extraction", Some("same"), 10))?
    else {
        panic!("expected first enqueue");
    };
    let EnqueueOutcome::Existing(second) =
        queue.enqueue(enqueue("claim_extraction", Some("same"), 20))?
    else {
        panic!("expected existing enqueue");
    };

    assert_eq!(second.id, first.id);
    assert_eq!(second.payload, first.payload);
    assert_eq!(second.created_at, 10);

    Ok(())
}

#[test]
fn attempt_queue_pause_resume_are_durable_and_idempotent() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let EnqueueOutcome::Enqueued(attempt) =
        queue.enqueue(enqueue("claim_extraction", Some("same"), 10))?
    else {
        panic!("expected enqueue");
    };

    let paused = queue.intervene(InterveneAttempt {
        id: attempt.id,
        kind: AttemptInterventionKind::Pause,
        actor: "dashboard".to_owned(),
        note: Some("hold branch".to_owned()),
        now: 20,
    })?;

    assert_eq!(paused.effect, AttemptInterventionEffect::Paused);
    assert_eq!(paused.record.state, AttemptState::Paused);
    assert_eq!(paused.record.lease_owner, None);
    assert_eq!(paused.record.events.len(), 1);
    assert_eq!(paused.record.events[0].sequence, 1);
    assert_eq!(paused.record.events[0].kind, AttemptInterventionKind::Pause);
    assert_eq!(paused.record.events[0].actor, "dashboard");
    assert_eq!(paused.record.events[0].note.as_deref(), Some("hold branch"));
    assert!(matches!(
        queue.claim(ClaimAttempt {
            lease_owner: "worker-b".to_owned(),
            now: 21,
        })?,
        ClaimOutcome::Empty
    ));
    let EnqueueOutcome::Existing(existing) =
        queue.enqueue(enqueue("claim_extraction", Some("same"), 22))?
    else {
        panic!("expected paused dedupe hit");
    };
    assert_eq!(existing.id, attempt.id);

    let repeated_pause = queue.intervene(InterveneAttempt {
        id: attempt.id,
        kind: AttemptInterventionKind::Pause,
        actor: "dashboard".to_owned(),
        note: Some("hold branch".to_owned()),
        now: 23,
    })?;
    assert_eq!(
        repeated_pause.effect,
        AttemptInterventionEffect::AlreadyPaused
    );
    assert_eq!(repeated_pause.record.events.len(), 1);
    assert_eq!(repeated_pause.record.updated_at, 20);

    let resumed = queue.intervene(InterveneAttempt {
        id: attempt.id,
        kind: AttemptInterventionKind::Resume,
        actor: "dashboard".to_owned(),
        note: None,
        now: 30,
    })?;
    assert_eq!(resumed.effect, AttemptInterventionEffect::Resumed);
    assert_eq!(resumed.record.state, AttemptState::Queued);
    assert_eq!(resumed.record.events.len(), 2);
    assert_eq!(resumed.record.events[1].sequence, 2);
    assert_eq!(
        resumed.record.events[1].kind,
        AttemptInterventionKind::Resume
    );

    let repeated_resume = queue.intervene(InterveneAttempt {
        id: attempt.id,
        kind: AttemptInterventionKind::Resume,
        actor: "dashboard".to_owned(),
        note: None,
        now: 31,
    })?;
    assert_eq!(
        repeated_resume.effect,
        AttemptInterventionEffect::AlreadyResumed
    );
    assert_eq!(repeated_resume.record.events.len(), 2);
    assert_eq!(repeated_resume.record.updated_at, 30);

    let ClaimOutcome::Claimed(reclaimed) = queue.claim(ClaimAttempt {
        lease_owner: "worker-b".to_owned(),
        now: 40,
    })?
    else {
        panic!("expected resumed claim");
    };
    assert_eq!(reclaimed.id, attempt.id);
    assert_eq!(reclaimed.attempt_count, 1);

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
fn attempt_queue_interrupt_records_event_without_changing_claimability() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(enqueue("claim_extraction", None, 10))?
    else {
        panic!("expected enqueue");
    };

    let interrupted = queue.intervene(InterveneAttempt {
        id: attempt.id,
        kind: AttemptInterventionKind::Interrupt,
        actor: "dashboard".to_owned(),
        note: Some("inject observation".to_owned()),
        now: 20,
    })?;

    assert_eq!(interrupted.effect, AttemptInterventionEffect::Interrupted);
    assert_eq!(interrupted.record.state, AttemptState::Queued);
    assert_eq!(interrupted.record.events.len(), 1);
    assert_eq!(
        interrupted.record.events[0].kind,
        AttemptInterventionKind::Interrupt
    );
    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".to_owned(),
        now: 21,
    })?
    else {
        panic!("expected interrupted queued attempt to remain claimable");
    };
    assert_eq!(claimed.id, attempt.id);
    assert_eq!(claimed.events.len(), 1);

    Ok(())
}

#[test]
fn attempt_queue_intervention_events_keep_bounded_tail() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(enqueue("claim_extraction", None, 10))?
    else {
        panic!("expected enqueue");
    };

    let mut latest = None;
    for index in 0..(MAX_ATTEMPT_EVENTS_PER_RECORD + 2) {
        latest = Some(queue.intervene(InterveneAttempt {
            id: attempt.id,
            kind: AttemptInterventionKind::Interrupt,
            actor: "dashboard".to_owned(),
            note: Some(format!("event-{index}")),
            now: 20 + index as u64,
        })?);
    }
    let latest = latest.expect("intervention outcome");
    assert_eq!(latest.record.events.len(), MAX_ATTEMPT_EVENTS_PER_RECORD);
    assert_eq!(latest.record.events.first().unwrap().sequence, 3);
    assert_eq!(
        latest.record.events.last().unwrap().sequence,
        (MAX_ATTEMPT_EVENTS_PER_RECORD + 2) as u64
    );

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

    let index_key = dedupe_index_key("claim_extraction", "same");
    assert_eq!(index_key.len(), DEDUPE_INDEX_KEY_LEN);
    assert_ne!(index_key.as_slice(), b"\0\x10claim_extractionsame");

    let rtxn = vault.store.env.read_txn()?;
    let stored_id = vault
        .store
        .attempt_dedupe
        .get(&rtxn, &index_key)?
        .expect("dedupe row");
    assert_eq!(AttemptId::from_bytes(&stored_id)?, attempt.id);

    Ok(())
}

#[test]
fn attempt_queue_enqueue_self_heals_legacy_dedupe_index_key() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(attempt) =
        queue.enqueue(enqueue("claim_extraction", Some("same"), 10))?
    else {
        panic!("expected enqueue");
    };
    let blake3_key = dedupe_index_key("claim_extraction", "same");
    let legacy_key = legacy_dedupe_index_key("claim_extraction", "same");
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.attempt_dedupe.delete(&mut wtxn, &blake3_key)?;
        vault
            .store
            .attempt_dedupe
            .put(&mut wtxn, &legacy_key, attempt.id.as_bytes())?;
        wtxn.commit()?;
    }

    let EnqueueOutcome::Existing(existing) =
        queue.enqueue(enqueue("claim_extraction", Some("same"), 20))?
    else {
        panic!("expected legacy dedupe hit");
    };
    assert_eq!(existing.id, attempt.id);

    let rtxn = vault.store.env.read_txn()?;
    let stored_id = vault
        .store
        .attempt_dedupe
        .get(&rtxn, &blake3_key)?
        .expect("self-healed BLAKE3 dedupe row");
    assert_eq!(AttemptId::from_bytes(&stored_id)?, attempt.id);
    assert!(
        vault
            .store
            .attempt_dedupe
            .get(&rtxn, &legacy_key)?
            .is_none()
    );

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
