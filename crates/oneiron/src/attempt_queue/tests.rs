use super::*;
use crate::{Vault, VaultConfig};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct TelemetryCapture {
    records: Arc<Mutex<Vec<CapturedTelemetry>>>,
}

#[derive(Debug)]
struct CapturedTelemetry {
    kind: &'static str,
    name: String,
    fields: BTreeMap<String, String>,
}

impl tracing::Subscriber for TelemetryCapture {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn register_callsite(
        &self,
        _metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::always()
    }

    fn max_level_hint(&self) -> Option<tracing::metadata::LevelFilter> {
        Some(tracing::metadata::LevelFilter::TRACE)
    }

    fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let mut fields = BTreeMap::new();
        attrs.record(&mut TelemetryVisitor(&mut fields));
        self.records.lock().unwrap().push(CapturedTelemetry {
            kind: "span",
            name: attrs.metadata().name().to_owned(),
            fields,
        });
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = BTreeMap::new();
        event.record(&mut TelemetryVisitor(&mut fields));
        self.records.lock().unwrap().push(CapturedTelemetry {
            kind: "event",
            name: event.metadata().name().to_owned(),
            fields,
        });
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

struct TelemetryVisitor<'a>(&'a mut BTreeMap<String, String>);

impl tracing::field::Visit for TelemetryVisitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
}

fn open_queue() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::device())
}

fn enqueue(kind: &str, dedupe_key: Option<&str>, now: u64) -> EnqueueAttempt {
    EnqueueAttempt {
        kind: kind.to_owned(),
        payload: format!("payload-{now}").into_bytes(),
        dedupe_key: dedupe_key.map(str::to_owned),
        run_id: Some(format!("run-{now}")),
        now,
    }
}

fn assert_invalid_transition(err: Error, action: &'static str, state: &'static str) {
    assert!(matches!(
        err,
        Error::InvalidAttemptQueueTransition {
            action: got_action,
            state: got_state,
        } if got_action == action && got_state == state
    ));
}

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

        let RetryOutcome::Retried(_) = queue.retry(RetryAttempt {
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
        assert_eq!(second_attempt.id, attempt.id);
        assert_eq!(
            second_attempt.attempt_count,
            first_attempt.attempt_count + 1
        );
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

#[test]
fn attempt_queue_transitions_retry_preserves_payload_provenance_and_backoff() -> Result<()> {
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
    assert_eq!(retried.id, attempt.id);
    assert_eq!(retried.state, AttemptState::Queued);
    assert_eq!(retried.lease_owner, None);
    assert_eq!(retried.attempt_count, 1);
    assert_eq!(retried.backoff_until, Some(100));
    assert_eq!(retried.last_error.as_deref(), Some("rate limited"));
    assert_eq!(retried.payload, b"payload-10");
    assert_eq!(retried.run_id.as_deref(), Some("run-10"));
    assert_eq!(retried.dedupe_key.as_deref(), Some("turn:retry"));

    let EnqueueOutcome::Existing(duplicate_pending) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:retry"), 40))?
    else {
        panic!("pending dedupe key should coalesce");
    };
    assert_eq!(duplicate_pending.id, attempt.id);

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
        panic!("expected claim after backoff");
    };
    assert_eq!(second_attempt.id, attempt.id);
    assert_eq!(second_attempt.attempt_count, 2);
    assert_eq!(second_attempt.backoff_until, None);
    assert_eq!(second_attempt.last_error.as_deref(), Some("rate limited"));
    assert_eq!(second_attempt.payload, b"payload-10");
    assert_eq!(second_attempt.run_id.as_deref(), Some("run-10"));
    assert_eq!(second_attempt.dedupe_key.as_deref(), Some("turn:retry"));

    Ok(())
}

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

    assert_eq!(
        queue.claim(ClaimAttempt {
            lease_owner: "worker-a".to_owned(),
            now: 20,
        })?,
        ClaimOutcome::Empty
    );

    let index_key = dedupe_index_key("claim_extraction", "turn:missing");
    let second_index_key = dedupe_index_key("claim_extraction", "turn:missing-too");
    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(vault.store.attempt_ready.iter(&rtxn)?.next().is_none());
        assert!(vault.store.attempt_dedupe.get(&rtxn, &index_key)?.is_none());
        assert!(
            vault
                .store
                .attempt_dedupe
                .get(&rtxn, &second_index_key)?
                .is_none()
        );
    }

    let EnqueueOutcome::Enqueued(replacement) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:missing"), 30))?
    else {
        panic!("expected stale dedupe key to be reusable");
    };
    assert_ne!(replacement.id, first.id);

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
        Error::InvalidAttemptQueueRecord("job_records key/id mismatch")
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
        Error::InvalidAttemptQueueRecord("leased attempt must have a lease owner")
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
        Error::InvalidAttemptQueueRecord(ERR_LEASE_TIMEOUT_ZERO)
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
    let RetryOutcome::Retried(_) = queue.retry(RetryAttempt {
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
        id: backoff_attempt.id,
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
    assert_eq!(report.failed, 1);
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
    let before = attempt_queue_cleanup_metrics_snapshot();

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

    let after = attempt_queue_cleanup_metrics_snapshot();
    assert!(after.runs > before.runs);
    assert!(after.stale_requeued > before.stale_requeued);
    let labels = after
        .retry_reasons
        .iter()
        .map(|counter| counter.reason.as_str())
        .collect::<Vec<_>>();
    assert_eq!(labels, ["lease_timeout", "retry_backoff"]);
    assert!(
        after.retry_reasons[AttemptQueueRetryReason::LeaseTimeout.metric_index()].count
            > before.retry_reasons[AttemptQueueRetryReason::LeaseTimeout.metric_index()].count
    );

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
    let id = AttemptId::now();
    let key = ready_key(42, id);
    assert_eq!(decode_ready_key(&key)?, (42, id));
    Ok(())
}

// ─── ONE-1737 · ARCH-0053 §3 attempt-alive pack manifest ────────────────

fn skill_entry(reference: &str, version: &str, at: u64) -> ManifestEntry {
    ManifestEntry::new(ManifestKind::Skill, reference, version, at)
}

fn enqueued(queue: &AttemptQueue<'_>, now: u64) -> Result<AttemptRecord> {
    match queue.enqueue(enqueue("pack", None, now))? {
        EnqueueOutcome::Enqueued(record) => Ok(record),
        EnqueueOutcome::Existing(record) => Ok(record),
    }
}

/// The pack is ALIVE: the manifest grows across the pending states and every
/// earlier row survives verbatim (§3, r5 — the one-and-done reading is
/// rejected).
#[test]
fn manifest_appends_across_the_live_attempt_and_never_mutates() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let attempt = enqueued(&queue, 10)?;

    let at_t0 = queue.append_manifest_entry(attempt.id, skill_entry("index", "1", 11))?;
    let ClaimOutcome::Claimed(_) = queue.claim(ClaimAttempt {
        lease_owner: "worker".to_owned(),
        now: 12,
    })?
    else {
        panic!("expected claim");
    };
    let at_mid = queue.append_manifest_entry(attempt.id, skill_entry("pdf", "3", 13))?;

    assert_eq!(at_t0.manifest().len(), 1);
    assert_eq!(at_mid.manifest().len(), 2);
    assert_eq!(
        at_mid.manifest()[0],
        at_t0.manifest()[0],
        "the t0 row survives the mid-run append verbatim"
    );
    assert_eq!(at_mid.manifest()[1].wire_form(), "pdf@3");
    assert_eq!(
        queue.get(attempt.id)?.expect("row persists").manifest(),
        at_mid.manifest(),
        "the manifest is durable, not in-memory"
    );
    Ok(())
}

/// A paused attempt is still live — its pack can still pull.
#[test]
fn manifest_appends_on_a_paused_attempt() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let attempt = enqueued(&queue, 10)?;
    queue.intervene(InterveneAttempt {
        id: attempt.id,
        kind: AttemptInterventionKind::Pause,
        actor: "operator".to_owned(),
        note: None,
        now: 11,
    })?;

    let paused = queue.append_manifest_entry(attempt.id, skill_entry("index", "1", 12))?;

    assert_eq!(paused.state, AttemptState::Paused);
    assert_eq!(paused.manifest().len(), 1);
    Ok(())
}

/// Every terminal state refuses: a closed attempt's manifest is the evidence
/// its terminal receipt already projected, so appending would rewrite history.
#[test]
fn manifest_door_refuses_every_terminal_state() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let completed = enqueued(&queue, 10)?;
    let ClaimOutcome::Claimed(leased) = queue.claim(ClaimAttempt {
        lease_owner: "worker".to_owned(),
        now: 11,
    })?
    else {
        panic!("expected claim");
    };
    queue.complete(CompleteAttempt {
        id: completed.id,
        lease_owner: "worker".to_owned(),
        attempt_count: leased.attempt_count,
        now: 12,
    })?;

    let cancelled = enqueued(&queue, 20)?;
    queue.intervene(InterveneAttempt {
        id: cancelled.id,
        kind: AttemptInterventionKind::Cancel,
        actor: "operator".to_owned(),
        note: None,
        now: 21,
    })?;

    for (id, state) in [(completed.id, "completed"), (cancelled.id, "cancelled")] {
        let error = queue
            .append_manifest_entry(id, skill_entry("late", "9", 30))
            .expect_err("a terminal attempt refuses manifest appends");
        assert!(
            matches!(
                error,
                Error::InvalidAttemptQueueTransition {
                    action: "append_manifest_entry",
                    state: observed,
                } if observed == state
            ),
            "expected a typed refusal naming {state}, got {error:?}"
        );
    }
    Ok(())
}

/// The append door does not touch `updated_at`: that field is the lease-expiry
/// clock, and turning a pack load into a lease heartbeat would silently change
/// reclaim timing.
#[test]
fn manifest_append_leaves_the_lease_clock_alone() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let attempt = enqueued(&queue, 10)?;

    let after = queue.append_manifest_entry(attempt.id, skill_entry("index", "1", 999))?;

    assert_eq!(after.updated_at, attempt.updated_at);
    Ok(())
}

/// The cap REFUSES; it never drains. This is the deliberate divergence from
/// `MAX_ATTEMPT_EVENTS_PER_RECORD`, whose drain would silently violate the
/// append-only invariant.
#[test]
fn manifest_refuses_at_the_cap_instead_of_dropping_the_oldest_row() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let attempt = enqueued(&queue, 10)?;

    // Seed a full manifest through the record path (appending 4096 rows one
    // door call at a time is a needless minute of LMDB writes).
    let mut record = queue.get(attempt.id)?.expect("row persists");
    record.manifest = (0..MAX_ATTEMPT_MANIFEST_ENTRIES)
        .map(|index| skill_entry(&format!("skill-{index}"), "1", 11))
        .collect();
    let first = record.manifest[0].clone();
    let encoded = encode_record(&record)?;
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .attempt_records
            .put(wtxn, record.id.as_bytes(), &encoded)?;
        Ok(())
    })?;

    let error = queue
        .append_manifest_entry(attempt.id, skill_entry("overflow", "1", 12))
        .expect_err("a full manifest refuses");

    assert!(matches!(
        error,
        Error::InvalidAttemptQueueRecord(ERR_MANIFEST_FULL)
    ));
    let after = queue.get(attempt.id)?.expect("row persists");
    assert_eq!(
        after.manifest().len(),
        MAX_ATTEMPT_MANIFEST_ENTRIES,
        "nothing was appended"
    );
    assert_eq!(
        after.manifest()[0],
        first,
        "and nothing was dropped: fail loud, never drain"
    );
    Ok(())
}

/// Malformed rows are refused at the door and at decode, so a corrupt manifest
/// cannot enter the store through either path.
#[test]
fn manifest_entries_are_validated() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let attempt = enqueued(&queue, 10)?;

    for (entry, expected) in [
        (skill_entry("", "1", 11), ERR_MANIFEST_REFERENCE_EMPTY),
        (skill_entry("skill", "", 11), ERR_MANIFEST_VERSION_EMPTY),
        (
            skill_entry(&"r".repeat(MAX_MANIFEST_REFERENCE_LEN + 1), "1", 11),
            ERR_MANIFEST_REFERENCE_TOO_LONG,
        ),
        (
            skill_entry("skill", &"v".repeat(MAX_MANIFEST_VERSION_LEN + 1), 11),
            ERR_MANIFEST_VERSION_TOO_LONG,
        ),
    ] {
        let error = queue
            .append_manifest_entry(attempt.id, entry)
            .expect_err("a malformed manifest row is refused");
        assert!(
            matches!(error, Error::InvalidAttemptQueueRecord(reason) if reason == expected),
            "expected {expected}, got {error:?}"
        );
    }
    assert!(
        queue
            .get(attempt.id)?
            .expect("row persists")
            .manifest()
            .is_empty()
    );
    Ok(())
}

/// A row written before the manifest existed decodes to an empty manifest:
/// additive `#[serde(default)]`, no migration.
#[test]
fn a_record_without_the_manifest_key_decodes_empty() -> Result<()> {
    #[derive(serde::Serialize)]
    struct PreManifestAttemptRecord {
        id: AttemptId,
        kind: String,
        payload: Vec<u8>,
        state: AttemptState,
        lease_owner: Option<String>,
        attempt_count: u32,
        claimed_at: Option<u64>,
        backoff_until: Option<u64>,
        last_error: Option<String>,
        task_ref: Option<String>,
        run_id: Option<String>,
        dedupe_key: Option<String>,
        created_at: u64,
        updated_at: u64,
        events: Vec<AttemptEvent>,
    }

    let id = AttemptId::now();
    let legacy = PreManifestAttemptRecord {
        id,
        kind: "pack".to_owned(),
        payload: Vec::new(),
        state: AttemptState::Queued,
        lease_owner: None,
        attempt_count: 0,
        claimed_at: None,
        backoff_until: None,
        last_error: None,
        task_ref: None,
        run_id: None,
        dedupe_key: None,
        created_at: 10,
        updated_at: 10,
        events: Vec::new(),
    };
    let mut encoded = vec![ATTEMPT_RECORD_VERSION];
    encoded.extend(rmp_serde::to_vec_named(&legacy).expect("serialize pre-manifest record"));

    assert!(decode_record(&encoded, id)?.manifest().is_empty());
    Ok(())
}

/// `AttemptEvent` and the intervention enum stay untouched: the manifest is a
/// PARALLEL field, never a shoehorned event payload (the seam rule).
#[test]
fn interventions_and_manifest_rows_stay_separate_lanes() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let attempt = enqueued(&queue, 10)?;

    queue.append_manifest_entry(attempt.id, skill_entry("index", "1", 11))?;
    let interrupted = queue.intervene(InterveneAttempt {
        id: attempt.id,
        kind: AttemptInterventionKind::Interrupt,
        actor: "operator".to_owned(),
        note: None,
        now: 12,
    })?;

    assert_eq!(interrupted.record.events.len(), 1);
    assert_eq!(
        interrupted.record.manifest().len(),
        1,
        "the intervention did not land in the manifest"
    );
    assert_eq!(
        interrupted.record.events[0].kind,
        AttemptInterventionKind::Interrupt
    );
    Ok(())
}
