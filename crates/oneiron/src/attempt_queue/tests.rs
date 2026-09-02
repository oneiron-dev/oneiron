use super::encoding::{
    DEDUPE_DOMAIN, DEDUPE_INDEX_KEY_LEN, decode_ready_key, dedupe_index_key, encode_record,
    legacy_dedupe_index_key, ready_at, ready_key,
};
use super::engine::RETRY_REASON_UNSPECIFIED;
use super::telemetry::emit_attempt_queue_cleanup_span;
use super::types::MAX_ATTEMPT_EVENTS_PER_RECORD;
use super::validate::{
    ERR_CANCEL_ACTOR_IS_RUNTIME, ERR_FAILURE_REASON_EMPTY, ERR_HANDOFF_WITHOUT_RESUME_POINT,
    ERR_LANDING_RECORD_MISPLACED, ERR_LANDING_WITHOUT_LEASE, ERR_LEASE_TIMEOUT_ZERO,
    ERR_MANIFEST_FULL, ERR_MANIFEST_REFERENCE_EMPTY, ERR_MANIFEST_REFERENCE_HAS_AT,
    ERR_MANIFEST_REFERENCE_TOO_LONG, ERR_MANIFEST_VERSION_EMPTY, ERR_MANIFEST_VERSION_TOO_LONG,
    ERR_RUN_ID_TOO_LONG, MAX_FAILURE_REASON_LEN, MAX_MANIFEST_REFERENCE_LEN,
    MAX_MANIFEST_VERSION_LEN, MAX_RUN_ID_LEN,
};
use super::*;
use crate::error::{Error, Result};
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

/// REGRESSION (owner ruling R-20260807-04): the `reference@version` delimiter
/// is the FIRST `@`, and a reference may not contain one.
///
/// The old parse split from the RIGHT, so a legal `s@1@beta` row — skill `s`
/// at revision `1@beta` — read back as skill `s@1` at revision `beta`, and
/// attribution then credited or blamed a skill entity that never existed.
/// Rejecting `@` in the reference at the door is what makes the first-`@`
/// split lossless: the two halves cannot both be ambiguous.
#[test]
fn a_manifest_wire_form_splits_on_the_first_at_and_refs_may_not_hold_one() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let attempt = enqueued(&queue, 10)?;

    let versioned = queue.append_manifest_entry(attempt.id, skill_entry("s", "1@beta", 11))?;
    let wire = versioned.manifest()[0].wire_form();
    assert_eq!(wire, "s@1@beta");
    assert_eq!(
        ManifestEntry::parse_wire_form(&wire),
        Some(("s", "1@beta")),
        "the version keeps every `@` past the delimiter; the reference keeps none"
    );

    let error = queue
        .append_manifest_entry(attempt.id, skill_entry("s@1", "beta", 12))
        .expect_err("a reference carrying the delimiter is refused at the door");
    assert!(
        matches!(
            error,
            Error::InvalidAttemptQueueRecord(reason) if reason == ERR_MANIFEST_REFERENCE_HAS_AT
        ),
        "expected {ERR_MANIFEST_REFERENCE_HAS_AT}, got {error:?}"
    );

    assert_eq!(
        ManifestEntry::parse_wire_form("no-delimiter"),
        None,
        "a string carrying no `@` is not a wire form"
    );
    assert_eq!(
        queue
            .get(attempt.id)?
            .expect("row persists")
            .manifest()
            .len(),
        1,
        "the refused row never landed"
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

// ─── ONE-1737 · terminal pack receipt is stamped BY the queue ───────────

/// Runs one attempt with a two-kind pack manifest to the requested terminal
/// door, returning its stamped receipt (if any) and its receipt id.
fn run_packed_attempt(
    vault: &Vault,
    terminal: fn(&AttemptQueue<'_>, AttemptId, u32) -> Result<()>,
) -> Result<(String, Option<crate::receipt::ReceiptRecord>)> {
    let queue = AttemptQueue::new(vault);
    let attempt = enqueued(&queue, 10)?;
    queue.append_manifest_entry(attempt.id, skill_entry("index", "1", 11))?;
    let ClaimOutcome::Claimed(leased) = queue.claim(ClaimAttempt {
        lease_owner: "worker".to_owned(),
        now: 12,
    })?
    else {
        panic!("expected claim");
    };
    queue.append_manifest_entry(attempt.id, skill_entry("pdf", "3", 13))?;
    queue.append_manifest_entry(
        attempt.id,
        ManifestEntry::new(ManifestKind::ActorClaim, "claim-a", "2", 13),
    )?;
    terminal(&queue, attempt.id, leased.attempt_count)?;

    let receipt_id = crate::receipt::attempt_pack_receipt_id(&attempt.id);
    let receipt = crate::receipt::attempt_pack_receipt(vault, &receipt_id)?;
    Ok((receipt_id, receipt))
}

fn complete_at_14(queue: &AttemptQueue<'_>, id: AttemptId, attempt_count: u32) -> Result<()> {
    queue.complete(CompleteAttempt {
        id,
        lease_owner: "worker".to_owned(),
        attempt_count,
        now: 14,
    })?;
    Ok(())
}

fn fail_at_14(queue: &AttemptQueue<'_>, id: AttemptId, attempt_count: u32) -> Result<()> {
    queue.fail(FailAttempt {
        id,
        lease_owner: "worker".to_owned(),
        attempt_count,
        reason: "boom".to_owned(),
        now: 14,
    })?;
    Ok(())
}

/// The terminal transition itself stamps the pack receipt: no caller opts in,
/// so no execute lane can forget it. The receipt carries the FULL accumulated
/// manifest, split by kind, in append order.
#[test]
fn completing_an_attempt_under_a_pack_stamps_its_terminal_receipt() -> Result<()> {
    let (_dir, vault) = open_queue();

    let (receipt_id, receipt) = run_packed_attempt(&vault, complete_at_14)?;
    let receipt = receipt.expect("the terminal transition stamped a pack receipt");

    assert_eq!(receipt.receipt_id, receipt_id);
    assert_eq!(receipt.outcome, "completed");
    assert_eq!(receipt.occurred_at, 14, "the receipt is stamped at close");
    assert_eq!(receipt.actor.as_deref(), Some("worker"));
    assert_eq!(
        receipt.pack_manifest_skills(),
        Some(vec!["index@1".to_owned(), "pdf@3".to_owned()]),
        "both the t0 index and the mid-run pull are on the terminal receipt"
    );
    assert_eq!(
        receipt.pack_manifest_actor_claims(),
        Some(vec!["claim-a@2".to_owned()])
    );

    // …and it is on the RS1 receipt family, not only in its own ledger.
    let family = vault.receipts(crate::receipt::ReceiptQuery::new(16))?;
    assert_eq!(
        family
            .iter()
            .filter(|row| row.receipt_id == receipt_id)
            .count(),
        1,
        "the stamped receipt projects into the unified receipt family exactly once"
    );
    Ok(())
}

/// A failed execute is attribution's primary input, so the fail door stamps
/// too — and the outcome distinguishes the two terminals.
#[test]
fn failing_an_attempt_under_a_pack_stamps_its_terminal_receipt() -> Result<()> {
    let (_dir, vault) = open_queue();

    let (_, receipt) = run_packed_attempt(&vault, fail_at_14)?;
    let receipt = receipt.expect("the fail door stamped a pack receipt");

    assert_eq!(receipt.outcome, "failed");
    assert_eq!(
        receipt.pack_manifest_skills(),
        Some(vec!["index@1".to_owned(), "pdf@3".to_owned()])
    );
    Ok(())
}

/// The manifest IS the reason the receipt exists: an attempt that ran under no
/// pack mints no row, so the ledger stays the attribution surface rather than
/// a second copy of the attempt queue.
#[test]
fn an_attempt_with_no_pack_stamps_no_receipt() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let attempt = enqueued(&queue, 10)?;
    let ClaimOutcome::Claimed(leased) = queue.claim(ClaimAttempt {
        lease_owner: "worker".to_owned(),
        now: 11,
    })?
    else {
        panic!("expected claim");
    };
    complete_at_14(&queue, attempt.id, leased.attempt_count)?;

    assert_eq!(
        crate::receipt::attempt_pack_receipt(
            &vault,
            &crate::receipt::attempt_pack_receipt_id(&attempt.id),
        )?,
        None
    );
    assert!(
        vault
            .receipts(crate::receipt::ReceiptQuery::new(16))?
            .is_empty()
    );
    Ok(())
}

/// A row written before `scheduled_at`/`retry_of` existed, at the unchanged
/// record version.
#[derive(serde::Serialize)]
struct PreScheduledAttemptRecord {
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

#[test]
fn legacy_backoff_row_decodes_and_keeps_its_readiness_instant() -> Result<()> {
    // Record version is unchanged: appending a unit-enum variant and two
    // defaulted fields must not force a bump or a migration.
    assert_eq!(ATTEMPT_RECORD_VERSION, 2);

    let id = AttemptId::from_bytes(&[0x7A; 16])?;
    let legacy = PreScheduledAttemptRecord {
        id,
        kind: "claim_extraction".to_owned(),
        payload: b"legacy-payload".to_vec(),
        state: AttemptState::Queued,
        lease_owner: None,
        attempt_count: 1,
        claimed_at: Some(20),
        backoff_until: Some(100),
        last_error: Some("rate limited".to_owned()),
        task_ref: None,
        run_id: Some("run-legacy".to_owned()),
        dedupe_key: Some("turn:legacy".to_owned()),
        created_at: 10,
        updated_at: 30,
        events: Vec::new(),
    };
    let mut encoded = vec![ATTEMPT_RECORD_VERSION];
    encoded.extend(rmp_serde::to_vec_named(&legacy).expect("serialize legacy attempt record"));

    let decoded = decode_record(&encoded, id)?;
    assert_eq!(decoded.state, AttemptState::Queued);
    assert_eq!(decoded.backoff_until, Some(100));
    assert_eq!(decoded.scheduled_at, None);
    assert_eq!(decoded.retry_of, None);
    assert_eq!(decoded.attempt_count, 1);
    assert_eq!(decoded.last_error.as_deref(), Some("rate limited"));

    // The legacy spelling still drives readiness, at the exact same instant.
    assert_eq!(ready_at(&decoded), 100);

    // Re-encoding a decoded legacy row keeps it decodable and unchanged.
    let round_tripped = decode_record(&encode_record(&decoded)?, id)?;
    assert_eq!(round_tripped, decoded);

    Ok(())
}

#[test]
fn legacy_backoff_row_stays_claimable_at_its_original_instant() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    let EnqueueOutcome::Enqueued(attempt) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:legacy-live"), 10))?
    else {
        panic!("expected enqueue");
    };

    // Plant a pre-ONE-1795 row in place: Queued with only `backoff_until`, and
    // a ready entry at that instant. No bulk rewrite converts it.
    let mut record = queue.get(attempt.id)?.expect("enqueued row");
    record.state = AttemptState::Queued;
    record.backoff_until = Some(100);
    record.attempt_count = 1;
    record.claimed_at = Some(20);
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .attempt_ready
            .delete(&mut wtxn, &ready_key(0, record.id))?;
        let encoded = encode_record(&record)?;
        vault
            .store
            .attempt_records
            .put(&mut wtxn, record.id.as_bytes(), &encoded)?;
        vault.store.attempt_ready.put(
            &mut wtxn,
            &ready_key(100, record.id),
            record.id.as_bytes(),
        )?;
        wtxn.commit()?;
    }

    assert_eq!(
        queue.claim(ClaimAttempt {
            lease_owner: "worker-a".to_owned(),
            now: 99,
        })?,
        ClaimOutcome::Empty
    );
    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".to_owned(),
        now: 100,
    })?
    else {
        panic!("legacy backoff row must claim at its own instant");
    };
    assert_eq!(claimed.id, attempt.id);
    assert_eq!(claimed.backoff_until, None);
    assert_eq!(claimed.scheduled_at, None);
    assert_eq!(claimed.attempt_count, 2);

    Ok(())
}

#[test]
fn dedupe_hash_domain_stays_pinned() {
    // Changing this silently orphans every live dedupe entry.
    assert_eq!(DEDUPE_DOMAIN, b"oneiron.job_queue.dedupe.v1\0");
}

mod one_1695_tests {
    use super::*;

    #[derive(serde::Serialize)]
    struct LegacyAttemptRecord {
        id: AttemptId,
        kind: String,
        payload: Vec<u8>,
        state: AttemptState,
        lease_owner: Option<String>,
        attempt_count: u32,
        claimed_at: Option<u64>,
        backoff_until: Option<u64>,
        last_error: Option<String>,
        run_id: Option<String>,
        dedupe_key: Option<String>,
        created_at: u64,
        updated_at: u64,
        events: Vec<AttemptEvent>,
    }

    fn record(task_ref: Option<&str>) -> AttemptRecord {
        AttemptRecord {
            id: AttemptId::from_bytes(&[0x42; 16]).expect("attempt id from 16 bytes"),
            kind: "sync".to_owned(),
            payload: b"payload".to_vec(),
            state: AttemptState::Queued,
            lease_owner: None,
            attempt_count: 0,
            claimed_at: None,
            scheduled_at: None,
            retry_of: None,
            backoff_until: None,
            last_error: None,
            task_ref: task_ref.map(str::to_owned),
            run_id: Some("run-owner".to_owned()),
            dedupe_key: Some("owner-job".to_owned()),
            created_at: 10,
            updated_at: 10,
            events: Vec::new(),
            manifest: Vec::new(),
            cancel_state: AttemptCancelState::default(),
        }
    }

    #[test]
    fn task_ref_serde_round_trips() {
        let expected = record(Some("tk_owner"));
        let encoded = rmp_serde::to_vec_named(&expected).expect("serialize attempt record");
        let decoded: AttemptRecord =
            rmp_serde::from_slice(&encoded).expect("deserialize attempt record");

        assert_eq!(decoded, expected);
    }

    #[test]
    fn task_ref_defaults_when_legacy_record_omits_key() -> Result<()> {
        let current = record(None);
        let legacy = LegacyAttemptRecord {
            id: current.id,
            kind: current.kind,
            payload: current.payload,
            state: current.state,
            lease_owner: current.lease_owner,
            attempt_count: current.attempt_count,
            claimed_at: current.claimed_at,
            backoff_until: current.backoff_until,
            last_error: current.last_error,
            run_id: current.run_id,
            dedupe_key: current.dedupe_key,
            created_at: current.created_at,
            updated_at: current.updated_at,
            events: current.events,
        };
        let mut encoded = vec![ATTEMPT_RECORD_VERSION];
        encoded.extend(
            rmp_serde::to_vec_named(&legacy).expect("serialize legacy attempt record without key"),
        );

        let decoded = decode_record(&encoded, legacy.id)?;

        assert_eq!(decoded.task_ref, None);
        Ok(())
    }

    #[test]
    fn attempt_queue_sets_and_reads_optional_task_ref() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
        let queue = AttemptQueue::new(&vault);
        let input = |now| EnqueueAttempt {
            kind: "sync".to_owned(),
            payload: format!("payload-{now}").into_bytes(),
            dedupe_key: None,
            run_id: None,
            now,
        };

        queue.enqueue_with_task_ref(input(10), Some("tk_owner".to_owned()))?;
        queue.enqueue(input(20))?;

        let records = queue.list()?;
        assert_eq!(records.len(), 2);
        assert_eq!(
            records
                .iter()
                .filter(|record| record.task_ref.is_some())
                .count(),
            1
        );
        assert_eq!(records[0].task_ref.as_deref(), Some("tk_owner"));
        assert_eq!(records[1].task_ref, None);
        Ok(())
    }
}

/// ONE-1449 K3 M-3: the queue's run-id bound and the skill-edit CYCLE bound are
/// one contract, not two.
///
/// A run id becomes the Dreamer cycle label `skill_optimize::proven_cycle`
/// counts the per-cycle accept cap against, under a pinned `run:` prefix. A run
/// id this door admitted but no cycle could name stranded every proposal that
/// run drafted — and only after the author had been paid for the draft.
#[test]
fn a_run_id_leaves_room_for_the_skill_edit_cycle_prefix() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    assert_eq!(
        MAX_RUN_ID_LEN,
        crate::skill_optimize::SKILL_EDIT_CYCLE_MAX_BYTES
            - crate::skill_optimize::SKILL_EDIT_CYCLE_RUN_PREFIX.len(),
        "the budget is DERIVED from the label it has to fit inside"
    );

    let longest = "r".repeat(MAX_RUN_ID_LEN);
    let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(EnqueueAttempt {
        kind: "dreamer.skill_optimize".to_owned(),
        payload: Vec::new(),
        dedupe_key: None,
        run_id: Some(longest.clone()),
        now: 10,
    })?
    else {
        panic!("expected new attempt");
    };
    let persisted = queue.get(attempt.id)?.expect("persisted attempt");
    assert_eq!(persisted.run_id.as_deref(), Some(longest.as_str()));
    assert_eq!(
        crate::skill_optimize::SKILL_EDIT_CYCLE_RUN_PREFIX.len() + longest.len(),
        crate::skill_optimize::SKILL_EDIT_CYCLE_MAX_BYTES,
        "the longest admitted run id names a cycle label of exactly the bound"
    );

    let refused = queue
        .enqueue(EnqueueAttempt {
            kind: "dreamer.skill_optimize".to_owned(),
            payload: Vec::new(),
            dedupe_key: None,
            run_id: Some(format!("{longest}r")),
            now: 20,
        })
        .expect_err("a run no cycle could name is not enqueued");
    assert!(matches!(
        refused,
        Error::InvalidAttemptQueueRecord(reason) if reason == ERR_RUN_ID_TOO_LONG
    ));
    Ok(())
}

// ─── ONE-1896 · two-rung graceful cancel, landing, and reserve ──────────
//
// Termination is a worker-participating transition. Rung 1 (`cancel.request`)
// is a QUESTION any actor with standing may ask and the worker may refuse;
// rung 2 (`cancel.force`) is an unrefusable, runtime-authored stop only the
// owner, lease expiry, or criticality can reach. Between them sits LANDING: a
// durable, non-completed state that owns the lease long enough to finish, spend
// a held-back reserve, and record where a successor picks up.

/// Enqueues, claims, and returns the leased row ready to be asked to stop.
fn leased_attempt(queue: &AttemptQueue<'_>, dedupe_key: &str) -> Result<AttemptRecord> {
    queue.enqueue(enqueue("sync", Some(dedupe_key), 10))?;
    let ClaimOutcome::Claimed(leased) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".to_owned(),
        now: 11,
    })?
    else {
        panic!("expected claim");
    };
    Ok(leased)
}

fn soft_request(id: AttemptId, actor: &str, standing: CancelStanding) -> RequestAttemptCancel {
    RequestAttemptCancel {
        id,
        actor: actor.to_owned(),
        standing,
        trigger: LandingTrigger::CancelRequest,
        reason: Some("owner asked for the machine back".to_owned()),
        now: 12,
    }
}

fn accept_landing_at(
    queue: &AttemptQueue<'_>,
    leased: &AttemptRecord,
    trigger: LandingTrigger,
    now: u64,
) -> Result<AttemptRecord> {
    let LandingOutcome::Landing(landing) = queue.accept_landing(AcceptAttemptLanding {
        id: leased.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: leased.attempt_count,
        trigger,
        status: Some("green + pushed + packet-only".to_owned()),
        resume_point: None,
        now,
    })?
    else {
        panic!("expected a fresh landing");
    };
    Ok(landing)
}

/// Proof 1: `landing` survives the wire, is shape-validated, and no read
/// surface calls it completed.
#[test]
fn landing_round_trips_on_the_wire_and_never_projects_as_completed() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let leased = leased_attempt(&queue, "turn:landing-wire")?;
    queue.request_cancel(soft_request(leased.id, "peer-1", CancelStanding::PeerAgent))?;
    let landing = accept_landing_at(&queue, &leased, LandingTrigger::CancelRequest, 13)?;

    // Durable and byte-stable through the row codec.
    let reread = queue.get(leased.id)?.expect("landing row");
    assert_eq!(reread, landing);
    assert_eq!(reread.state, AttemptState::Landing);
    assert_eq!(AttemptState::Landing.as_str(), "landing");
    assert_eq!(
        reread.landing().expect("landing record").trigger,
        LandingTrigger::CancelRequest
    );
    assert_eq!(
        reread.landing().expect("landing record").status.as_deref(),
        Some("green + pushed + packet-only")
    );
    assert_eq!(
        reread.landing().expect("landing record").requested_by,
        "peer-1",
        "the landing names the requester it answered"
    );

    // Append-only state ordering: `Landing` is the newest variant, so every
    // older row's encoded index is unchanged.
    let encoded_scheduled = rmp_serde::to_vec_named(&AttemptState::Scheduled).expect("encode");
    let encoded_landing = rmp_serde::to_vec_named(&AttemptState::Landing).expect("encode");
    assert_ne!(encoded_scheduled, encoded_landing);
    assert_eq!(
        rmp_serde::from_slice::<AttemptState>(&encoded_scheduled).expect("decode"),
        AttemptState::Scheduled,
        "appending Landing did not re-map an existing variant"
    );

    // A landing row must keep the lease that buys it the time to finish.
    let mut malformed = reread.clone();
    malformed.lease_owner = None;
    let encoded = rmp_serde::to_vec_named(&malformed).expect("encode");
    let mut raw = vec![super::types::ATTEMPT_RECORD_VERSION];
    raw.extend(encoded);
    assert!(matches!(
        decode_record(&raw, malformed.id).expect_err("landing without a lease is refused"),
        Error::InvalidAttemptQueueRecord(reason) if reason == ERR_LANDING_WITHOUT_LEASE
    ));

    // A landing record may not ride a row that is not landing or landed.
    let mut misplaced = reread.clone();
    misplaced.state = AttemptState::Leased;
    let encoded = rmp_serde::to_vec_named(&misplaced).expect("encode");
    let mut raw = vec![super::types::ATTEMPT_RECORD_VERSION];
    raw.extend(encoded);
    assert!(matches!(
        decode_record(&raw, misplaced.id).expect_err("misplaced landing record is refused"),
        Error::InvalidAttemptQueueRecord(reason) if reason == ERR_LANDING_RECORD_MISPLACED
    ));

    // Projections: still running, never completed, never cancelled.
    assert_eq!(
        crate::run_tree::RunTreeStatus::from(AttemptState::Landing),
        crate::run_tree::RunTreeStatus::Running
    );
    let a2a = crate::run_tree::project_attempt_to_a2a(&reread);
    assert_eq!(a2a.state, crate::consult_ladder::A2aBaseTaskState::Working);
    assert_eq!(a2a.extensions.cancel_mode.as_deref(), Some("landing"));
    assert_eq!(
        a2a.extensions.landing_trigger.as_deref(),
        Some("cancel_request")
    );

    // An operator interrupt may leave an audit event on a landing row, but it
    // is not a lease heartbeat: only accepting the landing starts its one
    // bounded finishing window.
    let interrupted = queue.intervene(InterveneAttempt {
        id: leased.id,
        kind: AttemptInterventionKind::Interrupt,
        actor: "operator".to_owned(),
        note: Some("observed landing".to_owned()),
        now: 100,
    })?;
    assert_eq!(interrupted.effect, AttemptInterventionEffect::Interrupted);
    assert_eq!(
        interrupted.record.updated_at, landing.updated_at,
        "an interrupt must not extend a landing lease"
    );

    // And the queue itself refuses to call it completed.
    assert_invalid_transition(
        queue
            .complete(CompleteAttempt {
                id: leased.id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: leased.attempt_count,
                now: 14,
            })
            .expect_err("a landing attempt is never completed"),
        "complete",
        "landing",
    );
    Ok(())
}

/// Proof 2: standing asks, the worker lands with an exact resume point, and the
/// handoff carries that point to a claimable successor.
#[test]
fn soft_request_lands_with_a_resume_point_a_successor_resumes_from() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let leased = leased_attempt(&queue, "turn:landing-handoff")?;

    let CancelRequestOutcome::Requested { record, pressure } =
        queue.request_cancel(soft_request(leased.id, "healer-1", CancelStanding::Healer))?
    else {
        panic!("an actor with standing may ask");
    };
    assert_eq!(
        record.state,
        AttemptState::Leased,
        "asking never terminates"
    );
    assert_eq!(pressure.requests, 1);
    assert_eq!(pressure.pending, 1);
    let request_receipt = record.cancel_receipts().last().expect("request receipt");
    assert_eq!(
        request_receipt.kind,
        AttemptCancelReceiptKind::SoftRequested
    );
    assert_eq!(request_receipt.standing, Some(CancelStanding::Healer));
    assert_eq!(request_receipt.trigger, Some(LandingTrigger::CancelRequest));

    let landing = accept_landing_at(&queue, &leased, LandingTrigger::CancelRequest, 13)?;
    assert_eq!(landing.cancel_pressure().pending, 0, "the ask was answered");

    // A landing is not claimable as ordinary queued work.
    assert!(matches!(
        queue.claim(ClaimAttempt {
            lease_owner: "worker-b".to_owned(),
            now: 14,
        })?,
        ClaimOutcome::Empty
    ));

    let with_point = queue.record_resume_point(RecordAttemptResumePoint {
        id: leased.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: leased.attempt_count,
        resume_point: AttemptResumePoint::new("step-7/of-12", 15)
            .with_artifact_ref("artifact:checkpoint"),
        now: 15,
    })?;
    assert_eq!(
        with_point.resume_point().expect("resume point").marker,
        "step-7/of-12"
    );

    // The landing is fenced like any other lease transition: a stranger cannot
    // end it early and strand the work the worker had not finished.
    assert_invalid_transition(
        queue
            .finish_landing(FinishAttemptLanding {
                id: leased.id,
                lease_owner: "worker-b".to_owned(),
                attempt_count: leased.attempt_count,
                hand_off: true,
                scheduled_at: None,
                now: 16,
            })
            .expect_err("only the landing worker finishes its landing"),
        "finish_landing",
        "leased_by_other",
    );

    let FinishLandingOutcome::HandedOff { landed, successor } =
        queue.finish_landing(FinishAttemptLanding {
            id: leased.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: leased.attempt_count,
            hand_off: true,
            scheduled_at: None,
            now: 16,
        })?
    else {
        panic!("expected a handoff");
    };

    assert_eq!(landed.state, AttemptState::Cancelled);
    let cancellation = landed.cancellation().expect("terminal cancellation");
    assert_eq!(cancellation.mode, CancelMode::Landed);
    assert_eq!(cancellation.grounds, None);
    assert_eq!(cancellation.trigger, Some(LandingTrigger::CancelRequest));
    assert_eq!(cancellation.actor, "worker-a");
    assert_eq!(
        landed
            .cancel_receipts()
            .iter()
            .filter(|receipt| receipt.kind == AttemptCancelReceiptKind::Landed)
            .count(),
        1
    );

    // The successor carries the EXACT point and is claimable; the landed row
    // is superseded history and can never be completed.
    assert_eq!(successor.state, AttemptState::Queued);
    assert_eq!(successor.retry_of, Some(landed.id));
    let successor_point = successor.resume_point().expect("successor resume point");
    assert_eq!(successor_point.marker, "step-7/of-12");
    assert_eq!(
        successor_point.artifact_ref.as_deref(),
        Some("artifact:checkpoint")
    );
    let ClaimOutcome::Claimed(resumed) = queue.claim(ClaimAttempt {
        lease_owner: "worker-b".to_owned(),
        now: 17,
    })?
    else {
        panic!("the successor is ordinary claimable work");
    };
    assert_eq!(resumed.id, successor.id);
    assert_eq!(
        resumed
            .resume_point()
            .expect("point survives the claim")
            .marker,
        "step-7/of-12"
    );
    assert_invalid_transition(
        queue
            .complete(CompleteAttempt {
                id: landed.id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: landed.attempt_count,
                now: 18,
            })
            .expect_err("a landed row cannot also complete"),
        "complete",
        "cancelled",
    );
    Ok(())
}

/// Proof 3: refusal is structured, append-only, and repeated refusal becomes an
/// observable pathology that still cannot stop the worker by itself.
#[test]
fn repeated_soft_rejection_stays_nonterminal_and_becomes_observable_pathology() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let leased = leased_attempt(&queue, "turn:stubborn")?;

    let mut pathology = false;
    for round in 0..SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD {
        queue.request_cancel(soft_request(leased.id, "peer-1", CancelStanding::PeerAgent))?;
        let rejection = queue.reject_cancel(RejectAttemptCancel {
            id: leased.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: leased.attempt_count,
            reason: "mid-write; landing now would corrupt the packet".to_owned(),
            status: Some("red + unpushed".to_owned()),
            now: 20 + u64::from(round),
        })?;
        assert_eq!(
            rejection.record.state,
            AttemptState::Leased,
            "a refusal never terminates the attempt"
        );
        assert_eq!(rejection.pressure.rejections, round + 1);
        assert_eq!(rejection.pressure.pending, 0);
        pathology = rejection.pathology;
    }
    assert!(
        pathology,
        "repeated refusal is observable, not silently tolerated"
    );

    let stubborn = queue.get(leased.id)?.expect("row");
    assert!(stubborn.soft_cancel_pathology());
    let rejections: Vec<_> = stubborn
        .cancel_receipts()
        .iter()
        .filter(|receipt| receipt.kind == AttemptCancelReceiptKind::SoftRejected)
        .collect();
    assert_eq!(
        rejections.len(),
        SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD as usize,
        "every refusal is kept; evidence is append-only"
    );
    assert_eq!(
        rejections[0].reason.as_deref(),
        Some("mid-write; landing now would corrupt the packet")
    );
    assert_eq!(rejections[0].status.as_deref(), Some("red + unpushed"));
    assert_eq!(
        rejections[0].trigger,
        Some(LandingTrigger::CancelRequest),
        "a refusal preserves the trigger it answered"
    );
    let sequences: Vec<u64> = stubborn
        .cancel_receipts()
        .iter()
        .map(|receipt| receipt.sequence)
        .collect();
    assert!(
        sequences.windows(2).all(|pair| pair[0] < pair[1]),
        "receipt sequence is strictly increasing"
    );
    let a2a = crate::run_tree::project_attempt_to_a2a(&stubborn);
    assert_eq!(a2a.state, crate::consult_ladder::A2aBaseTaskState::Working);
    assert_eq!(a2a.extensions.cancel_mode.as_deref(), Some("rejected"));
    assert_eq!(
        a2a.extensions.cancel_rejections,
        SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD
    );

    // Only the hard rung ends it, and the refusal history survives the stop.
    let ForceCancelOutcome::Cancelled(forced) = queue.force_cancel(ForceAttemptCancel {
        id: leased.id,
        authority: ForceCancelAuthority::from_standing(CancelStanding::Authority, "owner-1")
            .expect("owner standing forces"),
        reason: Some("refused to land three times".to_owned()),
        now: 30,
    })?
    else {
        panic!("authority forces");
    };
    assert_eq!(forced.state, AttemptState::Cancelled);
    assert_eq!(
        forced.cancel_pressure().rejections,
        SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD
    );
    Ok(())
}

/// Proof 4: no standing, no ask — and the attempt is byte-identical afterwards.
#[test]
fn soft_request_without_standing_changes_nothing() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let leased = leased_attempt(&queue, "turn:no-standing")?;
    let before = queue.get(leased.id)?.expect("row");

    let CancelRequestOutcome::NoStanding(unchanged) =
        queue.request_cancel(soft_request(leased.id, "stranger", CancelStanding::None))?
    else {
        panic!("an actor without standing may not ask");
    };
    assert_eq!(unchanged, before);
    assert_eq!(queue.get(leased.id)?.expect("row"), before);
    assert_eq!(before.cancel_pressure().requests, 0);
    assert!(before.cancel_receipts().is_empty());

    // Nor may a requester borrow the runtime's identity to look authoritative.
    assert!(matches!(
        queue
            .request_cancel(soft_request(
                leased.id,
                ATTEMPT_RUNTIME_ACTOR,
                CancelStanding::PeerAgent
            ))
            .expect_err("the runtime identity is reserved"),
        Error::InvalidAttemptQueueRecord(reason) if reason == ERR_CANCEL_ACTOR_IS_RUNTIME
    ));
    assert_eq!(queue.get(leased.id)?.expect("row"), before);

    // A worker may answer only an outstanding request; an unsolicited refusal
    // cannot manufacture pathology evidence.
    assert_invalid_transition(
        queue
            .reject_cancel(RejectAttemptCancel {
                id: leased.id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: leased.attempt_count,
                reason: "nothing to answer".to_owned(),
                status: None,
                now: 13,
            })
            .expect_err("a refusal without a request is invalid"),
        "cancel_reject",
        "no_request",
    );
    Ok(())
}

/// Proof 5: the hard rung is authority-only, runtime-authored, and unforgeable.
#[test]
fn hard_force_is_authority_only_and_runtime_authored() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);

    // No non-authority standing can even MINT the authority token, so an
    // unauthorized force is impossible to express, not merely refused.
    for standing in [
        CancelStanding::PeerAgent,
        CancelStanding::Healer,
        CancelStanding::Automation,
        CancelStanding::None,
    ] {
        assert!(
            ForceCancelAuthority::from_standing(standing, "impostor").is_none(),
            "{} may ask but never force",
            standing.as_str()
        );
    }

    // Owner grounds: terminal, with the authority's own actor on the receipt.
    let owned = leased_attempt(&queue, "turn:force-owner")?;
    queue.append_manifest_entry(
        owned.id,
        ManifestEntry::new(ManifestKind::Skill, "skill.cancel", "v1", 12),
    )?;
    let ForceCancelOutcome::Cancelled(forced) = queue.force_cancel(ForceAttemptCancel {
        id: owned.id,
        authority: ForceCancelAuthority::from_standing(CancelStanding::Authority, "owner-1")
            .expect("owner standing"),
        reason: Some("owner reclaimed the machine".to_owned()),
        now: 20,
    })?
    else {
        panic!("authority forces");
    };
    let cancellation = forced.cancellation().expect("cancellation receipt");
    assert_eq!(cancellation.mode, CancelMode::Forced);
    assert_eq!(cancellation.grounds, Some(ForceCancelGrounds::Owner));
    assert_eq!(cancellation.actor, "owner-1");
    assert_eq!(forced.lease_owner, None, "a forced stop releases the lease");
    assert_eq!(
        forced.last_error, None,
        "a cancelled row is not a failed one; the reason rides the receipt"
    );
    assert_eq!(
        cancellation.reason.as_deref(),
        Some("owner reclaimed the machine")
    );
    let pack_receipt = crate::receipt::attempt_pack_receipt(
        &vault,
        &crate::receipt::attempt_pack_receipt_id(&owned.id),
    )?
    .expect("hard cancellation stamps the accumulated pack manifest");
    assert_eq!(pack_receipt.outcome, "cancelled");
    // Terminal is terminal: the worker cannot report a second success.
    assert_invalid_transition(
        queue
            .complete(CompleteAttempt {
                id: owned.id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: owned.attempt_count,
                now: 21,
            })
            .expect_err("completion after a force is refused"),
        "complete",
        "cancelled",
    );
    let ForceCancelOutcome::AlreadyCancelled(replay) = queue.force_cancel(ForceAttemptCancel {
        id: owned.id,
        authority: ForceCancelAuthority::criticality(),
        reason: None,
        now: 22,
    })?
    else {
        panic!("a second force is an idempotent replay");
    };
    assert_eq!(
        replay.cancellation().expect("receipt").actor,
        "owner-1",
        "the first authority's receipt is not overwritten"
    );

    // Criticality grounds: runtime-authored, whatever the worker holds.
    let critical = leased_attempt(&queue, "turn:force-critical")?;
    let ForceCancelOutcome::Cancelled(stopped) = queue.force_cancel(ForceAttemptCancel {
        id: critical.id,
        authority: ForceCancelAuthority::criticality(),
        reason: None,
        now: 23,
    })?
    else {
        panic!("criticality forces");
    };
    assert_eq!(
        stopped.cancellation().expect("receipt").actor,
        ATTEMPT_RUNTIME_ACTOR
    );
    assert_eq!(
        stopped.cancellation().expect("receipt").grounds,
        Some(ForceCancelGrounds::Criticality)
    );

    // Lease-expiry grounds: a landing whose lease died is force-cancelled by
    // cleanup, not requeued as ordinary work, and the warning rung is a
    // DIFFERENT, non-terminal thing.
    let expiring = leased_attempt(&queue, "turn:force-expiry")?;
    assert!(matches!(
        queue.warn_lease_expiry(WarnAttemptLeaseExpiry {
            id: expiring.id,
            lease_timeout_secs: 100,
            now: 12,
        })?,
        LeaseWarningOutcome::NotDue(_)
    ));
    let LeaseWarningOutcome::LandingRequested(warned) =
        queue.warn_lease_expiry(WarnAttemptLeaseExpiry {
            id: expiring.id,
            lease_timeout_secs: 100,
            now: 100,
        })?
    else {
        panic!("inside the warning window the runtime asks");
    };
    assert_eq!(warned.state, AttemptState::Leased, "a warning never stops");
    let warning = warned.cancel_receipts().last().expect("warning receipt");
    assert_eq!(warning.actor, ATTEMPT_RUNTIME_ACTOR);
    assert_eq!(warning.trigger, Some(LandingTrigger::LeaseWarning));
    assert!(
        matches!(
            queue.warn_lease_expiry(WarnAttemptLeaseExpiry {
                id: expiring.id,
                lease_timeout_secs: 100,
                now: 101,
            })?,
            LeaseWarningOutcome::AlreadyRequested(_)
        ),
        "polling the warning records one row, not a hundred"
    );

    let landing = accept_landing_at(&queue, &expiring, LandingTrigger::LeaseWarning, 102)?;
    assert_eq!(landing.state, AttemptState::Landing);
    assert_eq!(
        landing.updated_at, 102,
        "accepting buys ONE fresh bounded window"
    );
    queue
        .dial_landing_reserve(DialLandingReserve {
            id: expiring.id,
            limit_units: 100,
            reserve_percent: None,
            now: 103,
        })
        .expect_err("a landing row is not re-dialed");
    let busy = queue.record_resume_point(RecordAttemptResumePoint {
        id: expiring.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: expiring.attempt_count,
        resume_point: AttemptResumePoint::new("still-going", 300),
        now: 300,
    })?;
    assert_eq!(
        busy.updated_at, 102,
        "landing work does not extend the window by looking busy"
    );
    let report = queue.cleanup_leases(CleanupAttemptLeases {
        now: 400,
        lease_timeout_secs: 100,
    })?;
    assert_eq!(report.landing_force_cancelled, 1);
    assert_eq!(report.stale_requeued, 0, "a landing is never requeued");
    let expired = queue.get(expiring.id)?.expect("row");
    assert_eq!(expired.state, AttemptState::Cancelled);
    let cancellation = expired.cancellation().expect("receipt");
    assert_eq!(cancellation.grounds, Some(ForceCancelGrounds::LeaseExpiry));
    assert_eq!(cancellation.actor, ATTEMPT_RUNTIME_ACTOR);
    assert_eq!(cancellation.trigger, Some(LandingTrigger::LeaseWarning));
    assert_eq!(
        crate::run_tree::project_attempt_to_a2a(&expired)
            .extensions
            .cancel_mode
            .as_deref(),
        Some("forced")
    );
    Ok(())
}

/// Proof 6: the reserve is unreachable outside landing, exact inside it, and
/// every trigger enters the same landing path with typed provenance.
#[test]
fn landing_reserve_is_landing_only_bounded_and_reports_exhaustion() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let leased = leased_attempt(&queue, "turn:reserve")?;

    let dialed = queue.dial_landing_reserve(DialLandingReserve {
        id: leased.id,
        limit_units: 10_000,
        reserve_percent: None,
        now: 12,
    })?;
    let reserve = dialed.landing_reserve();
    assert_eq!(reserve.limit_units, 10_000);
    assert_eq!(
        reserve.reserve_units,
        10_000 * LANDING_RESERVE_PERCENT / 100,
        "the dial is the named constant, in integer units"
    );
    assert_eq!(
        dialed.ordinary_budget_limit_units(),
        9_000,
        "the ordinary meter is built without the reserve, so normal work \
         cannot reach it"
    );

    // Out of landing mode the spend door fails closed.
    assert_invalid_transition(
        queue
            .spend_landing_reserve(SpendAttemptLandingReserve {
                id: leased.id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: leased.attempt_count,
                units: 1,
                now: 13,
            })
            .expect_err("running work may not spend the landing reserve"),
        "spend_landing_reserve",
        "leased",
    );

    // Budget warning is a first-class trigger into the same landing path.
    accept_landing_at(&queue, &leased, LandingTrigger::BudgetWarning, 14)?;
    let landing = queue.get(leased.id)?.expect("row");
    assert_eq!(
        landing.landing().expect("landing").trigger,
        LandingTrigger::BudgetWarning
    );

    let spend = |units: u64, now: u64| SpendAttemptLandingReserve {
        id: leased.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: leased.attempt_count,
        units,
        now,
    };
    let LandingReserveSpendOutcome::Spent {
        remaining_units, ..
    } = queue.spend_landing_reserve(spend(600, 15))?
    else {
        panic!("landing may spend its reserve");
    };
    assert_eq!(remaining_units, 400);

    // Over the remaining reserve spends NOTHING and reports exhaustion.
    let LandingReserveSpendOutcome::Exhausted {
        record,
        requested_units,
        remaining_units,
    } = queue.spend_landing_reserve(spend(401, 16))?
    else {
        panic!("the reserve is bounded at the dialed amount");
    };
    assert_eq!(requested_units, 401);
    assert_eq!(remaining_units, 400);
    assert_eq!(
        record.landing_reserve().spent_units,
        600,
        "a refused spend moves no units"
    );

    let LandingReserveSpendOutcome::Spent {
        record,
        remaining_units,
    } = queue.spend_landing_reserve(spend(400, 17))?
    else {
        panic!("the exact remainder is spendable");
    };
    assert_eq!(remaining_units, 0);
    assert!(record.landing_reserve().is_exhausted());

    // A landing that cannot say where to resume may not hand off.
    assert!(matches!(
        queue
            .finish_landing(FinishAttemptLanding {
                id: leased.id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: leased.attempt_count,
                hand_off: true,
                scheduled_at: None,
                now: 18,
            })
            .expect_err("a handoff without a resume point is refused"),
        Error::InvalidAttemptQueueRecord(reason) if reason == ERR_HANDOFF_WITHOUT_RESUME_POINT
    ));

    let FinishLandingOutcome::Landed(landed) = queue.finish_landing(FinishAttemptLanding {
        id: leased.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: leased.attempt_count,
        hand_off: false,
        scheduled_at: None,
        now: 19,
    })?
    else {
        panic!("a landing may end without a successor");
    };
    let cancellation = landed.cancellation().expect("receipt");
    assert_eq!(cancellation.reserve_units, 1_000);
    assert_eq!(
        cancellation.reserve_spent_units, 1_000,
        "the terminal receipt reports the landing's accounting"
    );
    assert_eq!(cancellation.trigger, Some(LandingTrigger::BudgetWarning));

    // Re-dialing a settled row is refused, so the accounting cannot be rewritten.
    assert_invalid_transition(
        queue
            .dial_landing_reserve(DialLandingReserve {
                id: leased.id,
                limit_units: 1,
                reserve_percent: None,
                now: 20,
            })
            .expect_err("a settled row is not re-dialed"),
        "dial_landing_reserve",
        "cancelled",
    );
    Ok(())
}

/// Proof 7: the sticky-executor completion law is unchanged for non-landing
/// work, and the cancel doors carry the same lease-generation fence.
#[test]
fn sticky_completion_and_cancel_doors_share_one_lease_fence() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let leased = leased_attempt(&queue, "turn:fence")?;
    queue.request_cancel(soft_request(leased.id, "peer-1", CancelStanding::PeerAgent))?;

    // Wrong owner and stale generation are refused on every worker-facing door.
    assert_invalid_transition(
        queue
            .accept_landing(AcceptAttemptLanding {
                id: leased.id,
                lease_owner: "worker-b".to_owned(),
                attempt_count: leased.attempt_count,
                trigger: LandingTrigger::CancelRequest,
                status: None,
                resume_point: None,
                now: 13,
            })
            .expect_err("a stranger cannot land someone else's attempt"),
        "accept_landing",
        "leased_by_other",
    );
    assert_invalid_transition(
        queue
            .reject_cancel(RejectAttemptCancel {
                id: leased.id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: leased.attempt_count + 1,
                reason: "still working".to_owned(),
                status: None,
                now: 13,
            })
            .expect_err("a stale lease generation cannot answer"),
        "cancel_reject",
        "stale_attempt",
    );

    // The unchanged sticky law: the bound owner and generation still complete.
    let CompleteOutcome::Completed(done) = queue.complete(CompleteAttempt {
        id: leased.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: leased.attempt_count,
        now: 14,
    })?
    else {
        panic!("an executor with standing still completes its own attempt");
    };
    assert_eq!(done.state, AttemptState::Completed);
    assert_eq!(
        done.cancel_receipts().len(),
        1,
        "the outstanding request stays as evidence on the completed row"
    );

    // A settled attempt is reported, never re-asked or re-killed.
    assert!(matches!(
        queue.request_cancel(soft_request(leased.id, "peer-1", CancelStanding::PeerAgent))?,
        CancelRequestOutcome::AlreadySettled(_)
    ));
    assert!(matches!(
        queue.force_cancel(ForceAttemptCancel {
            id: leased.id,
            authority: ForceCancelAuthority::from_standing(CancelStanding::Authority, "owner-1")
                .expect("owner standing"),
            reason: None,
            now: 15,
        })?,
        ForceCancelOutcome::AlreadySettled(_)
    ));
    assert_eq!(
        queue.get(leased.id)?.expect("row").state,
        AttemptState::Completed,
        "a completed attempt is not retroactively cancelled"
    );
    Ok(())
}
