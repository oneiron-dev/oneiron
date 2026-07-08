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

fn enqueue(kind: &str, dedupe_key: Option<&str>, now: u64) -> EnqueueJob {
    EnqueueJob {
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
        Error::InvalidJobQueueTransition {
            action: got_action,
            state: got_state,
        } if got_action == action && got_state == state
    ));
}

#[test]
fn job_queue_enqueue_persists_required_fields() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);

    let EnqueueOutcome::Enqueued(job) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:1"), 10))?
    else {
        panic!("expected new job");
    };

    let persisted = queue.get(job.id)?.expect("persisted job");
    assert_eq!(persisted.kind, "claim_extraction");
    assert_eq!(persisted.payload, b"payload-10");
    assert_eq!(persisted.state, JobState::Queued);
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
fn job_queue_enqueue_is_idempotent_for_dedupe_key() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);

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
fn job_queue_pause_resume_are_durable_and_idempotent() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);
    let EnqueueOutcome::Enqueued(job) =
        queue.enqueue(enqueue("claim_extraction", Some("same"), 10))?
    else {
        panic!("expected enqueue");
    };

    let paused = queue.intervene(InterveneJob {
        id: job.id,
        kind: JobInterventionKind::Pause,
        actor: "dashboard".to_owned(),
        note: Some("hold branch".to_owned()),
        now: 20,
    })?;

    assert_eq!(paused.effect, JobInterventionEffect::Paused);
    assert_eq!(paused.record.state, JobState::Paused);
    assert_eq!(paused.record.lease_owner, None);
    assert_eq!(paused.record.events.len(), 1);
    assert_eq!(paused.record.events[0].sequence, 1);
    assert_eq!(paused.record.events[0].kind, JobInterventionKind::Pause);
    assert_eq!(paused.record.events[0].actor, "dashboard");
    assert_eq!(paused.record.events[0].note.as_deref(), Some("hold branch"));
    assert!(matches!(
        queue.claim(ClaimJob {
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
    assert_eq!(existing.id, job.id);

    let repeated_pause = queue.intervene(InterveneJob {
        id: job.id,
        kind: JobInterventionKind::Pause,
        actor: "dashboard".to_owned(),
        note: Some("hold branch".to_owned()),
        now: 23,
    })?;
    assert_eq!(repeated_pause.effect, JobInterventionEffect::AlreadyPaused);
    assert_eq!(repeated_pause.record.events.len(), 1);
    assert_eq!(repeated_pause.record.updated_at, 20);

    let resumed = queue.intervene(InterveneJob {
        id: job.id,
        kind: JobInterventionKind::Resume,
        actor: "dashboard".to_owned(),
        note: None,
        now: 30,
    })?;
    assert_eq!(resumed.effect, JobInterventionEffect::Resumed);
    assert_eq!(resumed.record.state, JobState::Queued);
    assert_eq!(resumed.record.events.len(), 2);
    assert_eq!(resumed.record.events[1].sequence, 2);
    assert_eq!(resumed.record.events[1].kind, JobInterventionKind::Resume);

    let repeated_resume = queue.intervene(InterveneJob {
        id: job.id,
        kind: JobInterventionKind::Resume,
        actor: "dashboard".to_owned(),
        note: None,
        now: 31,
    })?;
    assert_eq!(
        repeated_resume.effect,
        JobInterventionEffect::AlreadyResumed
    );
    assert_eq!(repeated_resume.record.events.len(), 2);
    assert_eq!(repeated_resume.record.updated_at, 30);

    let ClaimOutcome::Claimed(reclaimed) = queue.claim(ClaimJob {
        lease_owner: "worker-b".to_owned(),
        now: 40,
    })?
    else {
        panic!("expected resumed claim");
    };
    assert_eq!(reclaimed.id, job.id);
    assert_eq!(reclaimed.attempt_count, 1);

    Ok(())
}

#[test]
fn job_queue_pause_and_cancel_reject_leased_jobs() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);
    let EnqueueOutcome::Enqueued(job) =
        queue.enqueue(enqueue("claim_extraction", Some("leased"), 10))?
    else {
        panic!("expected enqueue");
    };
    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
        lease_owner: "worker-a".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claim");
    };

    let pause = queue
        .intervene(InterveneJob {
            id: job.id,
            kind: JobInterventionKind::Pause,
            actor: "dashboard".to_owned(),
            note: None,
            now: 30,
        })
        .unwrap_err();
    assert_invalid_transition(pause, "pause", "leased");

    let cancel = queue
        .intervene(InterveneJob {
            id: job.id,
            kind: JobInterventionKind::Cancel,
            actor: "dashboard".to_owned(),
            note: None,
            now: 31,
        })
        .unwrap_err();
    assert_invalid_transition(cancel, "cancel", "leased");

    let CompleteOutcome::Completed(completed) = queue.complete(CompleteJob {
        id: job.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: claimed.attempt_count,
        now: 40,
    })?
    else {
        panic!("expected leased job to remain completable");
    };
    assert_eq!(completed.state, JobState::Completed);
    assert!(completed.events.is_empty());

    Ok(())
}

#[test]
fn job_queue_cancel_is_terminal_and_clears_dedupe() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);
    let EnqueueOutcome::Enqueued(job) =
        queue.enqueue(enqueue("claim_extraction", Some("same"), 10))?
    else {
        panic!("expected enqueue");
    };

    let cancelled = queue.intervene(InterveneJob {
        id: job.id,
        kind: JobInterventionKind::Cancel,
        actor: "dashboard".to_owned(),
        note: Some("stop branch".to_owned()),
        now: 20,
    })?;

    assert_eq!(cancelled.effect, JobInterventionEffect::Cancelled);
    assert_eq!(cancelled.record.state, JobState::Cancelled);
    assert_eq!(cancelled.record.events.len(), 1);
    assert_eq!(cancelled.record.events[0].kind, JobInterventionKind::Cancel);
    assert!(matches!(
        queue.claim(ClaimJob {
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
    assert_ne!(replacement.id, job.id);

    let repeated_cancel = queue.intervene(InterveneJob {
        id: job.id,
        kind: JobInterventionKind::Cancel,
        actor: "dashboard".to_owned(),
        note: None,
        now: 23,
    })?;
    assert_eq!(
        repeated_cancel.effect,
        JobInterventionEffect::AlreadyCancelled
    );
    assert_eq!(repeated_cancel.record.events.len(), 1);
    assert_eq!(repeated_cancel.record.updated_at, 20);

    Ok(())
}

#[test]
fn job_queue_interrupt_records_event_without_changing_claimability() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);
    let EnqueueOutcome::Enqueued(job) = queue.enqueue(enqueue("claim_extraction", None, 10))?
    else {
        panic!("expected enqueue");
    };

    let interrupted = queue.intervene(InterveneJob {
        id: job.id,
        kind: JobInterventionKind::Interrupt,
        actor: "dashboard".to_owned(),
        note: Some("inject observation".to_owned()),
        now: 20,
    })?;

    assert_eq!(interrupted.effect, JobInterventionEffect::Interrupted);
    assert_eq!(interrupted.record.state, JobState::Queued);
    assert_eq!(interrupted.record.events.len(), 1);
    assert_eq!(
        interrupted.record.events[0].kind,
        JobInterventionKind::Interrupt
    );
    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
        lease_owner: "worker-a".to_owned(),
        now: 21,
    })?
    else {
        panic!("expected interrupted queued job to remain claimable");
    };
    assert_eq!(claimed.id, job.id);
    assert_eq!(claimed.events.len(), 1);

    Ok(())
}

#[test]
fn job_queue_intervention_events_keep_bounded_tail() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);
    let EnqueueOutcome::Enqueued(job) = queue.enqueue(enqueue("claim_extraction", None, 10))?
    else {
        panic!("expected enqueue");
    };

    let mut latest = None;
    for index in 0..(MAX_JOB_EVENTS_PER_RECORD + 2) {
        latest = Some(queue.intervene(InterveneJob {
            id: job.id,
            kind: JobInterventionKind::Interrupt,
            actor: "dashboard".to_owned(),
            note: Some(format!("event-{index}")),
            now: 20 + index as u64,
        })?);
    }
    let latest = latest.expect("intervention outcome");
    assert_eq!(latest.record.events.len(), MAX_JOB_EVENTS_PER_RECORD);
    assert_eq!(latest.record.events.first().unwrap().sequence, 3);
    assert_eq!(
        latest.record.events.last().unwrap().sequence,
        (MAX_JOB_EVENTS_PER_RECORD + 2) as u64
    );

    Ok(())
}

#[test]
fn job_queue_enqueue_uses_blake3_advisory_dedupe_key() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);

    let EnqueueOutcome::Enqueued(job) =
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
        .job_dedupe
        .get(&rtxn, &index_key)?
        .expect("dedupe row");
    assert_eq!(JobId::from_bytes(stored_id)?, job.id);

    Ok(())
}

#[test]
fn job_queue_enqueue_self_heals_legacy_dedupe_index_key() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);

    let EnqueueOutcome::Enqueued(job) =
        queue.enqueue(enqueue("claim_extraction", Some("same"), 10))?
    else {
        panic!("expected enqueue");
    };
    let blake3_key = dedupe_index_key("claim_extraction", "same");
    let legacy_key = legacy_dedupe_index_key("claim_extraction", "same");
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.job_dedupe.delete(&mut wtxn, &blake3_key)?;
        vault
            .store
            .job_dedupe
            .put(&mut wtxn, &legacy_key, job.id.as_bytes())?;
        wtxn.commit()?;
    }

    let EnqueueOutcome::Existing(existing) =
        queue.enqueue(enqueue("claim_extraction", Some("same"), 20))?
    else {
        panic!("expected legacy dedupe hit");
    };
    assert_eq!(existing.id, job.id);

    let rtxn = vault.store.env.read_txn()?;
    let stored_id = vault
        .store
        .job_dedupe
        .get(&rtxn, &blake3_key)?
        .expect("self-healed BLAKE3 dedupe row");
    assert_eq!(JobId::from_bytes(stored_id)?, job.id);
    assert!(vault.store.job_dedupe.get(&rtxn, &legacy_key)?.is_none());

    Ok(())
}

#[test]
fn job_queue_dedupe_key_is_scoped_by_kind() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);

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
fn job_queue_claim_is_atomic_and_returns_typed_states() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);

    assert_eq!(
        queue.claim(ClaimJob {
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

    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
        lease_owner: "worker-a".to_owned(),
        now: 30,
    })?
    else {
        panic!("expected claimed job");
    };
    assert_eq!(claimed.id, first.id);
    assert_eq!(claimed.state, JobState::Leased);
    assert_eq!(claimed.lease_owner.as_deref(), Some("worker-a"));
    assert_eq!(claimed.attempt_count, 1);
    assert_eq!(claimed.updated_at, 30);

    let persisted = queue.get(first.id)?.expect("claimed job persisted");
    assert_eq!(persisted, claimed);

    let ClaimOutcome::Claimed(next) = queue.claim(ClaimJob {
        lease_owner: "worker-b".to_owned(),
        now: 40,
    })?
    else {
        panic!("expected second claimed job");
    };
    assert_eq!(next.id, second.id);

    assert_eq!(
        queue.claim(ClaimJob {
            lease_owner: "worker-c".to_owned(),
            now: 50,
        })?,
        ClaimOutcome::Empty
    );

    Ok(())
}

#[test]
fn job_queue_claim_kind_skips_other_ready_jobs_without_leasing_them() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);

    let EnqueueOutcome::Enqueued(other) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:other"), 10))?
    else {
        panic!("expected other job enqueue");
    };
    let EnqueueOutcome::Enqueued(companion) =
        queue.enqueue(enqueue("companion_task", Some("companion:task"), 11))?
    else {
        panic!("expected companion job enqueue");
    };

    let ClaimOutcome::Claimed(claimed_companion) = queue.claim_kind(
        "companion_task",
        ClaimJob {
            lease_owner: "companion-worker".to_owned(),
            now: 20,
        },
    )?
    else {
        panic!("expected companion job claim");
    };
    assert_eq!(claimed_companion.id, companion.id);
    assert_eq!(claimed_companion.kind, "companion_task");
    assert_eq!(
        claimed_companion.lease_owner.as_deref(),
        Some("companion-worker")
    );

    let persisted_other = queue.get(other.id)?.expect("other job persisted");
    assert_eq!(persisted_other.state, JobState::Queued);
    assert_eq!(persisted_other.lease_owner, None);

    let ClaimOutcome::Claimed(claimed_other) = queue.claim(ClaimJob {
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
fn job_queue_claim_kind_preserves_stale_ready_index_for_skipped_kind() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);

    let EnqueueOutcome::Enqueued(other) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:stale-skip"), 10))?
    else {
        panic!("expected other job enqueue");
    };
    {
        let mut stale_record = other.clone();
        stale_record.backoff_until = Some(5);
        stale_record.updated_at = 11;
        let encoded = encode_record(&stale_record)?;
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .job_records
            .put(&mut wtxn, other.id.as_bytes(), &encoded)?;
        wtxn.commit()?;
    }

    assert_eq!(
        queue.claim_kind(
            "companion_task",
            ClaimJob {
                lease_owner: "companion-worker".to_owned(),
                now: 20,
            },
        )?,
        ClaimOutcome::Empty
    );

    let ClaimOutcome::Claimed(claimed_other) = queue.claim(ClaimJob {
        lease_owner: "generic-worker".to_owned(),
        now: 21,
    })?
    else {
        panic!("expected skipped stale-ready job to remain claimable");
    };
    assert_eq!(claimed_other.id, other.id);
    assert_eq!(claimed_other.kind, "claim_extraction");
    assert_eq!(claimed_other.backoff_until, None);
    assert_eq!(claimed_other.lease_owner.as_deref(), Some("generic-worker"));

    Ok(())
}

#[test]
fn job_queue_claim_treats_non_backoff_jobs_as_immediately_ready() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);

    let EnqueueOutcome::Enqueued(job) = queue.enqueue(enqueue("future-created", None, 1_000))?
    else {
        panic!("expected enqueue");
    };

    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
        lease_owner: "worker-a".to_owned(),
        now: 1,
    })?
    else {
        panic!("expected future-created job without backoff to be claimable");
    };
    assert_eq!(claimed.id, job.id);
    assert_eq!(claimed.created_at, 1_000);
    assert_eq!(claimed.backoff_until, None);
    assert_eq!(claimed.attempt_count, 1);

    Ok(())
}

#[test]
fn job_queue_claim_cleans_ready_key_id_mismatch_and_continues() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);

    let EnqueueOutcome::Enqueued(job) = queue.enqueue(enqueue("first", None, 10))? else {
        panic!("expected enqueue");
    };
    let stale_ready_key = ready_key(0, JobId { bytes: [0; 16] });
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .job_ready
            .put(&mut wtxn, &stale_ready_key, job.id.as_bytes())?;
        wtxn.commit()?;
    }

    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
        lease_owner: "worker-a".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claim past stale ready row");
    };
    assert_eq!(claimed.id, job.id);

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .job_ready
            .get(&rtxn, &stale_ready_key)?
            .is_none()
    );

    Ok(())
}

#[test]
fn job_queue_claim_cleans_malformed_ready_rows_and_continues() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);

    let EnqueueOutcome::Enqueued(job) = queue.enqueue(enqueue("first", None, 10))? else {
        panic!("expected enqueue");
    };
    let malformed_key = vec![0];
    let malformed_value_key = ready_key(0, JobId { bytes: [0; 16] });
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .job_ready
            .put(&mut wtxn, &malformed_key, job.id.as_bytes())?;
        vault
            .store
            .job_ready
            .put(&mut wtxn, &malformed_value_key, b"bad")?;
        wtxn.commit()?;
    }

    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
        lease_owner: "worker-a".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claim past malformed ready rows");
    };
    assert_eq!(claimed.id, job.id);

    let rtxn = vault.store.env.read_txn()?;
    assert!(vault.store.job_ready.get(&rtxn, &malformed_key)?.is_none());
    assert!(
        vault
            .store
            .job_ready
            .get(&rtxn, &malformed_value_key)?
            .is_none()
    );

    Ok(())
}

#[test]
fn job_queue_transitions_complete_is_idempotent_and_rejects_invalid_states() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);

    let EnqueueOutcome::Enqueued(job) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:complete"), 10))?
    else {
        panic!("expected enqueue");
    };

    let queued_complete = queue
        .complete(CompleteJob {
            id: job.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: 0,
            now: 11,
        })
        .unwrap_err();
    assert_invalid_transition(queued_complete, "complete", "queued");

    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
        lease_owner: "worker-a".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claimed job");
    };
    assert_eq!(claimed.id, job.id);

    let wrong_owner_complete = queue
        .complete(CompleteJob {
            id: job.id,
            lease_owner: "worker-b".to_owned(),
            attempt_count: claimed.attempt_count,
            now: 25,
        })
        .unwrap_err();
    assert_invalid_transition(wrong_owner_complete, "complete", "leased_by_other");

    let CompleteOutcome::Completed(completed) = queue.complete(CompleteJob {
        id: job.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: claimed.attempt_count,
        now: 30,
    })?
    else {
        panic!("expected complete");
    };
    assert_eq!(completed.state, JobState::Completed);
    assert_eq!(completed.lease_owner, None);
    assert_eq!(completed.backoff_until, None);
    assert_eq!(completed.last_error, None);
    assert_eq!(completed.payload, b"payload-10");
    assert_eq!(completed.run_id.as_deref(), Some("run-10"));
    assert_eq!(completed.dedupe_key.as_deref(), Some("turn:complete"));
    assert_eq!(completed.updated_at, 30);

    let CompleteOutcome::AlreadyCompleted(again) = queue.complete(CompleteJob {
        id: job.id,
        lease_owner: String::new(),
        attempt_count: 0,
        now: 40,
    })?
    else {
        panic!("expected idempotent complete");
    };
    assert_eq!(again.updated_at, 30);

    let completed_fail = queue
        .fail(FailJob {
            id: job.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: 0,
            reason: "boom".to_owned(),
            now: 50,
        })
        .unwrap_err();
    assert_invalid_transition(completed_fail, "fail", "completed");

    let completed_retry = queue
        .retry(RetryJob {
            id: job.id,
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
    assert_ne!(replacement.id, job.id);

    Ok(())
}

#[test]
fn job_queue_transitions_fail_is_idempotent_and_rejects_invalid_states() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);

    let EnqueueOutcome::Enqueued(job) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:fail"), 10))?
    else {
        panic!("expected enqueue");
    };

    let queued_fail = queue
        .fail(FailJob {
            id: job.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: 0,
            reason: "boom".to_owned(),
            now: 11,
        })
        .unwrap_err();
    assert_invalid_transition(queued_fail, "fail", "queued");

    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
        lease_owner: "worker-a".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claimed job");
    };
    assert_eq!(claimed.id, job.id);

    let wrong_owner_fail = queue
        .fail(FailJob {
            id: job.id,
            lease_owner: "worker-b".to_owned(),
            attempt_count: claimed.attempt_count,
            reason: "fatal".to_owned(),
            now: 25,
        })
        .unwrap_err();
    assert_invalid_transition(wrong_owner_fail, "fail", "leased_by_other");

    let FailOutcome::Failed(failed) = queue.fail(FailJob {
        id: job.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: claimed.attempt_count,
        reason: "fatal".to_owned(),
        now: 30,
    })?
    else {
        panic!("expected fail");
    };
    assert_eq!(failed.state, JobState::Failed);
    assert_eq!(failed.lease_owner, None);
    assert_eq!(failed.backoff_until, None);
    assert_eq!(failed.last_error.as_deref(), Some("fatal"));
    assert_eq!(failed.payload, b"payload-10");
    assert_eq!(failed.run_id.as_deref(), Some("run-10"));
    assert_eq!(failed.dedupe_key.as_deref(), Some("turn:fail"));

    let FailOutcome::AlreadyFailed(again) = queue.fail(FailJob {
        id: job.id,
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
        .complete(CompleteJob {
            id: job.id,
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
    assert_ne!(replacement.id, job.id);

    Ok(())
}

#[test]
fn job_queue_transitions_reject_stale_attempt_tokens() -> Result<()> {
    fn lease_second_attempt(queue: &JobQueue<'_>, dedupe_key: &str) -> Result<JobRecord> {
        let EnqueueOutcome::Enqueued(job) =
            queue.enqueue(enqueue("claim_extraction", Some(dedupe_key), 10))?
        else {
            panic!("expected enqueue");
        };
        let ClaimOutcome::Claimed(first_attempt) = queue.claim(ClaimJob {
            lease_owner: "worker-a".to_owned(),
            now: 20,
        })?
        else {
            panic!("expected first attempt");
        };
        assert_eq!(first_attempt.id, job.id);

        let RetryOutcome::Retried(_) = queue.retry(RetryJob {
            id: job.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: first_attempt.attempt_count,
            backoff_until: 30,
            last_error: Some("retryable".to_owned()),
            now: 25,
        })?;

        let ClaimOutcome::Claimed(second_attempt) = queue.claim(ClaimJob {
            lease_owner: "worker-a".to_owned(),
            now: 30,
        })?
        else {
            panic!("expected second attempt");
        };
        assert_eq!(second_attempt.id, job.id);
        assert_eq!(
            second_attempt.attempt_count,
            first_attempt.attempt_count + 1
        );
        Ok(second_attempt)
    }

    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);

    let complete_attempt = lease_second_attempt(&queue, "stale-complete")?;
    let stale_complete = queue
        .complete(CompleteJob {
            id: complete_attempt.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: complete_attempt.attempt_count - 1,
            now: 40,
        })
        .unwrap_err();
    assert_invalid_transition(stale_complete, "complete", "stale_attempt");

    let fail_attempt = lease_second_attempt(&queue, "stale-fail")?;
    let stale_fail = queue
        .fail(FailJob {
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
        .retry(RetryJob {
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
fn job_queue_transitions_reject_empty_failure_reasons() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);

    let EnqueueOutcome::Enqueued(job) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:empty-fail"), 10))?
    else {
        panic!("expected enqueue");
    };
    let ClaimOutcome::Claimed(mut claimed) = queue.claim(ClaimJob {
        lease_owner: "worker-a".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claim");
    };

    let err = queue
        .fail(FailJob {
            id: job.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: claimed.attempt_count,
            reason: String::new(),
            now: 30,
        })
        .unwrap_err();
    assert!(matches!(
        err,
        Error::InvalidJobQueueRecord(ERR_FAILURE_REASON_EMPTY)
    ));

    claimed.state = JobState::Failed;
    claimed.lease_owner = None;
    claimed.last_error = Some(String::new());
    let encoded = encode_record(&claimed)?;
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .job_records
            .put(&mut wtxn, claimed.id.as_bytes(), &encoded)?;
        wtxn.commit()?;
    }

    let err = queue.get(claimed.id).unwrap_err();
    assert!(matches!(
        err,
        Error::InvalidJobQueueRecord(ERR_FAILURE_REASON_EMPTY)
    ));

    Ok(())
}

#[test]
fn job_queue_transitions_retry_preserves_payload_provenance_and_backoff() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);

    let EnqueueOutcome::Enqueued(job) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:retry"), 10))?
    else {
        panic!("expected enqueue");
    };

    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
        lease_owner: "worker-a".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claimed job");
    };
    assert_eq!(claimed.id, job.id);
    assert_eq!(claimed.attempt_count, 1);

    let wrong_owner_retry = queue
        .retry(RetryJob {
            id: job.id,
            lease_owner: "worker-b".to_owned(),
            attempt_count: claimed.attempt_count,
            backoff_until: 100,
            last_error: Some("rate limited".to_owned()),
            now: 25,
        })
        .unwrap_err();
    assert_invalid_transition(wrong_owner_retry, "retry", "leased_by_other");

    let RetryOutcome::Retried(retried) = queue.retry(RetryJob {
        id: job.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: claimed.attempt_count,
        backoff_until: 100,
        last_error: Some("rate limited".to_owned()),
        now: 30,
    })?;
    assert_eq!(retried.id, job.id);
    assert_eq!(retried.state, JobState::Queued);
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
    assert_eq!(duplicate_pending.id, job.id);

    assert_eq!(
        queue.claim(ClaimJob {
            lease_owner: "worker-b".to_owned(),
            now: 99,
        })?,
        ClaimOutcome::Empty
    );

    let ClaimOutcome::Claimed(second_attempt) = queue.claim(ClaimJob {
        lease_owner: "worker-b".to_owned(),
        now: 100,
    })?
    else {
        panic!("expected claim after backoff");
    };
    assert_eq!(second_attempt.id, job.id);
    assert_eq!(second_attempt.attempt_count, 2);
    assert_eq!(second_attempt.backoff_until, None);
    assert_eq!(second_attempt.last_error.as_deref(), Some("rate limited"));
    assert_eq!(second_attempt.payload, b"payload-10");
    assert_eq!(second_attempt.run_id.as_deref(), Some("run-10"));
    assert_eq!(second_attempt.dedupe_key.as_deref(), Some("turn:retry"));

    Ok(())
}

#[test]
fn job_queue_claim_cleans_missing_record_ready_and_dedupe() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);

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
            .job_records
            .delete(&mut wtxn, first.id.as_bytes())?;
        vault
            .store
            .job_records
            .delete(&mut wtxn, second.id.as_bytes())?;
        wtxn.commit()?;
    }

    assert_eq!(
        queue.claim(ClaimJob {
            lease_owner: "worker-a".to_owned(),
            now: 20,
        })?,
        ClaimOutcome::Empty
    );

    let index_key = dedupe_index_key("claim_extraction", "turn:missing");
    let second_index_key = dedupe_index_key("claim_extraction", "turn:missing-too");
    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(vault.store.job_ready.iter(&rtxn)?.next().is_none());
        assert!(vault.store.job_dedupe.get(&rtxn, &index_key)?.is_none());
        assert!(
            vault
                .store
                .job_dedupe
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
fn job_queue_decode_fails_closed_on_record_key_id_mismatch() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);

    let EnqueueOutcome::Enqueued(job) = queue.enqueue(enqueue("claim_extraction", None, 10))?
    else {
        panic!("expected enqueue");
    };
    let mut corrupt = job.clone();
    corrupt.id = JobId::now();
    let encoded = encode_record(&corrupt)?;
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .job_records
            .put(&mut wtxn, job.id.as_bytes(), &encoded)?;
        wtxn.commit()?;
    }

    let err = queue
        .claim(ClaimJob {
            lease_owner: "worker-a".to_owned(),
            now: 20,
        })
        .unwrap_err();
    assert!(matches!(
        err,
        Error::InvalidJobQueueRecord("job_records key/id mismatch")
    ));

    Ok(())
}

#[test]
fn job_queue_decode_fails_closed_on_lease_owner_state_mismatch() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);

    let EnqueueOutcome::Enqueued(job) = queue.enqueue(enqueue("claim_extraction", None, 10))?
    else {
        panic!("expected enqueue");
    };
    let mut corrupt = job.clone();
    corrupt.state = JobState::Leased;
    corrupt.lease_owner = None;
    let encoded = encode_record(&corrupt)?;
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .job_records
            .put(&mut wtxn, job.id.as_bytes(), &encoded)?;
        wtxn.commit()?;
    }

    let err = queue.get(job.id).unwrap_err();
    assert!(matches!(
        err,
        Error::InvalidJobQueueRecord("leased job must have a lease owner")
    ));

    Ok(())
}

#[test]
fn job_queue_cleanup_recovers_stale_leases_through_claim() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);

    let EnqueueOutcome::Enqueued(job) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:stale"), 10))?
    else {
        panic!("expected enqueue");
    };
    let ClaimOutcome::Claimed(first_attempt) = queue.claim(ClaimJob {
        lease_owner: "worker-a".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected first claim");
    };

    let report = queue.cleanup_leases(CleanupJobLeases {
        now: 40,
        lease_timeout_secs: 10,
    })?;
    assert_eq!(report.pending, 1);
    assert_eq!(report.running, 0);
    assert_eq!(report.stale_requeued, 1);
    assert_eq!(
        report.retry_reason_count(JobQueueRetryReason::LeaseTimeout),
        1
    );

    let requeued = queue.get(job.id)?.expect("requeued job");
    assert_eq!(requeued.state, JobState::Queued);
    assert_eq!(requeued.lease_owner, None);
    assert_eq!(requeued.attempt_count, first_attempt.attempt_count);
    assert_eq!(requeued.last_error.as_deref(), Some("lease_timeout"));
    assert_eq!(requeued.updated_at, 40);

    let stale_complete = queue
        .complete(CompleteJob {
            id: job.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: first_attempt.attempt_count,
            now: 41,
        })
        .unwrap_err();
    assert_invalid_transition(stale_complete, "complete", "queued");

    let ClaimOutcome::Claimed(second_attempt) = queue.claim(ClaimJob {
        lease_owner: "worker-b".to_owned(),
        now: 42,
    })?
    else {
        panic!("expected reclaim through claim");
    };
    assert_eq!(second_attempt.id, job.id);
    assert_eq!(second_attempt.lease_owner.as_deref(), Some("worker-b"));
    assert_eq!(
        second_attempt.attempt_count,
        first_attempt.attempt_count + 1
    );

    Ok(())
}

#[test]
fn job_queue_cleanup_rejects_zero_timeout_without_requeuing() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);

    let EnqueueOutcome::Enqueued(job) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:zero"), 10))?
    else {
        panic!("expected enqueue");
    };
    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
        lease_owner: "worker-a".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claim");
    };

    let err = queue
        .cleanup_leases(CleanupJobLeases {
            now: 20,
            lease_timeout_secs: 0,
        })
        .unwrap_err();
    assert!(matches!(
        err,
        Error::InvalidJobQueueRecord(ERR_LEASE_TIMEOUT_ZERO)
    ));

    let persisted = queue.get(job.id)?.expect("leased job");
    assert_eq!(persisted.state, JobState::Leased);
    assert_eq!(persisted.lease_owner.as_deref(), Some("worker-a"));
    assert_eq!(
        queue.claim(ClaimJob {
            lease_owner: "worker-b".to_owned(),
            now: 21,
        })?,
        ClaimOutcome::Empty
    );
    assert!(matches!(
        queue.complete(CompleteJob {
            id: job.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: claimed.attempt_count,
            now: 22,
        })?,
        CompleteOutcome::Completed(_)
    ));

    Ok(())
}

#[test]
fn job_queue_cleanup_does_not_duplicate_completed_jobs() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);

    let EnqueueOutcome::Enqueued(job) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:done"), 10))?
    else {
        panic!("expected enqueue");
    };
    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
        lease_owner: "worker-a".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claim");
    };
    let CompleteOutcome::Completed(_) = queue.complete(CompleteJob {
        id: job.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: claimed.attempt_count,
        now: 30,
    })?
    else {
        panic!("expected complete");
    };

    let report = queue.cleanup_leases(CleanupJobLeases {
        now: 1_000,
        lease_timeout_secs: 1,
    })?;
    assert_eq!(report.done, 1);
    assert_eq!(report.pending, 0);
    assert_eq!(report.running, 0);
    assert_eq!(report.stale_requeued, 0);
    assert_eq!(
        queue.claim(ClaimJob {
            lease_owner: "worker-b".to_owned(),
            now: 1_001,
        })?,
        ClaimOutcome::Empty
    );

    Ok(())
}

#[test]
fn job_queue_cleanup_reports_counts_and_retry_reasons() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);

    let EnqueueOutcome::Enqueued(backoff_job) =
        queue.enqueue(enqueue("backoff", Some("turn:backoff"), 10))?
    else {
        panic!("expected enqueue");
    };
    let ClaimOutcome::Claimed(backoff_claim) = queue.claim(ClaimJob {
        lease_owner: "worker-a".to_owned(),
        now: 11,
    })?
    else {
        panic!("expected claim");
    };
    let RetryOutcome::Retried(_) = queue.retry(RetryJob {
        id: backoff_job.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: backoff_claim.attempt_count,
        backoff_until: 80,
        last_error: Some("provider said secret text".to_owned()),
        now: 12,
    })?;
    let InterveneOutcome {
        effect: JobInterventionEffect::Paused,
        ..
    } = queue.intervene(InterveneJob {
        id: backoff_job.id,
        kind: JobInterventionKind::Pause,
        actor: "cleanup-test".to_owned(),
        note: None,
        now: 13,
    })?
    else {
        panic!("expected pause");
    };

    let EnqueueOutcome::Enqueued(stale_job) =
        queue.enqueue(enqueue("stale", Some("turn:stale"), 13))?
    else {
        panic!("expected enqueue");
    };
    let ClaimOutcome::Claimed(stale_claim) = queue.claim(ClaimJob {
        lease_owner: "worker-stale".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected stale claim");
    };
    assert_eq!(stale_claim.id, stale_job.id);

    let EnqueueOutcome::Enqueued(live_job) =
        queue.enqueue(enqueue("live", Some("turn:live"), 21))?
    else {
        panic!("expected enqueue");
    };
    let ClaimOutcome::Claimed(live_claim) = queue.claim(ClaimJob {
        lease_owner: "worker-live".to_owned(),
        now: 30,
    })?
    else {
        panic!("expected live claim");
    };
    assert_eq!(live_claim.id, live_job.id);

    let EnqueueOutcome::Enqueued(done_job) =
        queue.enqueue(enqueue("done", Some("turn:done"), 31))?
    else {
        panic!("expected enqueue");
    };
    let ClaimOutcome::Claimed(done_claim) = queue.claim(ClaimJob {
        lease_owner: "worker-done".to_owned(),
        now: 32,
    })?
    else {
        panic!("expected done claim");
    };
    assert_eq!(done_claim.id, done_job.id);
    let CompleteOutcome::Completed(_) = queue.complete(CompleteJob {
        id: done_job.id,
        lease_owner: "worker-done".to_owned(),
        attempt_count: done_claim.attempt_count,
        now: 33,
    })?
    else {
        panic!("expected complete");
    };

    let EnqueueOutcome::Enqueued(failed_job) =
        queue.enqueue(enqueue("failed", Some("turn:failed"), 34))?
    else {
        panic!("expected enqueue");
    };
    let ClaimOutcome::Claimed(failed_claim) = queue.claim(ClaimJob {
        lease_owner: "worker-failed".to_owned(),
        now: 35,
    })?
    else {
        panic!("expected failed claim");
    };
    assert_eq!(failed_claim.id, failed_job.id);
    let FailOutcome::Failed(_) = queue.fail(FailJob {
        id: failed_job.id,
        lease_owner: "worker-failed".to_owned(),
        attempt_count: failed_claim.attempt_count,
        reason: "fatal".to_owned(),
        now: 36,
    })?
    else {
        panic!("expected fail");
    };

    let EnqueueOutcome::Enqueued(queued_job) =
        queue.enqueue(enqueue("queued", Some("turn:queued"), 37))?
    else {
        panic!("expected enqueue");
    };

    let report = queue.cleanup_leases(CleanupJobLeases {
        now: 39,
        lease_timeout_secs: 10,
    })?;
    assert_eq!(report.pending, 3);
    assert_eq!(report.running, 1);
    assert_eq!(report.failed, 1);
    assert_eq!(report.done, 1);
    assert_eq!(report.stale_requeued, 1);
    assert_eq!(
        report.retry_reason_count(JobQueueRetryReason::LeaseTimeout),
        1
    );
    assert_eq!(
        report.retry_reason_count(JobQueueRetryReason::RetryBackoff),
        1
    );

    let requeued = queue.get(stale_job.id)?.expect("stale job persisted");
    assert_eq!(requeued.state, JobState::Queued);
    assert_eq!(requeued.lease_owner, None);
    assert_eq!(
        queue.get(live_job.id)?.expect("live job").state,
        JobState::Leased
    );
    assert_eq!(
        queue.get(done_job.id)?.expect("done job").state,
        JobState::Completed
    );
    assert_eq!(
        queue.get(failed_job.id)?.expect("failed job").state,
        JobState::Failed
    );
    assert_eq!(
        queue.get(queued_job.id)?.expect("queued job").state,
        JobState::Queued
    );

    Ok(())
}

#[test]
fn job_queue_cleanup_metrics_have_stable_privacy_preserving_labels() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);
    let before = job_queue_cleanup_metrics_snapshot();

    let EnqueueOutcome::Enqueued(job) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:metrics"), 10))?
    else {
        panic!("expected enqueue");
    };
    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
        lease_owner: "worker-secret-owner".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claim");
    };
    assert_eq!(claimed.id, job.id);

    queue.cleanup_leases(CleanupJobLeases {
        now: 40,
        lease_timeout_secs: 10,
    })?;

    let after = job_queue_cleanup_metrics_snapshot();
    assert!(after.runs > before.runs);
    assert!(after.stale_requeued > before.stale_requeued);
    let labels = after
        .retry_reasons
        .iter()
        .map(|counter| counter.reason.as_str())
        .collect::<Vec<_>>();
    assert_eq!(labels, ["lease_timeout", "retry_backoff"]);
    assert!(
        after.retry_reasons[JobQueueRetryReason::LeaseTimeout.metric_index()].count
            > before.retry_reasons[JobQueueRetryReason::LeaseTimeout.metric_index()].count
    );

    Ok(())
}

#[test]
fn job_queue_cleanup_log_span_has_stable_privacy_preserving_fields() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = JobQueue::new(&vault);
    let capture = TelemetryCapture::default();

    let EnqueueOutcome::Enqueued(job) =
        queue.enqueue(enqueue("claim_extraction", Some("turn:logs"), 10))?
    else {
        panic!("expected enqueue");
    };
    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
        lease_owner: "worker-secret-owner".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected claim");
    };
    assert_eq!(claimed.id, job.id);

    tracing::subscriber::with_default(capture.clone(), || {
        queue.cleanup_leases(CleanupJobLeases {
            now: 40,
            lease_timeout_secs: 10,
        })
    })?;

    let records = capture.records.lock().unwrap();
    let span = records
        .iter()
        .find(|record| record.kind == "span" && record.name == "job_queue_cleanup")
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
    let id = JobId::now();
    let key = ready_key(42, id);
    assert_eq!(decode_ready_key(&key)?, (42, id));
    Ok(())
}
