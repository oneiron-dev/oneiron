use super::super::*;
use super::support::*;
use crate::attempt_queue::*;
use crate::deletion::DeleteReason;
use crate::error::{ArtifactError, Error, Result};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::{TimeRange, Vault};

fn audit_and_blobs<P: Backend>(ports: &P) -> Result<()> {
    let a = id(51);
    let b = id(52);
    let actor = id(53);
    let person = id(54);
    let record = ChangeLogRecord {
        id: [7; 16],
        entity: a,
        op: ChangeOp::Create,
        actor_principal: actor,
        actor_person: Some(person),
        occurred_at: 90,
        recorded_at: 100,
        input_hash: [8; 32],
        patch: Some(b"[]".to_vec()),
        reason: None,
    };
    let mut txn = ports.write()?;
    ports.port_changelog_append(&mut txn, &record)?;
    ports.port_changelog_append(&mut txn, &record)?;
    assert_eq!(
        ports.port_changelog_list_by_entity(&txn, &a, 10)?,
        vec![record.clone()]
    );
    assert_eq!(
        ports.port_changelog_list_by_actor(&txn, &actor, 10)?,
        vec![record.clone()]
    );
    assert!(
        ports
            .port_changelog_list_by_actor(&txn, &person, 10)?
            .is_empty()
    );
    for reference in [a, b] {
        ports.port_entity_put(&mut txn, &reference, &row(ENTITY_TYPE_PERSON, b"reference"))?;
    }
    let occurred = TimeRange { start: 1, end: 1 };
    let hash = ports.port_blob_put(&mut txn, &a, b"payload", occurred, 1)?;
    assert_eq!(
        ports.port_blob_put(&mut txn, &b, b"payload", occurred, 1)?,
        hash
    );
    // Retrying the same reference does not acquire an anonymous extra hold.
    ports.port_blob_put(&mut txn, &b, b"payload", occurred, 1)?;
    assert_eq!(ports.port_blob_get(&txn, &hash)?, Some(b"payload".to_vec()));
    assert!(ports.port_blob_sign_upload_url(&hash, 60)?.is_none());
    assert!(ports.port_blob_sign_download_url(&hash, 60)?.is_none());
    assert!(!ports.port_blob_delete(&mut txn, &a, &hash, DeleteReason::UserDelete)?);
    assert!(ports.port_blob_get(&txn, &hash)?.is_some());
    assert!(ports.port_blob_delete(&mut txn, &b, &hash, DeleteReason::UserDelete)?);
    assert!(ports.port_blob_get(&txn, &hash)?.is_none());
    ports.port_blob_put(&mut txn, &a, b"payload", occurred, 1)?;
    ports.port_blob_put(&mut txn, &b, b"payload", occurred, 1)?;
    assert!(ports.port_blob_delete(&mut txn, &a, &hash, DeleteReason::GdprDelete)?);
    assert!(ports.port_blob_get(&txn, &hash)?.is_none());
    assert!(ports.port_entity_get(&txn, &a)?.is_none());
    assert!(ports.port_entity_get(&txn, &b)?.is_none());
    ports.commit(txn)?;
    let mut txn = ports.write()?;
    let mut changed = record.clone();
    changed.reason = Some("overwrite".into());
    assert!(matches!(
        ports.port_changelog_append(&mut txn, &changed),
        Err(Error::InvariantViolation(_))
    ));
    drop(txn);
    let txn = ports.read()?;
    assert!(
        ports
            .port_changelog_list_by_entity(&txn, &a, 100)?
            .contains(&record)
    );
    Ok(())
}
fn jobs<P: Backend>(ports: &P) -> Result<()> {
    let mut txn = ports.write()?;
    let input = EnqueueAttempt {
        kind: "ports.test".into(),
        payload: b"work".to_vec(),
        dedupe_key: Some("once".into()),
        run_id: None,
        now: 999,
    };
    let EnqueueOutcome::Enqueued(queued) = ports.port_job_enqueue(&mut txn, input.clone())? else {
        panic!("new queue")
    };
    assert_eq!(queued.created_at, 100); // supplied wall time cannot bypass injection
    assert!(
        matches!(ports.port_job_enqueue(&mut txn,input.clone())?,EnqueueOutcome::Existing(row) if row.id==queued.id)
    );
    let ClaimOutcome::Claimed(claimed) = ports.port_job_claim(
        &mut txn,
        Some("ports.test"),
        ClaimAttempt {
            lease_owner: "worker".into(),
            now: 999,
        },
    )?
    else {
        panic!("ready work")
    };
    assert_eq!(claimed.claimed_at, Some(100));
    assert_eq!(claimed.attempt_count, 1);
    let complete = CompleteAttempt {
        id: claimed.id,
        lease_owner: "worker".into(),
        attempt_count: claimed.attempt_count,
        now: 999,
    };
    let mut stale = complete.clone();
    stale.attempt_count = 0;
    assert!(matches!(
        ports.port_job_complete(&mut txn, stale),
        Err(Error::Artifact(
            ArtifactError::InvalidAttemptQueueTransition { .. }
        ))
    ));
    assert!(
        matches!(ports.port_job_complete(&mut txn,complete.clone())?,CompleteOutcome::Completed(row) if row.updated_at==100)
    );
    assert!(matches!(
        ports.port_job_complete(&mut txn, complete)?,
        CompleteOutcome::AlreadyCompleted(_)
    ));
    let EnqueueOutcome::Enqueued(next) = ports.port_job_enqueue(&mut txn, input)? else {
        panic!("dedupe retired")
    };
    assert_ne!(next.id, claimed.id);
    let ClaimOutcome::Claimed(claimed) = ports.port_job_claim(
        &mut txn,
        Some("ports.test"),
        ClaimAttempt {
            lease_owner: "worker".into(),
            now: 999,
        },
    )?
    else {
        panic!("next ready work")
    };
    let fail = FailAttempt {
        id: claimed.id,
        lease_owner: "worker".into(),
        attempt_count: claimed.attempt_count,
        reason: "failed".into(),
        now: 999,
    };
    assert!(
        matches!(ports.port_job_fail(&mut txn,fail.clone())?,FailOutcome::Failed(row) if row.updated_at==100)
    );
    assert!(matches!(
        ports.port_job_fail(&mut txn, fail)?,
        FailOutcome::AlreadyFailed(_)
    ));
    assert!(matches!(
        ports.port_job_claim(
            &mut txn,
            Some("ports.test"),
            ClaimAttempt {
                lease_owner: "worker".into(),
                now: 999
            }
        )?,
        ClaimOutcome::Empty
    ));
    ports.commit(txn)
}
#[test]
fn audit_and_reference_counted_blobs_lmdb_and_memory() -> Result<()> {
    let (_temp, vault, memory, _clock) = fixtures();
    audit_and_blobs(&vault)?;
    audit_and_blobs(&memory)
}
#[test]
fn job_lifecycle_lmdb_and_memory() -> Result<()> {
    let (_temp, vault, memory, _clock) = fixtures();
    jobs(&vault)?;
    jobs(&memory)
}
#[test]
fn clock_is_injected_and_persisted_floor_survives_reopen() -> Result<()> {
    let clock = ManualClock::new(100);
    let vault_config = config(&clock);
    let (temp, vault) = crate::test_util::open_test_vault_with(vault_config.clone());
    let enqueue = |vault: &Vault| -> Result<u64> {
        let mut txn = vault.store.env.write_txn()?;
        let EnqueueOutcome::Enqueued(record) = vault.port_job_enqueue(
            &mut txn,
            EnqueueAttempt {
                kind: "clock.test".into(),
                payload: Vec::new(),
                dedupe_key: None,
                run_id: None,
                now: 0,
            },
        )?
        else {
            panic!("new work")
        };
        txn.commit()?;
        Ok(record.created_at)
    };
    assert_eq!(enqueue(&vault)?, 100);
    clock.set(120);
    assert_eq!(enqueue(&vault)?, 120);
    clock.set(1);
    assert_eq!(enqueue(&vault)?, 120);
    drop(vault);
    let reopened = Vault::open(temp.path(), vault_config)?;
    assert_eq!(enqueue(&reopened)?, 120);
    // Sharing one source in a config must not share the per-vault floor.
    let (_other_temp, other) = crate::test_util::open_test_vault_with(config(&clock));
    assert_eq!(enqueue(&other)?, 1);
    Ok(())
}

#[test]
fn production_mutations_audit_atomically_and_keep_world_time() -> Result<()> {
    let clock = ManualClock::new(700);
    let (_dir, vault) = crate::test_util::open_test_vault_with(config(&clock));
    let entity = vault.new_entity_id()?;
    let occurred = TimeRange { start: 20, end: 25 };
    vault.put_entity(&entity, ENTITY_TYPE_PERSON, occurred, 30, b"original")?;
    let records = {
        let txn = vault.store.env.read_txn()?;
        vault.port_changelog_list_by_entity(&txn, &entity, 100)?
    };
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].op, ChangeOp::Create);
    assert_eq!(records[0].occurred_at, 20);
    assert_eq!(records[0].recorded_at, 700);
    assert_eq!(records[0].actor_person, None);
    assert_eq!(records[0].patch, None);
    let failed: Result<()> = vault.with_write_txn(|txn| {
        vault.port_entity_put(
            txn,
            &entity,
            &EntityRecord {
                entity_type: ENTITY_TYPE_PERSON,
                occurred,
                learned_at: 30,
                body: b"rolled back".to_vec(),
            },
        )?;
        Err(Error::InvariantViolation("abort fixture"))
    });
    assert!(failed.is_err());
    let after = {
        let txn = vault.store.env.read_txn()?;
        vault.port_changelog_list_by_entity(&txn, &entity, 100)?
    };
    assert_eq!(records, after);
    assert_eq!(vault.get(&entity)?, Some(b"original".to_vec()));
    Ok(())
}

#[test]
fn repeated_id_source_never_overwrites_queue_even_after_reopen() -> Result<()> {
    struct Repeated;
    impl IdGen for Repeated {
        fn ulid(&self) -> [u8; 16] {
            [0x71; 16]
        }
    }
    let clock = ManualClock::new(100);
    let mut config = config(&clock);
    config.store_clock = StoreClock::new(clock, std::sync::Arc::new(Repeated));
    let (dir, vault) = crate::test_util::open_test_vault_with(config.clone());
    let enqueue = |vault: &Vault| -> Result<AttemptRecord> {
        match AttemptQueue::new(vault).enqueue(EnqueueAttempt {
            kind: "clock.unique".into(),
            payload: vec![],
            dedupe_key: None,
            run_id: None,
            now: 900,
        })? {
            EnqueueOutcome::Enqueued(record) => Ok(record),
            EnqueueOutcome::Existing(_) => panic!("no dedupe key"),
        }
    };
    let first = enqueue(&vault)?;
    let second = enqueue(&vault)?;
    assert_ne!(first.id, second.id);
    drop(vault);
    let vault = Vault::open(dir.path(), config)?;
    let third = enqueue(&vault)?;
    assert_ne!(first.id, third.id);
    assert_ne!(second.id, third.id);
    assert_eq!(AttemptQueue::new(&vault).get(first.id)?, Some(first));
    assert_eq!(AttemptQueue::new(&vault).get(second.id)?, Some(second));
    Ok(())
}

#[test]
fn scoped_enqueue_composes_without_collapsing_actor_dedupe() -> Result<()> {
    let clock = ManualClock::new(300);
    let (_dir, vault) = crate::test_util::open_test_vault_with(config(&clock));
    let queue = AttemptQueue::new(&vault);
    let input = EnqueueAttempt {
        kind: "scope.clock".into(),
        payload: vec![],
        dedupe_key: Some("same".into()),
        run_id: None,
        now: 999,
    };
    let mut txn = vault.store.env.write_txn()?;
    let first = queue.port_job_enqueue_scoped(
        &mut txn,
        input.clone(),
        JobScope {
            task_ref: Some("task-a".into()),
            dedupe_actor_ref: Some("actor-a"),
        },
    )?;
    let EnqueueOutcome::Enqueued(first) = first else {
        panic!("first")
    };
    let second = queue.port_job_enqueue_scoped(
        &mut txn,
        input.clone(),
        JobScope {
            task_ref: Some("task-b".into()),
            dedupe_actor_ref: Some("actor-b"),
        },
    )?;
    let EnqueueOutcome::Enqueued(second) = second else {
        panic!("second actor")
    };
    assert_ne!(first.id, second.id);
    assert_eq!(first.created_at, 300);
    assert_eq!(first.task_ref.as_deref(), Some("task-a"));
    assert_eq!(second.task_ref.as_deref(), Some("task-b"));
    let repeat = queue.port_job_enqueue_scoped(
        &mut txn,
        input,
        JobScope {
            task_ref: Some("not-a-rebind".into()),
            dedupe_actor_ref: Some("actor-a"),
        },
    )?;
    assert_eq!(repeat, EnqueueOutcome::Existing(first.clone()));
    drop(txn);
    assert_eq!(queue.get(first.id)?, None);
    assert_eq!(queue.get(second.id)?, None);
    Ok(())
}
