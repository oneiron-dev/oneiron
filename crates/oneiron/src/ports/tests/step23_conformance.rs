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
    assert_eq!(
        ports.port_changelog_list_by_entity(&txn, &a, 10)?,
        vec![record]
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
