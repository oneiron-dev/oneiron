use super::*;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::edge::EdgeActorClass;
use crate::task_verb::{TaskAssignee, TaskCreateSpec, TaskResultInput, TaskTerminalDisposition};
use crate::{EntityId, TimeRange, Vault, VaultConfig};
use rmpv::Value;

#[test]
fn retention_archives_only_old_completed_tasks_and_resolver_restores_same_bytes()
-> crate::Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let actor = EntityId::now();
    vault.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let facade = vault.memory(actor, EdgeActorClass::Human);
    let now = crate::unix_seconds_now();
    let mut ids = Vec::new();
    for age in [91 * 86400, 2 * 86400, 92 * 86400] {
        let task = facade
            .tasks_create(
                &TaskCreateSpec::new(Value::from("retention"), None, None, Some(now - age))
                    .with_assignee(TaskAssignee::Peer { actor_ref: actor }),
            )
            .expect("create")
            .task_ref
            .unwrap();
        if ids.len() < 2 {
            facade
                .land_task_result(
                    task,
                    &TaskResultInput {
                        result_ref: actor,
                        disposition: TaskTerminalDisposition::Completed,
                        finished_at: now - age,
                    },
                )
                .expect("complete");
        }
        ids.push(task);
    }
    let raw = vault.get_raw(&ids[0])?;
    assert_eq!(vault.task_retention_days()?, 90);
    for days in [Some(0), None] {
        vault.set_task_retention_days(days)?;
        assert!(scan_cleanup_candidates(&vault)?.is_empty());
    }
    vault.set_task_retention_days(Some(90))?;
    assert_eq!(
        scan_cleanup_candidates(&vault)?,
        vec![CleanupCandidate {
            entity: ids[0],
            kind: CleanupKind::CompletedTask
        }]
    );
    super::rollout::close_blockers_for_test(&vault);
    set_cleanup_posture(&vault, CleanupPosture::AutoWithDigest)?;
    let report = run_vault_cleanup(&vault, &crate::attempt_queue::AttemptId::now())?;
    assert_eq!(report.archived, vec![ids[0]]);
    assert_eq!(vault.get_raw(&ids[0])?, raw);
    let evidence = EntityId::now();
    let mut body = ClaimBody::new(
        crate::PREDICATE_PROVIDER_ENRICHMENT,
        ClaimSubject::Entity(ids[0]),
        Value::Map(vec![(
            Value::from("provider"),
            Value::from("retention-test"),
        )]),
        0.99,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::Observed);
    vault.put_claim(
        &evidence,
        &body,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    let count = vault.count_entities_by_type(crate::registry::ENTITY_TYPE_TASK)?;
    let found = crate::evaluate_entity_resolution_waterfall(
        &vault,
        &[crate::EntityResolutionCandidate {
            subject: ids[0],
            confidence_claim_ref: evidence,
        }],
        false,
    )?;
    assert_eq!(found.selected, Some(ids[0]));
    assert_eq!(vault.archived_entity(&ids[0])?, None);
    assert_eq!(vault.get_raw(&ids[0])?, raw);
    assert_eq!(
        vault.count_entities_by_type(crate::registry::ENTITY_TYPE_TASK)?,
        count
    );
    Ok(())
}

#[test]
fn archive_purge_previews_bytes_requires_owner_and_returns_erase_receipts() -> crate::Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let ids = [EntityId::now(), EntityId::now()];
    for id in ids {
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_SUMMARY,
            TimeRange { start: 1, end: 1 },
            1,
            b"archived summary",
        )?;
    }
    let run = run_vault_cleanup(&vault, &crate::attempt_queue::AttemptId::now())?;
    accept_cleanup_proposal(&vault, &run.proposal.unwrap())?;
    assert!(
        vault
            .memory(owner, EdgeActorClass::Agent)
            .preview_archive_purge(&ids)
            .is_err()
    );
    let facade = vault.memory(owner, EdgeActorClass::Human);
    let preview = facade.preview_archive_purge(&ids).expect("owner preview");
    assert_eq!(preview.entries().len(), 2);
    assert_eq!(
        preview.record_bytes(),
        2 * (25 + b"archived summary".len() as u64)
    );
    vault.restore_archived(&ids[0])?;
    let receipts = facade.confirm_archive_purge(&preview);
    assert_eq!(receipts.len(), 2);
    for (id, receipt) in receipts {
        if id == ids[0] {
            assert!(receipt.is_err());
            assert!(vault.get_raw(&id)?.is_some());
        } else {
            let receipt = receipt.expect("erase");
            assert!(receipt.existed);
            assert!(receipt.receipt_ref.is_some());
            assert!(vault.get_raw(&id)?.is_none());
        }
    }
    Ok(())
}

#[test]
fn completed_attempt_retention_is_reversible_and_never_changes_queue_bytes() -> crate::Result<()> {
    use crate::attempt_queue::{
        AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, EnqueueAttempt,
    };
    let dir = tempfile::tempdir()?;
    let old = 1_000;
    let clock = crate::ports::ManualClock::new(old);
    let vault = Vault::open(
        dir.path(),
        VaultConfig {
            store_clock: clock.bundle(),
            ..VaultConfig::default()
        },
    )?;
    let queue = AttemptQueue::new(&vault);
    queue.enqueue(EnqueueAttempt {
        kind: "test.retained".into(),
        payload: vec![1, 2, 3],
        dedupe_key: None,
        run_id: None,
        now: old,
    })?;
    let ClaimOutcome::Claimed(record) = queue.claim(ClaimAttempt {
        lease_owner: "test".into(),
        now: old,
    })?
    else {
        panic!("claimed");
    };
    queue.complete(CompleteAttempt {
        id: record.id,
        lease_owner: "test".into(),
        attempt_count: record.attempt_count,
        now: old,
    })?;
    let before = queue.get(record.id)?;
    clock.set(old + 91 * 86_400);
    for days in [None, Some(0)] {
        vault.set_task_retention_days(days)?;
        assert!(scan_cleanup_candidates(&vault)?.is_empty());
    }
    vault.set_task_retention_days(Some(90))?;
    let report = run_vault_cleanup(&vault, &crate::attempt_queue::AttemptId::now())?;
    assert!(report.archived.is_empty());
    assert_eq!(report.candidates[0].kind, CleanupKind::CompletedAttempt);
    accept_cleanup_proposal(&vault, &report.proposal.unwrap())?;
    assert!(queue.list()?.is_empty());
    assert_eq!(queue.get(record.id)?, before);
    vault.restore_archived_attempt(record.id)?;
    assert_eq!(queue.list()?, vec![before.unwrap()]);
    Ok(())
}
