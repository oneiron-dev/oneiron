//! The Coach, the second base agent (owner ruling 2026-10-16): its own
//! principal row and its own stamp on the Dreamer's runner.
use super::*;

fn coach_id() -> EntityId {
    crate::codebase::entity_id_from_hash_material(b"oneiron.coach.authority.v1", &[]).unwrap()
}

fn attempt_id(outcome: EnqueueDreamerAttemptOutcome) -> crate::attempt_queue::AttemptId {
    let (EnqueueDreamerAttemptOutcome::Enqueued(status)
    | EnqueueDreamerAttemptOutcome::Existing(status)) = outcome;
    status.attempt.id
}

#[test]
fn skill_optimize_runs_under_the_coach_stamp_and_consolidation_under_the_dreamer() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let runner = DreamerRunnerStore::new(&vault);
    let skill = attempt_id(
        runner.enqueue_skill_optimize(EnqueueDreamerSkillOptimizeAttempt {
            input: rmpv::Value::Nil,
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: 10,
        })?,
    );
    let micro = attempt_id(
        runner.enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            input: rmpv::Value::Nil,
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: 10,
        })?,
    );
    let dreamer = vault.dreamer_authority()?.entity_ref();
    assert_ne!(coach_id(), dreamer);

    let stamp = vault.dreamer_attempt_authority(skill)?.unwrap();
    assert_eq!(stamp.actor, coach_id(), "SKILL-OPT is the Coach's job");
    assert_eq!(
        vault.dreamer_actor_for_attempt(skill)?,
        WriteActor::new(coach_id(), EdgeActorClass::System)
    );
    let envelope = vault.dreamer_proposal_envelope(&stamp.facet, skill)?;
    assert_eq!(envelope.actor().entity_ref(), coach_id());
    assert_eq!(envelope.approval(), ClaimApprovalStatus::Proposed);
    assert_eq!(
        vault.dreamer_attempt_authority(micro)?.unwrap().actor,
        dreamer
    );

    let receipts = vault.store.gate_decisions(100)?;
    let receipt = receipts
        .iter()
        .find(|r| r.decision_id.as_bytes() == stamp.receipt_id)
        .expect("the stamp's gate receipt");
    assert_eq!(receipt.reason_codes, ["gate.coach.facet_admitted"]);
    assert_eq!(
        receipt.actor_ref.as_deref(),
        Some(coach_id().to_hex().as_str())
    );
    Ok(())
}

#[test]
fn open_seeds_an_immutable_coach_row() -> Result<()> {
    let (dir, vault) = open_test_vault_with(embedding_test_config());
    let id = coach_id();
    let original = vault.get_raw(&id)?.expect("open seeds the Coach's row");
    assert_eq!(
        vault.get_entity_type(&id)?,
        Some(crate::registry::ENTITY_TYPE_MACHINE)
    );
    let at = TimeRange { start: 2, end: 2 };
    let err = vault
        .put_entity(
            &id,
            crate::registry::ENTITY_TYPE_MACHINE,
            at,
            2,
            b"not the Coach",
        )
        .expect_err("the Coach row cannot be rewritten");
    assert_eq!(err.kind(), crate::ErrorKind::DreamerActorImmutable);
    let err = vault
        .batch()
        .delete(&id)
        .commit()
        .expect_err("batch delete refuses the Coach");
    assert_eq!(err.kind(), crate::ErrorKind::DreamerActorImmutable);
    for reason in [
        crate::deletion::DeleteReason::UserDelete,
        crate::deletion::DeleteReason::UserHardDelete,
    ] {
        let err = vault
            .delete_entity_with_reason(&id, reason)
            .expect_err("the Coach cannot be deleted");
        assert_eq!(err.kind(), crate::ErrorKind::DreamerActorImmutable);
    }
    drop(vault);
    let reopened = Vault::open(dir.path(), embedding_test_config())?;
    assert_eq!(reopened.get_raw(&id)?.as_deref(), Some(original.as_slice()));
    Ok(())
}
