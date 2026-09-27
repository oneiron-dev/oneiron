use super::*;
use crate::error::Result;

fn stamped_resident_receipt(
    vault: &Vault,
    resident: &EntityId,
    skill: &EntityId,
) -> Result<String> {
    let queue = AttemptQueue::new(vault);
    let EnqueueOutcome::Enqueued(row) = queue.enqueue(EnqueueAttempt {
        kind: "resident.rank".into(),
        payload: Vec::new(),
        dedupe_key: None,
        run_id: None,
        now: 10,
    })?
    else {
        panic!("new attempt")
    };
    vault.load_resident_skill_pack(row.id, resident, skill, 11)?;
    let ClaimOutcome::Claimed(leased) = queue.claim_kind(
        "resident.rank",
        ClaimAttempt {
            lease_owner: "resident-rank".into(),
            now: 12,
        },
    )?
    else {
        panic!("claim")
    };
    queue.fail(crate::attempt_queue::FailAttempt {
        id: row.id,
        lease_owner: "resident-rank".into(),
        attempt_count: leased.attempt_count,
        reason: "failed".into(),
        now: 13,
    })?;
    Ok(attempt_pack_receipt_id(&row.id))
}

#[test]
fn version_bandit_ranks_only_one_residents_forks_and_own_receipts() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let a = EntityId::now();
    let b = EntityId::now();
    put_actor(&vault, &a);
    put_actor(&vault, &b);
    let base = EntityId::now();
    put_active(
        &vault,
        &base,
        record("shared.base", ClaimSource::UserStated, false),
    );
    let make = |resident: EntityId, id: EntityId| -> Result<EntityId> {
        let mut fork =
            vault.fork_skill_for_resident(&resident, &base, &id, "resident.version", t(20), 20)?;
        fork.lifecycle_status = SkillLifecycle::Active;
        vault.update_skill_record(&id, &fork, t(21), 21)?;
        Ok(id)
    };
    let a_old = make(a, EntityId::now())?;
    let a_new = make(a, EntityId::now())?;
    let b_version = make(b, EntityId::now())?;
    let queue = AttemptQueue::new(&vault);
    let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(EnqueueAttempt {
        kind: "resident.pack".into(),
        payload: Vec::new(),
        dedupe_key: None,
        run_id: None,
        now: 25,
    })?
    else {
        panic!("new attempt")
    };
    assert!(
        vault
            .load_attempt_skill_pack(attempt.id, &a_old, 26)
            .is_err()
    );
    assert!(
        vault
            .load_resident_skill_pack(attempt.id, &b, &a_old, 26)
            .is_err()
    );
    assert!(queue.get(attempt.id)?.expect("attempt").manifest.is_empty());
    let loaded = vault.load_resident_skill_pack(attempt.id, &a, &a_old, 27)?;
    assert_eq!(loaded.record.version, "1");
    for at in 30..38 {
        let receipt = stamped_resident_receipt(&vault, &a, &a_old)?;
        assert!(
            record_attribution_evidence(
                &vault,
                &OutcomeEvidence::new(&receipt, a, AttemptOutcome::Failed, at)
                    .with_skill(a_new)
                    .with_routing_facts(true, true),
            )
            .is_err(),
            "the same name/version does not make another fork's receipt ours"
        );
        record_attribution_evidence(
            &vault,
            &OutcomeEvidence::new(receipt, a, AttemptOutcome::Failed, at)
                .with_skill(a_old)
                .with_routing_facts(true, true),
        )?;
    }
    let rows = run_attribution_projector(&vault, 0)?;
    project_skill_reliability(&vault, &rows)?;
    let ranked = rank_resident_skill_versions(&vault, &a, &[a_old, a_new])?;
    assert_eq!(ranked[0].0, a_new);
    assert!(ranked[0].1 > ranked[1].1);
    assert!(rank_resident_skill_versions(&vault, &a, &[a_old, b_version]).is_err());
    assert!(rank_resident_skill_versions(&vault, &a, &[a_old, base]).is_err());
    let EnqueueOutcome::Enqueued(selection) = queue.enqueue(EnqueueAttempt {
        kind: "resident.selected".into(),
        payload: Vec::new(),
        dedupe_key: None,
        run_id: None,
        now: 39,
    })?
    else {
        panic!("new selection attempt")
    };
    let (selected, _) = vault
        .select_and_load_resident_skill_pack(selection.id, &a, &[a_old, a_new], 40)?
        .expect("candidate");
    assert_eq!(selected, a_new);
    let ClaimOutcome::Claimed(leased) = queue.claim_kind(
        "resident.selected",
        ClaimAttempt {
            lease_owner: "resident-selected".into(),
            now: 41,
        },
    )?
    else {
        panic!("claim selected attempt")
    };
    queue.fail(crate::attempt_queue::FailAttempt {
        id: selection.id,
        lease_owner: "resident-selected".into(),
        attempt_count: leased.attempt_count,
        reason: "failed".into(),
        now: 42,
    })?;
    let selected_receipt = attempt_pack_receipt_id(&selection.id);
    assert!(
        record_attribution_evidence(
            &vault,
            &OutcomeEvidence::new(&selected_receipt, a, AttemptOutcome::Failed, 43)
                .with_skill(a_old)
                .with_routing_facts(true, true)
        )
        .is_err(),
        "an unselected fork cannot claim the winner's terminal receipt"
    );
    record_attribution_evidence(
        &vault,
        &OutcomeEvidence::new(&selected_receipt, a, AttemptOutcome::Failed, 43)
            .with_skill(a_new)
            .with_routing_facts(true, true),
    )?;
    assert_eq!(skill_reliability_posterior(&vault, &a_new)?, None);
    assert_eq!(skill_reliability_posterior(&vault, &b_version)?, None);
    // The same manifest without the fork's exact version is not evidence.
    let old_receipt = stamped_receipt_for_revision(&vault, "resident.version", "1.0.0");
    vault.with_write_txn(|txn| {
        crate::skill::resident::bind_receipt_in_txn(&vault, txn, &old_receipt, &a)?;
        crate::skill::resident::bind_skill_in_txn(&vault, txn, &old_receipt, &a_new)
    })?;
    assert!(
        record_attribution_evidence(
            &vault,
            &OutcomeEvidence::new(old_receipt, a, AttemptOutcome::Failed, 40)
                .with_skill(a_new)
                .with_routing_facts(true, true),
        )
        .is_err()
    );
    Ok(())
}
