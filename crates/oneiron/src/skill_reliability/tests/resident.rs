use super::*;
use crate::error::Result;

fn stamped_resident_receipt(
    vault: &Vault,
    resident: &EntityId,
    skill: &EntityId,
) -> Result<String> {
    let queue = AttemptQueue::new(vault);
    let dispatcher = AgentDispatcher::new(vault);
    let now = vault.now_recorded_at();
    let AgentDispatchOutcome::Dispatched(dispatched) =
        dispatcher.dispatch_default_base(None, None, None, now)?
    else {
        panic!("new attempt")
    };
    let row = dispatched.attempt;

    let ClaimOutcome::Claimed(leased) = queue.claim_kind(
        DREAMER_RUNNER_ATTEMPT_KIND,
        ClaimAttempt {
            lease_owner: "resident-rank".into(),
            now: vault.now_recorded_at(),
        },
    )?
    else {
        panic!("claim")
    };
    assert_eq!(leased.id, row.id);
    vault.load_resident_skill_pack(
        row.id,
        resident,
        skill,
        "resident-rank",
        leased.attempt_count,
        "fixture/model@1",
        now,
    )?;
    queue.fail(crate::attempt_queue::FailAttempt {
        id: row.id,
        lease_owner: "resident-rank".into(),
        attempt_count: leased.attempt_count,
        reason: "failed".into(),
        now: vault.now_recorded_at(),
    })?;
    let receipt_id = attempt_pack_receipt_id(&row.id);
    // The projector mints numerical claims only for anchored outcomes
    // (projector.rs:535-548): stamp the harness's held-out score beside the
    // executor revision, so the routed failure below moves the posterior.
    let mut receipt =
        crate::receipt::attempt_pack_receipt(vault, &receipt_id)?.expect("stamped pack receipt");
    receipt.fields.insert(
        FIELD_SKILL_LEARNING_ANCHOR.to_owned(),
        serde_json::to_string(&crate::learning::Anchor::HeldOut).expect("anchor encodes"),
    );
    crate::receipt::overwrite_attempt_pack_receipt_for_test(vault, &receipt)?;
    Ok(receipt_id)
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
            .load_attempt_skill_pack(
                attempt.id,
                &a_old,
                "resident-pack",
                1,
                "fixture/model@1",
                26
            )
            .is_err()
    );
    assert!(
        vault
            .load_resident_skill_pack(
                attempt.id,
                &b,
                &a_old,
                "resident-pack",
                1,
                "fixture/model@1",
                26
            )
            .is_err()
    );
    assert!(queue.get(attempt.id)?.expect("attempt").manifest.is_empty());
    let ClaimOutcome::Claimed(pack_lease) = queue.claim_kind(
        "resident.pack",
        ClaimAttempt {
            lease_owner: "resident-pack".into(),
            now: 27,
        },
    )?
    else {
        panic!("claim pack")
    };
    let loaded = vault.load_resident_skill_pack(
        attempt.id,
        &a,
        &a_old,
        "resident-pack",
        pack_lease.attempt_count,
        "fixture/model@1",
        27,
    )?;
    assert_eq!(loaded.record.version, "1");
    // The typed dispatch freezes one project/type cell for every receipt; the
    // ranking must read that cell, not the vault query (see
    // reliability_query_for_receipt).
    let mut query_receipt = String::new();
    for at in 30..38 {
        let receipt = stamped_resident_receipt(&vault, &a, &a_old)?;
        query_receipt.clone_from(&receipt);
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
    let ranked = rank_resident_skill_versions(
        &vault,
        &a,
        &[a_old, a_new],
        "fixture/model@1",
        &reliability_query_for_receipt(&vault, &query_receipt),
    )?;
    assert_eq!(ranked[0].0, a_new);
    assert!(ranked[0].1 > ranked[1].1);
    assert!(
        rank_resident_skill_versions(
            &vault,
            &a,
            &[a_old, b_version],
            "fixture/model@1",
            &reliability_query(),
        )
        .is_err()
    );
    assert!(
        rank_resident_skill_versions(
            &vault,
            &a,
            &[a_old, base],
            "fixture/model@1",
            &reliability_query(),
        )
        .is_err()
    );
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
    let (selected, _) = vault
        .select_and_load_resident_skill_pack(
            selection.id,
            &a,
            &[a_old, a_new],
            "resident-selected",
            leased.attempt_count,
            "fixture/model@1",
            &reliability_query_for_receipt(&vault, &query_receipt),
            40,
        )?
        .expect("candidate");
    assert_eq!(selected, a_new);
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
