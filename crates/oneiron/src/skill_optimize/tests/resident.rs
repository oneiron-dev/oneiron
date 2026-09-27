use super::*;

fn stamped_resident_receipt(
    vault: &Vault,
    resident: &EntityId,
    skill: &EntityId,
    now: u64,
) -> Result<String> {
    let queue = AttemptQueue::new(vault);
    let EnqueueOutcome::Enqueued(row) = queue.enqueue(EnqueueAttempt {
        kind: "resident.optimize".into(),
        payload: Vec::new(),
        dedupe_key: None,
        run_id: None,
        now,
    })?
    else {
        panic!("new attempt")
    };
    vault.load_resident_skill_pack(row.id, resident, skill, now)?;
    let ClaimOutcome::Claimed(leased) = queue.claim_kind(
        "resident.optimize",
        ClaimAttempt {
            lease_owner: "resident-opt".into(),
            now: now + 1,
        },
    )?
    else {
        panic!("claim")
    };
    queue.fail(crate::attempt_queue::FailAttempt {
        id: row.id,
        lease_owner: "resident-opt".into(),
        attempt_count: leased.attempt_count,
        reason: "failed".into(),
        now: now + 2,
    })?;
    Ok(attempt_pack_receipt_id(&row.id))
}

#[test]
fn resident_optimization_reads_only_its_fork_and_preserves_the_owner_on_proposal() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let a = EntityId::now();
    let b = EntityId::now();
    put_actor(&vault, &a);
    put_actor(&vault, &b);
    let (base, _) = put_standard_active(&vault, "shared.workflow");
    let make = |resident: EntityId, name: &str| -> Result<EntityId> {
        let id = EntityId::now();
        let mut record = vault.fork_skill_for_resident(&resident, &base, &id, name, t(20), 20)?;
        record.lifecycle_status = SkillLifecycle::Active;
        vault.update_skill_record(&id, &record, t(21), 21)?;
        Ok(id)
    };
    let own = make(a, "resident.a.workflow")?;
    let other = make(b, "resident.b.workflow")?;
    set_skill_optimize_min_outcomes(&vault, 2)?;
    let mut at = 30_u64;
    while dev_receipts(&vault, &own)?.len() < 2 || held_out_receipts(&vault, &own)?.is_empty() {
        assert!(at < 1000, "reserve must populate");
        let receipt = stamped_resident_receipt(&vault, &a, &own, at)?;
        record_attribution_evidence(
            &vault,
            &OutcomeEvidence::new(receipt, a, AttemptOutcome::Failed, at + 3)
                .with_skill(own)
                .with_routing_facts(true, true),
        )?;
        let cursor = read_attribution_cursor(&vault)?;
        let judgments = run_attribution_projector(&vault, cursor)?;
        project_skill_reliability(&vault, &judgments)?;
        at += 10;
    }
    assert!(
        optimize_candidates(&vault)?.is_empty(),
        "vault-wide wake must not edit a resident fork"
    );
    assert!(optimize_candidates_for_resident(&vault, &b)?.is_empty());
    assert_eq!(optimize_candidates_for_resident(&vault, &a)?[0].skill, own);
    let author = StubAuthor::editing();
    let outcome = run_skill_optimize_for_resident(
        &vault,
        a,
        enqueue_attempt(&vault, None, 5),
        &author,
        t(300),
        301,
    )?;
    assert_eq!(outcome.skill, Some(own));
    let proposal = stored(&vault, &outcome.proposal.expect("resident proposal"));
    assert_eq!(crate::skill::resident_of(&proposal)?, Some(a));
    assert_eq!(proposal.forked_from, Some(base));
    assert_eq!(author.brief().skill, own);
    assert_eq!(crate::skill::resident_of(&stored(&vault, &other))?, Some(b));
    Ok(())
}
