use super::*;

fn stamped_resident_receipt(
    vault: &Vault,
    resident: &EntityId,
    skill: &EntityId,
    now: u64,
) -> Result<String> {
    let now = vault.now_recorded_at().max(now);
    let queue = AttemptQueue::new(vault);
    let dispatcher = AgentDispatcher::new(vault);
    let AgentDispatchOutcome::Dispatched(dispatched) =
        dispatcher.dispatch_default_base(None, None, None, now)?
    else {
        panic!("new attempt")
    };
    let row = dispatched.attempt;

    let ClaimOutcome::Claimed(leased) = queue.claim_kind(
        DREAMER_RUNNER_ATTEMPT_KIND,
        ClaimAttempt {
            lease_owner: "resident-opt".into(),
            now,
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
        "resident-opt",
        leased.attempt_count,
        "fixture/model@1",
        now,
    )?;
    // L16: settlement.rs refuses generic `fail` for a typed dispatch attempt; fail through the typed ladder.
    let fail_now = vault.now_recorded_at().max(now);
    crate::failure_ladder::FailureLadder::new(vault).handle_attempt_failure(
        crate::failure_ladder::HandleAttemptFailure {
            attempt_id: row.id,
            lease_owner: "resident-opt".into(),
            attempt_count: leased.attempt_count,
            evidence: crate::failure_ladder::TypedFailureEvidence {
                evidence_ref: None,
                verdict: crate::failure_ladder::TypedFailureVerdict::Indeterminate,
                tier: None,
                stable_reason: "failed".into(),
            },
            blocked_reports: Vec::new(),
            pre_fail_checkpoint_ref: EntityId::now(),
            qa_thread_ref: EntityId::now(),
            retry_at: fail_now,
            now: fail_now,
        },
        crate::failure_ladder::FailureScopePolicy::auto(crate::failure_ladder::FailureScope {
            agent_ref: vault
                .get_seeded_agent_definition_by_logical_id("sys.default")?
                .unwrap()
                .0
                .to_hex(),
            skill_ref: None,
        }),
    )?;
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
    let own = make(a, "resident.workflow")?;
    let other = make(b, "resident.workflow")?;
    set_skill_optimize_min_outcomes(&vault, 2)?;
    for (resident, skill) in [(a, own), (b, other)] {
        let mut at = 30_u64;
        while dev_receipts(&vault, &skill)?.len() < 2
            || held_out_receipts(&vault, &skill)?.is_empty()
        {
            assert!(at < 1000, "reserve must populate");
            let receipt = stamped_resident_receipt(&vault, &resident, &skill, at)?;
            record_attribution_evidence(
                &vault,
                &OutcomeEvidence::new(receipt, resident, AttemptOutcome::Failed, at + 3)
                    .with_skill(skill)
                    .with_routing_facts(true, true),
            )?;
            let cursor = read_attribution_cursor(&vault)?;
            let judgments = run_attribution_projector(&vault, cursor)?;
            project_skill_reliability(&vault, &judgments)?;
            at += 10;
        }
    }
    let (global, _) = put_standard_active(&vault, "resident.workflow");
    attribute_defects_across_split(&vault, &global, "resident.workflow");
    assert_eq!(
        optimize_candidates(&vault)?[0].skill,
        global,
        "vault-wide wake must see only its own same-named skill"
    );
    assert_eq!(
        optimize_candidates_for_resident(&vault, &b)?[0].skill,
        other
    );
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
    assert_eq!(
        optimize_candidates_for_resident(&vault, &b)?[0].skill,
        other,
        "A's pending question must not suppress B's same-named fork"
    );
    assert_eq!(
        optimize_candidates(&vault)?[0].skill,
        global,
        "A's pending question must not suppress the unowned lane"
    );
    Ok(())
}

#[test]
fn optimizer_proposal_cannot_change_resident_across_recreation() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let a = EntityId::now();
    let b = EntityId::now();
    put_actor(&vault, &a);
    put_actor(&vault, &b);
    let (base, _) = put_standard_active(&vault, "shared.recreate");
    let fork_id = EntityId::now();
    let mut fork =
        vault.fork_skill_for_resident(&a, &base, &fork_id, "resident.recreate", t(20), 20)?;
    fork.lifecycle_status = SkillLifecycle::Active;
    vault.update_skill_record(&fork_id, &fork, t(21), 21)?;
    set_skill_optimize_min_outcomes(&vault, 2)?;
    let mut at = 30_u64;
    while dev_receipts(&vault, &fork_id)?.len() < 2
        || held_out_receipts(&vault, &fork_id)?.is_empty()
    {
        assert!(at < 1000);
        let receipt = stamped_resident_receipt(&vault, &a, &fork_id, at)?;
        record_attribution_evidence(
            &vault,
            &OutcomeEvidence::new(receipt, a, AttemptOutcome::Failed, at + 3)
                .with_skill(fork_id)
                .with_routing_facts(true, true),
        )?;
        let judgments = run_attribution_projector(&vault, read_attribution_cursor(&vault)?)?;
        project_skill_reliability(&vault, &judgments)?;
        at += 10;
    }
    let proposal_id = run_skill_optimize_for_resident(
        &vault,
        a,
        enqueue_attempt(&vault, None, 5),
        &StubAuthor::editing(),
        t(300),
        301,
    )?
    .proposal
    .expect("proposal");
    let original = stored(&vault, &proposal_id);
    let mut swapped = original.clone();
    let Value::Map(entries) = &mut swapped.provenance else {
        panic!("provenance")
    };
    entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("residentActor"))
        .expect("owner")
        .1 = Value::from(b.to_hex());
    let raw = crate::skill::encode_skill_record(&swapped)?;
    assert_eq!(
        vault
            .batch()
            .delete(&proposal_id)
            .put(&proposal_id, ENTITY_TYPE_SKILL, t(302), 302, &raw)
            .commit()
            .expect_err("same-batch reassignment")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert_eq!(stored(&vault, &proposal_id), original);
    assert!(vault.delete_entity(&proposal_id)?);
    assert_eq!(
        vault
            .batch()
            .put_replicated(&proposal_id, ENTITY_TYPE_SKILL, t(303), 303, None, &raw)
            .commit()
            .expect_err("replay cannot reassign optimizer origin")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    // The local deletion dominates the older same-owner replay: it is refused,
    // and it never permits a new owner on this proposal ID.
    assert_eq!(
        vault
            .batch()
            .put_replicated(
                &proposal_id,
                ENTITY_TYPE_SKILL,
                t(304),
                304,
                None,
                &crate::skill::encode_skill_record(&original)?,
            )
            .commit()
            .expect_err("a deletion here dominates the replay")
            .kind(),
        ErrorKind::InvariantViolation
    );
    assert!(vault.get_skill_record(&proposal_id)?.is_none());
    Ok(())
}
