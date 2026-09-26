use super::*;
use crate::dreamer_runner::{
    DreamerConsolidationScope, DreamerRunnerStore, EnqueueDreamerAttempt,
    EnqueueDreamerAttemptOutcome, EnqueueDreamerConsolidationAttempt,
    EnqueueDreamerSkillOptimizeAttempt,
};
use crate::test_util::{embedding_test_config, open_test_vault_with};
#[test]
fn micro_meso_and_skill_optimization_share_actor_and_receipt_ledger() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let runner = DreamerRunnerStore::new(&vault);
    let mut attempts = Vec::new();
    for scope in [
        DreamerConsolidationScope::Micro,
        DreamerConsolidationScope::Meso,
    ] {
        attempts.push(
            runner.enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
                scope,
                input: rmpv::Value::Nil,
                parent_attempt: None,
                dedupe_key: None,
                run_id: None,
                now: 10,
            })?,
        );
    }
    attempts.push(
        runner.enqueue_skill_optimize(EnqueueDreamerSkillOptimizeAttempt {
            input: rmpv::Value::Nil,
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: 10,
        })?,
    );
    let authority = vault.dreamer_authority()?;
    assert_eq!(authority.actor_class(), EdgeActorClass::System);
    assert_eq!(
        vault.get_entity_type(&authority.entity_ref())?.unwrap(),
        crate::registry::ENTITY_TYPE_MACHINE,
    );
    for outcome in attempts {
        let (EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status)) = outcome;
        let stamp = vault.dreamer_attempt_authority(status.attempt.id)?.unwrap();
        assert_eq!(stamp.actor, authority.entity_ref());
        assert_eq!(
            vault.dreamer_actor_for_attempt(status.attempt.id)?,
            authority
        );
        let envelope = vault.dreamer_proposal_envelope(&stamp.facet, status.attempt.id)?;
        assert_eq!(envelope.actor(), authority);
        assert_eq!(envelope.approval(), ClaimApprovalStatus::Proposed);
    }
    let records = vault.store.gate_decisions(100)?;
    let authority_records: Vec<_> = records
        .iter()
        .filter(|r| r.content_kind == "dreamer_authority")
        .collect();
    assert_eq!(authority_records.len(), 3);
    assert!(authority_records.iter().all(|r| r.actor_ref.as_deref()
        == Some(&authority.entity_ref().to_hex())
        && r.actor_class == "system"));
    assert_eq!(vault.dreamer_authority()?, authority);
    let (_other_dir, other_node) = open_test_vault_with(embedding_test_config());
    assert_eq!(other_node.dreamer_authority()?, authority);
    Ok(())
}

#[test]
fn vault_open_seeds_system_actor_without_claiming_resident_runs() -> Result<()> {
    let (dir, vault) = open_test_vault_with(embedding_test_config());
    let dreamer = vault.dreamer_authority()?;
    assert_eq!(dreamer.actor_class(), EdgeActorClass::System);
    assert_eq!(
        vault.get_entity_type(&dreamer.entity_ref())?,
        Some(crate::registry::ENTITY_TYPE_MACHINE)
    );
    let resident = crate::WriteActor::new(EntityId::now(), EdgeActorClass::Agent);
    vault.put_entity(
        &resident.entity_ref(),
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange { start: 1, end: 1 },
        1,
        b"resident",
    )?;
    let outcome = DreamerRunnerStore::new(&vault).enqueue(EnqueueDreamerAttempt {
        attempt_type: crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE.into(),
        input: rmpv::Value::Nil,
        parent_attempt: None,
        dedupe_key: None,
        run_id: None,
        now: 2,
    })?;
    let (EnqueueDreamerAttemptOutcome::Enqueued(status)
    | EnqueueDreamerAttemptOutcome::Existing(status)) = outcome;
    assert_eq!(vault.dreamer_attempt_authority(status.attempt.id)?, None);
    assert_ne!(resident, dreamer);
    drop(vault);
    let reopened = Vault::open(dir.path(), embedding_test_config())?;
    assert_eq!(reopened.dreamer_authority()?, dreamer);
    Ok(())
}

/// A host can supply a per-vault, agent-authored recipe after the actor exists.
/// The engine keeps the content as data; the host interprets it and the
/// resulting write still crosses the ordinary Gate under the Dreamer stamp.
#[test]
fn agent_authored_weave_recipe_executes_with_system_write_stamp() -> Result<()> {
    use crate::skill::{SkillGovernanceTier, SkillLifecycle, SkillRecord};
    use crate::{ClaimCandidate, ClaimSubject};
    use rmpv::Value;

    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let actor = vault.dreamer_authority()?;
    let skill_id = EntityId::now();
    let recipe = SkillRecord::new(
        "weave.recipe",
        "Per-vault weave recipe supplied by the host agent",
        "v1",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        0.5,
        true,
        false,
        Vec::new(),
        Value::Map(vec![
            (Value::from("author"), Value::from("resident-agent")),
            (Value::from("predicate"), Value::from("profile.weave_note")),
            (
                Value::from("value"),
                Value::from("derived from retained spans"),
            ),
        ]),
    )
    .with_governance_tier(SkillGovernanceTier::Standard);
    let at = TimeRange { start: 3, end: 3 };
    vault.put_skill_record(&skill_id, &recipe, at, 3)?;
    let mut admitted = recipe;
    admitted.lifecycle_status = SkillLifecycle::Active;
    vault.update_skill_record(&skill_id, &admitted, at, 4)?;

    let outcome = DreamerRunnerStore::new(&vault).enqueue(EnqueueDreamerAttempt {
        attempt_type: "weave.recipe".into(),
        input: Value::from(skill_id.to_hex()),
        parent_attempt: None,
        dedupe_key: None,
        run_id: None,
        now: 5,
    })?;
    let (EnqueueDreamerAttemptOutcome::Enqueued(status)
    | EnqueueDreamerAttemptOutcome::Existing(status)) = outcome;
    let loaded = vault.get_skill_record(&skill_id)?.expect("admitted recipe");
    assert_eq!(loaded.lifecycle_status, SkillLifecycle::Active);
    let Value::Map(ref fields) = loaded.provenance else {
        panic!("agent-authored recipe is a map");
    };
    let field = |name| {
        fields
            .iter()
            .find_map(|(key, value)| (key.as_str() == Some(name)).then(|| value.as_str()))
            .flatten()
            .expect("recipe field")
    };
    let subject = EntityId::now();
    vault.put_entity(
        &subject,
        crate::registry::ENTITY_TYPE_PERSON,
        at,
        3,
        b"weave subject",
    )?;
    let claim = EntityId::now();
    let envelope = vault.dreamer_proposal_envelope("weave.recipe", status.attempt.id)?;
    assert_eq!(envelope.actor(), actor);
    vault
        .batch()
        .claim_candidate(
            &claim,
            ClaimCandidate::new(
                field("predicate"),
                ClaimSubject::Entity(subject),
                Value::from(field("value")),
                0.8,
            ),
            &envelope,
            at,
            5,
        )
        .commit()?;
    let body = vault.get_claim(&claim)?.expect("weave proposal landed");
    assert_eq!(body.predicate, "profile.weave_note");
    let Value::Map(evidence) = body.evidence.expect("envelope evidence") else {
        panic!("envelope evidence must be a map");
    };
    assert!(evidence.iter().any(|(key, value)| {
        key.as_str() == Some("actor_class")
            && value.as_u64() == Some(u64::from(EdgeActorClass::System as u8))
    }));
    assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
    assert!(evidence.iter().any(|(key, value)| {
        key.as_str() == Some("actor_entity_ref")
            && value.as_slice() == Some(actor.entity_ref().as_bytes().as_slice())
    }));
    let stamp = vault
        .dreamer_attempt_authority(status.attempt.id)?
        .expect("the recipe attempt is bound to the Dreamer");
    assert_eq!(stamp.actor, actor.entity_ref());
    assert!(vault.store.gate_decisions(1_000)?.iter().any(|decision| {
        decision.decision_id.as_bytes() == stamp.receipt_id
            && decision.actor_class == "system"
            && decision.actor_ref.as_deref() == Some(actor.entity_ref().to_hex().as_str())
    }));
    Ok(())
}

#[test]
fn changed_system_actor_body_invalidates_queued_authority() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let actor = vault.dreamer_authority()?;
    let outcome = DreamerRunnerStore::new(&vault).enqueue(EnqueueDreamerAttempt {
        attempt_type: "weave".into(),
        input: rmpv::Value::Nil,
        parent_attempt: None,
        dedupe_key: None,
        run_id: None,
        now: 1,
    })?;
    let (EnqueueDreamerAttemptOutcome::Enqueued(status)
    | EnqueueDreamerAttemptOutcome::Existing(status)) = outcome;
    vault.put_entity(
        &actor.entity_ref(),
        crate::registry::ENTITY_TYPE_MACHINE,
        TimeRange { start: 2, end: 2 },
        2,
        b"not the Dreamer",
    )?;
    assert!(vault.dreamer_authority().is_err());
    assert!(vault.dreamer_attempt_authority(status.attempt.id).is_err());
    assert!(vault.dreamer_actor_for_attempt(status.attempt.id).is_err());
    Ok(())
}
