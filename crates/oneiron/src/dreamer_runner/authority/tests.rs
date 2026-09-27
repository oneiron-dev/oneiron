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
        assert_eq!(
            stamp.facet,
            dreamer_facet_for_job_type(&status.payload.attempt_type).unwrap()
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

struct UnreachableWeaveDelegate;

impl crate::dreamer_wake::DreamerAttemptExecutor for UnreachableWeaveDelegate {
    async fn execute(
        &mut self,
        _: &crate::dreamer_runner::DreamerAdmittedAttempt,
        _: &mut crate::dreamer_wake::WakeAttemptContext<'_>,
    ) -> Result<crate::dreamer_wake::DreamerAttemptExecution> {
        panic!("a weave attempt must not enter the consolidation executor")
    }
}

struct RecipeInterpreter;
impl crate::dreamer_wake::WeaveRecipeRuntime for RecipeInterpreter {
    fn draft(
        &mut self,
        markdown: &str,
        evidence: &[u8],
    ) -> Result<crate::dreamer_wake::WeaveRecipeDraft> {
        let predicate = markdown
            .lines()
            .find_map(|line| line.strip_prefix("PREDICATE: "))
            .ok_or(Error::InvalidClaimBody("recipe has no predicate"))?;
        let instruction = markdown
            .lines()
            .find_map(|line| line.strip_prefix("VALUE_PREFIX: "))
            .ok_or(Error::InvalidClaimBody("recipe has no instruction"))?;
        let source = std::str::from_utf8(evidence)
            .map_err(|_| Error::InvalidClaimBody("source is not text"))?;
        Ok(crate::dreamer_wake::WeaveRecipeDraft {
            predicate: predicate.to_owned(),
            value: rmpv::Value::from(format!("{instruction}{source}")),
            confidence: 0.8,
        })
    }
}

#[test]
fn agent_authored_weave_recipe_executes_with_system_write_stamp() -> Result<()> {
    use crate::attempt_queue::AttemptState;
    use crate::dreamer_wake::{
        DreamerWakeDriver, RunWakePass, WakeCancellation, WakePassDeadline, WakeTrigger,
        WeaveRecipeExecutor,
    };
    use crate::skill::{SkillGovernanceTier, SkillLifecycle, SkillRecord};
    use crate::skill_hub::HubFile;
    use rmpv::Value;

    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), embedding_test_config())?;
    let dreamer = vault.dreamer_authority()?;
    let agent = EntityId::now();
    let owner = EntityId::now();
    let subject = EntityId::now();
    let evidence = EntityId::now();
    let at = TimeRange { start: 1, end: 1 };
    for (id, body) in [
        (agent, b"resident".as_slice()),
        (owner, b"owner".as_slice()),
        (subject, b"subject".as_slice()),
        (evidence, b"retained evidence".as_slice()),
    ] {
        vault.put_entity(&id, crate::registry::ENTITY_TYPE_PERSON, at, 1, body)?;
    }
    let skill = EntityId::now();
    let proposal = SkillRecord::new(
        "weave.recipe",
        "A vault-local owner-admitted workflow",
        "v1",
        ClaimApprovalStatus::Proposed,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        0.5,
        true,
        false,
        Vec::new(),
        Value::Map(vec![("ask".into(), "write a v1 weave recipe".into())]),
    )
    .with_governance_tier(SkillGovernanceTier::Standard);
    let markdown =
        b"---\nname: weave.recipe\n---\nPREDICATE: profile.weave_note\nVALUE_PREFIX: Derived: \n";
    let authored = vault
        .memory(agent, EdgeActorClass::Agent)
        .skill_save_with_source(
            skill,
            &proposal,
            vec![HubFile::new("SKILL.md", markdown)],
            None,
            2,
        )
        .map_err(|err| Error::InvalidConfig(err.to_string()))?;
    assert_eq!(authored.author, agent);
    assert_eq!(
        vault.get_skill_record(&skill)?.unwrap().lifecycle_status,
        SkillLifecycle::Candidate
    );
    // A candidate cannot run and cannot inherit the actor's authority from its bytes.
    assert!(
        vault
            .load_attempt_skill_pack(crate::attempt_queue::AttemptId::now(), &skill, 2)
            .is_err()
    );
    let owner = vault.authenticate_owner(
        owner,
        "principal:recipe-owner",
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let outcome = vault.admit_and_enqueue_weave_recipe(&owner, skill, subject, evidence, 3)?;
    let (EnqueueDreamerAttemptOutcome::Enqueued(status)
    | EnqueueDreamerAttemptOutcome::Existing(status)) = outcome;
    let admission = vault
        .store
        .gate_decisions(100)?
        .into_iter()
        .find(|row| {
            row.content_kind == "dreamer_recipe"
                && row.actor_ref.as_deref() == Some(owner.actor().to_hex().as_str())
        })
        .expect("ruler admission is durable");
    assert_eq!(admission.actor_class, "human");
    assert_ne!(admission.read_frontier_hash, [0; 32]);

    let mut worker = WeaveRecipeExecutor {
        inner: UnreachableWeaveDelegate,
        runtime: RecipeInterpreter,
    };
    let mut driver = DreamerWakeDriver::new(&vault, "weave-budget", WakePassDeadline::new(180_000));
    let report = crate::dreamer_wake::block_on_ready(driver.run_wake_pass(
        RunWakePass {
            trigger: WakeTrigger::Event,
            scope: DreamerConsolidationScope::Micro,
            local_node_id: 1,
            lease_owner: "weave-host".into(),
            budget_total_units: 10_000,
            reserve_units: 100,
            now: 4,
        },
        &mut worker,
        &WakeCancellation::new(),
    ))?;
    assert_eq!(report.completed, 1);
    let settled = DreamerRunnerStore::new(&vault)
        .status(status.attempt.id)?
        .unwrap();
    assert_eq!(settled.attempt.state, AttemptState::Completed);
    let claim = crate::codebase::entity_id_from_hash_material(
        b"oneiron:dreamer:weave-recipe-claim:v1",
        &[status.attempt.id.as_bytes()],
    )?;
    let body = vault
        .get_claim(&claim)?
        .expect("executing the recipe writes a proposal");
    assert_eq!(body.predicate, "profile.weave_note");
    assert_eq!(body.value.as_str(), Some("Derived: retained evidence"));
    assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
    let Value::Map(fields) = body.evidence.as_ref().expect("stamped evidence") else {
        panic!("evidence");
    };
    assert!(
        fields
            .iter()
            .any(|(key, value)| key.as_str() == Some("actor_class")
                && value.as_u64() == Some(u64::from(EdgeActorClass::System as u8)))
    );
    assert!(
        fields
            .iter()
            .any(|(key, value)| key.as_str() == Some("actor_entity_ref")
                && value.as_slice() == Some(dreamer.entity_ref().as_bytes().as_slice()))
    );
    let decisions = vault.store.gate_decisions(10_000)?;
    assert!(
        decisions
            .iter()
            .any(|row| row.claim_id == Some(*claim.as_bytes()) && row.actor_class == "system"),
        "recipe claim receipt: {:?}; receipt count={}",
        decisions
            .iter()
            .find(|row| row.claim_id == Some(*claim.as_bytes())),
        decisions.len()
    );
    Ok(())
}

#[test]
fn actor_mutations_cannot_disable_a_vault_or_queued_attempt() -> Result<()> {
    let (dir, vault) = open_test_vault_with(embedding_test_config());
    let actor = vault.dreamer_authority()?;
    let id = actor.entity_ref();
    let original = vault.get_raw(&id)?.expect("seeded actor");
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
    let at = TimeRange { start: 2, end: 2 };
    for (kind, data) in [
        (
            crate::registry::ENTITY_TYPE_MACHINE,
            b"not the Dreamer".as_slice(),
        ),
        (
            crate::registry::ENTITY_TYPE_PERSON,
            b"Dreamer authority".as_slice(),
        ),
    ] {
        let err = vault
            .put_entity(&id, kind, at, 2, data)
            .expect_err("immutable actor");
        assert_eq!(err.kind(), crate::ErrorKind::DreamerActorImmutable);
    }
    let err = vault
        .batch()
        .put(&id, crate::registry::ENTITY_TYPE_MACHINE, at, 2, b"wrong")
        .commit()
        .expect_err("batch put refuses overwrite");
    assert_eq!(err.kind(), crate::ErrorKind::DreamerActorImmutable);
    let err = vault
        .batch()
        .delete(&id)
        .commit()
        .expect_err("batch delete refuses actor");
    assert_eq!(err.kind(), crate::ErrorKind::DreamerActorImmutable);
    for reason in [
        crate::deletion::DeleteReason::UserDelete,
        crate::deletion::DeleteReason::UserHardDelete,
    ] {
        let err = vault
            .delete_entity_with_reason(&id, reason)
            .expect_err("actor delete refused");
        assert_eq!(err.kind(), crate::ErrorKind::DreamerActorImmutable);
    }
    // Ordinary MACHINE entities remain mutable and deletable.
    let other = EntityId::now();
    vault.put_entity(
        &other,
        crate::registry::ENTITY_TYPE_MACHINE,
        at,
        2,
        b"device",
    )?;
    vault.put_entity(
        &other,
        crate::registry::ENTITY_TYPE_MACHINE,
        at,
        3,
        b"updated",
    )?;
    assert!(vault.delete_entity(&other)?);
    assert_eq!(vault.get_raw(&id)?.as_deref(), Some(original.as_slice()));
    assert_eq!(vault.dreamer_actor_for_attempt(status.attempt.id)?, actor);
    drop(vault);
    let reopened = Vault::open(dir.path(), embedding_test_config())?;
    assert_eq!(reopened.dreamer_authority()?, actor);
    assert_eq!(reopened.get_raw(&id)?.as_deref(), Some(original.as_slice()));
    Ok(())
}

#[test]
fn shared_facet_does_not_dedupe_distinct_job_types() -> Result<()> {
    use crate::dreamer_runner::EnqueueDreamerAttempt;

    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let runner = DreamerRunnerStore::new(&vault);
    let input = |attempt_type: &str| EnqueueDreamerAttempt {
        attempt_type: attempt_type.into(),
        input: rmpv::Value::Nil,
        parent_attempt: None,
        dedupe_key: Some("same-key".into()),
        run_id: None,
        now: 10,
    };
    let first = runner.enqueue(input("micro"))?;
    assert!(matches!(first, EnqueueDreamerAttemptOutcome::Enqueued(_)));
    assert!(matches!(
        runner.enqueue(input("meso")),
        Err(Error::InvalidConfig(_))
    ));
    let replay = runner.enqueue(input("micro"))?;
    assert!(matches!(replay, EnqueueDreamerAttemptOutcome::Existing(_)));
    Ok(())
}

#[test]
fn job_types_share_facets_without_minting_new_agents() {
    use super::{DreamerAgentBoundary, dreamer_facet_for_job_type, warrants_new_agent};
    use crate::agent_def::AgentCeiling;
    use crate::llm::ModelLocality;

    for (job, facet) in [
        ("micro", "dreamer.consolidation"),
        ("meso", "dreamer.consolidation"),
        ("macro", "dreamer.consolidation"),
        ("dreamer.reflection.gap_scan", "dreamer.consolidation"),
        (
            "dreamer.edit_distance.substitution_mine",
            "dreamer.consolidation",
        ),
        ("dreamer.skill_optimize", "dreamer.skill_optimize"),
        ("dreamer.vault_cleanup", "dreamer.vault_cleanup"),
        ("dreamer.weave_recipe", "dreamer.weave_recipe"),
        ("dreamer.curator", "dreamer.curator"),
        ("dreamer.harness_maintenance", "dreamer.harness_maintenance"),
        ("dreamer.representation", "dreamer.representation"),
        ("dreamer.plugin_suggest", "dreamer.plugin_suggest"),
        ("connector_event", "connector_event"),
    ] {
        assert_eq!(dreamer_facet_for_job_type(job), Some(facet));
    }
    assert_eq!(
        dreamer_facet_for_job_type(crate::consult_ladder::DREAMER_MAGISTRATE_ATTEMPT_TYPE),
        Some("dreamer.magistrate")
    );
    assert_eq!(dreamer_facet_for_job_type("agent_dispatch"), None);
    assert_eq!(dreamer_facet_for_job_type("unknown"), None);

    let original = DreamerAgentBoundary {
        soul: "same principal",
        access_ceiling: AgentCeiling::Proposed,
        locality: ModelLocality::OnDevice,
    };
    assert!(!warrants_new_agent(original, original));
    assert!(warrants_new_agent(
        original,
        DreamerAgentBoundary {
            soul: "another principal",
            ..original
        }
    ));
    assert!(warrants_new_agent(
        original,
        DreamerAgentBoundary {
            access_ceiling: AgentCeiling::Auto,
            ..original
        }
    ));
    assert!(warrants_new_agent(
        original,
        DreamerAgentBoundary {
            locality: ModelLocality::OwnServer,
            ..original
        }
    ));
}
