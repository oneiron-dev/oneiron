use super::*;
use crate::dreamer_runner::{
    DreamerConsolidationScope, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
    EnqueueDreamerConsolidationAttempt, EnqueueDreamerSkillOptimizeAttempt,
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
    for outcome in attempts {
        let (EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status)) = outcome;
        let stamp = vault.dreamer_attempt_authority(status.attempt.id)?.unwrap();
        assert_eq!(stamp.actor, authority.entity_ref());
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
    assert!(
        authority_records
            .iter()
            .all(|r| r.actor_ref.as_deref() == Some(&authority.entity_ref().to_hex()))
    );
    assert_eq!(vault.dreamer_authority()?, authority);
    let (_other_dir, other_node) = open_test_vault_with(embedding_test_config());
    assert_eq!(other_node.dreamer_authority()?, authority);
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
