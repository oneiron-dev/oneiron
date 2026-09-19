use super::*;
use crate::dreamer_runner::DreamerConsolidationScope;
use crate::dreamer_wake::{
    DreamerAttemptExecutor, DreamerWakeDriver, RunWakePass, WakeCancellation, WakePassDeadline,
    WakeTrigger,
};
use crate::test_util::{embedding_test_config, entity, open_test_vault_with};
use crate::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, WriteActor, WriteEnvelope, WriteProvenance,
};
use std::future::Future;
use std::task::{Context, Poll, Waker};
fn claims(vault: &Vault, subject: &EntityId) -> Result<Vec<(EntityId, crate::ClaimBody)>> {
    vault
        .claims_for_subject(subject)?
        .into_iter()
        .map(|id| {
            let body = vault.get_claim(&id)?.ok_or_else(invalid)?;
            Ok((id, body))
        })
        .collect()
}
struct UnusedExecutor;
impl DreamerAttemptExecutor for UnusedExecutor {
    async fn execute(
        &mut self,
        _attempt: &DreamerAdmittedAttempt,
        _ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        Err(invalid())
    }
}
fn drive(vault: &Vault, now: u64) -> Result<()> {
    let mut driver = DreamerWakeDriver::new(
        vault,
        format!("maintenance-{now}"),
        WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0)),
    );
    let input = RunWakePass {
        trigger: WakeTrigger::Event,
        scope: DreamerConsolidationScope::Micro,
        local_node_id: 1,
        lease_owner: "maintenance-fixture".into(),
        budget_total_units: 1000,
        reserve_units: 10,
        now,
    };
    let cancel = WakeCancellation::new();
    let mut exec = UnusedExecutor;
    let future = driver.run_wake_pass(input, &mut exec, &cancel);
    let mut future = std::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..100 {
        if let Poll::Ready(report) = future.as_mut().poll(&mut context) {
            assert_eq!(report?.completed, 1);
            return Ok(());
        }
    }
    Err(invalid())
}
#[test]
fn idle_curator_grades_own_consolidation_and_only_proposes_minimum_force() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let actor = vault.dreamer_authority()?;
    let target = entity(0x51);
    let envelope = WriteEnvelope::new(
        actor,
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![(
            Value::from("surface"),
            Value::from("dreamer"),
        )]))?,
        ClaimApprovalStatus::Proposed,
    );
    vault
        .batch()
        .claim_candidate(
            &target,
            ClaimCandidate::new(
                "profile.preference",
                ClaimSubject::Entity(actor.entity_ref()),
                Value::from("old consolidation"),
                0.9,
            ),
            &envelope,
            TimeRange { start: 1, end: 1 },
            1,
        )
        .commit()?;
    let mut body = vault.get_claim(&target)?.unwrap();
    body.approval = ClaimApprovalStatus::Approved;
    vault.put_claim(&target, &body, TimeRange { start: 1, end: 1 }, 1)?;
    vault.schedule_curator(CuratorTrigger::Idle, 100_000)?;
    drive(&vault, 100_000)?;
    assert_eq!(vault.get_claim(&target)?, Some(body));
    let proposals = claims(&vault, &target)?;
    let proposed = proposals
        .iter()
        .find(|(_, body)| body.predicate == "dreamer.curator.proposal")
        .unwrap();
    assert_eq!(proposed.1.approval, ClaimApprovalStatus::Proposed);
    let value: serde_json::Value =
        serde_json::from_str(proposed.1.value.as_str().unwrap()).unwrap();
    assert_eq!(value["action"]["kind"], "claim_of_weight");
    assert!(vault.get(&target)?.is_some());
    Ok(())
}
#[test]
fn config_artifact_version_and_backbone_change_emits_retune_proposal() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let owner = entity(0x61);
    let artifact = entity(0x62);
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    vault.put_blob_artifact(
        &artifact,
        &crate::blob_artifact::BlobArtifactBody::new("dreamer-config.json", "application/json"),
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    for (time, backbone) in [(10, "backbone-a"), (20, "backbone-b")] {
        let config = DreamerTuningConfig {
            backbone: backbone.into(),
            prompts: vec!["prompt/version-1".into()],
            weights: std::collections::BTreeMap::from([("type_prior".into(), 0.7)]),
            manifest_thresholds: std::collections::BTreeMap::from([("auto".into(), 0.8)]),
        };
        let bytes = serde_json::to_vec(&config).unwrap();
        let version = vault.append_blob_artifact_version(
            &artifact,
            &bytes,
            &crate::blob_artifact::BlobVersionProvenance::UserUpload,
            actor,
            TimeRange {
                start: time,
                end: time,
            },
            time,
        )?;
        vault.schedule_harness_evaluation(
            &HarnessEvaluation {
                artifact,
                version: version.version,
                score: 0.8,
            },
            time,
        )?;
        drive(&vault, time)?;
    }
    let claims = claims(&vault, &artifact)?;
    let proposals: Vec<_> = claims
        .iter()
        .filter(|(_, body)| body.predicate == "dreamer.harness.retune_proposal")
        .collect();
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].1.approval, ClaimApprovalStatus::Proposed);
    let value: serde_json::Value =
        serde_json::from_str(proposals[0].1.value.as_str().unwrap()).unwrap();
    assert_eq!(value["backbone_changed"], true);
    assert_eq!(value["targets"].as_array().unwrap().len(), 3);
    Ok(())
}
