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
        host_scope: None,
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
    crate::test_util::provision_engine_machines(&vault);
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
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(actor.entity_ref()),
        Value::from("old consolidation"),
        0.9,
    );
    let envelope = crate::test_util::sign_machine_candidate(&vault, &target, &candidate, &envelope);
    vault
        .batch()
        .claim_candidate(
            &target,
            candidate,
            &envelope,
            TimeRange { start: 1, end: 1 },
            1,
        )
        .commit()?;
    let mut body = vault.get_claim(&target)?.unwrap();
    body.approval = ClaimApprovalStatus::Approved;
    // The owner approves the Dreamer's MACHINE proposal through its signed
    // history.
    let approver = vault.ensure_embedded_owner_actor().expect("embedded owner");
    crate::test_util::bind_test_owner(&vault, approver);
    vault.approve_machine_claim_as(
        target,
        crate::WriteActor::new(approver, crate::EdgeActorClass::Human),
    )?;
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
    assert_eq!(value["grade"]["authorship"], "verified_dreamer_generated");
    assert_eq!(value["grade"]["freshness"]["learned_at"], 1);
    assert_eq!(
        value["grade"]["least_force"]["prior_rung"],
        serde_json::Value::Null
    );
    assert_eq!(
        value["grade"]["least_force"]["proposed_action"],
        "claim_of_weight"
    );
    assert!(
        value["rubric"]["questions"]["freshness"]
            .as_str()
            .is_some_and(|question| !question.is_empty())
    );
    assert!(vault.get(&target)?.is_some());

    let owner_id = entity(0x52);
    vault.put_entity(
        &owner_id,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let digest = vault.proactivity_digest(&owner, 100_000, None)?.unwrap();
    assert!(
        digest
            .groups
            .values()
            .flatten()
            .any(|item| item.claim_ref == proposed.0)
    );

    // A new nightly attempt and a later retry see the same source revision.
    // Neither creates a new proposal ID or resurfaces it in the digest.
    for (trigger, now) in [
        (CuratorTrigger::Nightly, 186_400),
        (CuratorTrigger::Idle, 272_800),
    ] {
        vault.schedule_curator(trigger, now)?;
        drive(&vault, now)?;
        let proposals: Vec<_> = claims(&vault, &target)?
            .into_iter()
            .filter(|(_, body)| body.predicate == "dreamer.curator.proposal")
            .collect();
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].0, proposed.0);
        assert!(vault.proactivity_digest(&owner, now, None)?.is_none());
    }
    Ok(())
}
#[test]
fn config_artifact_version_and_backbone_change_emits_retune_proposal() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    crate::test_util::provision_engine_machines(&vault);
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
    let artifact_claims = claims(&vault, &artifact)?;
    let proposals: Vec<_> = artifact_claims
        .iter()
        .filter(|(_, body)| body.predicate == "dreamer.harness.retune_proposal")
        .collect();
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].1.approval, ClaimApprovalStatus::Proposed);
    let value: serde_json::Value =
        serde_json::from_str(proposals[0].1.value.as_str().unwrap()).unwrap();
    assert_eq!(value["backbone_changed"], true);
    assert_eq!(value["targets"].as_array().unwrap().len(), 3);
    // Only the prompt changed in the next immutable config version. A real
    // regression must flag the changed surface, not every tuning knob.
    let config = DreamerTuningConfig {
        backbone: "backbone-b".into(),
        prompts: vec!["prompt/version-2".into()],
        weights: std::collections::BTreeMap::from([("type_prior".into(), 0.7)]),
        manifest_thresholds: std::collections::BTreeMap::from([("auto".into(), 0.8)]),
    };
    let version = vault.append_blob_artifact_version(
        &artifact,
        &serde_json::to_vec(&config).unwrap(),
        &crate::blob_artifact::BlobVersionProvenance::UserUpload,
        actor,
        TimeRange { start: 30, end: 30 },
        30,
    )?;
    vault.schedule_harness_evaluation(
        &HarnessEvaluation {
            artifact,
            version: version.version,
            score: 0.6,
        },
        30,
    )?;
    drive(&vault, 30)?;
    let proposals: Vec<_> = claims(&vault, &artifact)?
        .into_iter()
        .filter(|(_, body)| body.predicate == "dreamer.harness.retune_proposal")
        .collect();
    assert_eq!(proposals.len(), 2);
    let values: Vec<serde_json::Value> = proposals
        .iter()
        .map(|(_, body)| serde_json::from_str(body.value.as_str().unwrap()).unwrap())
        .collect();
    let value = values
        .iter()
        .find(|value| value["version"] == version.version)
        .unwrap();
    assert_eq!(value["score_regressed"], true);
    assert_eq!(value["backbone_changed"], false);
    assert_eq!(value["targets"], serde_json::json!(["prompts"]));
    for (time, score, weight, threshold, target) in [
        (40, 0.4, 0.6, 0.8, "weights"),
        (50, 0.2, 0.6, 0.7, "manifest_thresholds"),
    ] {
        let config = DreamerTuningConfig {
            backbone: "backbone-b".into(),
            prompts: vec!["prompt/version-2".into()],
            weights: std::collections::BTreeMap::from([("type_prior".into(), weight)]),
            manifest_thresholds: std::collections::BTreeMap::from([("auto".into(), threshold)]),
        };
        let version = vault.append_blob_artifact_version(
            &artifact,
            &serde_json::to_vec(&config).unwrap(),
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
                score,
            },
            time,
        )?;
        drive(&vault, time)?;
        let proposals = claims(&vault, &artifact)?;
        let value: serde_json::Value = proposals
            .iter()
            .filter(|(_, body)| body.predicate == "dreamer.harness.retune_proposal")
            .map(|(_, body)| serde_json::from_str(body.value.as_str().unwrap()).unwrap())
            .find(|value: &serde_json::Value| value["version"] == version.version)
            .unwrap();
        assert_eq!(value["targets"], serde_json::json!([target]));
    }
    Ok(())
}

#[test]
fn score_regression_flags_only_targets_past_their_v1_cutoffs() -> Result<()> {
    // Exercise both the shipped-default path and an explicit owner-set row.
    for thresholds in [
        None,
        Some(RetuneThresholds {
            prompts_score_regression: 0.05,
            weights_score_regression: 0.08,
            manifest_thresholds_score_regression: 0.10,
        }),
    ] {
        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        crate::test_util::provision_engine_machines(&vault);
        let owner = entity(0x63);
        let artifact = entity(0x64);
        vault.put_entity(
            &owner,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"owner",
        )?;
        vault.put_blob_artifact(
            &artifact,
            &crate::blob_artifact::BlobArtifactBody::new("dreamer-config.json", "application/json"),
            TimeRange { start: 1, end: 1 },
            1,
        )?;
        let config = DreamerTuningConfig {
            backbone: "backbone-a".into(),
            prompts: vec!["prompt/version-1".into()],
            weights: std::collections::BTreeMap::from([("type_prior".into(), 0.7)]),
            manifest_thresholds: std::collections::BTreeMap::from([("auto".into(), 0.8)]),
        };
        let bytes = serde_json::to_vec(&config).unwrap();
        let actor = WriteActor::new(owner, EdgeActorClass::Human);
        if let Some(thresholds) = thresholds {
            let proof = vault.authenticate_owner(
                owner,
                &owner.to_hex(),
                true,
                crate::store::GateDecisionId::now(),
            )?;
            vault.set_retune_thresholds(&proof, &thresholds)?;
        }
        // Each improvement resets the observed baseline. A config-version bump with
        // the same backbone must not turn a small score drift into an all-target flag.
        let mut expected_count = 0;
        for (time, score, expected) in [
            (10, 0.90, None),
            (20, 0.86, None),
            (30, 0.90, None),
            (40, 0.84, Some(vec!["prompts"])),
            (50, 0.90, None),
            (60, 0.81, Some(vec!["prompts", "weights"])),
            (70, 0.90, None),
            (
                80,
                0.79,
                Some(vec!["prompts", "weights", "manifest_thresholds"]),
            ),
        ] {
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
                    score,
                },
                time,
            )?;
            drive(&vault, time)?;
            let proposals: Vec<_> = claims(&vault, &artifact)?
                .into_iter()
                .filter(|(_, body)| body.predicate == "dreamer.harness.retune_proposal")
                .collect();
            if let Some(expected) = expected {
                expected_count += 1;
                let (body, value) = proposals
                    .iter()
                    .find_map(|(_, body)| {
                        let value: serde_json::Value =
                            serde_json::from_str(body.value.as_str().unwrap()).unwrap();
                        (value["version"] == version.version).then_some((body, value))
                    })
                    .expect("proposal for the evaluated artifact version");
                assert_eq!(value["backbone_changed"], false);
                assert_eq!(value["targets"], serde_json::json!(expected));
                assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
            }
            assert_eq!(
                proposals.len(),
                expected_count,
                "at version {}",
                version.version
            );
        }
    }
    Ok(())
}

#[test]
fn maintenance_revalidates_owner_in_target_vault() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    crate::test_util::provision_engine_machines(&vault);
    let (_other_dir, other) = open_test_vault_with(embedding_test_config());
    let actor = entity(0x71);
    other.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let proof = other.authenticate_owner(
        actor,
        &actor.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let cadence = digest::ProactivityCadence {
        period_secs: 100,
        group_by_facet: true,
        urgent_breakthrough: true,
    };
    let rubric: CuratorRubric =
        serde_json::from_str(include_str!("curator_defaults.json")).unwrap();
    let thresholds = RetuneThresholds {
        prompts_score_regression: 0.1,
        weights_score_regression: 0.1,
        manifest_thresholds_score_regression: 0.1,
    };
    let refuse = |target: &Vault| -> Result<()> {
        for result in [
            target.set_proactivity_cadence(&proof, &cadence),
            target.set_curator_rubric(&proof, &rubric),
            target.set_retune_thresholds(&proof, &thresholds),
            target.proactivity_digest(&proof, 10, None).map(|_| ()),
        ] {
            assert_eq!(
                result.unwrap_err().kind(),
                crate::ErrorKind::ConsentOwnerNotAuthenticated
            );
        }
        Ok(())
    };
    refuse(&vault)?;
    other.set_proactivity_cadence(&proof, &cadence)?;
    let mut invalid_rubric = rubric.clone();
    invalid_rubric.questions.freshness.clear();
    assert_eq!(
        other
            .set_curator_rubric(&proof, &invalid_rubric)
            .unwrap_err()
            .kind(),
        crate::ErrorKind::InvalidConfig
    );
    other.set_curator_rubric(&proof, &rubric)?;
    other.set_retune_thresholds(&proof, &thresholds)?;
    other.with_write_txn(|txn| {
        let marker = crate::deletion::TombstoneValueV2 {
            reason: crate::deletion::TombstoneReason::ArchivedByCleanup,
            deleted_at: 20,
            request_id: [0x72; 16],
        };
        other
            .store
            .sync_state
            .put(txn, &format!("ac:{}", actor.to_hex()), &marker.encode())?;
        Ok(())
    })?;
    refuse(&other)?;
    other.with_write_txn(|txn| {
        other
            .store
            .sync_state
            .delete(txn, &format!("ac:{}", actor.to_hex()))?;
        Ok(())
    })?;
    other.delete_entity_with_reason(&actor, crate::deletion::DeleteReason::UserDelete)?;
    refuse(&other)?;
    Ok(())
}
