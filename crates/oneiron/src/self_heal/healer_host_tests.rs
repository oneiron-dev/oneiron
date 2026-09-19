use super::healer_host::*;
use super::*;
use crate::{claim::ClaimSource, edge::EdgeActorClass, write_envelope::WriteActor};
fn fixture() -> (
    tempfile::TempDir,
    Vault,
    crate::consent::AuthenticatedOwner,
    WriteActor,
) {
    let d = tempfile::tempdir().unwrap();
    let v = Vault::open_owned(d.path(), crate::VaultConfig::device()).unwrap();
    let person = EntityId::now();
    v.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )
    .unwrap();
    let owner = v
        .authenticate_owner(person, "owner", true, crate::store::GateDecisionId::now())
        .unwrap();
    let actor = WriteActor::new(EntityId::now(), EdgeActorClass::Agent);
    (d, v, owner, actor)
}
fn patch(operation: RepairOperation) -> RepairProposal {
    RepairProposal {
        proposal_id: EntityId::now(),
        diagnostic_refs: vec![EntityId::now()],
        actor: RepairActor {
            actor_class: "human".into(),
            actor_ref: EntityId::now(),
        },
        source: ClaimSource::UserStated,
        target_predicate: "maintenance.patch".into(),
        operation,
        session_tag: "session".into(),
    }
}
#[test]
fn external_runner_reads_failure_corpus_and_patch_release_is_human_only() {
    let (_d, v, owner, actor) = fixture();
    let event = DiagnosticEvent {
        detector_id: "test.failure".into(),
        event_class: DiagnosticEventClass::TestFailure,
        actor_class: "system".into(),
        actor_ref: None,
        source: DiagnosticSourceKind::Receipt,
        criticality: DiagnosticCriticality::Critical,
        expected: Value::from(1),
        actual: Value::from(0),
        delta: Value::from(-1),
        replay: DiagnosticReplayCoordinate {
            content_hash: [1; 32],
            run_ref: Some("build".into()),
            checkpoint_ref: None,
        },
        evidence_refs: vec![],
        untrusted_detail: None,
        valid_from: 1,
        valid_to: None,
    };
    let id = diagnostic_event_id(
        &event.detector_id,
        &encode_diagnostic_event_body(&event).unwrap(),
    );
    v.emit_diagnostic_event(&id, &event).unwrap();
    let registration = v
        .register_dev_healer(HealerDeployment::Daemon, actor)
        .unwrap();
    assert_eq!(
        registration.failure_corpus().unwrap()[0].1.event_class,
        DiagnosticEventClass::TestFailure
    );
    let proposal = patch(RepairOperation::DevPatch {
        repo_ref: "repo".into(),
        patch_ref: "patch".into(),
    });
    let id = proposal.proposal_id;
    let bundle = registration.submit("run", "session", proposal).unwrap();
    assert_eq!(
        bundle.proposals()[0].route(),
        RepairConsentRoute::HumanReview
    );
    assert_eq!(
        v.healer_proposal(&id).unwrap().unwrap().state,
        ProposalState::Proposed
    );
    let pr = v
        .review_patch_pr(&owner, &id, Some("release-1"))
        .unwrap()
        .unwrap();
    assert_eq!(pr.patch_ref, "patch");
    assert_eq!(pr.release_ref, "release-1");
    assert!(v.review_patch_pr(&owner, &id, Some("release-2")).is_err());
    let proposal = patch(RepairOperation::SchemaPatch {
        schema_ref: "schema".into(),
        patch_ref: "migration".into(),
    });
    let id = proposal.proposal_id;
    registration.submit("run", "session", proposal).unwrap();
    assert!(v.review_patch_pr(&owner, &id, None).unwrap().is_none());
    assert_eq!(
        v.healer_proposal(&id).unwrap().unwrap().state,
        ProposalState::Denied
    );
}
#[test]
fn deployment_and_production_capabilities_refuse_code_at_admission() {
    let (_d, v, _owner, actor) = fixture();
    assert!(
        v.register_dev_healer(HealerDeployment::EmbeddedInProcess, actor)
            .is_err()
    );
    let d = tempfile::tempdir().unwrap();
    let embedded = Vault::open(d.path(), crate::VaultConfig::device()).unwrap();
    assert!(
        embedded
            .register_dev_healer(HealerDeployment::Daemon, actor)
            .is_err()
    );
    let prod = v.register_prod_healer(actor);
    for op in [
        RepairOperation::DevPatch {
            repo_ref: "repo".into(),
            patch_ref: "patch".into(),
        },
        RepairOperation::SchemaPatch {
            schema_ref: "schema".into(),
            patch_ref: "patch".into(),
        },
    ] {
        let proposal = patch(op);
        let id = proposal.proposal_id;
        assert!(prod.submit("run", "session", proposal).is_err());
        assert!(v.healer_proposal(&id).unwrap().is_none());
    }
}
#[test]
fn counted_burst_stays_proposed_one_check_and_one_reversal() {
    let (_d, v, owner, actor) = fixture();
    // Seed already-recorded prior submissions; four new calls cross the real
    // fleet-scale threshold without making this fixture perform 100,000 writes.
    let previous = super::healer_host::PROPOSAL_BURST_THRESHOLD - 2;
    v.with_write_txn(|txn| {
        let mut key = b"healer:count:".to_vec();
        key.extend_from_slice(actor.entity_ref().as_bytes());
        let body = rmp_serde::to_vec_named(&serde_json::json!({"count": previous, "check": null})).unwrap();
        v.store.vault_meta.put(txn, &key, &body)?;
        Ok(())
    }).unwrap();
    let registration = v
        .register_dev_healer(HealerDeployment::SelfHostSingleWriter, actor)
        .unwrap();
    let mut ids = Vec::new();
    for _ in 0..4 {
        let p = patch(RepairOperation::DevPatch {
            repo_ref: "repo".into(),
            patch_ref: "patch".into(),
        });
        ids.push(p.proposal_id);
        registration.submit("burst", "session", p).unwrap();
    }
    for id in &ids {
        assert_eq!(
            v.healer_proposal(id).unwrap().unwrap().state,
            ProposalState::Proposed
        );
    }
    let check = v
        .proposal_burst_check(&actor.entity_ref())
        .unwrap()
        .unwrap();
    assert_eq!(check.actor, actor.entity_ref());
    assert_eq!(check.count, super::healer_host::PROPOSAL_BURST_THRESHOLD + 1);
    let receipt = v
        .reverse_healer_run(&owner, &actor.entity_ref(), "burst")
        .unwrap();
    assert!(receipt.reversed);
    assert_eq!(receipt.proposals, ids);
    for id in &ids {
        assert_eq!(
            v.healer_proposal(id).unwrap().unwrap().state,
            ProposalState::Reversed
        );
    }
}
