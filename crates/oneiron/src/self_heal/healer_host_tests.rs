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
    // The runner reads through its own scoped key, which reads nothing until
    // the manifest grants it.
    crate::test_util::authorize_readers(&v, &[actor.entity_ref().to_hex().as_str()]);
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
fn set_proposal_threshold(vault: &Vault, threshold: u64) {
    let id = crate::gate::default_policy_manifest_id().unwrap();
    let body = vault.get(&id).unwrap().unwrap();
    let mut manifest = rmpv::decode::read_value(&mut std::io::Cursor::new(body)).unwrap();
    let Value::Map(entries) = &mut manifest else {
        panic!("manifest map")
    };
    let (_, Value::Array(rows)) = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("policy_values"))
        .unwrap()
    else {
        panic!("value rows")
    };
    let Value::Map(fields) = rows
        .iter_mut()
        .find(|row| match row {
            Value::Map(fields) => fields.iter().any(|(key, value)| {
                key.as_str() == Some("key") && value.as_str() == Some("proposal_check_threshold")
            }),
            _ => false,
        })
        .unwrap()
    else {
        panic!("threshold row")
    };
    fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("value"))
        .unwrap()
        .1 = Value::from(threshold);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &manifest).unwrap();
    crate::test_util::put_policy_manifest_bytes(vault, id, &bytes).unwrap();
}

#[test]
fn counted_burst_stays_proposed_one_check_and_one_reversal() {
    let (_d, v, owner, actor) = fixture();
    set_proposal_threshold(&v, 2);
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
    assert_eq!(check.count, 3);
    let typed = v
        .proposal_submission_check(&actor.entity_ref())
        .unwrap()
        .unwrap();
    assert_eq!(typed.actor, actor.entity_ref().to_hex());
    assert_eq!(typed.count, 3);
    assert_eq!(typed.threshold, 2);
    assert_eq!(typed.proposal_ref, format!("healer:{}", ids[2].to_hex()));
    for id in &ids {
        let receipt = v
            .proposal_submission_receipt(&actor.entity_ref(), &format!("healer:{}", id.to_hex()))
            .unwrap()
            .unwrap();
        assert_eq!(receipt.actor, actor.entity_ref().to_hex());
    }
    let backup_dir = tempfile::tempdir().unwrap();
    let checkpoint = backup_dir.path().join("checkpoint");
    v.snapshot_checkpoint(&checkpoint, 100).unwrap();
    let (restored, _) = Vault::restore_checkpoint(
        &checkpoint,
        &backup_dir.path().join("restored"),
        crate::VaultConfig::device(),
        crate::recovery::checkpoint::RestoreReason::Restore,
        101,
    )
    .unwrap();
    assert_eq!(
        restored.proposal_burst_check(&actor.entity_ref()).unwrap(),
        Some(check)
    );
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

#[test]
fn production_refs_refuse_protected_namespaces_before_persistence() {
    let (_d, v, _owner, actor) = fixture();
    let prod = v.register_prod_healer(actor);
    for namespace in ["engine", "Soul", "CORE"] {
        for suffix in [
            "", ".index", ":index", "/index", "\\index", " index", "%2Findex",
        ] {
            let target = format!("{namespace}{suffix}");
            for op in [
                RepairOperation::Reindex {
                    scope_ref: target.clone(),
                },
                RepairOperation::Retry {
                    run_ref: target.clone(),
                },
            ] {
                let proposal = patch(op);
                let id = proposal.proposal_id;
                assert!(
                    matches!(
                        prod.submit("refusal", "session", proposal),
                        Err(crate::Error::InvalidConfig(_))
                    ),
                    "protected target {target}"
                );
                assert!(v.healer_proposal(&id).unwrap().is_none());
            }
        }
    }
    assert!(
        v.healer_run_receipt(&actor.entity_ref(), "refusal")
            .unwrap()
            .is_none()
    );
    for target in [
        "memory/index",
        "maintenance:run",
        "engineering/index",
        "core_notes/run",
    ] {
        for op in [
            RepairOperation::Reindex {
                scope_ref: target.into(),
            },
            RepairOperation::Retry {
                run_ref: target.into(),
            },
        ] {
            let proposal = patch(op);
            let id = proposal.proposal_id;
            prod.submit("allowed", "session", proposal).unwrap();
            assert_eq!(
                v.healer_proposal(&id).unwrap().unwrap().state,
                ProposalState::Proposed
            );
        }
    }
}

#[test]
fn healer_diagnostic_events_read_returns_its_receipt() {
    let (_d, v, _owner, actor) = fixture();
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
            content_hash: [2; 32],
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
    // Before the manifest grants the runner, the stored event is withheld and
    // the corpus says so rather than reading as an empty history.
    let withheld = registration.failure_corpus().unwrap();
    assert!(withheld.value.is_empty());
    assert_eq!(withheld.receipt.suppressed_count, 1);
    crate::test_util::authorize_readers(&v, &[actor.entity_ref().to_hex().as_str()]);
    let corpus = registration.failure_corpus().unwrap();
    assert_eq!(corpus.value.len(), 1);
    assert_eq!(corpus.value[0].0, id);
    assert_eq!(corpus.receipt.suppressed_count, 0);
}

#[test]
fn policy_revocation_between_preflight_and_proposal_write_refuses_all_receipts() -> Result<()> {
    let (_dir, vault, owner, actor) = fixture();
    let manifest = vault.manifest_contributions()?;
    assert_eq!(manifest.len(), 1, "fixture has one live policy");
    let policy_id = EntityId::from_hex(&manifest[0].id)?;
    let proposal = patch(RepairOperation::DevPatch {
        repo_ref: "repo".into(),
        patch_ref: "patch".into(),
    });
    let id = proposal.proposal_id;
    let registration = vault.register_dev_healer(HealerDeployment::Daemon, actor)?;
    let err = registration
        .submit_with_pre_write("revoked", "session", proposal, || {
            // Deterministic interleaving: this would admit under the previous
            // read-snapshot evaluation, then persist using stale consent.
            vault.quarantine_manifest_contribution(&owner, policy_id)
        })
        .expect_err("the write snapshot must observe manifest revocation");
    assert_eq!(err.kind(), crate::ErrorKind::InvalidConfig);
    assert!(vault.healer_proposal(&id)?.is_none());
    assert!(
        vault
            .healer_run_receipt(&actor.entity_ref(), "revoked")?
            .is_none()
    );
    assert!(vault.proposal_burst_check(&actor.entity_ref())?.is_none());
    Ok(())
}
