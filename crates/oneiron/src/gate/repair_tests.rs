//! ONE-1395 repair-only tests, kept separate from the existing Gate write-door tests.

use super::*;
use crate::self_heal::{
    DiagnosticCriticality, DiagnosticEvent, DiagnosticEventClass, DiagnosticReplayCoordinate,
    DiagnosticSourceKind, DiagnosticWorkingSet, Healer, HealerInvocationStamp, RegisteredHealer,
    RepairActor, RepairBundle, RepairConsentRoute, RepairCriticality, RepairOperation,
    RepairProposal, run_healer_proposals,
};

struct FixedHealer(Vec<RepairProposal>);

impl Healer for FixedHealer {
    fn propose(
        &self,
        _working_set: &DiagnosticWorkingSet<'_>,
        _diagnostics: &[DiagnosticEvent],
    ) -> Vec<RepairProposal> {
        self.0.clone()
    }
}

fn proposal() -> RepairProposal {
    RepairProposal {
        proposal_id: test_id(0x61),
        diagnostic_refs: vec![test_id(0x62)],
        actor: RepairActor {
            actor_class: "system".to_owned(),
            actor_ref: test_id(0x63),
        },
        source: ClaimSource::Generated,
        target_predicate: "maintenance.index".to_owned(),
        operation: RepairOperation::Reindex {
            scope_ref: "scope.repair".to_owned(),
        },
        session_tag: "session.repair".to_owned(),
    }
}

fn diagnostic() -> DiagnosticEvent {
    DiagnosticEvent {
        detector_id: "test.retrieval_detector".to_owned(),
        event_class: DiagnosticEventClass::RetrievalMiss,
        actor_class: "human".to_owned(),
        actor_ref: Some(test_id(0x64)),
        source: DiagnosticSourceKind::RetrievalTelemetry,
        criticality: DiagnosticCriticality::Normal,
        expected: Value::from(1),
        actual: Value::from(0),
        delta: Value::from(-1),
        replay: DiagnosticReplayCoordinate {
            content_hash: [7; 32],
            run_ref: Some("diagnostic.run".to_owned()),
            checkpoint_ref: None,
        },
        evidence_refs: vec![test_id(0x65)],
        untrusted_detail: None,
        valid_from: 1,
        valid_to: None,
    }
}

fn registration(
    healer: &dyn Healer,
    actor: WriteActor,
    ceiling: Option<PolicyApprovalCeiling>,
) -> RegisteredHealer<'_> {
    RegisteredHealer {
        healer_id: "test.mechanical_healer",
        actor,
        agent_definition_ceiling: ceiling,
        healer,
    }
}

fn review(
    policy: &PolicyManifestResolution,
    registration: &RegisteredHealer<'_>,
    diagnostics: &[DiagnosticEvent],
) -> Result<RepairBundle> {
    run_healer_proposals(
        policy,
        registration,
        "run.repair",
        "session.repair",
        &DiagnosticWorkingSet {
            scope_ref: "scope.repair",
            observations: &[],
        },
        diagnostics,
    )
}

fn repair_manifest(actor: EntityId, permit_generated: bool, criticality: &str) -> Vec<u8> {
    let entries = if permit_generated {
        vec![source_trust_entry(ClaimSource::Generated, 2)]
    } else {
        Vec::new()
    };
    let mut bytes = encode_policy_manifest(entries);
    replace_actor_ceilings(
        &mut bytes,
        vec![
            actor_ceiling_row_for_ref("system", &actor.to_hex(), "auto"),
            actor_ceiling_row_for_ref("agent", &actor.to_hex(), "auto"),
            actor_ceiling_row_for_ref("human", &actor.to_hex(), "auto"),
        ],
    );
    rewrite_policy_manifest_entries(&mut bytes, |entries| {
        for (key, value) in entries {
            if key.as_str() == Some(POLICY_DEFAULTS_KEY) {
                *value = Value::Map(vec![
                    (Value::from(AXIS_CRITICALITY_KEY), Value::from(criticality)),
                    (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                ]);
            }
        }
    });
    bytes
}

fn load_policy(vault: &crate::Vault, bytes: &[u8]) -> Result<PolicyManifestResolution> {
    put_policy_manifest_bytes(vault, test_id(0x6F), bytes)?;
    let txn = vault.store.env.read_txn()?;
    resolve_policy_manifest(&vault.store, &txn)
}

#[test]
fn repair_content_kind_wire() {
    assert_eq!(GateContentKind::Repair.as_str(), "repair");
}

#[test]
fn gate_recomputes_from_repair_actor() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x63);
    let policy = load_policy(&vault, &repair_manifest(actor, true, "normal"))?;
    let healer = FixedHealer(vec![proposal()]);
    let diagnostics = [diagnostic()];
    let system = registration(
        &healer,
        WriteActor::new(actor, EdgeActorClass::System),
        None,
    );
    let other = registration(
        &healer,
        WriteActor::new(test_id(0x66), EdgeActorClass::System),
        None,
    );
    let auto = review(&policy, &system, &diagnostics)?;
    let held = review(&policy, &other, &diagnostics)?;
    assert_eq!(
        auto.proposals()[0].route(),
        RepairConsentRoute::AutoEligible
    );
    assert_eq!(held.proposals()[0].route(), RepairConsentRoute::HumanReview);
    assert_eq!(
        auto.proposals()[0].proposal(),
        held.proposals()[0].proposal()
    );
    assert!(
        held.proposals()[0]
            .reason_codes()
            .iter()
            .any(|reason| reason == "gate.pending.actor_ceiling")
    );

    for (ceiling, expected) in [
        (
            PolicyApprovalCeiling::Auto,
            RepairConsentRoute::AutoEligible,
        ),
        (
            PolicyApprovalCeiling::Proposed,
            RepairConsentRoute::HumanReview,
        ),
    ] {
        let agent = registration(
            &healer,
            WriteActor::new(actor, EdgeActorClass::Agent),
            Some(ceiling),
        );
        assert_eq!(
            review(&policy, &agent, &diagnostics)?.proposals()[0].route(),
            expected
        );
    }
    let mut restrictive = repair_manifest(actor, true, "normal");
    replace_actor_ceilings(
        &mut restrictive,
        vec![actor_ceiling_row_for_ref(
            "system",
            &actor.to_hex(),
            "proposed",
        )],
    );
    let current = load_policy(&vault, &restrictive)?;
    assert_eq!(
        review(&current, &system, &diagnostics)?.proposals()[0].route(),
        RepairConsentRoute::HumanReview
    );
    Ok(())
}

#[test]
fn severity_label_not_trusted() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x63);
    let normal_policy = load_policy(&vault, &repair_manifest(actor, true, "normal"))?;
    let healer = FixedHealer(vec![proposal()]);
    let registered = registration(
        &healer,
        WriteActor::new(actor, EdgeActorClass::System),
        None,
    );
    let normal = diagnostic();
    let mut critical = normal.clone();
    critical.criticality = DiagnosticCriticality::Critical;
    let first = review(&normal_policy, &registered, std::slice::from_ref(&normal))?;
    let second = review(&normal_policy, &registered, std::slice::from_ref(&critical))?;
    assert_eq!(
        first, second,
        "diagnostic severity cannot choose repair authority"
    );
    assert_eq!(
        first.proposals()[0].route(),
        RepairConsentRoute::AutoEligible
    );

    let current = load_policy(&vault, &repair_manifest(actor, true, "critical"))?;
    for event in [normal, critical] {
        let bundle = review(&current, &registered, &[event])?;
        assert_eq!(
            bundle.proposals()[0].route(),
            RepairConsentRoute::HumanReview
        );
        assert_eq!(
            bundle.proposals()[0].criticality(),
            RepairCriticality::Critical
        );
    }
    Ok(())
}

#[test]
fn repair_proposal_disclosure_cannot_spoof_invocation() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x63);
    let policy = load_policy(&vault, &repair_manifest(actor, false, "normal"))?;
    let honest = proposal();
    let mut spoofed = honest.clone();
    spoofed.actor = RepairActor {
        actor_class: "human".to_owned(),
        actor_ref: test_id(0x64),
    };
    spoofed.source = ClaimSource::UserStated;
    let healer = FixedHealer(vec![spoofed.clone()]);
    let registered = registration(
        &healer,
        WriteActor::new(actor, EdgeActorClass::System),
        None,
    );
    let stamp = HealerInvocationStamp::mint(&registered, "run.repair", "session.repair")?;
    let honest_input = crate::gate::repair::repair_gate_input(&policy, &stamp, &honest);
    let spoofed_input = crate::gate::repair::repair_gate_input(&policy, &stamp, &spoofed);
    assert_eq!(honest_input, spoofed_input);
    for claimed_class in ["owner", "administrator", ""] {
        let mut invented = spoofed.clone();
        invented.actor.actor_class = claimed_class.to_owned();
        assert_eq!(
            crate::gate::repair::repair_gate_input(&policy, &stamp, &invented),
            honest_input
        );
    }
    assert_eq!(spoofed_input.actor.actor_class, "system");
    assert_eq!(spoofed_input.actor.actor_ref, Some(actor.to_hex()));
    assert_eq!(spoofed_input.source, Some(ClaimSource::Generated));
    assert_eq!(spoofed_input.provenance.actor_entity_ref, Some(actor));
    assert!(spoofed_input.provenance.dreamer_run_id.is_none());
    let (route, decision) = evaluate_repair_consent(&policy, &stamp, &spoofed);
    assert_eq!(route, RepairConsentRoute::HumanReview);
    assert_eq!(
        decision.reason_codes(),
        &[GateReasonCode::PendingSourceTrust]
    );
    assert_eq!(decision, policy.evaluate_gate(&spoofed_input));

    let bundle = review(&policy, &registered, &[diagnostic()])?;
    let member = &bundle.proposals()[0];
    assert_eq!(
        member.proposal(),
        &spoofed,
        "claimed attribution stays visible"
    );
    assert_eq!(member.invocation().actor().actor_ref, actor);
    assert_eq!(member.invocation().source(), ClaimSource::Generated);
    assert_eq!(member.invocation().healer_id(), "test.mechanical_healer");
    assert_eq!(member.invocation().run_ref(), "run.repair");
    Ok(())
}

#[test]
fn no_auto_apply() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x63);
    let policy = load_policy(&vault, &repair_manifest(actor, true, "normal"))?;
    let target = test_id(0x65);
    vault.put_entity(&target, ENTITY_TYPE_PERSON, test_time(1), 1, b"unchanged")?;
    let target_before = vault.get_raw(&target)?;
    let policy_before = vault.get_raw(&test_id(0x6F))?;
    let policy_snapshot = policy.clone();
    let mut intent = proposal();
    intent.operation = RepairOperation::Rescore { target_ref: target };
    let healer = FixedHealer(vec![intent.clone()]);
    let registered = registration(
        &healer,
        WriteActor::new(actor, EdgeActorClass::System),
        None,
    );
    let before_metrics = gate_metric_emission_count_for_test();
    let bundle = review(&policy, &registered, &[diagnostic()])?;
    assert_eq!(
        bundle.proposals()[0].route(),
        RepairConsentRoute::AutoEligible
    );
    assert_eq!(bundle.proposals()[0].proposal(), &intent);
    assert_eq!(gate_metric_emission_count_for_test(), before_metrics);
    assert_eq!(vault.get_raw(&target)?, target_before);
    assert_eq!(vault.get_raw(&test_id(0x6F))?, policy_before);
    assert_eq!(policy, policy_snapshot);
    assert!(vault.get_raw(&intent.proposal_id)?.is_none());
    Ok(())
}

#[test]
fn repair_bundle_discloses_each_member_without_summary_approval() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x63);
    let policy = load_policy(&vault, &repair_manifest(actor, true, "normal"))?;
    let safe = proposal();
    let mut poisoned = proposal();
    poisoned.proposal_id = test_id(0x67);
    poisoned.diagnostic_refs = vec![test_id(0x68), test_id(0x69)];
    poisoned.actor.actor_class = "human".to_owned();
    poisoned.actor.actor_ref = test_id(0x64);
    poisoned.source = ClaimSource::UserStated;
    poisoned.target_predicate = "health.record".to_owned();
    poisoned.operation = RepairOperation::ProposeClaim {
        predicate: poisoned.target_predicate.clone(),
        value: Value::from("suggested"),
    };
    let healer = FixedHealer(vec![safe.clone(), poisoned.clone()]);
    let registered = registration(
        &healer,
        WriteActor::new(actor, EdgeActorClass::System),
        None,
    );
    let bundle = review(&policy, &registered, &[diagnostic()])?;
    assert_eq!(bundle.session_tag(), "session.repair");
    assert_eq!(bundle.proposals().len(), 2);
    for (member, intent, criticality, route) in [
        (
            &bundle.proposals()[0],
            &safe,
            RepairCriticality::Normal,
            RepairConsentRoute::AutoEligible,
        ),
        (
            &bundle.proposals()[1],
            &poisoned,
            RepairCriticality::Critical,
            RepairConsentRoute::HumanReview,
        ),
    ] {
        assert_eq!(member.proposal(), intent);
        assert_eq!(member.criticality(), criticality);
        assert_eq!(member.route(), route);
        assert_eq!(member.invocation().actor().actor_ref, actor);
        assert_eq!(member.invocation().source(), ClaimSource::Generated);
        assert_eq!(member.proposal().session_tag, bundle.session_tag());
        assert_eq!(member.invocation().session_tag(), bundle.session_tag());
    }
    assert!(
        bundle.proposals()[1]
            .reason_codes()
            .iter()
            .any(|reason| reason == "gate.pending.criticality_floor")
    );
    Ok(())
}

#[test]
fn repair_code_schema_skill_and_policy_are_review_only() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x63);
    let policy = load_policy(&vault, &repair_manifest(actor, true, "normal"))?;
    let operations = [
        RepairOperation::DevPatch {
            repo_ref: "repo.fixture".to_owned(),
            patch_ref: "patch.fixture".to_owned(),
        },
        RepairOperation::SchemaPatch {
            schema_ref: "schema.fixture".to_owned(),
            patch_ref: "patch.fixture".to_owned(),
        },
        RepairOperation::SkillEdit {
            skill_ref: test_id(0x65),
            patch_ref: "patch.fixture".to_owned(),
        },
        RepairOperation::NarrowPolicy {
            predicate: "maintenance.index".to_owned(),
            value: Value::from("auto"), // A name alone cannot prove narrowing.
        },
    ];
    for operation in operations {
        for class in [
            EdgeActorClass::System,
            EdgeActorClass::Agent,
            EdgeActorClass::Human,
        ] {
            let mut intent = proposal();
            intent.operation = operation.clone();
            let healer = FixedHealer(vec![intent]);
            let registered = registration(
                &healer,
                WriteActor::new(actor, class),
                Some(PolicyApprovalCeiling::Auto),
            );
            let bundle = review(&policy, &registered, &[diagnostic()])?;
            assert_eq!(
                bundle.proposals()[0].criticality(),
                RepairCriticality::Critical
            );
            assert_eq!(
                bundle.proposals()[0].route(),
                RepairConsentRoute::HumanReview
            );
            let denied = review(&PolicyManifestResolution::default(), &registered, &[])?;
            assert_eq!(denied.proposals()[0].route(), RepairConsentRoute::Denied);
        }
    }
    Ok(())
}

#[test]
fn repair_absent_or_malformed_policy_denies_every_member() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let malformed = load_policy(&vault, b"not-msgpack")?;
    let healer = FixedHealer(vec![proposal()]);
    let registered = registration(
        &healer,
        WriteActor::new(test_id(0x63), EdgeActorClass::System),
        None,
    );
    for policy in [PolicyManifestResolution::default(), malformed] {
        let bundle = review(&policy, &registered, &[diagnostic()])?;
        assert_eq!(bundle.proposals()[0].route(), RepairConsentRoute::Denied);
        assert_eq!(
            bundle.proposals()[0].criticality(),
            RepairCriticality::Critical
        );
        assert_eq!(
            bundle.proposals()[0].reason_codes(),
            &["gate.deny.policy_fail_closed"]
        );
    }
    Ok(())
}

#[test]
fn repair_invalid_direct_adapter_input_is_never_auto() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x63);
    let policy = load_policy(&vault, &repair_manifest(actor, true, "normal"))?;
    let healer = FixedHealer(Vec::new());
    let registered = registration(
        &healer,
        WriteActor::new(actor, EdgeActorClass::System),
        None,
    );
    let stamp = HealerInvocationStamp::mint(&registered, "run.repair", "session.repair")?;
    let mut wrong_target = proposal();
    wrong_target.operation = RepairOperation::ProposeClaim {
        predicate: "health.record".to_owned(),
        value: Value::from("poisoned"),
    };
    let mut wrong_session = proposal();
    wrong_session.session_tag = "another.session".to_owned();
    let mut missing_target = proposal();
    missing_target.target_predicate.clear();
    for invalid in [wrong_target, wrong_session, missing_target] {
        let (route, decision) = evaluate_repair_consent(&policy, &stamp, &invalid);
        assert_eq!(route, RepairConsentRoute::HumanReview);
        assert!(
            decision
                .reason_codes()
                .contains(&GateReasonCode::PendingCriticalityFloor)
        );
    }
    Ok(())
}

#[test]
fn repair_generated_permit_is_bound_to_stamped_actor() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x63);
    let other = test_id(0x66);
    let mut bytes = repair_manifest(actor, true, "normal");
    append_actor_ceiling(
        &mut bytes,
        actor_ceiling_row_for_ref("system", &other.to_hex(), "auto"),
    );
    rewrite_policy_manifest_entries(&mut bytes, |entries| {
        for (key, value) in entries {
            if key.as_str() == Some(POLICY_SOURCE_TRUST_KEY) {
                let Value::Map(sources) = value else {
                    panic!("source map")
                };
                let Value::Map(row) = &mut sources[0].1 else {
                    panic!("source row")
                };
                row.push((Value::from("actor_ref"), Value::from(actor.to_hex())));
            }
        }
    });
    let policy = load_policy(&vault, &bytes)?;
    let healer = FixedHealer(vec![proposal()]);
    for (stamped_actor, expected) in [
        (actor, RepairConsentRoute::AutoEligible),
        (other, RepairConsentRoute::HumanReview),
    ] {
        let registered = registration(
            &healer,
            WriteActor::new(stamped_actor, EdgeActorClass::System),
            None,
        );
        let bundle = review(&policy, &registered, &[diagnostic()])?;
        assert_eq!(bundle.proposals()[0].route(), expected);
    }
    Ok(())
}
