use super::*;
use crate::config::VaultConfig;
use crate::off_record::OffRecordBackendClass;
use crate::self_heal::{
    ConsentDeniedDetector, DeterministicDetector, DiagnosticObservation, DiagnosticWorkingSet,
    diagnostic_event_id, encode_diagnostic_event_body, run_deterministic_detectors,
};

const ALL: [FailureClassV1; 9] = [
    FailureClassV1::RefusalOverreach,
    FailureClassV1::TaskFailure,
    FailureClassV1::UserFrustration,
    FailureClassV1::MemoryMiss,
    FailureClassV1::MemoryIntrusion,
    FailureClassV1::PersonaBreak,
    FailureClassV1::LatencyAbandon,
    FailureClassV1::SilentDegradation,
    FailureClassV1::Other,
];

fn input(class: FailureClassV1) -> FailureSignalInput {
    FailureSignalInput {
        taxonomy: FailureTaxonomy::V1(class),
        agent_surface: AgentSurface::Chat,
        agent_kind: AgentKind::Custom,
        agent: VersionedComponent {
            name: "assistant".into(),
            version: "2".into(),
        },
        agent_ref: None,
    }
}

fn on_record_diagnostic(vault: &crate::Vault, _time: u64) -> Result<EntityId> {
    use crate::consent::{ComposedEffect, EffectFacts};
    use crate::receipt::{ReceiptKind, ReceiptQuery};
    use crate::store::GateDecisionId;
    let owner_id = EntityId::now();
    vault.put_entity(
        &owner_id,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let owner =
        vault.authenticate_owner(owner_id, "principal:owner", true, GateDecisionId::now())?;
    let effect =
        ComposedEffect::new(EffectFacts::new("channel.send")?.with_external_observers(true));
    vault.approve_once(&owner, effect.digest())?;
    vault.deny_consent(&owner, effect.digest())?;
    let query = ReceiptQuery::new(16)
        .with_kind(ReceiptKind::Gate)
        .with_actor(owner_id.to_hex());
    let ids = vault.run_consent_denied_detector("scope.consent", query)?;
    Ok(*ids.first().expect("real denied-consent diagnostic"))
}

#[test]
fn taxonomy_round_trip_and_payload_has_only_opaque_identifiers() -> Result<()> {
    let counts = FailureSignalCounts::default();
    let config = FailureSignalConfig {
        export_opt_in: true,
        ..Default::default()
    };
    for class in ALL {
        let taxonomy = FailureTaxonomy::V1(class);
        let json = serde_json::to_string(&taxonomy).expect("serialize taxonomy");
        assert_eq!(
            serde_json::from_str::<FailureTaxonomy>(&json).expect("decode taxonomy"),
            taxonomy
        );
        // All of these are currently legal machine-id strings, yet they are
        // personal facts. Never let any of them survive into the export.
        let mut input = input(class);
        input.agent.name = "Alice-Smith".into();
        input.agent.version = "123-45-6789".into();
        counts.record(
            config,
            input,
            VerifiedIdentity::default(),
            policy::Resolved::default(),
            3601,
            "private-medical-fact",
        )?;
        let row = counts
            .export(config)?
            .into_iter()
            .find(|r| r.dimensions.taxonomy == taxonomy)
            .expect("class row");
        let payload = serde_json::to_value(&row).expect("serialize tier 1");
        let wire = payload.to_string();
        for private in [
            "Alice-Smith",
            "123-45-6789",
            "private-medical-fact",
            "assistant",
        ] {
            assert!(!wire.contains(private), "raw identifier leaked: {private}");
        }
        let keys: std::collections::BTreeSet<_> = payload
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        let mut expected: std::collections::BTreeSet<_> = [
            "taxonomy_version",
            "failure_class",
            "agent_surface",
            "agent_kind",
            "agent",
            "model",
            "engine",
            "ts_bucket",
            "bucket_seconds",
            "count",
        ]
        .into_iter()
        .collect();
        if class == FailureClassV1::Other {
            expected.insert("detector_id");
        }
        assert_eq!(keys, expected);
        for component in ["agent", "model", "engine"] {
            assert_eq!(
                payload[component]
                    .as_object()
                    .expect("component")
                    .keys()
                    .map(String::as_str)
                    .collect::<std::collections::BTreeSet<_>>(),
                ["name", "version"].into_iter().collect()
            );
            if component == "agent" {
                for token in ["name", "version"] {
                    let value = payload[component][token].as_str().expect("opaque token");
                    assert_eq!(value.len(), 64);
                    assert!(value.bytes().all(|c| c.is_ascii_hexdigit()));
                }
            }
        }
        assert_eq!(payload["taxonomy_version"], "v1");
        assert_eq!(
            serde_json::from_value::<Tier1FailureCount>(payload).expect("decode row"),
            row
        );
    }
    assert!(
        serde_json::from_str::<FailureTaxonomy>(
            r#"{"taxonomy_version":"v2","failure_class":"task_failure"}"#
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn on_record_witness_required_off_record_overlay_never_counts_even_after_close() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::default();
    config.failure_signals.export_opt_in = true;
    let vault = crate::Vault::open(dir.path(), config)?;
    let session = vault
        .off_record_session_vault()
        .enter("failure-room", OffRecordBackendClass::Local)?;
    let event = ConsentDeniedDetector
        .detect(&DiagnosticWorkingSet {
            scope_ref: "scope.consent",
            observations: &[DiagnosticObservation {
                source_ref: EntityId::now(),
                kind: crate::consent::CONSENT_REASON_DENIED,
                payload_digest: [3; 32],
                observed_at: 1234,
            }],
        })
        .remove(0);
    let body = encode_diagnostic_event_body(&event)?;
    let overlay_id = diagnostic_event_id(&event.detector_id, &body);
    let overlay = session.overlay();
    let segment = overlay.install_txn_segment()?;
    overlay.put(
        crate::session_overlay::OverlayKeyspace::Entities,
        overlay_id.as_bytes(),
        &body,
    )?;
    segment.commit()?;
    assert!(vault.tier1_observation(overlay_id)?.is_none());
    assert!(vault.export_tier1_failure_counts()?.is_empty());
    session.close()?;
    assert!(vault.tier1_observation(overlay_id)?.is_none());
    assert!(vault.export_tier1_failure_counts()?.is_empty());
    let base_id = on_record_diagnostic(&vault, 3601)?;
    let mut bad = input(FailureClassV1::TaskFailure);
    bad.agent.name = " ".repeat(300);
    assert!(
        vault
            .record_failure_signal(
                &vault.tier1_observation(base_id)?.expect("real producer"),
                bad
            )
            .is_err()
    );
    vault.record_failure_signal(
        &vault.tier1_observation(base_id)?.expect("real producer"),
        input(FailureClassV1::TaskFailure),
    )?;
    assert_eq!(vault.export_tier1_failure_counts()?.len(), 1);
    Ok(())
}

#[test]
fn opt_in_and_vault_isolation() -> Result<()> {
    let one = tempfile::tempdir()?;
    let two = tempfile::tempdir()?;
    let mut config = VaultConfig::default();
    config.failure_signals.export_opt_in = true;
    let vault = crate::Vault::open(one.path(), config.clone())?;
    let other = crate::Vault::open(two.path(), config)?;
    let id = on_record_diagnostic(&vault, 3601)?;
    vault.record_failure_signal(
        &vault.tier1_observation(id)?.expect("real producer"),
        input(FailureClassV1::TaskFailure),
    )?;
    assert_eq!(vault.export_tier1_failure_counts()?.len(), 1);
    assert!(other.tier1_observation(id)?.is_none());
    assert!(other.export_tier1_failure_counts()?.is_empty());
    let default_off = FailureSignalCounts::default();
    default_off.record(
        FailureSignalConfig::default(),
        input(FailureClassV1::TaskFailure),
        VerifiedIdentity::default(),
        policy::Resolved::default(),
        1,
        "detector",
    )?;
    assert!(
        default_off
            .export(FailureSignalConfig::default())?
            .is_empty()
    );
    let managed = FailureSignalConfig {
        deployment: crate::config::failure_signals::DeploymentTier::Managed,
        ..Default::default()
    };
    default_off.record(
        managed,
        input(FailureClassV1::TaskFailure),
        VerifiedIdentity::default(),
        policy::Resolved::default(),
        1,
        "detector",
    )?;
    assert_eq!(default_off.export(managed)?.len(), 1);
    Ok(())
}

#[test]
fn detector_cannot_materialize_off_record_source_in_base_or_export_after_close() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::default();
    config.failure_signals.export_opt_in = true;
    let vault = crate::Vault::open(dir.path(), config)?;
    let session = vault
        .off_record_session_vault()
        .enter("detector-room", OffRecordBackendClass::Local)?;
    let source_ref = EntityId::now();
    let overlay = session.overlay();
    let segment = overlay.install_txn_segment()?;
    overlay.put(
        crate::session_overlay::OverlayKeyspace::Entities,
        source_ref.as_bytes(),
        b"private turn",
    )?;
    segment.commit()?;
    let fact = DiagnosticObservation {
        source_ref,
        kind: crate::consent::CONSENT_REASON_DENIED,
        payload_digest: [7; 32],
        observed_at: 3_601,
    };
    let working_set = DiagnosticWorkingSet {
        scope_ref: "scope.consent",
        observations: &[fact],
    };
    let event = ConsentDeniedDetector.detect(&working_set).remove(0);
    let body = encode_diagnostic_event_body(&event)?;
    let diagnostic_id = diagnostic_event_id(&event.detector_id, &body);
    assert!(run_deterministic_detectors(&vault, &working_set, &[&ConsentDeniedDetector]).is_err());
    assert!(vault.tier1_observation(diagnostic_id)?.is_none());
    assert!(vault.export_tier1_failure_counts()?.is_empty());
    session.close()?;
    // A caller still holding the vanished source's ID can author a canonical
    // base diagnostic, but the tier-1 door requires a live base source.
    vault.emit_diagnostic_event(&diagnostic_id, &event)?;
    assert!(vault.tier1_observation(diagnostic_id)?.is_none());
    assert!(vault.export_tier1_failure_counts()?.is_empty());
    // A base TURN is also not a Gate-decision receipt, despite being live.
    let turn_id = EntityId::now();
    vault.put_entity(
        &turn_id,
        crate::registry::ENTITY_TYPE_TURN,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"turn",
    )?;
    let turn_fact = DiagnosticObservation {
        source_ref: turn_id,
        kind: crate::consent::CONSENT_REASON_DENIED,
        payload_digest: [9; 32],
        observed_at: 7_201,
    };
    let turn_input = DiagnosticWorkingSet {
        scope_ref: "scope.consent",
        observations: &[turn_fact],
    };
    let turn_ids = run_deterministic_detectors(&vault, &turn_input, &[&ConsentDeniedDetector])?;
    assert_eq!(turn_ids.len(), 1);
    assert!(vault.tier1_observation(turn_ids[0])?.is_none());
    assert!(vault.export_tier1_failure_counts()?.is_empty());
    // D1 is now a live base entity. A second real detector can cite D1,
    // but D2 cannot treat that nested DIAGNOSTIC as a Gate receipt.
    let second_fact = DiagnosticObservation {
        source_ref: diagnostic_id,
        kind: crate::consent::CONSENT_REASON_DENIED,
        payload_digest: [8; 32],
        observed_at: 7_201,
    };
    let second = DiagnosticWorkingSet {
        scope_ref: "scope.consent",
        observations: &[second_fact],
    };
    let second_ids = run_deterministic_detectors(&vault, &second, &[&ConsentDeniedDetector])?;
    assert_eq!(second_ids.len(), 1);
    assert!(vault.tier1_observation(second_ids[0])?.is_none());
    assert!(vault.export_tier1_failure_counts()?.is_empty());
    Ok(())
}

#[test]
fn registered_system_and_platform_versions_are_stable_across_vaults_and_reopen() -> Result<()> {
    let one = tempfile::tempdir()?;
    let two = tempfile::tempdir()?;
    let mut config = VaultConfig::default();
    config.failure_signals.export_opt_in = true;
    let vault = crate::Vault::open(one.path(), config.clone())?;
    let other = crate::Vault::open(two.path(), config.clone())?;
    let (agent_ref, definition) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
        .expect("seeded system agent");
    let registered = || {
        let mut signal = input(FailureClassV1::Other);
        signal.agent_kind = AgentKind::System;
        signal.agent_ref = Some(agent_ref);
        signal.agent = VersionedComponent {
            name: "sys.default".into(),
            version: definition.version.clone(),
        };
        signal
    };
    let id_one = on_record_diagnostic(&vault, 3_601)?;
    let id_two = on_record_diagnostic(&other, 3_601)?;
    vault.record_failure_signal(
        &vault.tier1_observation(id_one)?.expect("real producer"),
        registered(),
    )?;
    other.record_failure_signal(
        &other.tier1_observation(id_two)?.expect("real producer"),
        registered(),
    )?;
    let first = vault.export_tier1_failure_counts()?.remove(0).dimensions;
    let second = other.export_tier1_failure_counts()?.remove(0).dimensions;
    assert_eq!(first, second);
    assert_eq!(first.agent.name, "sys.default");
    assert_eq!(first.agent.version, definition.version);
    assert_eq!(first.engine.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(first.detector_id.as_deref(), Some("consent.denied.v1"));
    drop(vault);
    let reopened = crate::Vault::open(one.path(), config)?;
    assert!(
        reopened.tier1_observation(id_one)?.is_none(),
        "the open-vault witness must not persist"
    );
    let refreshed = reopened.run_consent_denied_detector(
        "scope.consent",
        crate::receipt::ReceiptQuery::new(16).with_kind(crate::receipt::ReceiptKind::Gate),
    )?;
    assert!(refreshed.contains(&id_one));
    let reopened_id = id_one;
    reopened.record_failure_signal(
        &reopened
            .tier1_observation(reopened_id)?
            .expect("fresh producer after reopen"),
        registered(),
    )?;
    assert_eq!(
        reopened.export_tier1_failure_counts()?.remove(0).dimensions,
        first
    );
    let mut impersonated = registered();
    impersonated.agent.name = "Alice-Smith".into();
    assert!(
        reopened
            .record_failure_signal(
                &reopened
                    .tier1_observation(reopened_id)?
                    .expect("fresh producer after reopen"),
                impersonated
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn retrieval_miss_uses_published_base_run_not_entity_impersonation() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::test_util::embedding_test_config();
    config.retrieval_telemetry_capture = true;
    config.failure_signals.export_opt_in = true;
    let vault = crate::Vault::open(dir.path(), config)?;
    let run = crate::store::RetrievalRunRecord::new(
        crate::store::RetrievalRunId::now(),
        crate::store::RetrievalAction::Pipeline,
        3_601,
        1,
        vec![crate::store::RetrievalSignal::Text],
        vec![],
        3,
        0,
        Some("no_results".into()),
    );
    vault.store.record_retrieval_run(&run)?;
    let ids = vault.run_retrieval_miss_detector("retrieval", 10)?;
    assert_eq!(ids.len(), 1);
    vault.record_failure_signal(
        &vault
            .tier1_observation(ids[0])?
            .expect("retrieval producer"),
        input(FailureClassV1::MemoryMiss),
    )?;
    assert_eq!(vault.export_tier1_failure_counts()?.len(), 1);
    vault.store.delete_retrieval_run(run.run_id)?;
    assert!(
        vault
            .record_failure_signal(
                &vault
                    .tier1_observation(ids[0])?
                    .expect("prior producer witness"),
                input(FailureClassV1::MemoryMiss)
            )
            .is_err()
    );
    assert_eq!(vault.export_tier1_failure_counts()?[0].count(), 1);
    Ok(())
}

#[test]
fn real_retrieval_abstention_is_a_ledger_backed_failure_signal() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::test_util::embedding_test_config();
    config.retrieval_telemetry_capture = true;
    config.failure_signals.export_opt_in = true;
    let vault = crate::Vault::open(dir.path(), config)?;
    let id = EntityId::now();
    vault
        .batch()
        .put(
            &id,
            1,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"candidate",
        )
        .text(
            &id,
            &[("body", "stored evidence with insufficient semantic match")],
        )
        .vector(&id, &[1.0, 0.0, 0.0, 0.0])
        .commit()?;
    let output = vault
        .context_pack()
        .search_text("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 10)
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .run_with_telemetry()?;
    assert!(output.value.results.is_empty());
    let run_id = output.run_id.expect("real published retrieval telemetry");
    let run = vault.retrieval_run(run_id)?.expect("published run");
    assert!(
        crate::self_heal::DiagnosticObservation::from_retrieval_run(&run).is_some(),
        "abstention with candidates should be a typed retrieval miss: {run:?}"
    );
    let ids = vault.run_retrieval_miss_detector("real.retrieval", 10)?;
    assert_eq!(ids.len(), 1);
    vault.record_failure_signal(
        &vault
            .tier1_observation(ids[0])?
            .expect("retrieval producer"),
        input(FailureClassV1::MemoryMiss),
    )?;
    assert_eq!(vault.export_tier1_failure_counts()?.len(), 1);
    Ok(())
}

#[test]
fn failure_signals_consolidation_requires_base_receipt_not_caller_copy() -> Result<()> {
    use crate::store::{GateDecisionId, GateDecisionRecord};
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.failure_signals.export_opt_in = true;
    let vault = crate::Vault::open(dir.path(), config)?;
    let decision = GateDecisionRecord {
        version: 0,
        decision_id: GateDecisionId::now(),
        created_at: 3_601,
        outcome: "denied".into(),
        reason_codes: vec!["gate.deny.dreamer_precommit.degenerate_output".into()],
        receipt_reasons: vec![],
        system_notices: vec![],
        actor_class: "agent".into(),
        actor_ref: None,
        content_kind: "claim".into(),
        policy_manifest_version: "v0".into(),
        claim_id: None,
        grant_ref: None,
        diff_handle: vec![0xAA],
        read_frontier_hash: [0xBB; 32],
        redacted_at: None,
    };
    vault.with_write_txn(|txn| vault.store.append_gate_decision_in_txn(txn, &decision))?;
    let receipt = crate::receipt::gate_decision_receipt(&decision);
    let ids = vault.project_receipt_tripwires("run", std::slice::from_ref(&receipt), 3_601)?;
    assert_eq!(ids.len(), 1);
    let observation = vault
        .tier1_observation(ids[0])?
        .expect("ledger-backed producer");
    vault.record_failure_signal(&observation, input(FailureClassV1::TaskFailure))?;
    let mut forged = receipt;
    forged
        .policy_trace
        .push("gate.deny.dreamer_precommit.foreign".into());
    let forged_ids = vault.project_receipt_tripwires("run", &[forged], 3_601)?;
    assert_eq!(forged_ids.len(), 1);
    assert_ne!(forged_ids[0], ids[0]);
    assert!(vault.tier1_observation(forged_ids[0])?.is_none());
    assert_eq!(vault.export_tier1_failure_counts()?.len(), 1);
    Ok(())
}

#[test]
fn public_door_counts_nine_classes_without_provenance_references() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::default();
    config.failure_signals.export_opt_in = true;
    let vault = crate::Vault::open(dir.path(), config)?;
    let id = on_record_diagnostic(&vault, 1)?;
    let observation = vault.tier1_observation(id)?.expect("real producer");
    for class in ALL {
        let mut signal = input(class);
        signal.agent.name = "Alice-Smith".into();
        vault.record_failure_signal(&observation, signal.clone())?;
        vault.record_failure_signal(&observation, signal)?;
    }
    let rows = vault.export_tier1_failure_counts()?;
    assert_eq!(rows.len(), 9);

    let body = vault.get(&id)?.expect("producer diagnostic");
    let event = crate::self_heal::decode_diagnostic_event_body(&body)?;
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let mut forbidden = vec![
        id.to_hex(),
        hex(blake3::hash(&body).as_bytes()),
        hex(&event.replay.content_hash),
        "scope.consent".to_owned(),
        "Alice-Smith".to_owned(),
    ];
    forbidden.extend(event.replay.run_ref.clone());
    forbidden.extend(event.evidence_refs.iter().map(EntityId::to_hex));
    for class in ALL {
        let taxonomy = FailureTaxonomy::V1(class);
        let row = rows
            .iter()
            .find(|row| row.dimensions().taxonomy() == taxonomy)
            .expect("class row");
        assert_eq!(row.count(), 2);
        let payload = serde_json::to_value(row).expect("serialize tier 1");
        let wire = payload.to_string();
        for private in &forbidden {
            assert!(
                !wire.contains(private.as_str()),
                "provenance leaked: {private}"
            );
        }
        let keys: std::collections::BTreeSet<_> = payload
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        let mut expected: std::collections::BTreeSet<_> = [
            "taxonomy_version",
            "failure_class",
            "agent_surface",
            "agent_kind",
            "agent",
            "model",
            "engine",
            "ts_bucket",
            "bucket_seconds",
            "count",
        ]
        .into_iter()
        .collect();
        if class == FailureClassV1::Other {
            expected.insert("detector_id");
        }
        assert_eq!(keys, expected);
        assert_eq!(
            serde_json::from_value::<Tier1FailureCount>(payload).expect("decode row"),
            *row
        );
    }
    Ok(())
}
