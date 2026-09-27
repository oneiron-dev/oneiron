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
        model_step_ref: None,
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
fn nine_classes_count_independently_per_hour_and_surface() -> Result<()> {
    let counts = FailureSignalCounts::default();
    let config = FailureSignalConfig {
        export_opt_in: true,
        ..Default::default()
    };
    for class in ALL {
        counts.record(
            config,
            input(class),
            VerifiedIdentity::default(),
            policy::Resolved::default(),
            3_601,
            "detector-1",
        )?;
        counts.record(
            config,
            input(class),
            VerifiedIdentity::default(),
            policy::Resolved::default(),
            7_199,
            "detector-1",
        )?;
        counts.record(
            config,
            input(class),
            VerifiedIdentity::default(),
            policy::Resolved::default(),
            7_200,
            "detector-1",
        )?;
    }
    let rows = counts.export(config)?;
    assert_eq!(rows.len(), 18);
    for class in ALL {
        assert_eq!(
            rows.iter()
                .find(|row| row.dimensions.taxonomy == FailureTaxonomy::V1(class)
                    && row.dimensions.ts_bucket == 3_600)
                .map(|row| row.count),
            Some(2)
        );
        assert_eq!(
            rows.iter()
                .find(|row| row.dimensions.taxonomy == FailureTaxonomy::V1(class)
                    && row.dimensions.ts_bucket == 7_200)
                .map(|row| row.count),
            Some(1)
        );
    }
    let mut different = input(FailureClassV1::Other);
    different.agent_surface = AgentSurface::Code;
    counts.record(
        config,
        different,
        VerifiedIdentity::default(),
        policy::Resolved::default(),
        3_601,
        "detector-1",
    )?;
    assert_eq!(
        counts
            .export(config)?
            .iter()
            .filter(
                |r| r.dimensions.taxonomy == FailureTaxonomy::V1(FailureClassV1::Other)
                    && r.dimensions.ts_bucket == 3_600
            )
            .count(),
        2
    );
    let mut different = input(FailureClassV1::Other);
    different.agent_kind = AgentKind::Custom;
    different.agent.version = "4".into();
    counts.record(
        config,
        different,
        VerifiedIdentity::default(),
        policy::Resolved::default(),
        -1,
        "detector-2",
    )?;
    assert_eq!(
        counts
            .export(config)?
            .iter()
            .filter(|r| r.dimensions.ts_bucket == -3_600)
            .count(),
        1
    );
    Ok(())
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
fn hourly_rounding_rejects_overflow_without_changing_counts() -> Result<()> {
    let counts = FailureSignalCounts::default();
    let config = FailureSignalConfig {
        export_opt_in: true,
        ..Default::default()
    };
    let first = i64::MIN + 1_808;
    for invalid in [i64::MIN, first - 1] {
        assert!(matches!(
            counts.record(
                config,
                input(FailureClassV1::TaskFailure),
                VerifiedIdentity::default(),
                policy::Resolved::default(),
                invalid,
                "detector"
            ),
            Err(Error::ArithmeticOverflow("failure signal hour bucket"))
        ));
        assert!(counts.export(config)?.is_empty());
    }
    counts.record(
        config,
        input(FailureClassV1::TaskFailure),
        VerifiedIdentity::default(),
        policy::Resolved::default(),
        first,
        "detector",
    )?;
    counts.record(
        config,
        input(FailureClassV1::TaskFailure),
        VerifiedIdentity::default(),
        policy::Resolved::default(),
        i64::MAX,
        "detector",
    )?;
    let rows = counts.export(config)?;
    assert!(rows.iter().any(|row| row.dimensions.ts_bucket == first));
    assert!(
        rows.iter()
            .any(|row| row.dimensions.ts_bucket == i64::MAX.div_euclid(3600) * 3600)
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
    assert!(
        vault
            .record_failure_signal(overlay_id, input(FailureClassV1::Other))
            .is_err()
    );
    assert!(vault.export_tier1_failure_counts()?.is_empty());
    session.close()?;
    assert!(
        vault
            .record_failure_signal(overlay_id, input(FailureClassV1::Other))
            .is_err()
    );
    assert!(vault.export_tier1_failure_counts()?.is_empty());
    let base_id = on_record_diagnostic(&vault, 3601)?;
    let mut bad = input(FailureClassV1::TaskFailure);
    bad.agent.name = " ".repeat(300);
    assert!(vault.record_failure_signal(base_id, bad).is_err());
    vault.record_failure_signal(base_id, input(FailureClassV1::TaskFailure))?;
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
    vault.record_failure_signal(id, input(FailureClassV1::TaskFailure))?;
    assert_eq!(vault.export_tier1_failure_counts()?.len(), 1);
    assert!(
        other
            .record_failure_signal(id, input(FailureClassV1::TaskFailure))
            .is_err()
    );
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
    assert!(
        vault
            .record_failure_signal(diagnostic_id, input(FailureClassV1::Other))
            .is_err()
    );
    assert!(vault.export_tier1_failure_counts()?.is_empty());
    session.close()?;
    // A caller still holding the vanished source's ID can author a canonical
    // base diagnostic, but the tier-1 door requires a live base source.
    vault.emit_diagnostic_event(&diagnostic_id, &event)?;
    assert!(
        vault
            .record_failure_signal(diagnostic_id, input(FailureClassV1::Other))
            .is_err()
    );
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
    assert!(
        vault
            .record_failure_signal(second_ids[0], input(FailureClassV1::Other))
            .is_err()
    );
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
    vault.record_failure_signal(id_one, registered())?;
    other.record_failure_signal(id_two, registered())?;
    let first = vault.export_tier1_failure_counts()?.remove(0).dimensions;
    let second = other.export_tier1_failure_counts()?.remove(0).dimensions;
    assert_eq!(first, second);
    assert_eq!(first.agent.name, "sys.default");
    assert_eq!(first.agent.version, definition.version);
    assert_eq!(first.engine.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(first.detector_id.as_deref(), Some("consent.denied.v1"));
    drop(vault);
    let reopened = crate::Vault::open(one.path(), config)?;
    reopened.record_failure_signal(id_one, registered())?;
    assert_eq!(
        reopened.export_tier1_failure_counts()?.remove(0).dimensions,
        first
    );
    let mut impersonated = registered();
    impersonated.agent.name = "Alice-Smith".into();
    assert!(
        reopened
            .record_failure_signal(id_one, impersonated)
            .is_err()
    );
    Ok(())
}

#[test]
fn custom_agent_revision_changes_only_agent_revision_token() -> Result<()> {
    let counts = FailureSignalCounts::default();
    let config = FailureSignalConfig {
        export_opt_in: true,
        ..Default::default()
    };
    let first = input(FailureClassV1::TaskFailure);
    let mut next = first.clone();
    next.agent.version = "new-private-version".into();
    counts.record(
        config,
        first,
        VerifiedIdentity::default(),
        policy::Resolved::default(),
        3_601,
        "detector",
    )?;
    counts.record(
        config,
        next,
        VerifiedIdentity::default(),
        policy::Resolved::default(),
        3_601,
        "detector",
    )?;
    let rows = counts.export(config)?;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].dimensions.agent.name, rows[1].dimensions.agent.name);
    assert_ne!(
        rows[0].dimensions.agent.version,
        rows[1].dimensions.agent.version
    );
    assert_eq!(rows[0].dimensions.model, rows[1].dimensions.model);
    assert_eq!(rows[0].dimensions.engine, rows[1].dimensions.engine);
    Ok(())
}

#[test]
fn policy_default_override_narrowing_and_resolution_changes_keep_separate_buckets() -> Result<()> {
    use rmpv::Value;
    let default = policy::Resolved::default();
    assert_eq!(
        (default.bucket_seconds, default.max_component_bytes),
        (3_600, 256)
    );
    let holder = EntityId::now();
    let baseline = policy::Row {
        scope: policy::Scope::Default,
        bucket_seconds: 3_600,
        max_component_bytes: 256,
        precedence: policy::Precedence::NestedNarrowing,
    };
    let vault_row = policy::Row {
        scope: policy::Scope::Vault,
        bucket_seconds: 7_200,
        max_component_bytes: 512,
        precedence: policy::Precedence::NestedNarrowing,
    };
    let holder_row = policy::Row {
        scope: policy::Scope::Holder(holder),
        bucket_seconds: 10_800,
        max_component_bytes: 384,
        precedence: policy::Precedence::NestedNarrowing,
    };
    let narrow = policy::resolve(&[baseline, vault_row, holder_row], Some(holder));
    assert_eq!(
        (narrow.bucket_seconds, narrow.max_component_bytes),
        (10_800, 256)
    );
    let override_row = policy::Row {
        precedence: policy::Precedence::HolderOverride,
        ..vault_row
    };
    let override_policy = policy::resolve(&[holder_row, override_row, baseline], Some(holder));
    assert_eq!(
        (
            override_policy.bucket_seconds,
            override_policy.max_component_bytes
        ),
        (10_800, 384)
    );
    let too_wide = policy::Row {
        bucket_seconds: 60,
        max_component_bytes: 2_048,
        ..holder_row
    };
    let capped = policy::resolve(&[baseline, override_row, too_wide], Some(holder));
    assert_eq!(
        (capped.bucket_seconds, capped.max_component_bytes),
        (7_200, 512)
    );

    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::default();
    config.failure_signals.export_opt_in = true;
    let vault = crate::Vault::open(dir.path(), config)?;
    let id = on_record_diagnostic(&vault, 1)?;
    let mut signal = input(FailureClassV1::TaskFailure);
    vault.record_failure_signal(id, signal.clone())?;
    let policy_id = crate::gate::default_policy_manifest_id()?;
    let mut manifest =
        rmpv::decode::read_value(&mut crate::gate::default_policy_manifest().as_slice())
            .expect("shipped manifest");
    let Value::Map(ref mut entries) = manifest else {
        panic!("manifest map")
    };
    let policy_value = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some(policy::POLICY_KEY))
        .expect("shipped policy row");
    let Value::Array(ref mut rows) = policy_value.1 else {
        panic!("policy array")
    };
    rows.push(Value::Map(vec![
        (Value::from("scope"), Value::from("vault")),
        (Value::from("bucket_seconds"), Value::from(7_200_u64)),
        (Value::from("max_component_bytes"), Value::from(512_u64)),
        (Value::from("precedence"), Value::from("holder_override")),
    ]));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &manifest).expect("encode manifest");
    crate::test_util::put_policy_manifest_bytes(&vault, policy_id, &bytes)?;
    signal.agent.name = "x".repeat(300);
    vault.record_failure_signal(id, signal)?;
    let rows = vault.export_tier1_failure_counts()?;
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().any(|r| r.dimensions.bucket_seconds == 3_600));
    assert!(rows.iter().any(|r| r.dimensions.bucket_seconds == 7_200));
    Ok(())
}

#[test]
fn policy_row_decode_rejects_unknown_and_duplicate_values() {
    use rmpv::Value;
    let Value::Array(mut rows) = policy::default_row() else {
        panic!("default array")
    };
    {
        let Value::Map(ref mut entries) = rows[0] else {
            panic!("default map")
        };
        entries.push((Value::from("bucket_seconds"), Value::from(900_u64)));
    }
    assert!(policy::decode(&Value::Array(rows.clone())).is_none());
    {
        let Value::Map(ref mut entries) = rows[0] else {
            panic!("default map")
        };
        entries.pop();
        entries.push((Value::from("unknown"), Value::from(1)));
    }
    assert!(policy::decode(&Value::Array(rows)).is_none());
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
    vault.record_failure_signal(ids[0], input(FailureClassV1::MemoryMiss))?;
    assert_eq!(vault.export_tier1_failure_counts()?.len(), 1);
    vault.store.delete_retrieval_run(run.run_id)?;
    assert!(
        vault
            .record_failure_signal(ids[0], input(FailureClassV1::MemoryMiss))
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
    vault.record_failure_signal(ids[0], input(FailureClassV1::MemoryMiss))?;
    assert_eq!(vault.export_tier1_failure_counts()?.len(), 1);
    Ok(())
}
