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
        model_role: LlmRole::Orchestrator,
    }
}

fn on_record_diagnostic(vault: &crate::Vault, time: u64) -> Result<EntityId> {
    let source_ref = EntityId::now();
    vault.put_entity(
        &source_ref,
        crate::registry::ENTITY_TYPE_TURN,
        crate::temporal::TimeRange {
            start: time,
            end: time,
        },
        time,
        b"on-record evidence",
    )?;
    let fact = DiagnosticObservation {
        source_ref,
        kind: crate::consent::CONSENT_REASON_DENIED,
        payload_digest: [2; 32],
        observed_at: time,
    };
    let event = ConsentDeniedDetector
        .detect(&DiagnosticWorkingSet {
            scope_ref: "scope.consent",
            observations: &[fact],
        })
        .remove(0);
    let body = encode_diagnostic_event_body(&event)?;
    let id = diagnostic_event_id(&event.detector_id, &body);
    vault.emit_diagnostic_event(&id, &event)?;
    Ok(id)
}

#[test]
fn nine_classes_count_independently_per_hour_and_surface() -> Result<()> {
    let counts = FailureSignalCounts::default();
    let config = FailureSignalConfig {
        export_opt_in: true,
        ..Default::default()
    };
    for class in ALL {
        counts.record(config, input(class), None, 3_601, "detector-1")?;
        counts.record(config, input(class), None, 7_199, "detector-1")?;
        counts.record(config, input(class), None, 7_200, "detector-1")?;
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
    counts.record(config, different, None, 3_601, "detector-1")?;
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
    different.model_role = LlmRole::Summarizer;
    counts.record(config, different, None, -1, "detector-2")?;
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
        counts.record(config, input, None, 3601, "private-medical-fact")?;
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
                None,
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
        None,
        first,
        "detector",
    )?;
    counts.record(
        config,
        input(FailureClassV1::TaskFailure),
        None,
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
        None,
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
        None,
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
    let registered = |role| {
        let mut signal = input(FailureClassV1::Other);
        signal.agent_kind = AgentKind::System;
        signal.agent_ref = Some(agent_ref);
        signal.agent = VersionedComponent {
            name: "sys.default".into(),
            version: definition.version.clone(),
        };
        signal.model_role = role;
        signal
    };
    let id_one = on_record_diagnostic(&vault, 3_601)?;
    let id_two = on_record_diagnostic(&other, 3_601)?;
    vault.record_failure_signal(id_one, registered(LlmRole::Orchestrator))?;
    other.record_failure_signal(id_two, registered(LlmRole::Orchestrator))?;
    let first = vault.export_tier1_failure_counts()?.remove(0).dimensions;
    let second = other.export_tier1_failure_counts()?.remove(0).dimensions;
    assert_eq!(first, second);
    assert_eq!(first.agent.name, "sys.default");
    assert_eq!(first.agent.version, definition.version);
    assert_eq!(first.engine.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(first.detector_id.as_deref(), Some("consent.denied.v1"));
    other.record_failure_signal(id_two, registered(LlmRole::Summarizer))?;
    let changed = other
        .export_tier1_failure_counts()?
        .into_iter()
        .find(|r| r.dimensions.model.name != first.model.name)
        .expect("changed registered model")
        .dimensions;
    assert_eq!(changed.agent, first.agent);
    assert_eq!(changed.engine, first.engine);
    assert_ne!(changed.model, first.model);
    drop(vault);
    let reopened = crate::Vault::open(one.path(), config)?;
    reopened.record_failure_signal(id_one, registered(LlmRole::Orchestrator))?;
    assert_eq!(
        reopened.export_tier1_failure_counts()?.remove(0).dimensions,
        first
    );
    let mut impersonated = registered(LlmRole::Orchestrator);
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
    counts.record(config, first, None, 3_601, "detector")?;
    counts.record(config, next, None, 3_601, "detector")?;
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
