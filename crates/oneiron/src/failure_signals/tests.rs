use super::*;
use crate::config::VaultConfig;
use crate::off_record::OffRecordBackendClass;
use crate::self_heal::{
    ConsentDeniedDetector, DeterministicDetector, DiagnosticObservation, DiagnosticWorkingSet,
    diagnostic_event_id, encode_diagnostic_event_body,
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
        agent_kind: AgentKind::System,
        agent: VersionedComponent {
            name: "assistant".into(),
            version: "2".into(),
        },
        model: VersionedComponent {
            name: "model".into(),
            version: "3".into(),
        },
        engine: VersionedComponent {
            name: "oneiron".into(),
            version: "4".into(),
        },
    }
}

fn on_record_diagnostic(vault: &crate::Vault, time: u64) -> Result<EntityId> {
    let fact = DiagnosticObservation {
        source_ref: EntityId::now(),
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
        counts.record(config, input(class), 3_601, "detector-1")?;
        counts.record(config, input(class), 7_199, "detector-1")?;
        counts.record(config, input(class), 7_200, "detector-1")?;
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
    counts.record(config, different, 3_601, "detector-1")?;
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
    different.model.version = "4".into();
    counts.record(config, different, -1, "detector-2")?;
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
        input.model.name = "private-medical-fact".into();
        counts.record(config, input, 3601, "private-medical-fact")?;
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
            for token in ["name", "version"] {
                let value = payload[component][token].as_str().expect("opaque token");
                assert_eq!(value.len(), 64);
                assert!(value.bytes().all(|c| c.is_ascii_hexdigit()));
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
        first,
        "detector",
    )?;
    counts.record(
        config,
        input(FailureClassV1::TaskFailure),
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
    default_off.record(managed, input(FailureClassV1::TaskFailure), 1, "detector")?;
    assert_eq!(default_off.export(managed)?.len(), 1);
    Ok(())
}
