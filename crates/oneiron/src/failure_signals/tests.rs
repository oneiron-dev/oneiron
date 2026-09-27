use super::*;
use crate::config::VaultConfig;

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

fn dimensions(class: FailureClassV1) -> FailureSignalDimensions {
    FailureSignalDimensions {
        taxonomy: FailureTaxonomy::V1(class),
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
        detector_id: (class == FailureClassV1::Other).then(|| "detector-1".into()),
        ts_bucket: 123,
    }
}

#[test]
fn nine_classes_count_independently_per_hour_and_version() -> Result<()> {
    let counts = FailureSignalCounts::default();
    let config = FailureSignalConfig {
        export_opt_in: true,
        ..Default::default()
    };
    for class in ALL {
        counts.record(config, dimensions(class), 3_601)?;
        counts.record(config, dimensions(class), 7_199)?;
        counts.record(config, dimensions(class), 7_200)?;
    }
    let rows = counts.export(config)?;
    assert_eq!(rows.len(), 18);
    for class in ALL {
        let mut first = dimensions(class);
        first.ts_bucket = 3_600;
        assert!(rows.contains(&Tier1FailureCount {
            dimensions: first,
            count: 2
        }));
        let mut second = dimensions(class);
        second.ts_bucket = 7_200;
        assert!(rows.contains(&Tier1FailureCount {
            dimensions: second,
            count: 1
        }));
    }
    let mut different = dimensions(FailureClassV1::Other);
    different.agent_kind = AgentKind::Custom;
    different.model.version = "4".into();
    different.detector_id = Some("detector-2".into());
    counts.record(config, different, -1)?;
    assert_eq!(
        counts
            .export(config)?
            .iter()
            .filter(|row| row.dimensions.ts_bucket == -3_600)
            .count(),
        1
    );
    assert_eq!(counts.export(config)?.len(), 19);
    Ok(())
}

#[test]
fn taxonomy_version_round_trip_and_payload_has_no_content_fields() {
    for class in ALL {
        let taxonomy = FailureTaxonomy::V1(class);
        let json = serde_json::to_string(&taxonomy).expect("serialize taxonomy");
        assert_eq!(
            serde_json::from_str::<FailureTaxonomy>(&json).expect("decode taxonomy"),
            taxonomy
        );
        let row = Tier1FailureCount {
            dimensions: dimensions(class),
            count: 1,
        };
        let payload = serde_json::to_value(&row).expect("serialize tier 1");
        let keys: std::collections::BTreeSet<_> = payload
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        let mut expected: std::collections::BTreeSet<_> = [
            "taxonomy_version",
            "failure_class",
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
}

#[test]
fn opt_in_validation_and_vault_isolation() -> Result<()> {
    let one = tempfile::tempdir()?;
    let two = tempfile::tempdir()?;
    let mut config = VaultConfig::default();
    config.failure_signals.export_opt_in = true;
    let vault = crate::Vault::open(one.path(), config.clone())?;
    let other = crate::Vault::open(two.path(), config)?;
    let mut bad = dimensions(FailureClassV1::Other);
    bad.detector_id = None;
    assert!(vault.record_failure_signal(bad, 1).is_err());
    let mut bad = dimensions(FailureClassV1::TaskFailure);
    bad.agent.version = "private notes here".into();
    assert!(vault.record_failure_signal(bad, 1).is_err());
    vault.record_failure_signal(dimensions(FailureClassV1::TaskFailure), 1)?;
    assert_eq!(vault.export_tier1_failure_counts()?.len(), 1);
    assert!(other.export_tier1_failure_counts()?.is_empty());
    let default_off = FailureSignalCounts::default();
    default_off.record(
        FailureSignalConfig::default(),
        dimensions(FailureClassV1::TaskFailure),
        1,
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
    default_off.record(managed, dimensions(FailureClassV1::TaskFailure), 1)?;
    assert_eq!(default_off.export(managed)?.len(), 1);
    Ok(())
}
