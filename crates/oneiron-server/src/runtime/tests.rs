use super::*;

#[test]
fn mode_presets_route_each_role_with_expected_provider_and_spend_boundary() {
    for (mode, provider_kind, spend_metered) in [
        (RuntimeMode::LocalFree, RuntimeProviderKind::Local, false),
        (
            RuntimeMode::ByoCloudKey,
            RuntimeProviderKind::ByoCloud,
            false,
        ),
        (
            RuntimeMode::OneironCloud,
            RuntimeProviderKind::OneironCloud,
            true,
        ),
    ] {
        let config = RuntimeConfig::for_mode(mode);

        for role in RuntimeRole::ALL {
            let route = config.route_for_role_with_key_lookup(role, |_| Some("key".into()));

            assert_eq!(route.mode, mode);
            assert_eq!(route.provider_kind, provider_kind);
            assert_eq!(route.provenance.source, RuntimeRouteSource::ModePreset);
            assert_eq!(route.oneiron_spend_metered, spend_metered);
        }
    }
}

#[test]
fn role_override_falls_back_to_mode_preset_for_missing_roles() {
    let mut config = RuntimeConfig::for_mode(RuntimeMode::ByoCloudKey);
    config.apply_override(RuntimeConfigOverride::with_role_override(
        RuntimeRole::Orchestrator,
        RuntimeRoleTargetOverride::target(RuntimeProviderKind::ByoCloud, "custom-orchestrator"),
    ));

    let orchestrator =
        config.route_for_role_with_key_lookup(RuntimeRole::Orchestrator, |_| Some("key".into()));
    let subagent =
        config.route_for_role_with_key_lookup(RuntimeRole::Subagent, |_| Some("key".into()));

    assert_eq!(orchestrator.model, "custom-orchestrator");
    assert_eq!(orchestrator.mode, RuntimeMode::ByoCloudKey);
    assert_eq!(
        orchestrator.provenance.source,
        RuntimeRouteSource::ConfigOverride
    );
    assert_eq!(subagent.mode, RuntimeMode::ByoCloudKey);
    assert_eq!(subagent.provider_kind, RuntimeProviderKind::ByoCloud);
    assert_eq!(subagent.provenance.source, RuntimeRouteSource::ModePreset);
}

#[test]
fn eiri_intimacy_and_repair_turns_absorb_all_subagent_lanes() {
    let mut config = RuntimeConfig::for_mode(RuntimeMode::LocalFree);
    config.apply_override(RuntimeConfigOverride::with_role_override(
        RuntimeRole::Orchestrator,
        RuntimeRoleTargetOverride::model("base-eiri"),
    ));
    config.apply_override(RuntimeConfigOverride::with_role_override(
        RuntimeRole::Subagent,
        RuntimeRoleTargetOverride::model("worker-subagent"),
    ));

    let turn = "I miss you. I'm sorry; can we repair this between us? Please stay with me.";

    assert!(should_absorb(turn));
    for subagent in EiriSubagent::ALL {
        assert_eq!(
            resolve_eiri_dispatch(subagent, turn),
            EiriDispatchTarget::BaseEiri,
            "{} must not receive absorb-classified turns",
            subagent.as_str()
        );

        let route = config.route_for_eiri_turn(subagent, turn);
        assert_eq!(route.role, RuntimeRole::Orchestrator);
        assert_eq!(route.model, "base-eiri");
    }
}

#[test]
fn eiri_ambiguous_terms_absorb_only_as_short_turns() {
    for turn in [
        "Please stay with me",
        "forgive me",
        "relationship repair",
        "turn me on",
        "naked",
    ] {
        assert!(should_absorb(turn), "{turn:?} must remain with Base Eiri");
    }

    for turn in [
        "The failing checksum aroused suspicion in the sync queue trace.",
        "Ask scout for the intimate details of the mmap layout.",
        "Stay with me while I debug the queue.",
        "Forgive me for asking, but summarize the failing rows.",
        "Run relationship repair for the database edge table.",
        "Turn me on to the latest sync protocol changes.",
    ] {
        assert!(
            !should_absorb(turn),
            "{turn:?} must still be eligible for sub-agent dispatch"
        );
    }
}

#[test]
fn eiri_negated_boundary_and_repair_turns_still_absorb() {
    for turn in [
        "Please do not touch me.",
        "I do not love you anymore.",
        "Do not kiss me; we need to repair this between us.",
    ] {
        assert!(
            should_absorb(turn),
            "{turn:?} is still an intimate or repair boundary"
        );
    }
}

#[test]
fn eiri_non_intimate_task_still_dispatches_to_requested_subagent() {
    let mut config = RuntimeConfig::for_mode(RuntimeMode::LocalFree);
    config.apply_override(RuntimeConfigOverride::with_role_override(
        RuntimeRole::Orchestrator,
        RuntimeRoleTargetOverride::model("base-eiri"),
    ));
    config.apply_override(RuntimeConfigOverride::with_role_override(
        RuntimeRole::Subagent,
        RuntimeRoleTargetOverride::model("worker-subagent"),
    ));

    let turn = "Ask scout to repair the sync queue index and summarize the failing rows.";

    assert!(!should_absorb(turn));
    assert_eq!(
        resolve_eiri_dispatch(EiriSubagent::Scout, turn),
        EiriDispatchTarget::Subagent(EiriSubagent::Scout)
    );

    let route = config.route_for_eiri_turn(EiriSubagent::Scout, turn);
    assert_eq!(route.role, RuntimeRole::Subagent);
    assert_eq!(route.model, "worker-subagent");
}

#[test]
fn per_role_modes_select_mode_defaults_for_each_role() {
    let mut config = RuntimeConfig::for_mode(RuntimeMode::LocalFree);
    let mut overrides = RuntimeRoleDefaultOverrides::default();
    overrides.merge(RuntimeRoleDefaultOverrides::with_role(
        RuntimeRole::Orchestrator,
        RuntimeRoleTargetOverride::mode(RuntimeMode::ByoCloudKey),
    ));
    overrides.merge(RuntimeRoleDefaultOverrides::with_role(
        RuntimeRole::Subagent,
        RuntimeRoleTargetOverride::mode(RuntimeMode::OneironCloud),
    ));
    overrides.merge(RuntimeRoleDefaultOverrides::with_role(
        RuntimeRole::Summarizer,
        RuntimeRoleTargetOverride::mode(RuntimeMode::LocalFree),
    ));
    config.apply_override(RuntimeConfigOverride {
        role_defaults: Some(overrides),
        ..Default::default()
    });

    let orchestrator =
        config.route_for_role_with_key_lookup(RuntimeRole::Orchestrator, |_| Some("key".into()));
    let subagent =
        config.route_for_role_with_key_lookup(RuntimeRole::Subagent, |_| Some("key".into()));
    let summarizer =
        config.route_for_role_with_key_lookup(RuntimeRole::Summarizer, |_| Some("key".into()));

    assert_eq!(
        (
            orchestrator.mode,
            orchestrator.provider_kind,
            orchestrator.model.as_str(),
            orchestrator.oneiron_spend_metered,
        ),
        (
            RuntimeMode::ByoCloudKey,
            RuntimeProviderKind::ByoCloud,
            "byo-orchestrator-default",
            false,
        )
    );
    assert_eq!(
        (
            subagent.mode,
            subagent.provider_kind,
            subagent.model.as_str(),
            subagent.oneiron_spend_metered,
        ),
        (
            RuntimeMode::OneironCloud,
            RuntimeProviderKind::OneironCloud,
            "oneiron-cloud-subagent-default",
            true,
        )
    );
    assert_eq!(
        (
            summarizer.mode,
            summarizer.provider_kind,
            summarizer.model.as_str(),
            summarizer.oneiron_spend_metered,
        ),
        (
            RuntimeMode::LocalFree,
            RuntimeProviderKind::Local,
            "local-summarizer-default",
            false,
        )
    );
}

#[test]
fn per_role_byo_and_local_modes_stay_unmetered_under_metered_default() {
    let mut config = RuntimeConfig::for_mode(RuntimeMode::OneironCloud);
    let mut overrides = RuntimeRoleDefaultOverrides::default();
    overrides.merge(RuntimeRoleDefaultOverrides::with_role(
        RuntimeRole::Orchestrator,
        RuntimeRoleTargetOverride::mode(RuntimeMode::ByoCloudKey),
    ));
    overrides.merge(RuntimeRoleDefaultOverrides::with_role(
        RuntimeRole::Subagent,
        RuntimeRoleTargetOverride::mode(RuntimeMode::LocalFree),
    ));
    config.apply_override(RuntimeConfigOverride {
        role_defaults: Some(overrides),
        ..Default::default()
    });

    let status = RuntimeStatus::from_config(&config);
    let orchestrator = status
        .routes
        .iter()
        .find(|route| route.role == RuntimeRole::Orchestrator)
        .unwrap();
    let subagent = status
        .routes
        .iter()
        .find(|route| route.role == RuntimeRole::Subagent)
        .unwrap();
    let summarizer = status
        .routes
        .iter()
        .find(|route| route.role == RuntimeRole::Summarizer)
        .unwrap();

    assert_eq!(orchestrator.mode, RuntimeMode::ByoCloudKey);
    assert!(!orchestrator.oneiron_spend_metered);
    assert_eq!(subagent.mode, RuntimeMode::LocalFree);
    assert!(!subagent.oneiron_spend_metered);
    assert_eq!(summarizer.mode, RuntimeMode::OneironCloud);
    assert!(summarizer.oneiron_spend_metered);
    assert!(status.oneiron_spend_metered);
}

#[test]
fn routing_returns_typed_unavailable_states() {
    let byo = RuntimeConfig::for_mode(RuntimeMode::ByoCloudKey);
    let missing_key = byo.route_for_role_with_key_lookup(RuntimeRole::Subagent, |_| None);
    assert_eq!(missing_key.state, RuntimeRouteState::Unavailable);
    assert_eq!(missing_key.reason, RuntimeRouteReason::MissingByoKey);

    let mut local = RuntimeConfig::for_mode(RuntimeMode::LocalFree);
    local.apply_override(RuntimeConfigOverride::with_role_override(
        RuntimeRole::Summarizer,
        RuntimeRoleTargetOverride::target(RuntimeProviderKind::OneironCloud, "cloud-model"),
    ));
    let mismatch =
        local.route_for_role_with_key_lookup(RuntimeRole::Summarizer, |_| Some("key".into()));
    assert_eq!(mismatch.state, RuntimeRouteState::Unavailable);
    assert_eq!(mismatch.reason, RuntimeRouteReason::ProviderModeMismatch);
    assert_eq!(mismatch.provider_kind, RuntimeProviderKind::OneironCloud);
    assert!(!mismatch.oneiron_spend_metered);
}

#[test]
fn unavailable_oneiron_cloud_routes_are_not_spend_metered() {
    let mut config = RuntimeConfig::for_mode(RuntimeMode::OneironCloud);
    for role in RuntimeRole::ALL {
        config.apply_override(RuntimeConfigOverride::with_role_override(
            role,
            RuntimeRoleTargetOverride::target(
                RuntimeProviderKind::Local,
                format!("unavailable-{}", role.as_str()),
            ),
        ));
    }

    let status = RuntimeStatus::from_config(&config);
    assert!(!status.oneiron_spend_metered);
    for route in status.routes {
        assert_eq!(route.mode, RuntimeMode::OneironCloud);
        assert_eq!(route.provider_kind, RuntimeProviderKind::Local);
        assert_eq!(route.state, RuntimeRouteState::Unavailable);
        assert_eq!(route.reason, RuntimeRouteReason::ProviderModeMismatch);
        assert!(!route.oneiron_spend_metered);
    }
}

#[test]
fn byo_key_env_requires_non_whitespace_value() {
    let config = RuntimeConfig::for_mode(RuntimeMode::ByoCloudKey);

    for key_value in [None, Some(""), Some(" \t\n")] {
        let route = config.route_for_role_with_key_lookup(RuntimeRole::Orchestrator, |_| {
            key_value.map(OsString::from)
        });

        assert_eq!(route.state, RuntimeRouteState::Unavailable);
        assert_eq!(route.reason, RuntimeRouteReason::MissingByoKey);
    }

    let available =
        config.route_for_role_with_key_lookup(RuntimeRole::Orchestrator, |_| Some("key".into()));
    assert_eq!(available.state, RuntimeRouteState::Available);
    assert_eq!(available.reason, RuntimeRouteReason::Ready);
}

#[test]
fn explicit_blank_byo_key_env_disables_default_key_fallback() {
    let mut config = RuntimeConfig::for_mode(RuntimeMode::ByoCloudKey);
    config.apply_override(RuntimeConfigOverride::with_byo_key_env(Some(String::new())));

    let route = config.route_for_role_with_key_lookup(RuntimeRole::Orchestrator, |key| {
        (key == DEFAULT_BYO_KEY_ENV).then_some("default-key".into())
    });

    assert_eq!(config.byo_key_env.as_deref(), Some(""));
    assert_eq!(route.state, RuntimeRouteState::Unavailable);
    assert_eq!(route.reason, RuntimeRouteReason::MissingByoKey);
}

#[test]
fn provider_mode_mismatch_is_fail_closed_for_local_and_byo() {
    for mode in [RuntimeMode::LocalFree, RuntimeMode::ByoCloudKey] {
        let mut config = RuntimeConfig::for_mode(mode);
        config.apply_override(RuntimeConfigOverride::with_role_override(
            RuntimeRole::Orchestrator,
            RuntimeRoleTargetOverride::target(RuntimeProviderKind::OneironCloud, "hosted-model"),
        ));

        let route = config
            .route_for_role_with_key_lookup(RuntimeRole::Orchestrator, |_| Some("key".into()));
        assert_eq!(route.provider_kind, RuntimeProviderKind::OneironCloud);
        assert_eq!(route.state, RuntimeRouteState::Unavailable);
        assert_eq!(route.reason, RuntimeRouteReason::ProviderModeMismatch);
        assert!(!route.oneiron_spend_metered);
    }
}

#[test]
fn runtime_mode_usage_mapping_keeps_byo_and_local_unmetered() {
    assert!(!RuntimeMode::LocalFree.usage_mode().debits_usage());
    assert!(!RuntimeMode::ByoCloudKey.usage_mode().debits_usage());
    assert!(RuntimeMode::OneironCloud.usage_mode().debits_usage());
}

#[test]
fn role_mode_repeat_preserves_existing_provider_and_model() {
    let mut config = RuntimeConfig::for_mode(RuntimeMode::ByoCloudKey);
    config.apply_override(RuntimeConfigOverride::with_role_override(
        RuntimeRole::Orchestrator,
        RuntimeRoleTargetOverride::target(RuntimeProviderKind::ByoCloud, "file-orchestrator"),
    ));
    config.apply_override(RuntimeConfigOverride::with_role_override(
        RuntimeRole::Orchestrator,
        RuntimeRoleTargetOverride::mode(RuntimeMode::ByoCloudKey),
    ));

    let target = config.role_defaults.target(RuntimeRole::Orchestrator);
    assert_eq!(target.mode, RuntimeMode::ByoCloudKey);
    assert_eq!(target.provider_kind, RuntimeProviderKind::ByoCloud);
    assert_eq!(target.model, "file-orchestrator");
}

#[test]
fn default_mode_change_updates_model_only_role_override() {
    let mut config = RuntimeConfig::for_mode(RuntimeMode::LocalFree);
    config.apply_override(RuntimeConfigOverride::with_role_override(
        RuntimeRole::Orchestrator,
        RuntimeRoleTargetOverride::model("file-orchestrator"),
    ));
    config.apply_override(RuntimeConfigOverride::mode(RuntimeMode::OneironCloud));

    let orchestrator = config.role_defaults.target(RuntimeRole::Orchestrator);
    assert_eq!(orchestrator.mode, RuntimeMode::OneironCloud);
    assert_eq!(
        orchestrator.provider_kind,
        RuntimeProviderKind::OneironCloud
    );
    assert_eq!(orchestrator.model, "file-orchestrator");

    let subagent = config.role_defaults.target(RuntimeRole::Subagent);
    assert_eq!(subagent.mode, RuntimeMode::OneironCloud);
    assert_eq!(subagent.provider_kind, RuntimeProviderKind::OneironCloud);
    assert_eq!(subagent.model, "oneiron-cloud-subagent-default");
}

#[test]
fn usage_mode_for_model_uses_available_routes_and_debit_boundaries() {
    let mut unavailable = RuntimeConfig::for_mode(RuntimeMode::OneironCloud);
    unavailable.apply_override(RuntimeConfigOverride::with_role_override(
        RuntimeRole::Orchestrator,
        RuntimeRoleTargetOverride::target(RuntimeProviderKind::Local, "mismatch-model"),
    ));
    let route = unavailable
        .route_for_role_with_key_lookup(RuntimeRole::Orchestrator, |_| Some("key".into()));
    assert_eq!(route.state, RuntimeRouteState::Unavailable);
    assert_eq!(route.reason, RuntimeRouteReason::ProviderModeMismatch);
    assert_eq!(
        unavailable.usage_mode_for_model(Some("mismatch-model")),
        None
    );
    assert!(unavailable.has_model_route_match(Some("mismatch-model")));

    let mut unmetered_duplicate = RuntimeConfig::for_mode(RuntimeMode::OneironCloud);
    unmetered_duplicate.apply_override(RuntimeConfigOverride::with_byo_key_env(Some(
        "PATH".to_owned(),
    )));
    for (role, mode) in [
        (RuntimeRole::Orchestrator, RuntimeMode::LocalFree),
        (RuntimeRole::Subagent, RuntimeMode::ByoCloudKey),
    ] {
        unmetered_duplicate.apply_override(RuntimeConfigOverride::with_role_override(
            role,
            RuntimeRoleTargetOverride {
                mode: Some(mode),
                provider_kind: None,
                model: Some("shared-unmetered-model".to_owned()),
            },
        ));
    }

    assert_eq!(
        unmetered_duplicate.usage_mode_for_model(Some("shared-unmetered-model")),
        Some(UsageMode::Local)
    );
}

#[test]
fn usage_classification_requires_resolved_route_availability() {
    let mut missing_byo_key = RuntimeConfig::for_mode(RuntimeMode::ByoCloudKey);
    missing_byo_key.apply_override(RuntimeConfigOverride::with_byo_key_env(Some(
        "ONEIRON_TEST_MISSING_RUNTIME_KEY_DO_NOT_SET".to_owned(),
    )));

    let model = missing_byo_key
        .role_defaults
        .target(RuntimeRole::Orchestrator)
        .model
        .clone();
    let route = missing_byo_key.route_for_role(RuntimeRole::Orchestrator);
    assert_eq!(route.state, RuntimeRouteState::Unavailable);
    assert_eq!(route.reason, RuntimeRouteReason::MissingByoKey);
    assert_eq!(missing_byo_key.usage_mode_for_model(Some(&model)), None);
    assert!(missing_byo_key.has_model_route_match(Some(&model)));
    assert_eq!(
        missing_byo_key.usage_mode_without_model(),
        Some(UsageMode::Byo)
    );

    let mut unavailable_hosted = RuntimeConfig::for_mode(RuntimeMode::OneironCloud);
    unavailable_hosted.apply_override(RuntimeConfigOverride::with_role_override(
        RuntimeRole::Orchestrator,
        RuntimeRoleTargetOverride::target(RuntimeProviderKind::Local, "mismatch-model"),
    ));

    let route = unavailable_hosted.route_for_role(RuntimeRole::Orchestrator);
    assert_eq!(route.state, RuntimeRouteState::Unavailable);
    assert_eq!(route.reason, RuntimeRouteReason::ProviderModeMismatch);
    assert_eq!(unavailable_hosted.usage_mode_without_model(), None);
}
