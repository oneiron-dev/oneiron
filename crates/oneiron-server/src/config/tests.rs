use super::*;
use clap::Parser;

#[derive(Parser)]
struct TestCli {
    #[command(flatten)]
    serve: ServeArgs,
}

#[test]
fn sync_server_config_debug_redacts_auth_secret() {
    let config = SyncServerConfig {
        auth_secret: Some("super-secret-value".to_owned()),
        ..Default::default()
    };

    let debug = format!("{config:?}");

    assert!(!debug.contains("super-secret-value"));
    assert!(debug.contains("auth_secret"));
    assert!(debug.contains("<redacted>"));
}

#[test]
fn sync_server_config_debug_prints_none_for_missing_auth_secret() {
    let debug = format!("{:?}", SyncServerConfig::default());

    assert!(debug.contains("auth_secret: None"));
}

#[test]
fn runtime_usage_mode_derives_from_runtime_mode() {
    for mode in [
        RuntimeMode::LocalFree,
        RuntimeMode::ByoCloudKey,
        RuntimeMode::OneironCloud,
    ] {
        let config = SyncServerConfig {
            runtime: RuntimeConfig::for_mode(mode),
            ..Default::default()
        };

        assert_eq!(config.runtime_usage_mode(), mode.usage_mode());
    }
}

#[test]
fn usage_mode_config_file_key_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("oneiron.toml");
    std::fs::write(&config_path, "usage_mode = \"byo\"\n").unwrap();
    let args = ServeArgs {
        config: Some(config_path.clone()),
        ..Default::default()
    };

    let error = resolve_serve_config_with_sources(&args, EnvConfig::default(), None)
        .unwrap_err()
        .to_string();

    assert!(error.contains(&format!("parse config file {}", config_path.display())));

    let env =
        EnvConfig::from_pairs([(concat!("ONEIRON_USAGE_", "MODE"), "oneiron_cloud")]).unwrap();
    let resolved = resolve_serve_config_with_sources(&ServeArgs::default(), env, None).unwrap();
    assert_eq!(resolved.runtime.mode, RuntimeMode::LocalFree);
}

#[test]
fn lease_vault_id_merges_into_sync_server_config() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("oneiron.toml");
    std::fs::write(&config_path, "lease_vault_id = 5\n").unwrap();
    let args = ServeArgs {
        lease_vault_id: Some(7),
        ..Default::default()
    };
    let env = EnvConfig::from_pairs([
        ("ONEIRON_CONFIG", config_path.to_str().unwrap()),
        ("ONEIRON_LEASE_VAULT_ID", "6"),
    ])
    .unwrap();

    let resolved = resolve_serve_config_with_sources(&args, env, None).unwrap();

    assert_eq!(resolved.lease_vault_id, 7);
    assert_eq!(resolved.sync_server_config().lease_vault_id, 7);
}

#[test]
fn serve_config_rejects_non_positive_ephemeral_timeout() {
    let env = EnvConfig::from_pairs([("ONEIRON_EPHEMERAL_TIMEOUT_MS", "0")]).unwrap();

    let error = resolve_serve_config_with_sources(&ServeArgs::default(), env, None)
        .unwrap_err()
        .to_string();

    assert!(error.contains("ephemeral_timeout_ms must be positive"));
}

#[test]
fn serve_config_rejects_zero_ephemeral_limits() {
    for (key, message) in [
        (
            "ONEIRON_MAX_EPHEMERAL_PAYLOAD_BYTES",
            "max_ephemeral_payload_bytes must be positive",
        ),
        (
            "ONEIRON_MAX_EPHEMERAL_SNAPSHOT_BYTES",
            "max_ephemeral_snapshot_bytes must be positive",
        ),
    ] {
        let env = EnvConfig::from_pairs([(key, "0")]).unwrap();

        let error = resolve_serve_config_with_sources(&ServeArgs::default(), env, None)
            .unwrap_err()
            .to_string();

        assert!(error.contains(message));
    }
}

#[test]
fn serve_args_debug_redacts_auth_secret() {
    let args = ServeArgs {
        auth_secret: Some("cli-secret-value".to_owned()),
        ..Default::default()
    };

    let debug = format!("{args:?}");

    assert!(!debug.contains("cli-secret-value"));
    assert!(debug.contains("auth_secret"));
    assert!(debug.contains("<redacted>"));
}

#[test]
fn serve_args_debug_prints_none_for_missing_auth_secret() {
    let debug = format!("{:?}", ServeArgs::default());

    assert!(debug.contains("auth_secret: None"));
}

#[test]
fn serve_config_debug_redacts_auth_secret() {
    let config = ServeConfig {
        auth_secret: Some("serve-config-secret".to_owned()),
        ..Default::default()
    };

    let debug = format!("{config:?}");

    assert!(!debug.contains("serve-config-secret"));
    assert!(debug.contains("auth_secret"));
    assert!(debug.contains("<redacted>"));
}

#[test]
fn serve_config_debug_prints_none_for_missing_auth_secret() {
    let debug = format!("{:?}", ServeConfig::default());

    assert!(debug.contains("auth_secret: None"));
}

#[test]
fn legacy_top_level_flags_parse_as_serve_args() {
    let cli = TestCli::try_parse_from([
        "oneiron-server",
        "--vault-path",
        "/tmp/oneiron-vault",
        "--port",
        "9191",
        "--insecure-allow-unauthenticated",
    ])
    .unwrap();

    assert_eq!(
        cli.serve.vault_path,
        Some(PathBuf::from("/tmp/oneiron-vault"))
    );
    assert_eq!(cli.serve.port, Some(9191));
    assert_eq!(cli.serve.insecure_allow_unauthenticated, Some(true));
}

#[test]
fn cors_origins_alias_parses_as_serve_args() {
    let cli = TestCli::try_parse_from([
        "oneiron-server",
        "--cors-origins",
        "https://a.example,https://b.example",
    ])
    .unwrap();

    assert_eq!(
        cli.serve.allowed_origins,
        Some(vec![
            "https://a.example".to_owned(),
            "https://b.example".to_owned()
        ])
    );
}

#[test]
fn env_allowed_origins_are_split_and_trimmed() {
    let env = EnvConfig::from_pairs([(
        "ONEIRON_ALLOWED_ORIGINS",
        "https://a.example, https://b.example",
    )])
    .unwrap();
    let resolved = resolve_serve_config_with_sources(&ServeArgs::default(), env, None).unwrap();

    assert_eq!(
        resolved.allowed_origins,
        vec!["https://a.example", "https://b.example"]
    );
}

#[test]
fn federation_quota_config_merges_into_sync_server_config() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("oneiron.toml");
    std::fs::write(
        &config_path,
        r#"
max_federation_windows_per_connection = 5
federation_flood_pause_secs = 20
"#,
    )
    .unwrap();
    let env = EnvConfig::from_pairs([
        ("ONEIRON_CONFIG", config_path.to_str().unwrap()),
        ("ONEIRON_MAX_FEDERATION_WINDOWS_PER_CONNECTION", "6"),
    ])
    .unwrap();
    let flags = ServeArgs {
        federation_flood_pause_secs: Some(7),
        ..Default::default()
    };

    let resolved = resolve_serve_config_with_sources(&flags, env, None).unwrap();
    let sync = resolved.sync_server_config();

    assert_eq!(resolved.max_federation_windows_per_connection, 6);
    assert_eq!(resolved.federation_flood_pause_secs, 7);
    assert_eq!(sync.max_federation_windows_per_connection, 6);
    assert_eq!(sync.federation_flood_pause_secs, 7);
}

#[test]
fn config_file_env_and_flags_merge_in_precedence_order() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("oneiron.toml");
    std::fs::write(
        &config_path,
        r#"
vault_path = "/file/vault"
host = "file-host"
port = 1000
allowed_origins = ["https://file.example"]
dimensions = 128
map_size = 67108864
log_level = "warn"
max_frame_size = 11
"#,
    )
    .unwrap();
    let env = EnvConfig::from_pairs([
        ("ONEIRON_CONFIG", config_path.to_str().unwrap()),
        ("ONEIRON_HOST", "env-host"),
        ("ONEIRON_PORT", "2000"),
        ("ONEIRON_AUTH_SECRET", "env-secret"),
    ])
    .unwrap();
    let flags = ServeArgs {
        host: Some("flag-host".to_owned()),
        allowed_origins: Some(vec!["https://flag.example".to_owned()]),
        ..Default::default()
    };

    let resolved = resolve_serve_config_with_sources(&flags, env, None).unwrap();

    assert_eq!(resolved.vault_path, PathBuf::from("/file/vault"));
    assert_eq!(resolved.host, "flag-host");
    assert_eq!(resolved.port, 2000);
    assert_eq!(resolved.auth_secret.as_deref(), Some("env-secret"));
    assert_eq!(resolved.allowed_origins, vec!["https://flag.example"]);
    assert_eq!(resolved.dimensions, 128);
    assert_eq!(resolved.map_size, 67_108_864);
    assert_eq!(resolved.log_level, "warn");
    assert_eq!(resolved.max_frame_size, 11);
}

#[test]
fn runtime_flags_parse_as_serve_args() {
    let cli = TestCli::try_parse_from([
        "oneiron-server",
        "--runtime-mode",
        "byo_cloud_key",
        "--runtime-byo-key-env",
        "OPENAI_API_KEY",
        "--runtime-orchestrator-mode",
        "byo_cloud_key",
        "--runtime-orchestrator-provider-kind",
        "byo_cloud",
        "--runtime-orchestrator-model",
        "gpt-orchestrator",
    ])
    .unwrap();

    assert_eq!(cli.serve.runtime_mode, Some(RuntimeMode::ByoCloudKey));
    assert_eq!(
        cli.serve.runtime_byo_key_env.as_deref(),
        Some("OPENAI_API_KEY")
    );
    assert_eq!(
        cli.serve.runtime_orchestrator_mode,
        Some(RuntimeMode::ByoCloudKey)
    );
    assert_eq!(
        cli.serve.runtime_orchestrator_provider_kind,
        Some(RuntimeProviderKind::ByoCloud)
    );
    assert_eq!(
        cli.serve.runtime_orchestrator_model.as_deref(),
        Some("gpt-orchestrator")
    );
}

#[test]
fn runtime_config_merges_file_env_and_flags_with_role_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("oneiron.toml");
    std::fs::write(
        &config_path,
        r#"
[runtime]
mode = "byo_cloud_key"
byo_key_env = "FILE_BYO_KEY"

[runtime.role_defaults.orchestrator]
mode = "byo_cloud_key"
provider_kind = "byo_cloud"
model = "file-orchestrator"
"#,
    )
    .unwrap();
    let env = EnvConfig::from_pairs([
        ("ONEIRON_CONFIG", config_path.to_str().unwrap()),
        ("ONEIRON_RUNTIME_SUBAGENT_MODE", "local_free"),
        ("ONEIRON_RUNTIME_SUBAGENT_MODEL", "env-subagent"),
    ])
    .unwrap();
    let flags = ServeArgs {
        runtime_summarizer_mode: Some(RuntimeMode::OneironCloud),
        runtime_summarizer_model: Some("flag-summarizer".to_owned()),
        ..Default::default()
    };

    let resolved = resolve_serve_config_with_sources(&flags, env, None).unwrap();

    assert_eq!(resolved.runtime.mode, RuntimeMode::ByoCloudKey);
    assert_eq!(resolved.runtime.mode.usage_mode(), UsageMode::Byo);
    assert_eq!(
        resolved.runtime.byo_key_env.as_deref(),
        Some("FILE_BYO_KEY")
    );
    assert_eq!(
        resolved
            .runtime
            .role_defaults
            .target(RuntimeRole::Orchestrator)
            .mode,
        RuntimeMode::ByoCloudKey
    );
    assert_eq!(
        resolved
            .runtime
            .role_defaults
            .target(RuntimeRole::Orchestrator)
            .model
            .as_str(),
        "file-orchestrator"
    );
    assert_eq!(
        resolved
            .runtime
            .role_defaults
            .target(RuntimeRole::Subagent)
            .mode,
        RuntimeMode::LocalFree
    );
    assert_eq!(
        resolved
            .runtime
            .role_defaults
            .target(RuntimeRole::Subagent)
            .model
            .as_str(),
        "env-subagent"
    );
    assert_eq!(
        resolved
            .runtime
            .role_defaults
            .target(RuntimeRole::Summarizer)
            .mode,
        RuntimeMode::OneironCloud
    );
    assert_eq!(
        resolved
            .runtime
            .role_defaults
            .target(RuntimeRole::Summarizer)
            .model
            .as_str(),
        "flag-summarizer"
    );
    assert_eq!(
        resolved
            .runtime
            .role_defaults
            .target(RuntimeRole::Summarizer)
            .provider_kind,
        RuntimeProviderKind::OneironCloud
    );
}

#[test]
fn privacy_posture_defaults_to_self_host_local() {
    let resolved =
        resolve_serve_config_with_sources(&ServeArgs::default(), EnvConfig::default(), None)
            .unwrap();

    assert_eq!(
        resolved.privacy_posture,
        HostingPrivacyPosture::SelfHostLocal
    );
    assert_eq!(resolved.hosted_kms_key_ref, None);

    // The default resolves into the engine's default pairing: owner-held key,
    // no host reference at all.
    let privacy = resolved.vault_config().privacy;
    assert_eq!(privacy, VaultPrivacyConfig::default());
    assert_eq!(
        privacy.data_key_custody,
        VaultDataKeyCustody::OwnerHeldLocal
    );
    assert!(!privacy.host_readable());
    assert_eq!(privacy.honest_label(), "owner-held-key");
    assert!(privacy.validate().is_ok());
}

#[test]
fn privacy_posture_flags_parse_as_serve_args() {
    let cli = TestCli::try_parse_from([
        "oneiron-server",
        "--privacy-posture",
        "hosted",
        "--hosted-kms-key-ref",
        "kms://example/flag-ref",
    ])
    .unwrap();

    assert_eq!(
        cli.serve.privacy_posture,
        Some(HostingPrivacyPosture::Hosted)
    );
    assert_eq!(
        cli.serve.hosted_kms_key_ref.as_deref(),
        Some("kms://example/flag-ref")
    );

    let cli = TestCli::try_parse_from(["oneiron-server", "--privacy-posture", "self_host_local"])
        .unwrap();

    assert_eq!(
        cli.serve.privacy_posture,
        Some(HostingPrivacyPosture::SelfHostLocal)
    );
}

#[test]
fn hosted_privacy_posture_merges_file_env_and_flags_in_precedence_order() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("oneiron.toml");
    std::fs::write(
        &config_path,
        r#"
privacy_posture = "hosted"
hosted_kms_key_ref = "kms://example/file-ref"
"#,
    )
    .unwrap();
    let env = EnvConfig::from_pairs([
        ("ONEIRON_CONFIG", config_path.to_str().unwrap()),
        ("ONEIRON_HOSTED_KMS_KEY_REF", "kms://example/env-ref"),
    ])
    .unwrap();
    let flags = ServeArgs {
        hosted_kms_key_ref: Some("kms://example/flag-ref".to_owned()),
        ..Default::default()
    };

    let resolved = resolve_serve_config_with_sources(&flags, env, None).unwrap();

    // Posture comes from the file; the reference is overridden by env and then
    // by flags — the same file -> env -> flags order as every other setting.
    assert_eq!(resolved.privacy_posture, HostingPrivacyPosture::Hosted);
    assert_eq!(
        resolved.hosted_kms_key_ref.as_deref(),
        Some("kms://example/flag-ref")
    );

    let privacy = resolved.vault_config().privacy;
    assert_eq!(privacy.posture, HostingPrivacyPosture::Hosted);
    assert_eq!(
        privacy.data_key_custody,
        VaultDataKeyCustody::HostManagedKms {
            key_ref: "kms://example/flag-ref".to_owned(),
        }
    );
    // Hosted is exposed as host-readable, never as something the host cannot
    // read.
    assert!(privacy.host_readable());
    assert_eq!(privacy.honest_label(), "host-readable");
    assert!(privacy.validate().is_ok());
}

#[test]
fn privacy_posture_resolves_from_the_environment() {
    let env = EnvConfig::from_pairs([
        ("ONEIRON_PRIVACY_POSTURE", "hosted"),
        ("ONEIRON_HOSTED_KMS_KEY_REF", "kms://example/env-ref"),
    ])
    .unwrap();

    let resolved = resolve_serve_config_with_sources(&ServeArgs::default(), env, None).unwrap();

    assert_eq!(resolved.privacy_posture, HostingPrivacyPosture::Hosted);
    assert_eq!(
        resolved.hosted_kms_key_ref.as_deref(),
        Some("kms://example/env-ref")
    );
}

#[test]
fn hosted_privacy_posture_requires_a_kms_key_reference() {
    let missing = ServeArgs {
        privacy_posture: Some(HostingPrivacyPosture::Hosted),
        ..Default::default()
    };
    let error = resolve_serve_config_with_sources(&missing, EnvConfig::default(), None)
        .expect_err("hosted without a key reference must be refused");
    assert!(
        error
            .to_string()
            .contains("non-empty host-managed KMS key reference")
    );

    let blank = ServeArgs {
        privacy_posture: Some(HostingPrivacyPosture::Hosted),
        hosted_kms_key_ref: Some("   ".to_owned()),
        ..Default::default()
    };
    let error = resolve_serve_config_with_sources(&blank, EnvConfig::default(), None)
        .expect_err("hosted with a blank key reference must be refused");
    assert!(
        error
            .to_string()
            .contains("non-empty host-managed KMS key reference")
    );
}

#[test]
fn self_host_local_privacy_posture_rejects_a_kms_key_reference() {
    for raw in ["kms://example/stray-ref", "   "] {
        let flags = ServeArgs {
            privacy_posture: Some(HostingPrivacyPosture::SelfHostLocal),
            hosted_kms_key_ref: Some(raw.to_owned()),
            ..Default::default()
        };
        let error = resolve_serve_config_with_sources(&flags, EnvConfig::default(), None)
            .expect_err("self-host/local must refuse any host-managed reference");
        assert!(
            error
                .to_string()
                .contains("rejects host-managed KMS key custody")
        );
    }

    // The default posture is self-host/local, so a stray reference is refused
    // even when no posture is named.
    let stray = ServeArgs {
        hosted_kms_key_ref: Some("kms://example/stray-ref".to_owned()),
        ..Default::default()
    };
    assert!(resolve_serve_config_with_sources(&stray, EnvConfig::default(), None).is_err());
}

#[test]
fn self_host_local_override_clears_an_inherited_kms_key_reference() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("oneiron.toml");
    std::fs::write(
        &config_path,
        r#"
privacy_posture = "hosted"
hosted_kms_key_ref = "kms://example/file-ref"
"#,
    )
    .unwrap();

    // A higher-precedence source that names self-host/local takes the vault
    // back to owner-held custody: the file's reference is dropped rather than
    // inherited into a pairing that startup would refuse. Env and flags behave
    // the same way.
    let from_env = EnvConfig::from_pairs([
        ("ONEIRON_CONFIG", config_path.to_str().unwrap()),
        ("ONEIRON_PRIVACY_POSTURE", "self_host_local"),
    ])
    .unwrap();
    let env_resolved =
        resolve_serve_config_with_sources(&ServeArgs::default(), from_env, None).unwrap();

    let flags = ServeArgs {
        config: Some(config_path.clone()),
        privacy_posture: Some(HostingPrivacyPosture::SelfHostLocal),
        ..Default::default()
    };
    let flag_resolved =
        resolve_serve_config_with_sources(&flags, EnvConfig::default(), None).unwrap();

    for resolved in [env_resolved, flag_resolved] {
        assert_eq!(
            resolved.privacy_posture,
            HostingPrivacyPosture::SelfHostLocal
        );
        assert_eq!(resolved.hosted_kms_key_ref, None);

        let privacy = resolved.vault_config().privacy;
        assert_eq!(privacy.posture, HostingPrivacyPosture::SelfHostLocal);
        assert_eq!(
            privacy.data_key_custody,
            VaultDataKeyCustody::OwnerHeldLocal
        );
        assert!(!privacy.host_readable());
        assert!(privacy.validate().is_ok());
    }

    // Clearing is scoped to an explicit posture override: a source that only
    // replaces the reference leaves the file's hosted posture in place.
    let ref_only = EnvConfig::from_pairs([
        ("ONEIRON_CONFIG", config_path.to_str().unwrap()),
        ("ONEIRON_HOSTED_KMS_KEY_REF", "kms://example/env-ref"),
    ])
    .unwrap();
    let resolved =
        resolve_serve_config_with_sources(&ServeArgs::default(), ref_only, None).unwrap();
    assert_eq!(resolved.privacy_posture, HostingPrivacyPosture::Hosted);
    assert_eq!(
        resolved.hosted_kms_key_ref.as_deref(),
        Some("kms://example/env-ref")
    );

    // A source naming self-host/local AND a reference is still a stray-custody
    // error, not a silent clear.
    let contradictory = ServeArgs {
        config: Some(config_path),
        privacy_posture: Some(HostingPrivacyPosture::SelfHostLocal),
        hosted_kms_key_ref: Some("kms://example/flag-ref".to_owned()),
        ..Default::default()
    };
    let error = resolve_serve_config_with_sources(&contradictory, EnvConfig::default(), None)
        .expect_err("self-host/local plus its own reference must stay an error");
    assert!(
        error
            .to_string()
            .contains("rejects host-managed KMS key custody")
    );
}

#[test]
fn env_config_debug_redacts_hosted_kms_key_ref() {
    let env = EnvConfig::from_pairs([
        ("ONEIRON_PRIVACY_POSTURE", "hosted"),
        ("ONEIRON_HOSTED_KMS_KEY_REF", "kms://example/secret-ref"),
        ("ONEIRON_AUTH_SECRET", "super-secret-value"),
    ])
    .unwrap();

    let debug = format!("{env:?}");

    assert!(!debug.contains("secret-ref"));
    assert!(!debug.contains("super-secret-value"));
    assert!(debug.contains("hosted_kms_key_ref"));
    assert!(debug.contains("<redacted>"));
    // The posture itself is not a secret and prints plainly.
    assert!(debug.contains("privacy_posture: Some(Hosted)"));
    assert!(format!("{:?}", EnvConfig::default()).contains("hosted_kms_key_ref: None"));
}

#[test]
fn unknown_privacy_posture_values_are_rejected() {
    for raw in [
        "private_hosted",
        "e2e_hosted",
        "encrypted_hosted",
        "unreadable_hosted",
        "Hosted",
        "cloud",
        "",
    ] {
        assert!(
            TestCli::try_parse_from(["oneiron-server", "--privacy-posture", raw]).is_err(),
            "--privacy-posture {raw:?} must not parse"
        );
        assert!(
            EnvConfig::from_pairs([("ONEIRON_PRIVACY_POSTURE", raw)]).is_err(),
            "ONEIRON_PRIVACY_POSTURE={raw:?} must not parse"
        );
    }
}

#[test]
fn serve_args_debug_redacts_hosted_kms_key_ref() {
    let args = ServeArgs {
        hosted_kms_key_ref: Some("kms://example/cli-secret-ref".to_owned()),
        ..Default::default()
    };

    let debug = format!("{args:?}");

    assert!(!debug.contains("cli-secret-ref"));
    assert!(debug.contains("hosted_kms_key_ref"));
    assert!(debug.contains("<redacted>"));
    assert!(format!("{:?}", ServeArgs::default()).contains("hosted_kms_key_ref: None"));
}

#[test]
fn serve_config_debug_redacts_hosted_kms_key_ref() {
    let config = ServeConfig {
        privacy_posture: HostingPrivacyPosture::Hosted,
        hosted_kms_key_ref: Some("kms://example/serve-secret-ref".to_owned()),
        ..Default::default()
    };

    let debug = format!("{config:?}");

    assert!(!debug.contains("serve-secret-ref"));
    assert!(debug.contains("hosted_kms_key_ref"));
    assert!(debug.contains("<redacted>"));
    // The posture itself is not a secret and prints plainly.
    assert!(debug.contains("privacy_posture: Hosted"));
    assert!(format!("{:?}", ServeConfig::default()).contains("hosted_kms_key_ref: None"));
}

#[test]
fn privacy_posture_has_exactly_two_variants_and_no_unreadable_hosted_tier() {
    const LEGACY_TOKENS: [&str; 5] = [
        "unreadable",
        "private_hosted",
        "e2e_hosted",
        "encrypted_hosted",
        "zero_knowledge",
    ];

    for posture in [
        HostingPrivacyPosture::Hosted,
        HostingPrivacyPosture::SelfHostLocal,
    ] {
        // Wildcard-free exhaustive match: a third posture variant — an
        // "unreadable hosted" tier included — stops compiling right here.
        let wire = match posture {
            HostingPrivacyPosture::Hosted => "hosted",
            HostingPrivacyPosture::SelfHostLocal => "self_host_local",
        };
        assert_eq!(
            serde_json::to_string(&posture).unwrap(),
            format!("\"{wire}\"")
        );
        assert_eq!(posture.to_string(), wire);
        assert_eq!(wire.parse::<HostingPrivacyPosture>().unwrap(), posture);
    }

    let hosted = ServeConfig {
        privacy_posture: HostingPrivacyPosture::Hosted,
        hosted_kms_key_ref: Some("kms://example/prod-ref".to_owned()),
        ..Default::default()
    };
    let self_host = ServeConfig::default();

    let hosted_privacy = serde_json::to_string(&hosted.vault_config().privacy).unwrap();
    let self_host_privacy = serde_json::to_string(&self_host.vault_config().privacy).unwrap();
    assert!(hosted_privacy.contains("host_managed_kms"));
    assert!(self_host_privacy.contains("owner_held_local"));
    // Self-host/local carries no host reference at all.
    assert!(!self_host_privacy.contains("key_ref"));

    for (config, serialized) in [(hosted, hosted_privacy), (self_host, self_host_privacy)] {
        let debug = format!("{config:?}");
        for token in LEGACY_TOKENS {
            assert!(
                !serialized.contains(token),
                "resolved privacy config must not name a {token:?} tier: {serialized}"
            );
            assert!(
                !debug.contains(token),
                "resolved serve config must not name a {token:?} tier"
            );
        }
    }
}
