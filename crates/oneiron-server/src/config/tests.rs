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
