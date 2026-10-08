use super::*;

#[test]
fn sync_server_config_debug_redacts_auth_secret() {
    let config = SyncServerConfig {
        auth_secret: Some("super-secret-value".to_owned()),
        ..Default::default()
    };

    let debug = format!("{config:?}");

    assert!(!debug.contains("super-secret-value"));
}

#[test]
fn serve_args_debug_redacts_auth_secret() {
    let args = ServeArgs {
        auth_secret: Some("cli-secret-value".to_owned()),
        ..Default::default()
    };

    let debug = format!("{args:?}");

    assert!(!debug.contains("cli-secret-value"));
}

#[test]
fn serve_config_debug_redacts_auth_secret() {
    let config = ServeConfig {
        auth_secret: Some("serve-config-secret".to_owned()),
        ..Default::default()
    };

    let debug = format!("{config:?}");

    assert!(!debug.contains("serve-config-secret"));
}

#[test]
fn env_config_debug_redacts_hosted_kms_key_ref() {
    let env = EnvConfig::from_pairs([
        ("ONEIRON_PRIVACY_POSTURE", "managed"),
        ("ONEIRON_HOSTED_KMS_KEY_REF", "kms://example/secret-ref"),
        ("ONEIRON_AUTH_SECRET", "super-secret-value"),
    ])
    .unwrap();

    let debug = format!("{env:?}");

    assert!(!debug.contains("secret-ref"));
    assert!(!debug.contains("super-secret-value"));
}

#[test]
fn serve_args_debug_redacts_hosted_kms_key_ref() {
    let args = ServeArgs {
        hosted_kms_key_ref: Some("kms://example/cli-secret-ref".to_owned()),
        ..Default::default()
    };

    let debug = format!("{args:?}");

    assert!(!debug.contains("cli-secret-ref"));
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
}
