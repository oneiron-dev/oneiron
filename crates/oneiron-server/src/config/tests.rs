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

#[test]
fn an_unreadable_trusted_proxy_stops_startup() {
    // A block that would believe everyone, or a whole network where one host
    // was written, is refused with the rest (C7 review r1).
    for entry in [
        "10.0.0.0/33",
        "proxy.internal",
        "10.0.0.0/8/1",
        "0.0.0.0/0",
        "::/0",
        "10.0.0.5/8",
    ] {
        let env = EnvConfig::from_pairs([("ONEIRON_TRUSTED_PROXIES", entry)]).expect("env");
        assert!(
            resolve_serve_config_with_sources(&ServeArgs::default(), env, None).is_err(),
            "{entry} must not start serve"
        );
    }
    let env = EnvConfig::from_pairs([("ONEIRON_TRUSTED_PROXIES", "10.0.0.0/8, ::1")]).expect("env");
    let config =
        resolve_serve_config_with_sources(&ServeArgs::default(), env, None).expect("readable");
    let [block, host] = config.trusted_proxies.as_slice() else {
        panic!("two entries: {:?}", config.trusted_proxies);
    };
    let ip = |text: &str| text.parse::<std::net::IpAddr>().expect("address");
    assert!(block.contains(ip("10.255.0.1")) && block.contains(ip("::ffff:10.0.0.9")));
    assert!(!block.contains(ip("11.0.0.1")) && !block.contains(ip("::a00:1")));
    assert!(host.contains(ip("::1")) && !host.contains(ip("::2")));
}
