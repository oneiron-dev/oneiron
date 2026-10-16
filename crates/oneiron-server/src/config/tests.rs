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
        // An IPv4-mapped block is read as written (C7 review r2): bits set
        // past its IPv6 prefix, or the whole mapped range.
        "::ffff:10.0.0.0/8",
        "::ffff:10.0.0.0/96",
    ] {
        let env = EnvConfig::from_pairs([("ONEIRON_TRUSTED_PROXIES", entry)]).expect("env");
        assert!(
            resolve_serve_config_with_sources(&ServeArgs::default(), env, None).is_err(),
            "{entry} must not start serve"
        );
    }
    let env = EnvConfig::from_pairs([(
        "ONEIRON_TRUSTED_PROXIES",
        "10.0.0.0/8, ::1, ::ffff:192.0.2.0/120",
    )])
    .expect("env");
    let config =
        resolve_serve_config_with_sources(&ServeArgs::default(), env, None).expect("readable");
    let [block, host, mapped] = config.trusted_proxies.as_slice() else {
        panic!("three entries: {:?}", config.trusted_proxies);
    };
    let ip = |text: &str| text.parse::<std::net::IpAddr>().expect("address");
    assert!(block.contains(ip("10.255.0.1")) && block.contains(ip("::ffff:10.0.0.9")));
    assert!(!block.contains(ip("11.0.0.1")) && !block.contains(ip("::a00:1")));
    assert!(host.contains(ip("::1")) && !host.contains(ip("::2")));
    assert!(mapped.contains(ip("192.0.2.200")) && !mapped.contains(ip("192.0.3.1")));
}

/// Review r9 (Sol R9-1, Astra R9-1): an LFS memory row smaller than one
/// transfer's room was held to one transfer anyway, past what it said. A
/// row without room for one transfer in each half now stops startup.
#[test]
fn an_lfs_memory_row_without_room_for_a_transfer_stops_startup() {
    let dir = tempfile::tempdir().expect("config dir");
    let path = dir.path().join("config.toml");
    let room = crate::api::LFS_MEMORY_ROOM;
    for (bytes, starts) in [(1, false), (2 * room - 1, false), (2 * room, true)] {
        std::fs::write(&path, format!("[limits]\nlfs_memory_bytes = {bytes}\n")).expect("config");
        let args = ServeArgs {
            config: Some(path.clone()),
            ..ServeArgs::default()
        };
        let env = EnvConfig::from_pairs(std::iter::empty::<(&str, &str)>()).expect("env");
        let resolved = resolve_serve_config_with_sources(&args, env, None);
        assert_eq!(resolved.is_ok(), starts, "{bytes}: {:?}", resolved.err());
    }
}
