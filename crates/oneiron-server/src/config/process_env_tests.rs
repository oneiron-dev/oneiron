use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::process::Command;

use super::*;

const CHILD_CASE: &str = "ONEIRON_TEST_PROCESS_PRIVACY_CASE";
const CHECKED: &str = "process privacy environment checked";
const PRIVATE_VALUE: &str = "private-environment-value-must-not-leak";

#[test]
fn process_privacy_environment() {
    if let Ok(case) = std::env::var(CHILD_CASE) {
        check_child_environment(&case);
        println!("{CHECKED}");
        return;
    }

    for case in [
        "unset",
        "self_host_local",
        "hosted",
        "non_unicode_posture",
        "non_unicode_key_default",
        "non_unicode_key_self_host_local",
        "non_unicode_key_hosted",
        "unrelated_non_unicode",
    ] {
        let mut child = Command::new(std::env::current_exe().unwrap());
        child.args([
            "--exact",
            "config::process_env_tests::process_privacy_environment",
            "--nocapture",
            "--test-threads=1",
        ]);
        // Only the child's environment changes. Retain the test binary's
        // loader/runtime environment, but isolate every Oneiron setting.
        for (key, _) in std::env::vars_os() {
            if key.as_bytes().starts_with(b"ONEIRON_") {
                child.env_remove(key);
            }
        }
        child.env(CHILD_CASE, case);
        let mut malformed = PRIVATE_VALUE.as_bytes().to_vec();
        malformed.push(0xff);
        let malformed = OsString::from_vec(malformed);
        match case {
            "unset" => {}
            "self_host_local" => {
                child.env("ONEIRON_PRIVACY_POSTURE", "self_host_local");
            }
            "hosted" => {
                child.env("ONEIRON_PRIVACY_POSTURE", "hosted");
                child.env("ONEIRON_HOSTED_KMS_KEY_REF", "kms://example/clé");
            }
            "non_unicode_posture" => {
                child.env("ONEIRON_PRIVACY_POSTURE", &malformed);
            }
            "non_unicode_key_default" => {
                child.env("ONEIRON_HOSTED_KMS_KEY_REF", &malformed);
            }
            "non_unicode_key_self_host_local" => {
                child.env("ONEIRON_PRIVACY_POSTURE", "self_host_local");
                child.env("ONEIRON_HOSTED_KMS_KEY_REF", &malformed);
            }
            "non_unicode_key_hosted" => {
                child.env("ONEIRON_PRIVACY_POSTURE", "hosted");
                child.env("ONEIRON_HOSTED_KMS_KEY_REF", &malformed);
            }
            "unrelated_non_unicode" => {
                child.env("ONEIRON_HOST", &malformed);
                child.env("ONEIRON_PORT", &malformed);
            }
            _ => unreachable!(),
        }
        let output = child.output().unwrap();
        assert!(
            output.status.success(),
            "case {case}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        // A mistyped --exact filter can exit successfully with zero tests.
        assert!(String::from_utf8_lossy(&output.stdout).contains(CHECKED));
    }
}

fn check_child_environment(case: &str) {
    let invalid_key = match case {
        "non_unicode_posture" => Some("ONEIRON_PRIVACY_POSTURE"),
        "non_unicode_key_default"
        | "non_unicode_key_self_host_local"
        | "non_unicode_key_hosted" => Some("ONEIRON_HOSTED_KMS_KEY_REF"),
        _ => None,
    };
    if let Some(key) = invalid_key {
        let error = EnvConfig::from_process()
            .expect_err("non-Unicode privacy input must fail process environment parsing");
        assert_redacted_unicode_error(error, key);
        // Valid, higher-precedence CLI input must not hide malformed process
        // inputs either. Refusal happens before file lookup or storage opens.
        let args = ServeArgs {
            privacy_posture: Some(HostingPrivacyPosture::Hosted),
            hosted_kms_key_ref: Some("kms://example/cli-ref".to_owned()),
            ..Default::default()
        };
        assert_redacted_unicode_error(
            resolve_serve_config(&args)
                .expect_err("valid CLI input must not mask non-Unicode privacy environment input"),
            key,
        );
        return;
    }

    let resolved = resolve_serve_config_with_sources(
        &ServeArgs::default(),
        EnvConfig::from_process().expect("valid privacy environment must parse"),
        None,
    )
    .expect("valid privacy environment must resolve with default CLI arguments");
    let expected = match case {
        "hosted" => ServeConfig {
            privacy_posture: HostingPrivacyPosture::Hosted,
            hosted_kms_key_ref: Some("kms://example/clé".to_owned()),
            ..Default::default()
        },
        "unset" | "self_host_local" | "unrelated_non_unicode" => ServeConfig::default(),
        _ => panic!("unexpected child case: {case}"),
    };
    assert_eq!(resolved, expected);
    resolved
        .vault_config()
        .privacy
        .validate()
        .expect("resolved process privacy configuration must have valid custody");
}

fn assert_redacted_unicode_error(error: anyhow::Error, key: &str) {
    assert_eq!(
        error.to_string(),
        format!("{key} must contain valid Unicode")
    );
    assert_eq!(error.chain().count(), 1);
    for diagnostic in [format!("{error:#}"), format!("{error:?}")] {
        assert!(diagnostic.contains(key));
        assert!(!diagnostic.contains(PRIVATE_VALUE));
        assert!(!diagnostic.contains('\u{fffd}'));
    }
}
