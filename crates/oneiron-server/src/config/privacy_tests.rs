use super::*;

fn resolve_privacy_layers(
    postures: [Option<HostingPrivacyPosture>; 3],
    key_refs: [Option<&str>; 3],
) -> anyhow::Result<ServeConfig> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("oneiron.toml");
    let mut file = String::new();
    if let Some(posture) = postures[0] {
        file.push_str(&format!("privacy_posture = \"{posture}\"\n"));
    }
    if let Some(key_ref) = key_refs[0] {
        file.push_str(&format!("hosted_kms_key_ref = \"{key_ref}\"\n"));
    }
    std::fs::write(&config_path, file)?;

    let mut pairs = Vec::new();
    if let Some(posture) = postures[1] {
        pairs.push(("ONEIRON_PRIVACY_POSTURE", posture.to_string()));
    }
    if let Some(key_ref) = key_refs[1] {
        pairs.push(("ONEIRON_HOSTED_KMS_KEY_REF", key_ref.to_owned()));
    }
    let env = EnvConfig::from_pairs(pairs)?;
    let args = ServeArgs {
        config: Some(config_path),
        privacy_posture: postures[2],
        hosted_kms_key_ref: key_refs[2].map(ToOwned::to_owned),
        ..Default::default()
    };
    resolve_serve_config_with_sources(&args, env, None)
}

#[test]
fn privacy_posture_three_layer_transitions_use_the_final_winner() {
    use HostingPrivacyPosture::{Hosted, SelfHostLocal};

    // File -> environment -> CLI. Every row starts with the same valid hosted
    // file and reference. An overridden self-host layer must not erase it.
    for (env, cli, expected) in [
        (None, None, Hosted),
        (None, Some(Hosted), Hosted),
        (None, Some(SelfHostLocal), SelfHostLocal),
        (Some(Hosted), None, Hosted),
        (Some(Hosted), Some(Hosted), Hosted),
        (Some(Hosted), Some(SelfHostLocal), SelfHostLocal),
        (Some(SelfHostLocal), None, SelfHostLocal),
        (Some(SelfHostLocal), Some(Hosted), Hosted),
        (Some(SelfHostLocal), Some(SelfHostLocal), SelfHostLocal),
    ] {
        let resolved = resolve_privacy_layers(
            [Some(Hosted), env, cli],
            [Some("kms://example/file-ref"), None, None],
        )
        .unwrap();
        assert_eq!(
            resolved.privacy_posture, expected,
            "env={env:?}, cli={cli:?}"
        );
        let expected_ref = match expected {
            Hosted => Some("kms://example/file-ref"),
            SelfHostLocal => None,
        };
        assert_eq!(resolved.hosted_kms_key_ref.as_deref(), expected_ref);
        let privacy = resolved.vault_config().privacy;
        assert_eq!(privacy.posture, expected);
        assert_eq!(privacy.host_readable(), expected == Hosted);
        assert!(privacy.validate().is_ok());
        if expected == SelfHostLocal {
            assert_eq!(
                privacy.data_key_custody,
                VaultDataKeyCustody::OwnerHeldLocal
            );
        }
    }

    // A self-host file can also become hosted through either higher layer.
    // Neither a missing file posture nor the default posture creates a ref.
    for postures in [
        [Some(SelfHostLocal), Some(Hosted), None],
        [Some(SelfHostLocal), Some(SelfHostLocal), Some(Hosted)],
        [None, Some(SelfHostLocal), Some(Hosted)],
    ] {
        let error = resolve_privacy_layers(postures, [None; 3]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("non-empty host-managed KMS key reference")
        );
        let resolved =
            resolve_privacy_layers(postures, [None, None, Some("kms://example/cli-ref")]).unwrap();
        assert_eq!(resolved.privacy_posture, Hosted);
        assert_eq!(
            resolved.hosted_kms_key_ref.as_deref(),
            Some("kms://example/cli-ref")
        );
        assert!(resolved.vault_config().privacy.validate().is_ok());
    }
}

#[test]
fn privacy_reference_uses_its_highest_precedence_source() {
    use HostingPrivacyPosture::{Hosted, SelfHostLocal};

    let file_ref = "kms://example/file-ref";
    let env_ref = "kms://example/env-ref";
    let cli_ref = "kms://example/cli-ref";
    for (key_refs, expected) in [
        ([Some(file_ref), None, None], file_ref),
        ([None, Some(env_ref), None], env_ref),
        ([None, None, Some(cli_ref)], cli_ref),
        ([Some(file_ref), Some(env_ref), None], env_ref),
        ([Some(file_ref), None, Some(cli_ref)], cli_ref),
        ([None, Some(env_ref), Some(cli_ref)], cli_ref),
        ([Some(file_ref), Some(env_ref), Some(cli_ref)], cli_ref),
    ] {
        let resolved =
            resolve_privacy_layers([Some(Hosted), Some(Hosted), Some(Hosted)], key_refs).unwrap();
        assert_eq!(resolved.hosted_kms_key_ref.as_deref(), Some(expected));
        assert_eq!(
            resolved.vault_config().privacy.data_key_custody,
            VaultDataKeyCustody::HostManagedKms {
                key_ref: expected.to_owned(),
            }
        );
    }

    // Reselecting hosted restores the winning reference, not necessarily the
    // file's reference. A reference-only file has the same precedence rule.
    for (postures, key_refs, expected) in [
        (
            [Some(Hosted), Some(SelfHostLocal), Some(Hosted)],
            [Some(file_ref), None, Some(cli_ref)],
            cli_ref,
        ),
        (
            [None, Some(SelfHostLocal), Some(Hosted)],
            [Some(file_ref), None, None],
            file_ref,
        ),
        (
            [Some(SelfHostLocal), Some(Hosted), Some(Hosted)],
            [None, Some(env_ref), None],
            env_ref,
        ),
    ] {
        let resolved = resolve_privacy_layers(postures, key_refs).unwrap();
        assert_eq!(resolved.hosted_kms_key_ref.as_deref(), Some(expected));
        assert!(resolved.vault_config().privacy.validate().is_ok());
    }

    // An explicit blank winner is invalid; do not recover a lower valid ref.
    for blank in ["", "   "] {
        for key_refs in [
            [Some(file_ref), Some(blank), None],
            [Some(file_ref), Some(env_ref), Some(blank)],
        ] {
            let error =
                resolve_privacy_layers([Some(Hosted), None, Some(Hosted)], key_refs).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("non-empty host-managed KMS key reference")
            );
            assert!(!format!("{error:?}").contains(file_ref));
            assert!(!format!("{error:?}").contains(env_ref));
        }
    }
}

#[test]
fn final_self_host_posture_clears_only_lower_precedence_references() {
    use HostingPrivacyPosture::{Hosted, SelfHostLocal};

    for (posture_source, key_ref_source) in [(1, 0), (2, 0), (2, 1)] {
        let mut postures = [Some(Hosted), None, None];
        postures[posture_source] = Some(SelfHostLocal);
        let mut key_refs = [Some("kms://example/file-ref"), None, None];
        key_refs[key_ref_source] = Some("kms://example/winning-ref");
        let resolved = resolve_privacy_layers(postures, key_refs).unwrap();
        assert_eq!(resolved.privacy_posture, SelfHostLocal);
        assert_eq!(resolved.hosted_kms_key_ref, None);
        assert_eq!(
            resolved.vault_config().privacy,
            VaultPrivacyConfig::default()
        );
    }
}

#[test]
fn self_host_privacy_rejects_same_source_and_higher_source_key_references() {
    use HostingPrivacyPosture::SelfHostLocal;

    for posture_source in 0..3 {
        for key_ref_source in posture_source..3 {
            for key_ref in ["kms://example/stray-ref", "", "   "] {
                let mut postures = [None; 3];
                postures[posture_source] = Some(SelfHostLocal);
                let mut key_refs = [None; 3];
                key_refs[key_ref_source] = Some(key_ref);
                let error = resolve_privacy_layers(postures, key_refs).unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("rejects host-managed KMS key custody"),
                    "posture source {posture_source}, reference source {key_ref_source}: {error}"
                );
                assert!(!format!("{error:?}").contains("kms://example/stray-ref"));
            }
        }
    }
}
