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

#[test]
fn direct_vault_config_conversion_preserves_valid_privacy_pairs() {
    use HostingPrivacyPosture::{Hosted, SelfHostLocal};

    for (posture, key_ref, custody) in [
        (SelfHostLocal, None, VaultDataKeyCustody::OwnerHeldLocal),
        (
            Hosted,
            Some("kms://example/direct-ref"),
            VaultDataKeyCustody::HostManagedKms {
                key_ref: "kms://example/direct-ref".to_owned(),
            },
        ),
    ] {
        // Bypass the resolver, as a public library caller can.
        let direct = ServeConfig {
            privacy_posture: posture,
            hosted_kms_key_ref: key_ref.map(ToOwned::to_owned),
            dimensions: 8,
            map_size: 64 * 1024 * 1024,
            ..Default::default()
        };
        let converted = direct.vault_config();
        assert_eq!(converted.dimensions, direct.dimensions);
        assert_eq!(converted.map_size, direct.map_size);
        assert_eq!(converted.privacy.posture, posture);
        assert_eq!(converted.privacy.data_key_custody, custody);
        converted.privacy.validate().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault");
        let vault = oneiron::Vault::open(&path, converted).unwrap();
        assert_eq!(vault.privacy_posture(), posture);
        assert_eq!(vault.is_host_readable(), posture == Hosted);
        drop(vault);
        let reopened = oneiron::Vault::open_existing(&path, direct.vault_config()).unwrap();
        assert_eq!(reopened.privacy_posture(), posture);
        assert_eq!(reopened.is_host_readable(), posture == Hosted);
    }
}

#[test]
fn direct_vault_config_conversion_preserves_invalid_pairs_for_side_effect_free_refusal() {
    use HostingPrivacyPosture::{Hosted, SelfHostLocal};

    for (posture, key_ref) in [
        (SelfHostLocal, Some("kms://example/stray-ref")),
        (SelfHostLocal, Some("")),
        (SelfHostLocal, Some("   ")),
        (SelfHostLocal, Some("\t\n")),
        (Hosted, None),
        (Hosted, Some("")),
        (Hosted, Some("   ")),
        (Hosted, Some("\t\n")),
    ] {
        let direct = ServeConfig {
            privacy_posture: posture,
            hosted_kms_key_ref: key_ref.map(ToOwned::to_owned),
            dimensions: 8,
            map_size: 64 * 1024 * 1024,
            ..Default::default()
        };
        let converted = direct.vault_config();
        assert_eq!(converted.privacy.posture, posture);
        assert_eq!(
            converted.privacy.data_key_custody,
            VaultDataKeyCustody::HostManagedKms {
                key_ref: key_ref.unwrap_or_default().to_owned(),
            }
        );
        let validation_error = converted.privacy.validate().unwrap_err();
        let expected = match posture {
            Hosted => "non-empty host-managed KMS key reference",
            SelfHostLocal => "rejects host-managed KMS key custody",
        };
        assert!(matches!(
            &validation_error,
            oneiron::Error::InvalidConfig(message) if message.contains(expected)
        ));
        assert!(!format!("{converted:?}").contains("stray-ref"));

        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing-parent").join("vault");
        // Both public openers must refuse before creating even a parent
        // directory, or writing anything into an already-existing directory.
        for path in [missing.as_path(), dir.path()] {
            for existing_only in [false, true] {
                let result = if existing_only {
                    oneiron::Vault::open_existing(path, direct.vault_config())
                } else {
                    oneiron::Vault::open(path, direct.vault_config())
                };
                let error = result.err().expect("invalid custody must not open a vault");
                assert_eq!(error.to_string(), validation_error.to_string());
                assert!(!format!("{error:?}").contains("stray-ref"));
                assert!(!missing.exists());
                assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
            }
        }
    }
}
