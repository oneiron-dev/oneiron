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
            // e8ac4951713 (#2955): the blank check names the custody, not the posture.
            assert!(
                error
                    .to_string()
                    .contains("KMS key custody requires a non-empty key reference")
            );
            assert!(!format!("{error:?}").contains(file_ref));
            assert!(!format!("{error:?}").contains(env_ref));
        }
    }
}

/// e8ac4951713 (#2955, HOSTED_OWNER_KEY_SUPPORT): only a blind relay refuses
/// a KMS reference now, so the same-source and higher-source rule is pinned
/// on Relay. A blank reference is refused first, on any posture.
#[test]
fn relay_privacy_rejects_same_source_and_higher_source_key_references() {
    use HostingPrivacyPosture::Relay;

    for posture_source in 0..3 {
        for key_ref_source in posture_source..3 {
            for key_ref in ["kms://example/stray-ref", "", "   "] {
                let mut postures = [None; 3];
                postures[posture_source] = Some(Relay);
                let mut key_refs = [None; 3];
                key_refs[key_ref_source] = Some(key_ref);
                let error = resolve_privacy_layers(postures, key_refs).unwrap_err();
                let expected = if key_ref.trim().is_empty() {
                    "KMS key custody requires a non-empty key reference"
                } else {
                    "a blind relay holds no data key"
                };
                assert!(
                    error.to_string().contains(expected),
                    "posture source {posture_source}, reference source {key_ref_source}: {error}"
                );
                assert!(!format!("{error:?}").contains("kms://example/stray-ref"));
            }
        }
    }
}

/// e8ac4951713 (#2955): a self-hosted vault keeps a KMS reference as the
/// custody of its own key.
#[test]
fn self_host_privacy_keeps_its_key_reference_as_kms_custody() {
    use HostingPrivacyPosture::SelfHostLocal;

    let key_ref = "kms://example/owner-ref";
    let resolved =
        resolve_privacy_layers([Some(SelfHostLocal), None, None], [Some(key_ref), None, None])
            .unwrap();
    assert_eq!(resolved.hosted_kms_key_ref.as_deref(), Some(key_ref));
    assert_eq!(
        resolved.vault_config().privacy.data_key_custody,
        VaultDataKeyCustody::HostManagedKms {
            key_ref: key_ref.to_owned(),
        }
    );
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
        // e8ac4951713 (#2955): the owner's own KMS on a self-hosted vault,
        // and a hosted vault on the owner's key.
        (
            SelfHostLocal,
            Some("kms://example/direct-ref"),
            VaultDataKeyCustody::HostManagedKms {
                key_ref: "kms://example/direct-ref".to_owned(),
            },
        ),
        (Hosted, None, VaultDataKeyCustody::OwnerHeldLocal),
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
        // The strict existing-only opener requires Linux's descriptor-bound
        // root path. Validation and the create-capable positive control above
        // still run on every platform; do not bypass production preflight.
        #[cfg(target_os = "linux")]
        {
            let reopened = oneiron::Vault::open_existing(&path, direct.vault_config())
                .expect("valid privacy pair reopens through the Linux existing-only door");
            assert_eq!(reopened.privacy_posture(), posture);
            assert_eq!(reopened.is_host_readable(), posture == Hosted);
        }
    }
}

#[test]
fn direct_vault_config_conversion_preserves_invalid_pairs_for_side_effect_free_refusal() {
    use HostingPrivacyPosture::{Hosted, Relay, SelfHostLocal};

    // e8ac4951713 (#2955): a self-hosted KMS reference and a hosted vault
    // with no reference are valid now; a relay holds no data key.
    for (posture, key_ref) in [
        (Relay, Some("kms://example/stray-ref")),
        (SelfHostLocal, Some("")),
        (SelfHostLocal, Some("   ")),
        (SelfHostLocal, Some("\t\n")),
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
        assert!(matches!(
            &validation_error,
            oneiron::Error::InvalidConfig(_)
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
                assert!(matches!(&error, oneiron::Error::InvalidConfig(_)));
                assert!(!format!("{error:?}").contains("stray-ref"));
                assert!(!missing.exists());
                assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
            }
        }
    }
}
