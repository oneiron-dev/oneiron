//! SECRET-01 (ONE-1919) manifest tests: parse, narrow-only validation, the
//! widening-reject fixture.

use super::*;
use crate::error::SecretError;

fn floor() -> SecretCustodyFloor {
    SecretCustodyFloor::default()
}

fn binding(effector: &str, ceiling: CustodyTier) -> SecretBinding {
    SecretBinding {
        effector: effector.to_owned(),
        tier_ceiling: ceiling,
        scopes: vec!["read".to_owned()],
    }
}

fn manifest(entries: Vec<SecretManifestEntry>) -> SecretManifest {
    SecretManifest {
        schema_version: SECRET_MANIFEST_SCHEMA_VERSION,
        secrets: entries,
    }
}

fn entry(
    name: &str,
    class: CustodyClass,
    bindings: Vec<SecretBinding>,
    paths: &[&str],
) -> SecretManifestEntry {
    SecretManifestEntry {
        name: name.to_owned(),
        class,
        bindings,
        declared_paths: paths.iter().map(|s| (*s).to_owned()).collect(),
    }
}

#[test]
fn binding_ceiling_above_floor_max_is_rejected() {
    // cross-vault floor is T0..T0; binding asks T2 — widens the floor.
    let m = manifest(vec![entry(
        "door-key",
        CustodyClass::CrossVault,
        vec![binding("door:receive-pack", CustodyTier::T2LocalRegistered)],
        &[".secrets/door.key"],
    )]);
    let err = validate_secret_manifest(&m, &floor()).expect_err("widening reject");
    match err {
        Error::Secret(SecretError::ManifestWidensFloor {
            secret_ref,
            class,
            requested,
            floor_max,
        }) => {
            assert_eq!(secret_ref, "door-key");
            assert_eq!(class, CustodyClass::CrossVault);
            assert_eq!(requested, CustodyTier::T2LocalRegistered);
            assert_eq!(floor_max, CustodyTier::T0Doored);
        }
        other => panic!("expected ManifestWidensFloor, got {other:?}"),
    }
}

#[test]
fn duplicate_entry_name_is_rejected() {
    let m = manifest(vec![
        entry("dup", CustodyClass::CustodyPortable, vec![], &[]),
        entry("dup", CustodyClass::CustodyPortable, vec![], &[]),
    ]);
    let err = validate_secret_manifest(&m, &floor()).expect_err("dup name reject");
    assert!(
        matches!(err, Error::Secret(SecretError::InvalidSecretCustodyBody(_))),
        "got {err:?}"
    );
}
