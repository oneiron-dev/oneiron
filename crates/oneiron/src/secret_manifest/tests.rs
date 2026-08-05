//! SECRET-01 (ONE-1919) manifest tests: parse, narrow-only validation, the
//! widening-reject fixture.

use super::*;

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
fn narrow_manifest_inside_floor_validates() {
    // Floor allows portable T0..T2; entry asks T1 (narrower than max T2) — ok.
    let m = manifest(vec![entry(
        "api-key",
        CustodyClass::CustodyPortable,
        vec![binding("connector:gmail", CustodyTier::T1Leased)],
        &[".secrets/api.key"],
    )]);
    validate_secret_manifest(&m, &floor()).expect("narrow validates");
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
        Error::ManifestWidensFloor {
            secret_ref,
            class,
            requested,
            floor_max,
        } => {
            assert_eq!(secret_ref, "door-key");
            assert_eq!(class, CustodyClass::CrossVault);
            assert_eq!(requested, CustodyTier::T2LocalRegistered);
            assert_eq!(floor_max, CustodyTier::T0Doored);
        }
        other => panic!("expected ManifestWidensFloor, got {other:?}"),
    }
}

#[test]
fn entry_class_inside_floor_band_validates() {
    // device-bound floor is T0..T2; binding ceiling T2 sits at the floor max —
    // not wider, so it validates.
    let m = manifest(vec![entry(
        "device-pin",
        CustodyClass::CustodyDeviceBound,
        vec![binding(
            "connector:calendar",
            CustodyTier::T2LocalRegistered,
        )],
        &[],
    )]);
    validate_secret_manifest(&m, &floor()).expect("at-max binding validates");
}

#[test]
fn duplicate_entry_name_is_rejected() {
    let m = manifest(vec![
        entry("dup", CustodyClass::CustodyPortable, vec![], &[]),
        entry("dup", CustodyClass::CustodyPortable, vec![], &[]),
    ]);
    let err = validate_secret_manifest(&m, &floor()).expect_err("dup name reject");
    assert!(
        matches!(err, Error::InvalidSecretCustodyBody(_)),
        "got {err:?}"
    );
}

#[test]
fn parse_minimal_toml_manifest() {
    let text = r#"
schema_version = 1

[[secrets]]
name = "api-key"
class = "custody-portable"
declared_paths = [".secrets/api.key", ".secrets/api.key.bak"]

[[secrets.bindings]]
effector = "connector:gmail"
tier_ceiling = 2
scopes = ["read", "send"]

[[secrets]]
name = "door-key"
class = "cross-vault"
declared_paths = [".secrets/door.key"]
"#;
    let m = parse_secret_manifest(text).expect("parse");
    assert_eq!(m.schema_version, 1);
    assert_eq!(m.secrets.len(), 2);
    assert_eq!(m.secrets[0].name, "api-key");
    assert_eq!(m.secrets[0].class, CustodyClass::CustodyPortable);
    assert_eq!(m.secrets[0].declared_paths.len(), 2);
    assert_eq!(m.secrets[0].bindings[0].effector, "connector:gmail");
    assert_eq!(
        m.secrets[0].bindings[0].tier_ceiling,
        CustodyTier::T2LocalRegistered
    );
    assert_eq!(m.secrets[1].class, CustodyClass::CrossVault);
}

#[test]
fn parse_rejects_unknown_class() {
    let text = r#"
schema_version = 1
[[secrets]]
name = "x"
class = "not-a-class"
"#;
    assert!(parse_secret_manifest(text).is_err());
}

#[test]
fn parse_rejects_missing_class() {
    let text = r#"
schema_version = 1
[[secrets]]
name = "x"
"#;
    assert!(parse_secret_manifest(text).is_err());
}
