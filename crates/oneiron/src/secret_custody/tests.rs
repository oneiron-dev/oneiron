//! SECRET-01 (ONE-1919) unit tests: custody classes, record round-trip and
//! redacted `Debug`, the name index, floor resolution, binding discipline,
//! and the `device_only` dial semantics.

use super::*;
use crate::config::VaultConfig;

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

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

fn record(
    name: &str,
    class: CustodyClass,
    value: &[u8],
    bindings: Vec<SecretBinding>,
) -> SecretCustodyRecord {
    SecretCustodyRecord {
        schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
        name: name.to_owned(),
        class,
        device_only: false,
        value_bytes: value.to_vec(),
        status: SecretCustodyStatus::Active,
        registered_at: 1_700_000_000,
        rotated_at: None,
        rotation_generation: 0,
        bindings,
        manifest_ref: "secrets.toml".to_owned(),
        declared_paths: vec![".secrets/api.key".to_owned()],
        policy_floor_snapshot: floor(),
    }
}

#[test]
fn custody_class_wire_strings_match_canon() {
    // ARCH-0069 canon nouns, kebab-case on the wire.
    assert_eq!(CustodyClass::CustodyPortable.as_str(), "custody-portable");
    assert_eq!(
        CustodyClass::CustodyDeviceBound.as_str(),
        "custody-device-bound"
    );
    assert_eq!(CustodyClass::CrossVault.as_str(), "cross-vault");
    assert_eq!(
        CustodyClass::parse("cross-vault"),
        Some(CustodyClass::CrossVault)
    );
    assert_eq!(CustodyClass::parse("CustodyPortable"), None);
    assert_eq!(CustodyClass::parse("portable"), None);
}

#[test]
fn tier_orders_by_exposure() {
    assert!(CustodyTier::T0Doored < CustodyTier::T1Leased);
    assert!(CustodyTier::T1Leased < CustodyTier::T2LocalRegistered);
    assert_eq!(CustodyTier::from_u8(0), Some(CustodyTier::T0Doored));
    assert_eq!(
        CustodyTier::from_u8(2),
        Some(CustodyTier::T2LocalRegistered)
    );
    assert_eq!(CustodyTier::from_u8(3), None);
}

#[test]
fn body_keys_are_thirteen_and_complete() {
    assert_eq!(SECRET_CUSTODY_BODY_KEYS.len(), 13);
    assert_eq!(SECRET_CUSTODY_BODY_KEYS[0], "schema_version");
    assert_eq!(SECRET_CUSTODY_BODY_KEYS[4], "value_bytes");
    assert_eq!(SECRET_CUSTODY_BODY_KEYS[12], "policy_floor_snapshot");
}

#[test]
fn record_round_trips_encode_decode() {
    let rec = record(
        "api-key",
        CustodyClass::CustodyPortable,
        b"hunter2",
        vec![binding("connector:gmail", CustodyTier::T2LocalRegistered)],
    );
    let bytes = encode_secret_custody_body(&rec).expect("encode");
    let back = decode_secret_custody_body(&bytes).expect("decode");
    assert_eq!(back, rec);
    assert_eq!(back.value_bytes, b"hunter2");
}

#[test]
fn metadata_has_no_value_field_by_construction() {
    let rec = record("api-key", CustodyClass::CrossVault, b"hunter2", vec![]);
    let meta = rec.metadata();
    assert_eq!(meta.name, "api-key");
    assert_eq!(meta.class, CustodyClass::CrossVault);
    // Compile-time: SecretCustodyMetadata simply has no value_bytes member.
    // (The field list is the type-level proof; nothing to assert at runtime.)
    let _ = &meta.bindings;
}

#[test]
fn record_debug_redacts_value_bytes() {
    let rec = record(
        "api-key",
        CustodyClass::CustodyDeviceBound,
        b"super-secret-value",
        vec![],
    );
    let dbg = format!("{rec:?}");
    assert!(
        !dbg.contains("super-secret-value"),
        "Debug must never leak the value, got: {dbg}"
    );
    assert!(
        dbg.contains("<redacted"),
        "Debug shows a redacted marker: {dbg}"
    );
}

#[test]
fn floor_defaults_match_canon() {
    let floor = SecretCustodyFloor::default();
    assert_eq!(
        floor.portable,
        TierBand {
            min: CustodyTier::T0Doored,
            max: CustodyTier::T2LocalRegistered
        }
    );
    assert_eq!(
        floor.device_bound,
        TierBand {
            min: CustodyTier::T0Doored,
            max: CustodyTier::T2LocalRegistered
        }
    );
    assert_eq!(floor.cross_vault, TierBand::only(CustodyTier::T0Doored));
    assert_eq!(floor.rotation_max_age_secs, None);
    assert!(floor.env_bindings.is_empty());
}

#[test]
fn floor_merge_is_most_restrictive_per_field() {
    let mut a = SecretCustodyFloor::default();
    let b = SecretCustodyFloor {
        // narrower than a's T0..T2
        portable: TierBand::only(CustodyTier::T0Doored),
        rotation_max_age_secs: Some(86_400),
        env_bindings: BTreeMap::from([("prod".to_owned(), "require-lease".to_owned())]),
        ..SecretCustodyFloor::default()
    };
    a.merge(b);
    assert_eq!(a.portable, TierBand::only(CustodyTier::T0Doored));
    assert_eq!(a.rotation_max_age_secs, Some(86_400));
    assert_eq!(
        a.env_bindings.get("prod").map(String::as_str),
        Some("require-lease")
    );
    // device_bound / cross_vault untouched by b → defaults remain.
    assert_eq!(a.cross_vault, TierBand::only(CustodyTier::T0Doored));
}

#[test]
fn resolve_on_empty_vault_returns_defaults() {
    let (_tmp, vault) = temp_vault();
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let floor = SecretCustodyFloor::resolve(&vault.store, &rtxn).expect("resolve");
    assert_eq!(floor, SecretCustodyFloor::default());
}

#[test]
fn register_then_resolve_and_metadata() {
    let (_tmp, vault) = temp_vault();
    let rec = record("api-key", CustodyClass::CustodyPortable, b"hunter2", vec![]);
    let id = vault.register_secret(rec).expect("register");
    assert_eq!(
        vault.resolve_secret_ref("api-key").expect("resolve"),
        Some(id)
    );
    let meta = vault
        .get_secret_metadata(&id)
        .expect("metadata")
        .expect("some");
    assert_eq!(meta.name, "api-key");
    assert_eq!(meta.status, SecretCustodyStatus::Active);
    // Unknown name resolves to None.
    assert_eq!(vault.resolve_secret_ref("nope").expect("resolve"), None);
}

#[test]
fn duplicate_live_name_is_denied() {
    let (_tmp, vault) = temp_vault();
    let a = record("dup", CustodyClass::CustodyPortable, b"one", vec![]);
    vault.register_secret(a).expect("first register");
    let b = record("dup", CustodyClass::CustodyPortable, b"two", vec![]);
    let err = vault
        .register_secret(b)
        .expect_err("duplicate live name denied");
    assert!(matches!(err, Error::SecretNameInUse { .. }), "got {err:?}");
}

#[test]
fn raw_put_doors_reject_secret_custody_byte() {
    use crate::temporal::TimeRange;

    let (_tmp, vault) = temp_vault();
    let rec = record("raw-put", CustodyClass::CustodyPortable, b"hunter2", vec![]);
    let body = encode_secret_custody_body(&rec).expect("encode");
    let id = EntityId::now();
    let occurred = TimeRange { start: 1, end: 1 };

    // The convenience `Vault::put_entity` door (BatchBuilder::put) must reject.
    let err = vault
        .put_entity(&id, ENTITY_TYPE_SECRET_CUSTODY, occurred, 1, &body)
        .expect_err("put_entity on SECRET_CUSTODY must be denied");
    assert!(
        matches!(err, Error::MaintenanceKindNotWritable(77)),
        "got {err:?}"
    );

    // The raw batch door must reject at apply, not just at builder time.
    let err = vault
        .batch()
        .put(&id, ENTITY_TYPE_SECRET_CUSTODY, occurred, 1, &body)
        .commit()
        .expect_err("batch put on SECRET_CUSTODY must be denied");
    assert!(
        matches!(err, Error::MaintenanceKindNotWritable(77)),
        "got {err:?}"
    );

    // The raw-write rejection never minted a record on this id.
    assert!(
        vault.get_raw(&id).expect("raw read").is_none(),
        "rejected raw put must not leave a stored row"
    );
}

#[cfg(feature = "sync")]
#[test]
fn replicated_put_door_rejects_secret_custody_byte() {
    // C1 APPLY-TIME SEAL: the public raw doors reject byte 77 through the
    // `Maintenance` classification, but the REPLICATED door opens both admit
    // bands at once and its type gate listed only POLICY_MANIFEST /
    // ACCESS_GRANT / OUTBOUND_GRANT — so a peer-authored custody body (with
    // its plaintext `value_bytes`) reached `apply_put` and landed in LMDB.
    // Both replicated entry points must now fail typed and store nothing.
    use crate::temporal::TimeRange;

    let (_tmp, vault) = temp_vault();
    let rec = record(
        "replicated",
        CustodyClass::CustodyPortable,
        b"hunter2",
        vec![],
    );
    let body = encode_secret_custody_body(&rec).expect("encode");
    let occurred = TimeRange { start: 1, end: 1 };

    let batch_id = EntityId::now();
    let err = vault
        .batch()
        .put_replicated(&batch_id, ENTITY_TYPE_SECRET_CUSTODY, occurred, 1, &body)
        .commit()
        .expect_err("replicated custody put must be denied");
    assert!(
        matches!(err, Error::InvalidSecretCustodyBody(_)),
        "got {err:?}"
    );
    assert!(
        vault.get_raw(&batch_id).expect("raw read").is_none(),
        "rejected replicated put must not leave a stored row"
    );

    let txn_id = EntityId::now();
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put_replicated(&txn_id, ENTITY_TYPE_SECRET_CUSTODY, occurred, 1, &body)
                .apply(wtxn)
        })
        .expect_err("in-txn replicated custody put must be denied");
    assert!(
        matches!(err, Error::InvalidSecretCustodyBody(_)),
        "got {err:?}"
    );
    assert!(
        vault.get_raw(&txn_id).expect("raw read").is_none(),
        "rejected in-txn replicated put must not leave a stored row"
    );

    // The refusal classifies as a REMOTE rejection so one poisoned custody row
    // quarantines instead of wedging every other change in the window.
    assert_eq!(
        crate::sync::quarantine::remote_rejection_reason(&err).as_deref(),
        Some("InvalidSecretCustodyBody"),
    );
}

/// Decodes a custody body and re-encodes its MessagePack map minus one key.
fn drop_key(bytes: &[u8], drop: &str) -> Vec<u8> {
    let mut cursor = std::io::Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).expect("decode");
    let Value::Map(entries) = value else {
        panic!("map")
    };
    let kept: Vec<(Value, Value)> = entries
        .into_iter()
        .filter(|(k, _)| k.as_str() != Some(drop))
        .collect();
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(kept)).expect("encode");
    out
}

#[test]
fn decode_rejects_missing_required_body_keys() {
    // FIX5 BODY-SCHEMA: every key except rotated_at is required. Build a body
    // with each of bindings / manifest_ref / declared_paths omitted and pin
    // the immediate body-schema reject.
    let rec = record("c", CustodyClass::CustodyPortable, b"v", vec![]);
    let full = encode_secret_custody_body(&rec).expect("encode");

    for key in [
        "bindings",
        "manifest_ref",
        "declared_paths",
        "policy_floor_snapshot",
    ] {
        let body = drop_key(&full, key);
        let err = decode_secret_custody_body(&body)
            .expect_err(&format!("missing required key {key} must reject"));
        assert!(
            matches!(err, Error::InvalidSecretCustodyBody(_)),
            "key {key}: got {err:?}"
        );
    }

    // Present-but-empty required values still decode (empty != missing).
    let rec = SecretCustodyRecord {
        bindings: vec![],
        manifest_ref: String::new(),
        declared_paths: vec![],
        ..record("c", CustodyClass::CustodyPortable, b"v", vec![])
    };
    let bytes = encode_secret_custody_body(&rec).expect("encode");
    let back = decode_secret_custody_body(&bytes).expect("decode");
    assert!(back.bindings.is_empty());
    assert_eq!(back.manifest_ref(), "");
    assert!(back.declared_paths.is_empty());
}

#[test]
fn register_rejects_binding_wider_than_live_floor() {
    // FIX4 FLOOR-TOCTOU: resolve_secret runs inside the write txn against the
    // LIVE floor. A CrossVault record binding T2LocalRegistered against the
    // DEFAULT floor (T0..T0 band) must be rejected even though the same
    // binding would pass a stale/wider snapshot the caller asserted.
    let (_tmp, vault) = temp_vault();
    let rec = record(
        "xv-t2",
        CustodyClass::CrossVault,
        b"v",
        vec![binding("door:receive-pack", CustodyTier::T2LocalRegistered)],
    );
    let err = vault
        .register_secret(rec)
        .expect_err("CrossVault + T2 binding exceeds live floor");
    assert!(
        matches!(err, Error::ManifestWidensFloor { .. }),
        "got {err:?}"
    );
    // The rejected registration must not hold the name.
    assert_eq!(vault.resolve_secret_ref("xv-t2").expect("resolve"), None);
}

#[test]
fn register_custody_portable_t2_binding_passes_default_floor() {
    // The default floor's portable band is T0..T2, so a portable T2 binding is
    // inside it: same shape, class that admits it, must commit.
    let (_tmp, vault) = temp_vault();
    let rec = record(
        "port-t2",
        CustodyClass::CustodyPortable,
        b"v",
        vec![binding("connector:gmail", CustodyTier::T2LocalRegistered)],
    );
    vault
        .register_secret(rec)
        .expect("portable T2 binding fits the default floor");
}

#[test]
fn register_secret_with_credential_shaped_value_commits() {
    // FIX3 SCAN-CONFLICT: the batch secret scanner skips the credential-shape
    // scan for SECRET_CUSTODY Put bodies only. Registering a secret whose
    // value IS credential-shaped (ghp_ + 36 ASCII) must commit — the custody
    // record is the safe container, not a leak.
    let (_tmp, vault) = temp_vault();
    let token = b"ghp_0123456789abcdefghijklmnopqrstuvwxyz";
    let rec = record("gh-token", CustodyClass::CrossVault, token, vec![]);
    let id = vault
        .register_secret(rec)
        .expect("custody body with credential-shaped value must commit");
    let meta = vault
        .get_secret_metadata(&id)
        .expect("metadata")
        .expect("some");
    assert_eq!(meta.name, "gh-token");
}

#[test]
fn credential_scan_still_rejects_other_entity_types() {
    use crate::temporal::TimeRange;

    let (_tmp, vault) = temp_vault();
    let token = b"token=ghp_0123456789abcdefghijklmnopqrstuvwxyz";
    let id = EntityId::now();
    let occurred = TimeRange { start: 1, end: 1 };
    let err = vault
        .put_entity(&id, crate::registry::ENTITY_TYPE_TURN, occurred, 1, token)
        .expect_err("credential-shaped bytes on a non-custody type still reject");
    assert!(
        matches!(err, Error::GateWriteRejected { .. }),
        "got {err:?}"
    );
}

#[test]
fn value_read_goes_through_get_secret_value_in_txn_door() {
    // FIX2 BINDING-DOOR regression: the decode output carries the value, but
    // the ONLY read path for an external effector is the bound door. This test
    // pins both halves at the crate boundary:
    //   * `get_secret_value_in_txn` enforces the effector binding (typed deny
    //     on an unbound effector; returns the bytes on a bound one);
    //   * the record fields `value_bytes` / `manifest_ref` are `pub(crate)`,
    //     so no out-of-crate caller can bypass the door by decoding a record
    //     and reading the field (that bypass is a *compile* error outside the
    //     crate — the privacy boundary, asserted by the field attributes).
    let (_tmp, vault) = temp_vault();
    let rec = record(
        "door-only-key",
        CustodyClass::CrossVault,
        b"hunter2",
        vec![binding("door:receive-pack", CustodyTier::T0Doored)],
    );
    let id = vault.register_secret(rec).expect("register");

    let wtxn = vault.store.env.write_txn().expect("write txn");
    // Unbound effector is denied through the door.
    let err = vault
        .get_secret_value_in_txn(&wtxn, &id, "connector:evil")
        .expect_err("unbound effector must be denied at the door");
    assert!(
        matches!(err, Error::SecretBindingDenied { .. }),
        "got {err:?}"
    );
    // Bound effector reads the value — this is the sanctioned plaintext path.
    let value = vault
        .get_secret_value_in_txn(&wtxn, &id, "door:receive-pack")
        .expect("bound read")
        .expect("value present");
    assert_eq!(value, b"hunter2");
    wtxn.abort();

    // A generic `Vault::get` returns the *body bytes*, not a decoded record;
    // decoding it yields a SecretCustodyRecord but its value field is
    // crate-private — so the only value a caller can produce out-of-crate is
    // the re-encoded body, never the raw field. Pin that the door path above
    // (not a field read) is what returned the plaintext.
    let raw_body = vault.get(&id).expect("get body").expect("body present");
    let decoded = decode_secret_custody_body(&raw_body).expect("decode body");
    // Read-only accessor is the binding-door-safe surface for manifest_ref.
    assert_eq!(decoded.manifest_ref(), "secrets.toml");
    // (Out-of-crate, `decoded.value_bytes` is a compile error by `pub(crate)`.)
}

#[test]
fn value_read_requires_binding() {
    let (_tmp, vault) = temp_vault();
    let rec = record(
        "door-key",
        CustodyClass::CrossVault,
        b"hunter2",
        vec![binding("door:receive-pack", CustodyTier::T0Doored)],
    );
    let id = vault.register_secret(rec).expect("register");
    let wtxn = vault.store.env.write_txn().expect("write txn");
    // No binding for this effector → typed deny.
    let err = vault
        .get_secret_value_in_txn(&wtxn, &id, "connector:other")
        .expect_err("unbound effector denied");
    assert!(
        matches!(err, Error::SecretBindingDenied { .. }),
        "got {err:?}"
    );
    // Bound effector reads the value.
    let value = vault
        .get_secret_value_in_txn(&wtxn, &id, "door:receive-pack")
        .expect("bound read")
        .expect("value present");
    assert_eq!(value, b"hunter2");
    wtxn.abort();
}

#[test]
fn device_only_round_trips_on_portable() {
    let mut rec = record("portable-pin", CustodyClass::CustodyPortable, b"v", vec![]);
    rec.device_only = true;
    let bytes = encode_secret_custody_body(&rec).expect("encode");
    let back = decode_secret_custody_body(&bytes).expect("decode");
    assert!(back.device_only, "device_only survives the body codec");
}

#[test]
fn device_only_is_stored_but_inert_on_cross_vault() {
    // On a cross-vault record the dial is data only: it is stored and
    // round-trips, but it moves nothing — cross-vault is door-only regardless.
    let mut rec = record("xv", CustodyClass::CrossVault, b"v", vec![]);
    rec.device_only = true;
    let bytes = encode_secret_custody_body(&rec).expect("encode");
    let back = decode_secret_custody_body(&bytes).expect("decode");
    assert!(back.device_only);
    assert_eq!(back.class, CustodyClass::CrossVault);
    // The cross-vault floor band stays door-only regardless of the dial.
    assert_eq!(floor().cross_vault, TierBand::only(CustodyTier::T0Doored));
}
