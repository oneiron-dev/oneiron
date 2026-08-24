//! SECRET-02 (ONE-1920) unit tests: the tier-admission truth table
//! (cap-only; SOL-1920-01), the T0 door (value un-returnable, receipt
//! value-free), T1 lease materialization with the receipt-before-value
//! fault hook, teardown (revoke/expiry/sweep), T2 local registration
//! (second-path conflict, occupant/symlink file policy, write-failure
//! guard), the value-less admission projection (SOL-1920-04), and S6
//! lease-scoped staleness.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

use super::*;
use crate::batch::{BatchOp, apply_ops};
use crate::config::VaultConfig;
use crate::registry::ENTITY_TYPE_SECRET_CUSTODY;
use crate::secret_custody::{
    SECRET_CUSTODY_SCHEMA_VERSION, SecretCustodyRecord, TierBand,
    decode_secret_custody_admission_body, encode_secret_custody_body, read_secret_custody_in_txn,
};
use crate::temporal::TimeRange;

// Benign test values: no detector-shaped credential material (the gate
// write wall scans bodies).
const VALUE_V1: &[u8] = b"wave5-lease-test-value-v1";
const VALUE_V2: &[u8] = b"wave5-lease-test-value-v2";
const EFFECTOR: &str = "connector:test";

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
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
    declared_paths: Vec<String>,
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
        declared_paths,
        policy_floor_snapshot: SecretCustodyFloor::default(),
    }
}

fn register(vault: &Vault, rec: SecretCustodyRecord) -> EntityId {
    vault.register_secret(rec).expect("register secret")
}

fn default_record(name: &str, class: CustodyClass, ceiling: CustodyTier) -> SecretCustodyRecord {
    record(
        name,
        class,
        VALUE_V1,
        vec![binding(EFFECTOR, ceiling)],
        vec![".secrets/api.key".to_owned()],
    )
}

fn read_lease_row(vault: &Vault, lease_id: &EntityId) -> Option<SecretLease> {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    read_secret_lease_in_txn(&vault.store, &rtxn, lease_id).expect("read lease row")
}

fn count_rows(vault: &Vault, prefix: &str) -> usize {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let mut count = 0;
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, prefix.as_bytes())
        .expect("prefix iter")
    {
        entry.expect("entry");
        count += 1;
    }
    count
}

fn read_receipt_row(vault: &Vault, receipt_id: &EntityId) -> Vec<u8> {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    vault
        .store
        .vault_meta
        .get(&rtxn, &receipt_key(receipt_id))
        .expect("read receipt row")
        .expect("receipt row present")
        .to_vec()
}

/// SECRET-04 owns rotation; until it lands, tests rotate by re-writing the
/// custody body with a bumped generation through the same sealed put shape
/// `register_secret` uses.
fn rotate_record_for_test(vault: &Vault, id: &EntityId, new_value: &[u8]) {
    let mut wtxn = vault.store.env.write_txn().expect("write txn");
    let rec = read_secret_custody_in_txn(&vault.store, &wtxn, id)
        .expect("read record")
        .expect("record present");
    let mut rotated = rec;
    rotated.rotation_generation += 1;
    rotated.rotated_at = Some(unix_seconds_now());
    rotated.value_bytes = new_value.to_vec();
    let data = encode_secret_custody_body(&rotated).expect("encode body");
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![BatchOp::Put {
            id: *id,
            entity_type: ENTITY_TYPE_SECRET_CUSTODY,
            occurred: TimeRange {
                start: rotated.registered_at,
                end: rotated.registered_at,
            },
            learned_at: rotated.registered_at,
            data,
            allow_maintenance: true,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }],
        vault.text_index_trusted.load(Ordering::Acquire),
        false,
        true,
    )
    .expect("apply rotation put");
    wtxn.commit().expect("commit rotation");
}

// ---------------------------------------------------------------------------
// The tier matrix (pure `tier_admission` truth table)
// ---------------------------------------------------------------------------

#[test]
fn tier_matrix_cross_vault_admits_t0_only() {
    let floor = SecretCustodyFloor::default();
    let binding = binding(EFFECTOR, CustodyTier::T2LocalRegistered);
    // Even a T2 binding ceiling cannot widen the cross-vault floor band
    // (registration of such a binding would already fail narrow-only, but
    // the gate itself is tested here directly).
    assert_eq!(
        tier_admission(
            CustodyClass::CrossVault,
            CustodyTier::T0Doored,
            &binding,
            &floor
        )
        .expect("T0 admits"),
        CustodyTier::T0Doored
    );
    for requested in [CustodyTier::T1Leased, CustodyTier::T2LocalRegistered] {
        let err = tier_admission(CustodyClass::CrossVault, requested, &binding, &floor)
            .expect_err("above the cross-vault floor band denies");
        assert!(matches!(err, Error::SecretTierDenied { .. }), "got {err:?}");
    }
}

#[test]
fn tier_matrix_portable_admits_up_to_binding_ceiling() {
    let floor = SecretCustodyFloor::default();
    let binding = binding(EFFECTOR, CustodyTier::T1Leased);
    for requested in [CustodyTier::T0Doored, CustodyTier::T1Leased] {
        assert_eq!(
            tier_admission(CustodyClass::CustodyPortable, requested, &binding, &floor)
                .expect("at or below the ceiling admits"),
            requested
        );
    }
    let err = tier_admission(
        CustodyClass::CustodyPortable,
        CustodyTier::T2LocalRegistered,
        &binding,
        &floor,
    )
    .expect_err("above the binding ceiling denies");
    assert!(matches!(err, Error::SecretTierDenied { .. }), "got {err:?}");
}

#[test]
fn tier_matrix_device_bound_admits_any_tier() {
    let floor = SecretCustodyFloor::default();
    let binding = binding(EFFECTOR, CustodyTier::T2LocalRegistered);
    for requested in [
        CustodyTier::T0Doored,
        CustodyTier::T1Leased,
        CustodyTier::T2LocalRegistered,
    ] {
        assert_eq!(
            tier_admission(
                CustodyClass::CustodyDeviceBound,
                requested,
                &binding,
                &floor
            )
            .expect("device-bound band spans all tiers"),
            requested
        );
    }
}

#[test]
fn tier_matrix_request_above_binding_ceiling_denies() {
    let floor = SecretCustodyFloor::default();
    let binding = binding(EFFECTOR, CustodyTier::T0Doored);
    let err = tier_admission(
        CustodyClass::CustodyPortable,
        CustodyTier::T1Leased,
        &binding,
        &floor,
    )
    .expect_err("T1 request against a T0 ceiling denies");
    match err {
        Error::SecretTierDenied {
            requested,
            binding_ceiling,
            ..
        } => {
            assert_eq!(requested, CustodyTier::T1Leased);
            assert_eq!(binding_ceiling, CustodyTier::T0Doored);
        }
        other => panic!("expected SecretTierDenied, got {other:?}"),
    }
}

#[test]
fn tier_matrix_request_outside_floor_band_denies() {
    // A vault floor narrowed to {T0..T1} for portable.
    let floor = SecretCustodyFloor {
        portable: TierBand {
            min: CustodyTier::T0Doored,
            max: CustodyTier::T1Leased,
        },
        ..Default::default()
    };
    let binding = binding(EFFECTOR, CustodyTier::T2LocalRegistered);
    let err = tier_admission(
        CustodyClass::CustodyPortable,
        CustodyTier::T2LocalRegistered,
        &binding,
        &floor,
    )
    .expect_err("above the floor band max denies");
    assert!(matches!(err, Error::SecretTierDenied { .. }), "got {err:?}");
}

#[test]
fn tier_matrix_below_band_min_never_forces_upward() {
    // SOL-1920-01 (K3 disposition, cap-only): the band's `min` is
    // informational — ONE-1919 floors narrow the MAX, never force
    // exposure. A portable floor of {T1..T2} must still admit the SAFER
    // T0 request; there is no minimum-exposure rule anywhere.
    let floor = SecretCustodyFloor {
        portable: TierBand {
            min: CustodyTier::T1Leased,
            max: CustodyTier::T2LocalRegistered,
        },
        ..Default::default()
    };
    let binding_wide = binding(EFFECTOR, CustodyTier::T2LocalRegistered);
    for requested in [
        CustodyTier::T0Doored,
        CustodyTier::T1Leased,
        CustodyTier::T2LocalRegistered,
    ] {
        assert_eq!(
            tier_admission(
                CustodyClass::CustodyPortable,
                requested,
                &binding_wide,
                &floor
            )
            .expect("at or below the band max admits, however high the informational min"),
            requested
        );
    }

    // The binding ceiling still caps under a raised informational min: a
    // T0 ceiling admits exactly T0.
    let binding_t0 = binding(EFFECTOR, CustodyTier::T0Doored);
    assert_eq!(
        tier_admission(
            CustodyClass::CustodyPortable,
            CustodyTier::T0Doored,
            &binding_t0,
            &floor
        )
        .expect("T0 admits under a T0 ceiling"),
        CustodyTier::T0Doored
    );
    let err = tier_admission(
        CustodyClass::CustodyPortable,
        CustodyTier::T1Leased,
        &binding_t0,
        &floor,
    )
    .expect_err("the binding ceiling still caps");
    assert!(matches!(err, Error::SecretTierDenied { .. }), "got {err:?}");
}

// ---------------------------------------------------------------------------
// The value-less admission projection (SOL-1920-04)
// ---------------------------------------------------------------------------

#[test]
fn admission_projection_matches_the_full_record_without_the_value() {
    // The doors' admission read decodes every metadata field the full
    // codec does, but the projection has no value field at all — the
    // borrowing decode leaves the plaintext a slice of the store page.
    let rec = record(
        "projection",
        CustodyClass::CustodyDeviceBound,
        VALUE_V1,
        vec![binding(EFFECTOR, CustodyTier::T1Leased)],
        vec![
            ".secrets/api.key".to_owned(),
            ".secrets/other.key".to_owned(),
        ],
    );
    let body = encode_secret_custody_body(&rec).expect("encode body");
    let admission = decode_secret_custody_admission_body(&body).expect("projection decode");
    assert_eq!(admission.name, rec.name);
    assert_eq!(admission.class, rec.class);
    assert_eq!(admission.status, rec.status);
    assert_eq!(admission.rotation_generation, rec.rotation_generation);
    assert_eq!(admission.bindings, rec.bindings);
    assert_eq!(admission.declared_paths, rec.declared_paths);
    assert_eq!(
        admission
            .binding_for(EFFECTOR)
            .expect("binding resolved")
            .tier_ceiling,
        CustodyTier::T1Leased
    );
}

// ---------------------------------------------------------------------------
// T0 door injection
// ---------------------------------------------------------------------------

#[test]
fn door_injection_injects_header_without_leaking_value() {
    let (_tmp, vault) = temp_vault();
    register(
        &vault,
        default_record(
            "api-key",
            CustodyClass::CustodyPortable,
            CustodyTier::T0Doored,
        ),
    );

    // A mock outbound request: the closure sets the injected header and
    // returns only () — the value cannot come back through the return type.
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    let receipt = vault
        .inject_secret_at_door("api-key", EFFECTOR, &mut |value: &[u8]| {
            headers.insert(
                "authorization".to_owned(),
                format!("Bearer {}", String::from_utf8_lossy(value)),
            );
            Ok(())
        })
        .expect("door injection admits");

    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer wave5-lease-test-value-v1")
    );
    assert_eq!(receipt.secret_ref, "api-key");
    assert_eq!(receipt.effector, EFFECTOR);
    assert_eq!(receipt.value_generation, 0);
    assert_eq!(
        receipt.taint_token,
        vec![SecretTaintRef {
            secret_ref: "api-key".to_owned(),
            generation: 0,
        }]
    );

    // Grep-guard: neither Debug nor serde output carries the value bytes.
    let debug = format!("{receipt:?}");
    let json = serde_json::to_string(&receipt).expect("serialize receipt");
    let value_str = String::from_utf8_lossy(VALUE_V1);
    assert!(!debug.contains(value_str.as_ref()), "debug leaks: {debug}");
    assert!(!json.contains(value_str.as_ref()), "serde leaks: {json}");
}

#[test]
fn door_injection_is_the_only_cross_vault_rung() {
    let (_tmp, vault) = temp_vault();
    register(
        &vault,
        default_record("door-only", CustodyClass::CrossVault, CustodyTier::T0Doored),
    );

    // T0 admits for cross-vault...
    let receipt = vault
        .inject_secret_at_door("door-only", EFFECTOR, &mut |_value| Ok(()))
        .expect("cross-vault admits T0");
    assert_eq!(receipt.secret_ref, "door-only");

    // ...and T1 denies: the cross-vault floor band is {T0..T0}.
    let err = vault
        .materialize_secret_lease("door-only", EFFECTOR, 3600)
        .expect_err("cross-vault denies T1");
    assert!(matches!(err, Error::SecretTierDenied { .. }), "got {err:?}");
}

#[test]
fn missing_binding_denies_at_the_door() {
    let (_tmp, vault) = temp_vault();
    // Record bound only to a different effector.
    register(
        &vault,
        record(
            "scoped",
            CustodyClass::CustodyPortable,
            VALUE_V1,
            vec![binding("connector:other", CustodyTier::T2LocalRegistered)],
            Vec::new(),
        ),
    );
    let err = vault
        .inject_secret_at_door("scoped", EFFECTOR, &mut |_value| Ok(()))
        .expect_err("no binding for (secret_ref, effector) denies");
    assert!(
        matches!(err, Error::SecretBindingDenied { .. }),
        "got {err:?}"
    );
}

#[test]
fn binding_without_read_scope_denies_the_value_read() {
    let (_tmp, vault) = temp_vault();
    // The binding exists (admission rule (a) passes) but declares no `read`
    // scope: ONE-1919's value door is the second, fail-closed layer.
    register(
        &vault,
        record(
            "no-read-scope",
            CustodyClass::CustodyPortable,
            VALUE_V1,
            vec![SecretBinding {
                effector: EFFECTOR.to_owned(),
                tier_ceiling: CustodyTier::T2LocalRegistered,
                scopes: Vec::new(),
            }],
            Vec::new(),
        ),
    );
    let err = vault
        .inject_secret_at_door("no-read-scope", EFFECTOR, &mut |_value| Ok(()))
        .expect_err("an empty scope list grants no read");
    assert!(
        matches!(err, Error::SecretBindingDenied { .. }),
        "got {err:?}"
    );
}

#[test]
fn unknown_secret_ref_denies() {
    let (_tmp, vault) = temp_vault();
    let err = vault
        .inject_secret_at_door("absent", EFFECTOR, &mut |_value| Ok(()))
        .expect_err("unknown ref denies");
    assert!(
        matches!(err, Error::SecretRefNotFound { .. }),
        "got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// T1 lease materialization
// ---------------------------------------------------------------------------

#[test]
fn materialize_lease_writes_rows_and_returns_value() {
    let (_tmp, vault) = temp_vault();
    register(
        &vault,
        default_record(
            "leased",
            CustodyClass::CustodyPortable,
            CustodyTier::T1Leased,
        ),
    );

    let materialization = vault
        .materialize_secret_lease("leased", EFFECTOR, 3600)
        .expect("T1 admits");
    // The materialization's own Debug redacts the returned value
    // (`Zeroizing`'s Debug would print the inner bytes — the wrapper's
    // hand-rolled Debug exists precisely so it cannot).
    let materialization_debug = format!("{materialization:?}");
    assert!(
        !materialization_debug.contains("wave5-lease-test-value-v1"),
        "materialization Debug leaks: {materialization_debug}"
    );
    assert_eq!(materialization.value.as_slice(), VALUE_V1);
    let lease = materialization.lease;
    assert_eq!(lease.tier, CustodyTier::T1Leased);
    assert_eq!(lease.status, SecretLeaseStatus::Active);
    assert_eq!(lease.secret_ref, "leased");
    assert_eq!(lease.binding_effector, EFFECTOR);
    assert_eq!(lease.value_generation, 0);
    assert_eq!(lease.expires_at, lease.granted_at + 3600);

    // The lease row and the receipt row are durable.
    let stored = read_lease_row(&vault, &lease.lease_id).expect("lease row present");
    assert_eq!(stored, lease);
    assert_eq!(count_rows(&vault, SECRET_LEASE_KEY_PREFIX), 1);
    assert_eq!(count_rows(&vault, SECRET_MATERIALIZATION_RECEIPT_PREFIX), 1);

    // The receipt row attests the materialization and carries no value bytes.
    let raw = read_receipt_row(&vault, &lease.materialization_receipt);
    let receipt = decode_materialization_receipt_body(&raw).expect("decode receipt");
    assert_eq!(receipt.lease_id, lease.lease_id);
    assert_eq!(receipt.secret_ref, "leased");
    assert_eq!(receipt.effector, EFFECTOR);
    assert_eq!(receipt.tier, CustodyTier::T1Leased);
    assert_eq!(receipt.value_generation, 0);
    let receipt_debug = format!("{receipt:?}");
    assert!(!receipt_debug.contains("wave5-lease-test-value-v1"));
    let body_text = String::from_utf8_lossy(&raw);
    assert!(
        !body_text.contains("wave5-lease-test-value-v1"),
        "receipt body carries value bytes"
    );
    assert!(body_text.contains(SECRET_MATERIALIZATION_RECEIPT_KIND));
}

#[test]
fn receipt_write_failure_leaves_no_lease_row_and_no_value() {
    let (_tmp, vault) = temp_vault();
    register(
        &vault,
        default_record(
            "fault",
            CustodyClass::CustodyPortable,
            CustodyTier::T1Leased,
        ),
    );

    receipt_fault_hook::arm_receipt_write_failure();
    let err = vault
        .materialize_secret_lease("fault", EFFECTOR, 3600)
        .expect_err("the injected receipt-write failure is typed");
    assert!(
        matches!(err, Error::SecretLeaseReceiptWriteFailed(_)),
        "got {err:?}"
    );

    // No lease row, no receipt row — and no value was returned above.
    assert_eq!(count_rows(&vault, SECRET_LEASE_KEY_PREFIX), 0);
    assert_eq!(count_rows(&vault, SECRET_MATERIALIZATION_RECEIPT_PREFIX), 0);

    // The hook is one-shot: the retry succeeds.
    let materialization = vault
        .materialize_secret_lease("fault", EFFECTOR, 3600)
        .expect("retry succeeds after the one-shot hook is consumed");
    assert_eq!(&*materialization.value, VALUE_V1);
    assert_eq!(count_rows(&vault, SECRET_LEASE_KEY_PREFIX), 1);
}

#[test]
fn teardown_revoke_flips_status_and_rematerialize_mints_fresh_id() {
    let (_tmp, vault) = temp_vault();
    register(
        &vault,
        default_record(
            "cycle",
            CustodyClass::CustodyPortable,
            CustodyTier::T1Leased,
        ),
    );

    let first = vault
        .materialize_secret_lease("cycle", EFFECTOR, 3600)
        .expect("first lease");
    let revoked = vault
        .revoke_secret_lease(&first.lease.lease_id, 1_700_000_100)
        .expect("revoke");
    assert_eq!(revoked.status, SecretLeaseStatus::Revoked);
    assert_eq!(
        read_lease_row(&vault, &first.lease.lease_id)
            .expect("row persists")
            .status,
        SecretLeaseStatus::Revoked
    );

    // A second materialize after revoke mints a fresh lease id.
    let second = vault
        .materialize_secret_lease("cycle", EFFECTOR, 3600)
        .expect("re-materialize");
    assert_ne!(first.lease.lease_id, second.lease.lease_id);
    assert_eq!(second.lease.status, SecretLeaseStatus::Active);

    // Revoking an unknown lease denies.
    let err = vault
        .revoke_secret_lease(&EntityId::now(), 1_700_000_100)
        .expect_err("unknown lease denies");
    assert!(
        matches!(err, Error::SecretLeaseNotFound { .. }),
        "got {err:?}"
    );
}

#[test]
fn expire_secret_leases_sweeps_past_due_leases() {
    let (_tmp, vault) = temp_vault();
    register(
        &vault,
        default_record(
            "sweep",
            CustodyClass::CustodyPortable,
            CustodyTier::T1Leased,
        ),
    );

    let live = vault
        .materialize_secret_lease("sweep", EFFECTOR, 3600)
        .expect("live lease");
    let past_due = vault
        .materialize_secret_lease("sweep", EFFECTOR, 0)
        .expect("past-due lease (ttl 0)");

    // now == expires_at is expired (the lease is valid until expires_at).
    let expired = vault
        .expire_secret_leases(past_due.lease.expires_at)
        .expect("sweep");
    assert_eq!(expired, 1);
    assert_eq!(
        read_lease_row(&vault, &past_due.lease.lease_id)
            .expect("row persists")
            .status,
        SecretLeaseStatus::Expired
    );
    assert_eq!(
        read_lease_row(&vault, &live.lease.lease_id)
            .expect("row persists")
            .status,
        SecretLeaseStatus::Active
    );

    // Idempotent: nothing left past due at the same instant.
    assert_eq!(
        vault
            .expire_secret_leases(past_due.lease.expires_at)
            .expect("re-sweep"),
        0
    );
}

// ---------------------------------------------------------------------------
// T2 local registration
// ---------------------------------------------------------------------------

fn declared_target(tmp: &tempfile::TempDir) -> (String, PathBuf) {
    let path = tmp.path().join(".secrets").join("api.key");
    (path.to_string_lossy().into_owned(), path)
}

fn t2_vault() -> (tempfile::TempDir, Vault, String, PathBuf) {
    let (tmp, vault) = temp_vault();
    let (declared, path) = declared_target(&tmp);
    std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    register(
        &vault,
        record(
            "local",
            CustodyClass::CustodyPortable,
            VALUE_V1,
            vec![binding(EFFECTOR, CustodyTier::T2LocalRegistered)],
            vec![declared.clone()],
        ),
    );
    (tmp, vault, declared, path)
}

#[test]
fn register_local_writes_file_records_registration_and_revoke_removes() {
    let (_tmp, vault, _declared, path) = t2_vault();
    let materialization = vault
        .materialize_secret_lease("local", EFFECTOR, 3600)
        .expect("lease");
    let lease_id = materialization.lease.lease_id;

    let registration = vault
        .register_secret_local(&lease_id, &path, "project-alpha")
        .expect("T2 admits");
    assert_eq!(registration.lease_id, lease_id);
    assert_eq!(registration.path, path);
    assert_eq!(registration.project_id, "project-alpha");
    assert_eq!(
        registration.content_hash,
        *blake3::hash(VALUE_V1).as_bytes()
    );

    // The value file holds the materialized bytes; the lease climbed to T2.
    assert_eq!(std::fs::read(&path).expect("read file"), VALUE_V1);
    let stored = read_lease_row(&vault, &lease_id).expect("lease row");
    assert_eq!(stored.tier, CustodyTier::T2LocalRegistered);
    assert_eq!(count_rows(&vault, SECRET_LOCAL_REGISTRATION_PREFIX), 1);

    // Owner-only permissions on unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "secret file permissions");
    }

    // Revoke removes the file and closes the registration.
    let revoked = vault
        .revoke_secret_lease(&lease_id, 1_700_000_100)
        .expect("revoke");
    assert_eq!(revoked.status, SecretLeaseStatus::Revoked);
    assert!(!path.exists(), "revoke removed the registered file");
    assert_eq!(count_rows(&vault, SECRET_LOCAL_REGISTRATION_PREFIX), 0);
}

#[test]
fn register_local_denies_an_undeclared_path() {
    let (tmp, vault, _declared, _path) = t2_vault();
    let materialization = vault
        .materialize_secret_lease("local", EFFECTOR, 3600)
        .expect("lease");
    let stray = tmp.path().join(".env");
    let err = vault
        .register_secret_local(&materialization.lease.lease_id, &stray, "project-alpha")
        .expect_err("an undeclared path denies");
    assert!(
        matches!(err, Error::SecretLeasePathNotDeclared { .. }),
        "got {err:?}"
    );
    assert!(!stray.exists(), "no file written on deny");
    // The lease stays a live T1 lease.
    let stored = read_lease_row(&vault, &materialization.lease.lease_id).expect("lease row");
    assert_eq!(stored.status, SecretLeaseStatus::Active);
    assert_eq!(stored.tier, CustodyTier::T1Leased);
}

#[test]
fn register_local_requires_a_live_lease() {
    let (_tmp, vault, _declared, path) = t2_vault();

    // Unknown lease id.
    let err = vault
        .register_secret_local(&EntityId::now(), &path, "project-alpha")
        .expect_err("unknown lease denies");
    assert!(
        matches!(err, Error::SecretLeaseNotFound { .. }),
        "got {err:?}"
    );

    // Revoked lease.
    let materialization = vault
        .materialize_secret_lease("local", EFFECTOR, 3600)
        .expect("lease");
    vault
        .revoke_secret_lease(&materialization.lease.lease_id, 1_700_000_100)
        .expect("revoke");
    let err = vault
        .register_secret_local(&materialization.lease.lease_id, &path, "project-alpha")
        .expect_err("a revoked lease denies");
    assert!(
        matches!(
            err,
            Error::SecretLeaseNotActive {
                status: SecretLeaseStatus::Revoked,
                ..
            }
        ),
        "got {err:?}"
    );

    // Past-due lease: lazy expiry at use flips the row durable, then denies.
    let stale = vault
        .materialize_secret_lease("local", EFFECTOR, 0)
        .expect("past-due lease");
    let err = vault
        .register_secret_local(&stale.lease.lease_id, &path, "project-alpha")
        .expect_err("a past-due lease denies");
    assert!(
        matches!(
            err,
            Error::SecretLeaseNotActive {
                status: SecretLeaseStatus::Expired,
                ..
            }
        ),
        "got {err:?}"
    );
    assert_eq!(
        read_lease_row(&vault, &stale.lease.lease_id)
            .expect("row persists")
            .status,
        SecretLeaseStatus::Expired,
        "lazy expiry is durable"
    );
}

#[test]
fn register_local_second_declared_path_conflicts() {
    let (tmp, vault) = temp_vault();
    let path_a = tmp.path().join(".secrets").join("a.key");
    let path_b = tmp.path().join(".secrets").join("b.key");
    std::fs::create_dir_all(path_a.parent().expect("parent")).expect("mkdir");
    let declared_a = path_a.to_string_lossy().into_owned();
    let declared_b = path_b.to_string_lossy().into_owned();
    register(
        &vault,
        record(
            "two-paths",
            CustodyClass::CustodyPortable,
            VALUE_V1,
            vec![binding(EFFECTOR, CustodyTier::T2LocalRegistered)],
            vec![declared_a, declared_b],
        ),
    );
    let materialization = vault
        .materialize_secret_lease("two-paths", EFFECTOR, 3600)
        .expect("lease");
    let lease_id = materialization.lease.lease_id;

    // The first registration lands at path A.
    let first = vault
        .register_secret_local(&lease_id, &path_a, "project-alpha")
        .expect("first registration");
    assert_eq!(first.path, path_a);

    // A DIFFERENT declared path under the same lease is the typed conflict
    // (SOL-1920-02): no file at B, and A's row and file stay intact.
    let err = vault
        .register_secret_local(&lease_id, &path_b, "project-alpha")
        .expect_err("a second declared path under one lease conflicts");
    match err {
        Error::SecretLeasePathConflict {
            lease_id: conflicted,
            registered_path,
            requested_path,
        } => {
            assert_eq!(conflicted, lease_id);
            assert_eq!(registered_path, path_a.display().to_string());
            assert_eq!(requested_path, path_b.display().to_string());
        }
        other => panic!("expected SecretLeasePathConflict, got {other:?}"),
    }
    assert!(!path_b.exists(), "no file written for the conflicted path");
    assert_eq!(std::fs::read(&path_a).expect("read A"), VALUE_V1);
    assert_eq!(count_rows(&vault, SECRET_LOCAL_REGISTRATION_PREFIX), 1);

    // Same-path re-materialization replaces file and row in place...
    let second = vault
        .register_secret_local(&lease_id, &path_a, "project-alpha")
        .expect("same-path re-materialization");
    assert_eq!(second.content_hash, first.content_hash);
    assert_eq!(count_rows(&vault, SECRET_LOCAL_REGISTRATION_PREFIX), 1);

    // ...and revoke still cleans the single registered path.
    vault
        .revoke_secret_lease(&lease_id, 1_700_000_100)
        .expect("revoke");
    assert!(!path_a.exists(), "revoke removed the registered file");
    assert_eq!(count_rows(&vault, SECRET_LOCAL_REGISTRATION_PREFIX), 0);
}

#[test]
fn register_local_refuses_occupants_the_vault_did_not_create() {
    let (_tmp, vault, _declared, path) = t2_vault();
    let materialization = vault
        .materialize_secret_lease("local", EFFECTOR, 3600)
        .expect("lease");
    let lease_id = materialization.lease.lease_id;

    // A stray regular file at the declared target is never clobbered by a
    // fresh registration (SOL-1920-03).
    std::fs::write(&path, b"stray occupant").expect("plant stray file");
    let err = vault
        .register_secret_local(&lease_id, &path, "project-alpha")
        .expect_err("a stray occupant denies");
    assert!(
        matches!(err, Error::SecretLeasePathRefused { .. }),
        "got {err:?}"
    );
    assert_eq!(
        std::fs::read(&path).expect("read stray"),
        b"stray occupant",
        "the stray file was not touched"
    );
    assert_eq!(count_rows(&vault, SECRET_LOCAL_REGISTRATION_PREFIX), 0);
    std::fs::remove_file(&path).expect("remove stray");

    // A symlink at the declared target is never followed.
    #[cfg(unix)]
    {
        let elsewhere = _tmp.path().join("elsewhere.key");
        std::os::unix::fs::symlink(&elsewhere, &path).expect("plant symlink");
        let err = vault
            .register_secret_local(&lease_id, &path, "project-alpha")
            .expect_err("a symlink target denies");
        assert!(
            matches!(err, Error::SecretLeasePathRefused { .. }),
            "got {err:?}"
        );
        assert!(!elsewhere.exists(), "the symlink was never followed");
        std::fs::remove_file(&path).expect("remove symlink");
    }

    // The lease is untouched by the refusals: a clean retry registers.
    vault
        .register_secret_local(&lease_id, &path, "project-alpha")
        .expect("retry after the refusals registers");
    assert_eq!(std::fs::read(&path).expect("read file"), VALUE_V1);
}

#[cfg(unix)]
#[test]
fn register_local_refuses_symlinked_parent_directory() {
    let (_tmp, vault, _declared, path) = t2_vault();
    let materialization = vault
        .materialize_secret_lease("local", EFFECTOR, 3600)
        .expect("lease");
    let lease_id = materialization.lease.lease_id;
    let parent = path.parent().expect("declared parent");
    let redirect = _tmp.path().join("redirected-parent");

    std::fs::remove_dir(parent).expect("remove declared parent");
    std::os::unix::fs::symlink(&redirect, parent).expect("plant parent symlink");
    let err = vault
        .register_secret_local(&lease_id, &path, "project-alpha")
        .expect_err("a symlinked parent denies");
    assert!(
        matches!(err, Error::SecretLeasePathRefused { .. }),
        "got {err:?}"
    );
    assert!(
        !redirect.join("api.key").exists(),
        "the parent symlink was never followed"
    );
    assert_eq!(count_rows(&vault, SECRET_LOCAL_REGISTRATION_PREFIX), 0);
}

#[test]
fn register_local_open_failure_leaves_no_file_and_no_row() {
    let (tmp, vault) = temp_vault();
    // A declared path whose parent directory does not exist: the create
    // fails, nothing lands, no row persists (SOL-1920-03).
    let path = tmp.path().join("missing-parent").join("api.key");
    let declared = path.to_string_lossy().into_owned();
    register(
        &vault,
        record(
            "no-parent",
            CustodyClass::CustodyPortable,
            VALUE_V1,
            vec![binding(EFFECTOR, CustodyTier::T2LocalRegistered)],
            vec![declared],
        ),
    );
    let materialization = vault
        .materialize_secret_lease("no-parent", EFFECTOR, 3600)
        .expect("lease");
    let lease_id = materialization.lease.lease_id;
    let err = vault
        .register_secret_local(&lease_id, &path, "project-alpha")
        .expect_err("an uncreatable target fails the write");
    assert!(matches!(err, Error::Io(_)), "got {err:?}");
    assert!(!path.exists());
    assert_eq!(count_rows(&vault, SECRET_LOCAL_REGISTRATION_PREFIX), 0);
    let stored = read_lease_row(&vault, &lease_id).expect("lease row");
    assert_eq!(stored.status, SecretLeaseStatus::Active);
    assert_eq!(stored.tier, CustodyTier::T1Leased);
}

#[test]
fn registration_write_failure_removes_the_fresh_file() {
    let (_tmp, vault, _declared, path) = t2_vault();
    let materialization = vault
        .materialize_secret_lease("local", EFFECTOR, 3600)
        .expect("lease");
    let lease_id = materialization.lease.lease_id;

    registration_fault_hook::arm_registration_write_failure();
    let err = vault
        .register_secret_local(&lease_id, &path, "project-alpha")
        .expect_err("the injected registration-write failure surfaces");
    assert!(matches!(err, Error::Io(_)), "got {err:?}");

    // The guard removed the file this attempt created fresh (SOL-1920-03):
    // no untracked plaintext, no row, lease still a live T1 lease.
    assert!(!path.exists(), "guard removed the fresh file");
    assert_eq!(count_rows(&vault, SECRET_LOCAL_REGISTRATION_PREFIX), 0);
    let stored = read_lease_row(&vault, &lease_id).expect("lease row");
    assert_eq!(stored.status, SecretLeaseStatus::Active);
    assert_eq!(stored.tier, CustodyTier::T1Leased);

    // The hook is one-shot: the retry registers.
    vault
        .register_secret_local(&lease_id, &path, "project-alpha")
        .expect("retry succeeds after the one-shot hook is consumed");
    assert_eq!(std::fs::read(&path).expect("read file"), VALUE_V1);
    assert_eq!(count_rows(&vault, SECRET_LOCAL_REGISTRATION_PREFIX), 1);
}

#[test]
fn file_write_failure_removes_the_fresh_file() {
    let (_tmp, vault, _declared, path) = t2_vault();
    let materialization = vault
        .materialize_secret_lease("local", EFFECTOR, 3600)
        .expect("lease");
    let lease_id = materialization.lease.lease_id;

    file_write_fault_hook::arm_file_write_failure();
    let err = vault
        .register_secret_local(&lease_id, &path, "project-alpha")
        .expect_err("the injected file-write failure surfaces");
    assert!(matches!(err, Error::Io(_)), "got {err:?}");

    assert!(!path.exists(), "guard removed the fresh file");
    assert_eq!(count_rows(&vault, SECRET_LOCAL_REGISTRATION_PREFIX), 0);
    let stored = read_lease_row(&vault, &lease_id).expect("lease row");
    assert_eq!(stored.status, SecretLeaseStatus::Active);
    assert_eq!(stored.tier, CustodyTier::T1Leased);

    // The hook is one-shot: the retry registers.
    vault
        .register_secret_local(&lease_id, &path, "project-alpha")
        .expect("retry succeeds after the one-shot hook is consumed");
    assert_eq!(std::fs::read(&path).expect("read file"), VALUE_V1);
    assert_eq!(count_rows(&vault, SECRET_LOCAL_REGISTRATION_PREFIX), 1);
}

#[test]
fn reregister_after_file_loss_rematerializes_from_the_vault() {
    let (_tmp, vault, _declared, path) = t2_vault();
    let materialization = vault
        .materialize_secret_lease("local", EFFECTOR, 3600)
        .expect("lease");
    let lease_id = materialization.lease.lease_id;
    let first = vault
        .register_secret_local(&lease_id, &path, "project-alpha")
        .expect("first registration");

    // The file is lost; recovery re-materializes from the vault (S4).
    std::fs::remove_file(&path).expect("lose the file");
    let second = vault
        .register_secret_local(&lease_id, &path, "project-alpha")
        .expect("re-register");
    assert_eq!(std::fs::read(&path).expect("read file"), VALUE_V1);
    assert_eq!(first.content_hash, second.content_hash);
    assert_eq!(count_rows(&vault, SECRET_LOCAL_REGISTRATION_PREFIX), 1);
}

#[test]
fn expire_secret_leases_tears_down_t2_files() {
    let (_tmp, vault, _declared, path) = t2_vault();
    let materialization = vault
        .materialize_secret_lease("local", EFFECTOR, 0)
        .expect("past-due lease");
    let lease_id = materialization.lease.lease_id;
    // Register before the sweep runs (the file lands while the lease is
    // still stored Active — the sweep then owns the teardown).
    vault
        .register_secret_local(&lease_id, &path, "project-alpha")
        .expect_err("past-due at use: lazy expiry denies");

    // Re-materialize with a real ttl and register, then expire by the sweep.
    let materialization = vault
        .materialize_secret_lease("local", EFFECTOR, 60)
        .expect("lease");
    let lease_id = materialization.lease.lease_id;
    vault
        .register_secret_local(&lease_id, &path, "project-alpha")
        .expect("registration");
    assert!(path.exists());
    let expired = vault
        .expire_secret_leases(materialization.lease.expires_at)
        .expect("sweep");
    assert_eq!(expired, 1);
    assert!(!path.exists(), "the sweep removed the T2 file");
    assert_eq!(count_rows(&vault, SECRET_LOCAL_REGISTRATION_PREFIX), 0);
    assert_eq!(
        read_lease_row(&vault, &lease_id).expect("row").status,
        SecretLeaseStatus::Expired
    );
}

#[test]
fn revoke_records_a_failed_file_removal() {
    let (_tmp, vault, _declared, path) = t2_vault();
    let materialization = vault
        .materialize_secret_lease("local", EFFECTOR, 3600)
        .expect("lease");
    let lease_id = materialization.lease.lease_id;
    vault
        .register_secret_local(&lease_id, &path, "project-alpha")
        .expect("registration");

    // Force the removal to fail deterministically under ANY user (root
    // included): replace the registered file with a non-empty directory at
    // the same path — `remove_file` on a directory always errors.
    std::fs::remove_file(&path).expect("remove file");
    std::fs::create_dir(&path).expect("mkdir at path");
    std::fs::write(path.join("occupant"), b"x").expect("occupant file");

    let revoked = vault
        .revoke_secret_lease(&lease_id, 1_700_000_100)
        .expect("revoke is best-effort: the status flip still lands");
    assert_eq!(revoked.status, SecretLeaseStatus::Revoked);
    assert!(path.exists(), "the failed removal left the path in place");

    // ...and the registration row is RETAINED with the failure recorded, so
    // the still-present path stays in SECRET-03's exclusion set (best-effort,
    // recorded — never a silent drop).
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let stored = read_local_registration_in_txn(&vault.store, &rtxn, &lease_id)
        .expect("read registration")
        .expect("registration row retained");
    assert!(stored.removal_error.is_some(), "removal failure recorded");
    assert_eq!(stored.removal_attempted_at, Some(1_700_000_100));
    drop(rtxn);

    std::fs::remove_dir_all(&path).expect("manual cleanup");
}

// ---------------------------------------------------------------------------
// S6 lease-scoped staleness
// ---------------------------------------------------------------------------

#[test]
fn lease_survives_record_rotation_with_observable_staleness() {
    let (_tmp, vault, _declared, path) = t2_vault();
    let id = vault
        .resolve_secret_ref("local")
        .expect("resolve")
        .expect("record present");

    let materialization = vault
        .materialize_secret_lease("local", EFFECTOR, 3600)
        .expect("lease at generation 0");
    let lease = materialization.lease.clone();
    assert_eq!(lease.value_generation, 0);
    assert_eq!(materialization.value.as_slice(), VALUE_V1);

    // The record rotates to generation 1 (SECRET-04's door; test-driven here).
    rotate_record_for_test(&vault, &id, VALUE_V2);

    // The lease is NOT force-killed: still Active, its mint generation
    // unchanged — staleness is observable, not enforced here.
    let stored = read_lease_row(&vault, &lease.lease_id).expect("lease row");
    assert_eq!(stored.status, SecretLeaseStatus::Active);
    assert_eq!(stored.value_generation, 0);

    // A fresh value read under the lease picks up the CURRENT (rotated)
    // value; the lease row keeps the mint generation as the signal.
    vault
        .register_secret_local(&lease.lease_id, &path, "project-alpha")
        .expect("T2 still admits after rotation");
    assert_eq!(std::fs::read(&path).expect("read file"), VALUE_V2);
    assert_eq!(
        read_lease_row(&vault, &lease.lease_id)
            .expect("lease row")
            .value_generation,
        0
    );

    // A new lease mints at the new generation.
    let fresh = vault
        .materialize_secret_lease("local", EFFECTOR, 3600)
        .expect("fresh lease");
    assert_eq!(fresh.lease.value_generation, 1);
    assert_eq!(fresh.value.as_slice(), VALUE_V2);
}
