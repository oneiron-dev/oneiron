//! ONE-1534 (OPS-SERVE): the custody contract for the scoped Wasabi snapshot
//! credential, pinned through the crate's PUBLIC custody surface.
//!
//! The provider-side legs — bucket preflight, sub-user mint, and the live
//! put/get smoke — are operator steps documented in
//! `docs/ops/wasabi-snapshot-credential-runbook.md` and run by hand, outside
//! this suite. Nothing here touches a network or a provider, and no real
//! credential material of any kind appears in this file: the registered value
//! is a fixed synthetic byte string.
//!
//! What is proven here:
//!
//! * the snapshot credential registers under exactly one custody name and
//!   resolves back to the same `EntityId`, so the repo references the secret
//!   BY NAME and never by value;
//! * the binding for the `ops-serve:wasabi-snapshot` effector grants exactly
//!   `put` / `get` / `multipart` at a `T1Leased` ceiling — no delete verb is
//!   reachable through the custody contract, mirroring the least-privilege
//!   provider policy the runbook specifies;
//! * the read a caller gets back is the value-less metadata projection.
//!
//! The record declares no `read` scope: materializing the value for a running
//! snapshot service is SECRET-02's door, not this registration's.

use oneiron::secret_custody::{
    CustodyClass, CustodyTier, SECRET_CUSTODY_BODY_KEYS, SECRET_CUSTODY_SCHEMA_VERSION,
    SecretBinding, SecretCustodyMetadata, SecretCustodyRecord, SecretCustodyStatus,
    decode_secret_custody_body,
};
use oneiron::{Vault, VaultConfig};
use rmpv::Value;

/// The custody name the repo stores as its only reference to the credential.
const SECRET_NAME: &str = "oneiron-snapshots-tokyo-serve-v1";

/// The effector the snapshot path names when it reaches for the credential.
const EFFECTOR: &str = "ops-serve:wasabi-snapshot";

/// The complete scope grant. No destructive verb, by construction.
const SCOPES: [&str; 3] = ["put", "get", "multipart"];

/// Fixed registration instant so the metadata projection compares exactly.
const REGISTERED_AT: u64 = 1_767_225_600;

/// Synthetic stand-in for the credential value. This is not a credential and
/// never was one: a real value only ever exists inside custody.
const DUMMY: &[u8] = b"dummy-wasabi-snapshot-secret";

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

/// The default vault floor, whose `custody-portable` band admits a `T1Leased`
/// ceiling.
fn default_floor_value() -> Value {
    let band = |min: u64, max: u64| {
        Value::Map(vec![
            (Value::from("min"), Value::from(min)),
            (Value::from("max"), Value::from(max)),
        ])
    };
    Value::Map(vec![
        (Value::from("portable"), band(0, 2)),
        (Value::from("device_bound"), band(0, 2)),
        (Value::from("cross_vault"), band(0, 0)),
        (Value::from("rotation_max_age_secs"), Value::Nil),
        (Value::from("env_bindings"), Value::Map(vec![])),
    ])
}

fn snapshot_binding_value() -> Value {
    let ceiling = u64::from(CustodyTier::T1Leased.as_u8());
    let scopes: Vec<Value> = SCOPES.iter().map(|s| Value::from(*s)).collect();
    Value::Map(vec![
        (Value::from("effector"), Value::from(EFFECTOR)),
        (Value::from("tier_ceiling"), Value::from(ceiling)),
        (Value::from("scopes"), Value::Array(scopes)),
    ])
}

/// Builds the custody body through the public codec shape, keyed by all 13
/// `SECRET_CUSTODY_BODY_KEYS` in field order. `value_bytes` and `manifest_ref`
/// are crate-private fields, so a struct literal is impossible out-of-crate:
/// encoding the canonical key map and decoding it is the sanctioned
/// construction path, the same one the manifest flow writes.
fn snapshot_custody_body() -> Vec<u8> {
    let key = |i: usize| Value::from(SECRET_CUSTODY_BODY_KEYS[i]);
    let body = Value::Map(vec![
        (
            key(0),
            Value::from(u64::from(SECRET_CUSTODY_SCHEMA_VERSION)),
        ),
        (key(1), Value::from(SECRET_NAME)),
        (key(2), Value::from(CustodyClass::CustodyPortable.as_str())),
        (key(3), Value::from(false)),
        (key(4), Value::Binary(DUMMY.to_vec())),
        (key(5), Value::from(SecretCustodyStatus::Active.as_str())),
        (key(6), Value::from(REGISTERED_AT)),
        (key(7), Value::Nil),
        (key(8), Value::from(0_u64)),
        (key(9), Value::Array(vec![snapshot_binding_value()])),
        (key(10), Value::from("")),
        (key(11), Value::Array(vec![])),
        (key(12), default_floor_value()),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body).expect("encode custody body");
    bytes
}

fn snapshot_custody_record() -> SecretCustodyRecord {
    decode_secret_custody_body(&snapshot_custody_body()).expect("decode custody body")
}

fn expected_binding() -> SecretBinding {
    SecretBinding {
        effector: EFFECTOR.to_owned(),
        tier_ceiling: CustodyTier::T1Leased,
        scopes: SCOPES.iter().map(|s| (*s).to_owned()).collect(),
    }
}

/// The repo references the credential by NAME; the name resolves to the one
/// custody record holding the value.
#[test]
fn wasabi_snapshot_credential_registers_and_resolves_by_name() {
    let (_tmp, vault) = temp_vault();

    let id = vault
        .register_secret(snapshot_custody_record())
        .expect("register the snapshot custody record");
    let resolved = vault
        .resolve_secret_ref(SECRET_NAME)
        .expect("resolve the secret name")
        .expect("the registered name is live");

    assert_eq!(
        resolved, id,
        "the snapshot credential's custody name must resolve to the record it registered"
    );
}

/// The custody grant matches the provider-side least-privilege policy: three
/// non-destructive verbs at a leased ceiling, and nothing else.
#[test]
fn wasabi_snapshot_binding_grants_exactly_put_get_multipart_at_t1_leased() {
    let record = snapshot_custody_record();

    let binding = record
        .binding_for(EFFECTOR)
        .cloned()
        .expect("the snapshot effector must carry a binding");
    let expected = expected_binding();

    assert_eq!(
        binding, expected,
        "the snapshot grant is exactly put/get/multipart at a T1Leased ceiling, no delete verb"
    );
    assert!(
        record.binding_for("ops-serve:wasabi-root").is_none(),
        "no effector outside the snapshot path may be bound to this credential"
    );
}

/// The read most callers get is value-less by construction: the projection has
/// no value field at all, and the full-field equality below is that proof.
#[test]
fn wasabi_snapshot_metadata_projection_carries_no_value() {
    let (_tmp, vault) = temp_vault();
    let id = vault
        .register_secret(snapshot_custody_record())
        .expect("register the snapshot custody record");

    let metadata = vault
        .get_secret_metadata(&id)
        .expect("read the custody metadata")
        .expect("the registered record has metadata");
    let expected = SecretCustodyMetadata {
        name: SECRET_NAME.to_owned(),
        class: CustodyClass::CustodyPortable,
        status: SecretCustodyStatus::Active,
        registered_at: REGISTERED_AT,
        rotated_at: None,
        rotation_generation: 0,
        bindings: vec![expected_binding()],
    };

    assert_eq!(
        metadata, expected,
        "the metadata projection is exactly the value-less field set for this credential"
    );

    let rendered = format!("{metadata:?}");
    let dummy = std::str::from_utf8(DUMMY).expect("the synthetic value is ASCII");
    assert!(
        !rendered.contains(dummy),
        "the value-less projection must never render the custody value bytes"
    );
}
