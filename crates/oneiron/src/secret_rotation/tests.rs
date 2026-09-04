//! SECRET-04 (ONE-1922) unit tests.
//!
//! The two halves of ARCH-0069 this ticket lands, plus the negatives that
//! keep the 2026-08-05 read-time amendment honest:
//!
//! * S6 rotation — generation/timestamp/receipt, the NEW value on the next
//!   lease, and the OLD lease left alive and observably stale;
//! * doored invisibility across a rotation;
//! * revoke as terminal value death (leases, doors, derived taint);
//! * action-boundary taint attach on both exhaust planes, read back at
//!   READ time;
//! * the publish gate and its override stamp;
//! * export honesty;
//! * the grep-guard: no value bytes anywhere in this plane's `Debug` or
//!   wire bodies.
//!
//! The load-bearing NEGATIVES (there is no reverse index, and rotation
//! flips nothing) live in `revoke_derives_stale_taint_without_writing_any_index`
//! and `rotation_does_not_touch_one_byte_of_exhaust`.

use rmpv::Value;

use super::*;
use crate::artifact_hosting::ArtifactPointerChannel;
use crate::batch::export::{
    ExportManifest, ExportSecretsNulledManifest, export_bundle_carries_tainted_exhaust,
    secrets_nulled_for_export_bundle, whole_vault_export_manifest_artifact_for_bundle,
};
use crate::blob_artifact::{
    BLOB_ARTIFACT_BODY_KEYS, BLOB_ARTIFACT_OPTIONAL_BODY_KEYS, BlobArtifactBody,
    decode_blob_artifact_body, encode_blob_artifact_body,
};
use crate::code_artifact::{CODE_ARTIFACT_SUMMARY_HASH_LEN, CodeArtifactBody, CodeArtifactClass};
use crate::code_run::CodeRunRawOutput;
use crate::codebase::{CodebaseFileEntry, CodebaseForkHash, CodebaseSnapshot, RepoRef};
use crate::config::VaultConfig;
use crate::entity_id::ENTITY_ID_LEN;
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::secret_custody::{
    CustodyClass, CustodyTier, SECRET_CUSTODY_SCHEMA_VERSION, SecretBinding, SecretCustodyFloor,
    SecretCustodyRecord,
};
use crate::secret_lease::SecretLeaseStatus;
use crate::store::Store;
use crate::temporal::TimeRange;

// Benign test material: nothing detector-shaped (the gate write wall scans
// bodies), and deliberately distinct per generation so a stale read is
// visible rather than merely equal-by-luck.
const VALUE_V1: &[u8] = b"wave6-rotation-test-value-v1";
const VALUE_V2: &[u8] = b"wave6-rotation-test-value-v2";
const EFFECTOR: &str = "connector:test";
const SECRET: &str = "build-token";
const OTHER_SECRET: &str = "other-token";

const AT_REGISTERED: u64 = 1_700_000_000;
const AT_ROTATED: u64 = 1_700_000_500;

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

fn record(name: &str, value: &[u8]) -> SecretCustodyRecord {
    SecretCustodyRecord {
        schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
        name: name.to_owned(),
        class: CustodyClass::CustodyPortable,
        device_only: false,
        value_bytes: value.to_vec(),
        status: SecretCustodyStatus::Active,
        registered_at: AT_REGISTERED,
        rotated_at: None,
        rotation_generation: 0,
        bindings: vec![binding(EFFECTOR, CustodyTier::T1Leased)],
        manifest_ref: "secrets.toml".to_owned(),
        declared_paths: vec![".secrets/api.key".to_owned()],
        policy_floor_snapshot: SecretCustodyFloor::default(),
    }
}

fn register(vault: &Vault, name: &str, value: &[u8]) -> EntityId {
    vault
        .register_secret(record(name, value))
        .expect("register")
}

fn taint(name: &str, generation: u32) -> SecretTaintRef {
    SecretTaintRef {
        secret_ref: name.to_owned(),
        generation,
    }
}

fn generation_of(vault: &Vault, id: &EntityId) -> u32 {
    vault
        .get_secret_metadata(id)
        .expect("metadata")
        .expect("record present")
        .rotation_generation
}

fn count_rows(vault: &Vault, prefix: &str) -> usize {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, prefix.as_bytes())
        .expect("prefix iter")
        .count()
}

fn row_bytes(vault: &Vault, key: &[u8]) -> Option<Vec<u8>> {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    vault
        .store
        .vault_meta
        .get(&rtxn, key)
        .expect("read row")
        .map(|v| v.to_vec())
}

/// Writes a POLICY_MANIFEST row the way the engine seeder does — the plane
/// the stale-publish dial resolves over (the ONE-1919 floor idiom).
fn put_policy_manifest(vault: &Vault, seed: u8, rows: Vec<(Value, Value)>) {
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &Value::Map(rows)).expect("encode manifest body");
    let id = EntityId::from_bytes([seed; ENTITY_ID_LEN]).expect("manifest id");
    let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
    payload.push(ENTITY_TYPE_POLICY_MANIFEST);
    for _ in 0..3 {
        payload.extend_from_slice(&2_u64.to_be_bytes());
    }
    payload.extend_from_slice(&data);

    let mut wtxn = vault.store.env.write_txn().expect("write txn");
    vault
        .store
        .entities
        .put(&mut wtxn, id.as_bytes(), &payload)
        .expect("put manifest");
    let type_key = Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id);
    vault
        .store
        .type_index
        .put(&mut wtxn, &type_key, &[])
        .expect("type index row");
    wtxn.commit().expect("commit manifest");
}

fn put_artifact(vault: &Vault, id: &EntityId, body: &BlobArtifactBody) {
    vault
        .put_blob_artifact(
            id,
            body,
            TimeRange {
                start: AT_REGISTERED,
                end: AT_REGISTERED,
            },
            AT_REGISTERED,
        )
        .expect("put blob artifact");
}

fn artifact_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; ENTITY_ID_LEN]).expect("artifact id")
}

// ---------------------------------------------------------------------------
// S6 — rotation is a vault update, and the caveat is lease-scoped
// ---------------------------------------------------------------------------

#[test]
fn rotate_bumps_generation_stamps_time_and_writes_a_value_free_receipt() {
    let (_tmp, vault) = temp_vault();
    let id = register(&vault, SECRET, VALUE_V1);
    assert_eq!(generation_of(&vault, &id), 0);

    let receipt = vault
        .rotate_secret(SECRET, VALUE_V2, AT_ROTATED)
        .expect("rotate");

    assert_eq!(receipt.secret_ref, SECRET);
    assert_eq!(receipt.from_generation, 0);
    assert_eq!(receipt.to_generation, 1);
    assert_eq!(receipt.rotated_at, AT_ROTATED);
    assert_eq!(receipt.kind, RotationKind::Rotated);

    let meta = vault
        .get_secret_metadata(&id)
        .expect("metadata")
        .expect("record present");
    assert_eq!(meta.rotation_generation, 1);
    assert_eq!(meta.rotated_at, Some(AT_ROTATED));
    assert_eq!(meta.status, SecretCustodyStatus::Active);

    let durable = vault
        .rotation_receipt(&receipt.receipt_id)
        .expect("read receipt")
        .expect("receipt row present");
    assert_eq!(durable, receipt, "the receipt round-trips through its row");
    assert_eq!(count_rows(&vault, SECRET_ROTATION_RECEIPT_PREFIX), 1);
}

#[test]
fn rotate_refuses_a_missing_or_inactive_record() {
    let (_tmp, vault) = temp_vault();
    assert!(matches!(
        vault.rotate_secret("nope", VALUE_V2, AT_ROTATED),
        Err(Error::SecretRefNotFound { .. })
    ));

    register(&vault, SECRET, VALUE_V1);
    vault.revoke_secret(SECRET, AT_ROTATED).expect("revoke");
    assert!(
        matches!(
            vault.rotate_secret(SECRET, VALUE_V2, AT_ROTATED),
            Err(Error::SecretCustodyNotActive { .. })
        ),
        "a revoked record has no value to rotate"
    );
    // The refused rotation wrote nothing: only the revoke's own receipt.
    assert_eq!(count_rows(&vault, SECRET_ROTATION_RECEIPT_PREFIX), 1);
}

#[test]
fn the_next_lease_gets_the_new_value_and_the_old_lease_stays_alive_and_observably_stale() {
    let (_tmp, vault) = temp_vault();
    let id = register(&vault, SECRET, VALUE_V1);

    let before = vault
        .materialize_secret_lease(SECRET, EFFECTOR, 3_600)
        .expect("lease before rotation");
    assert_eq!(before.value.as_slice(), VALUE_V1);
    assert_eq!(before.lease.value_generation, 0);

    vault
        .rotate_secret(SECRET, VALUE_V2, AT_ROTATED)
        .expect("rotate");

    // S6: the next lease materializes the NEW value.
    let after = vault
        .materialize_secret_lease(SECRET, EFFECTOR, 3_600)
        .expect("lease after rotation");
    assert_eq!(after.value.as_slice(), VALUE_V2);
    assert_eq!(after.lease.value_generation, 1);

    // ...and the OLD lease is neither killed nor silently repaired. It is
    // still Active, still stamped at the generation it minted under, and
    // its staleness is READ OFF that field against the record. That is the
    // honest lease-scoped caveat, stated rather than hidden.
    let raw = row_bytes(
        &vault,
        format!(
            "{SECRET_LEASE_KEY_PREFIX}{}",
            before.lease.lease_id.to_hex()
        )
        .as_bytes(),
    )
    .expect("old lease row survives the rotation");
    let old = decode_secret_lease_body(&raw).expect("decode old lease");
    assert_eq!(old.status, SecretLeaseStatus::Active);
    assert_eq!(old.value_generation, 0);
    assert!(
        old.value_generation < generation_of(&vault, &id),
        "the old lease reports itself stale against the record"
    );
}

#[test]
fn doored_uses_rotate_invisibly() {
    let (_tmp, vault) = temp_vault();
    register(&vault, SECRET, VALUE_V1);

    // Identical caller code on both sides of the rotation.
    let mut seen = Vec::new();
    let mut capture = |value: &[u8]| {
        seen.push(value.to_vec());
        Ok(())
    };

    let first = vault
        .inject_secret_at_door(SECRET, EFFECTOR, &mut capture)
        .expect("door before rotation");
    vault
        .rotate_secret(SECRET, VALUE_V2, AT_ROTATED)
        .expect("rotate");
    let second = vault
        .inject_secret_at_door(SECRET, EFFECTOR, &mut capture)
        .expect("door after rotation");

    assert_eq!(seen, vec![VALUE_V1.to_vec(), VALUE_V2.to_vec()]);
    assert_eq!(first.value_generation, 0);
    assert_eq!(second.value_generation, 1);
    assert_eq!(second.taint_token, vec![taint(SECRET, 1)]);
}

// ---------------------------------------------------------------------------
// Revoke — terminal value death
// ---------------------------------------------------------------------------

#[test]
fn revoke_kills_every_lease_and_every_door_for_the_ref() {
    let (_tmp, vault) = temp_vault();
    register(&vault, SECRET, VALUE_V1);
    register(&vault, OTHER_SECRET, VALUE_V1);

    let doomed = vault
        .materialize_secret_lease(SECRET, EFFECTOR, 3_600)
        .expect("lease");
    let spared = vault
        .materialize_secret_lease(OTHER_SECRET, EFFECTOR, 3_600)
        .expect("other lease");

    let receipt = vault.revoke_secret(SECRET, AT_ROTATED).expect("revoke");
    assert_eq!(receipt.kind, RotationKind::Revoked);
    assert_eq!(
        (receipt.from_generation, receipt.to_generation),
        (0, 0),
        "a revoke does not advance the generation: nothing replaced the value"
    );

    let lease_status = |lease_id: &EntityId| {
        let raw = row_bytes(
            &vault,
            format!("{SECRET_LEASE_KEY_PREFIX}{}", lease_id.to_hex()).as_bytes(),
        )
        .expect("lease row");
        decode_secret_lease_body(&raw).expect("decode lease").status
    };
    assert_eq!(
        lease_status(&doomed.lease.lease_id),
        SecretLeaseStatus::Revoked
    );
    assert_eq!(
        lease_status(&spared.lease.lease_id),
        SecretLeaseStatus::Active,
        "another secret's lease is untouched"
    );

    assert!(matches!(
        vault.materialize_secret_lease(SECRET, EFFECTOR, 3_600),
        Err(Error::SecretCustodyNotActive { .. })
    ));
    assert!(matches!(
        vault.inject_secret_at_door(SECRET, EFFECTOR, &mut |_: &[u8]| Ok(())),
        Err(Error::SecretCustodyNotActive { .. })
    ));
    // The spared secret still works: revoke is scoped to its ref.
    vault
        .materialize_secret_lease(OTHER_SECRET, EFFECTOR, 3_600)
        .expect("other secret still materializes");
}

/// The amendment's load-bearing NEGATIVE: a revoke invalidates tainted
/// exhaust WITHOUT writing an index row, walking artifacts, or flipping a
/// stored state. The stale read is derived, and it derives from a record
/// that died.
#[test]
fn revoke_derives_stale_taint_without_writing_any_index() {
    let (_tmp, vault) = temp_vault();
    register(&vault, SECRET, VALUE_V1);
    register(&vault, OTHER_SECRET, VALUE_V1);

    let tainted = artifact_id(0x21);
    put_artifact(
        &vault,
        &tainted,
        &BlobArtifactBody::new("build.log", "text/plain")
            .with_secret_taint_refs(vec![taint(SECRET, 0)]),
    );
    let untainted = artifact_id(0x22);
    put_artifact(
        &vault,
        &untainted,
        &BlobArtifactBody::new("readme.txt", "text/plain"),
    );
    let other = artifact_id(0x23);
    put_artifact(
        &vault,
        &other,
        &BlobArtifactBody::new("other.log", "text/plain")
            .with_secret_taint_refs(vec![taint(OTHER_SECRET, 0)]),
    );

    assert_eq!(
        vault.artifact_taint_state(&tainted).expect("state"),
        ArtifactTaintState::TaintedLive
    );

    vault.revoke_secret(SECRET, AT_ROTATED).expect("revoke");

    assert_eq!(
        vault.artifact_taint_state(&tainted).expect("state"),
        ArtifactTaintState::TaintedStale,
        "a revoked record makes its exhaust stale: the value that justified the taint is gone"
    );
    assert_eq!(
        vault.artifact_taint_state(&untainted).expect("state"),
        ArtifactTaintState::Clean,
        "untainted exhaust is unaffected"
    );
    assert_eq!(
        vault.artifact_taint_state(&other).expect("state"),
        ArtifactTaintState::TaintedLive,
        "exhaust tainted by a DIFFERENT secret is unaffected"
    );

    // The negative the 2026-08-05 amendment exists to guarantee: no reverse
    // index from a secret to the artifacts it tainted, anywhere, ever.
    assert_eq!(
        count_rows(&vault, "secret_taint:v1:"),
        0,
        "no secret->artifact index rows are written"
    );
    assert_eq!(
        count_rows(&vault, SECRET_EXHAUST_TAINT_PREFIX),
        0,
        "body-carried taint needs no sidecar row at all"
    );
}

/// Rotation writes the record and its receipt. Not one byte of exhaust.
#[test]
fn rotation_does_not_touch_one_byte_of_exhaust() {
    let (_tmp, vault) = temp_vault();
    register(&vault, SECRET, VALUE_V1);

    let entity = artifact_id(0x31);
    vault
        .mark_artifact_tainted(&entity, &[taint(SECRET, 0)])
        .expect("attach taint");
    let key = format!("{SECRET_EXHAUST_TAINT_PREFIX}{}", entity.to_hex()).into_bytes();
    let before = row_bytes(&vault, &key).expect("taint row");
    assert_eq!(
        vault.artifact_taint_state(&entity).expect("state"),
        ArtifactTaintState::TaintedLive
    );

    vault
        .rotate_secret(SECRET, VALUE_V2, AT_ROTATED)
        .expect("rotate");

    assert_eq!(
        row_bytes(&vault, &key).as_deref(),
        Some(before.as_slice()),
        "no bulk flip: the stored refs are byte-identical across the rotation"
    );
    assert_eq!(
        vault.artifact_taint_state(&entity).expect("state"),
        ArtifactTaintState::TaintedStale,
        "the answer changed because the RECORD moved, not because a row was rewritten"
    );
    assert_eq!(count_rows(&vault, "secret_taint:v1:"), 0);
}

// ---------------------------------------------------------------------------
// Action-boundary attach, read-time derivation
// ---------------------------------------------------------------------------

#[test]
fn raw_output_taint_attaches_at_the_action_boundary_and_derives_at_read_time() {
    let (_tmp, vault) = temp_vault();
    register(&vault, SECRET, VALUE_V1);

    let raw = b"build finished\n";
    let output = CodeRunRawOutput::from_bytes("out/build.log", raw).expect("raw output");
    vault
        .put_code_run_raw_output_tainted(&output, raw, &[taint(SECRET, 0)])
        .expect("tainted persist");

    // The exhaust bytes are still readable exactly as an untainted put's
    // are: the sidecar rides beside the row, never inside it.
    assert_eq!(
        vault
            .get_code_run_raw_output(&output)
            .expect("read raw")
            .as_deref(),
        Some(&raw[..])
    );
    assert_eq!(
        vault.code_run_raw_output_taint_refs(&output).expect("refs"),
        vec![taint(SECRET, 0)]
    );
    assert_eq!(
        vault
            .code_run_raw_output_taint_state(&output)
            .expect("state"),
        ArtifactTaintState::TaintedLive
    );

    vault
        .rotate_secret(SECRET, VALUE_V2, AT_ROTATED)
        .expect("rotate");
    assert_eq!(
        vault
            .code_run_raw_output_taint_state(&output)
            .expect("state"),
        ArtifactTaintState::TaintedStale
    );

    // A clean handle has no sidecar row and reads Clean.
    let clean_raw = b"nothing secret here\n";
    let clean = CodeRunRawOutput::from_bytes("out/clean.log", clean_raw).expect("raw output");
    vault
        .put_code_run_raw_output(&clean, clean_raw)
        .expect("untainted persist");
    assert_eq!(
        vault
            .code_run_raw_output_taint_state(&clean)
            .expect("state"),
        ArtifactTaintState::Clean
    );
    assert!(
        vault
            .code_run_raw_output_taint_refs(&clean)
            .expect("refs")
            .is_empty()
    );
}

#[test]
fn the_blob_body_taint_key_is_optional_and_old_two_key_bodies_still_decode() {
    let (_tmp, vault) = temp_vault();
    register(&vault, SECRET, VALUE_V1);

    assert_eq!(
        BLOB_ARTIFACT_BODY_KEYS,
        ["name", "media_type"],
        "the REQUIRED set is unchanged: an artifact is still complete on write"
    );
    assert_eq!(
        BLOB_ARTIFACT_OPTIONAL_BODY_KEYS,
        ["secret_taint.refs"],
        "the taint key is pinned, but its absence is meaningful rather than fatal"
    );

    // A body written before this key existed — two keys, nothing else.
    let mut legacy = Vec::new();
    rmpv::encode::write_value(
        &mut legacy,
        &Value::Map(vec![
            (Value::from("name"), Value::from("legacy.txt")),
            (Value::from("media_type"), Value::from("text/plain")),
        ]),
    )
    .expect("encode legacy body");
    let decoded = decode_blob_artifact_body(&legacy).expect("legacy body still decodes");
    assert_eq!(decoded.name, "legacy.txt");
    assert!(
        decoded.secret_taint_refs.is_empty(),
        "an absent taint key decodes Clean"
    );

    // An untainted body is BYTE-IDENTICAL to the legacy framing.
    assert_eq!(
        encode_blob_artifact_body(&BlobArtifactBody::new("legacy.txt", "text/plain"))
            .expect("encode"),
        legacy,
        "encode emits the taint key only when there is taint to declare"
    );

    // A tainted body round-trips through the pinned key.
    let tainted_body = BlobArtifactBody::new("build.log", "text/plain")
        .with_secret_taint_refs(vec![taint(SECRET, 0)]);
    let encoded = encode_blob_artifact_body(&tainted_body).expect("encode");
    assert_eq!(
        decode_blob_artifact_body(&encoded).expect("decode"),
        tainted_body
    );

    // ...and drives the derived state off the artifact row.
    let id = artifact_id(0x41);
    put_artifact(&vault, &id, &tainted_body);
    assert_eq!(
        vault.artifact_taint_refs(&id).expect("refs"),
        vec![taint(SECRET, 0)]
    );
    assert_eq!(
        vault.artifact_taint_state(&id).expect("state"),
        ArtifactTaintState::TaintedLive
    );

    let clean = artifact_id(0x42);
    put_artifact(
        &vault,
        &clean,
        &BlobArtifactBody::new("clean.txt", "text/plain"),
    );
    assert_eq!(
        vault.artifact_taint_state(&clean).expect("state"),
        ArtifactTaintState::Clean
    );
}

#[test]
fn a_taint_ref_naming_a_secret_that_never_existed_reads_stale() {
    let (_tmp, vault) = temp_vault();
    let id = artifact_id(0x51);
    vault
        .mark_artifact_tainted(&id, &[taint("never-registered", 0)])
        .expect("attach");
    assert_eq!(
        vault.artifact_taint_state(&id).expect("state"),
        ArtifactTaintState::TaintedStale,
        "a missing record fails closed: the value that justified the taint cannot be vouched for"
    );
}

#[test]
fn an_empty_ref_list_clears_the_sidecar_so_clean_has_one_representation() {
    let (_tmp, vault) = temp_vault();
    register(&vault, SECRET, VALUE_V1);
    let id = artifact_id(0x52);

    vault
        .mark_artifact_tainted(&id, &[taint(SECRET, 0)])
        .expect("attach");
    assert_eq!(count_rows(&vault, SECRET_EXHAUST_TAINT_PREFIX), 1);

    vault.mark_artifact_tainted(&id, &[]).expect("clear");
    assert_eq!(
        count_rows(&vault, SECRET_EXHAUST_TAINT_PREFIX),
        0,
        "clean is an ABSENT row, never an empty one"
    );
    assert_eq!(
        vault.artifact_taint_state(&id).expect("state"),
        ArtifactTaintState::Clean
    );
}

#[test]
fn malformed_taint_refs_refuse_rather_than_defaulting_to_clean() {
    let (_tmp, vault) = temp_vault();
    let id = artifact_id(0x53);

    assert!(matches!(
        vault.mark_artifact_tainted(&id, &[taint("", 0)]),
        Err(Error::InvalidSecretRotationBody(_))
    ));
    assert!(
        matches!(
            vault.mark_artifact_tainted(&id, &[taint(SECRET, 0), taint(SECRET, 1)]),
            Err(Error::InvalidSecretRotationBody(_))
        ),
        "one secret cannot be asserted at two generations by one body"
    );
    assert_eq!(count_rows(&vault, SECRET_EXHAUST_TAINT_PREFIX), 0);

    // A corrupted row REFUSES; it never silently reads Clean.
    let key = format!("{SECRET_EXHAUST_TAINT_PREFIX}{}", id.to_hex()).into_bytes();
    let mut wtxn = vault.store.env.write_txn().expect("write txn");
    vault
        .store
        .vault_meta
        .put(&mut wtxn, &key, b"not messagepack at all")
        .expect("put corrupt row");
    wtxn.commit().expect("commit");
    assert!(matches!(
        vault.artifact_taint_state(&id),
        Err(Error::InvalidSecretRotationBody(_))
    ));
}

// ---------------------------------------------------------------------------
// The publish gate — a dial, not a wall
// ---------------------------------------------------------------------------

/// A publishable artifact snapshot, built straight through the store doors.
///
/// Deliberately NOT a git ingest: the publish gate turns on the resolved
/// snapshot and the artifact class, and a subprocess would add nothing to
/// what is under test here.
fn publishable_site(vault: &Vault) -> (EntityId, CodebaseForkHash) {
    let id = EntityId::now();
    let repo_ref =
        RepoRef::parse("github:oneiron-dev/oneiron#9d561405a81ffbf29d1369cd848e0ef9fca4f277")
            .expect("repo ref");
    let snapshot = CodebaseSnapshot::new(
        "site",
        repo_ref.clone(),
        Some("9d561405a81ffbf29d1369cd848e0ef9fca4f277".to_owned()),
        vec![CodebaseFileEntry::new(
            "index.html",
            *blake3::hash(b"").as_bytes(),
            0,
        )],
    )
    .expect("snapshot");
    let fork_hash = snapshot.fork_hash;

    vault
        .put_code_artifact(
            &id,
            &CodeArtifactBody::new(
                "Summarize the artifact snapshot.",
                [0xA5; CODE_ARTIFACT_SUMMARY_HASH_LEN],
                repo_ref.canonical(),
            )
            .with_class(CodeArtifactClass::Artifact),
            TimeRange { start: 10, end: 10 },
            10,
        )
        .expect("put code artifact");
    vault
        .put_codebase_snapshot(&id, &snapshot, &|_| Some(Vec::new()))
        .expect("put codebase snapshot");
    (id, fork_hash)
}

#[test]
fn publish_refuses_stale_tainted_exhaust_then_stamps_the_pointer_when_the_dial_opens() {
    let (_tmp, vault) = temp_vault();
    register(&vault, SECRET, VALUE_V1);
    let (site_id, fork_hash) = publishable_site(&vault);

    // Clean and TaintedLive both publish, unstamped and ungated.
    let pointer = vault
        .publish_artifact_pointer("site", ArtifactPointerChannel::Published, &fork_hash)
        .expect("clean publish");
    assert!(!pointer.stale_taint_override);

    vault
        .mark_artifact_tainted(&site_id, &[taint(SECRET, 0)])
        .expect("attach taint at the action boundary");
    assert_eq!(
        vault.artifact_taint_state(&site_id).expect("state"),
        ArtifactTaintState::TaintedLive
    );
    vault
        .publish_artifact_pointer("site", ArtifactPointerChannel::Published, &fork_hash)
        .expect("live taint is not stale taint: it publishes");

    // The pointer row is still EXACTLY the 32-byte fork hash — unchanged
    // from every pointer written before SECRET-04.
    let key = {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        let mut found = None;
        for entry in vault
            .store
            .vault_meta
            .prefix_iter(&rtxn, b"artifact:pointer:v1:")
            .expect("prefix iter")
        {
            let (k, v) = entry.expect("entry");
            found = Some((k.to_vec(), v.to_vec()));
        }
        found.expect("pointer row")
    };
    assert_eq!(key.1.len(), 32, "an ordinary publish adds no bytes");

    // Rotate: the exhaust goes stale, and the gate refuses.
    vault
        .rotate_secret(SECRET, VALUE_V2, AT_ROTATED)
        .expect("rotate");
    assert_eq!(
        vault.artifact_taint_state(&site_id).expect("state"),
        ArtifactTaintState::TaintedStale
    );
    let refused = vault
        .publish_artifact_pointer("site", ArtifactPointerChannel::Preview, &fork_hash)
        .expect_err("stale tainted exhaust refuses publish");
    assert!(
        matches!(refused, Error::TaintedArtifactStale { ref artifact } if artifact == "site"),
        "got {refused:?}"
    );
    assert!(
        vault
            .artifact_pointer("site", ArtifactPointerChannel::Preview)
            .expect("read preview")
            .is_none(),
        "a refused publish writes no pointer"
    );

    // Open the dial: the publish proceeds AND the row is stamped.
    assert!(!vault.taint_allow_stale_publish().expect("dial default off"));
    put_policy_manifest(
        &vault,
        0x91,
        vec![(
            Value::from(POLICY_TAINT_ALLOW_STALE_PUBLISH_KEY),
            Value::from(true),
        )],
    );
    assert!(vault.taint_allow_stale_publish().expect("dial resolves on"));

    let overridden = vault
        .publish_artifact_pointer("site", ArtifactPointerChannel::Preview, &fork_hash)
        .expect("the dial admits the publish");
    assert!(overridden.stale_taint_override);

    let read_back = vault
        .artifact_pointer("site", ArtifactPointerChannel::Preview)
        .expect("read preview")
        .expect("pointer present");
    assert!(
        read_back.stale_taint_override,
        "the override is durable on the row, not merely remembered in process"
    );
    assert_eq!(read_back.fork_hash, fork_hash);

    // The unstamped pointer still decodes exactly as before.
    let unstamped = vault
        .artifact_pointer("site", ArtifactPointerChannel::Published)
        .expect("read published")
        .expect("pointer present");
    assert!(!unstamped.stale_taint_override);
    assert_eq!(unstamped.fork_hash, fork_hash);
}

// ---------------------------------------------------------------------------
// Export honesty
// ---------------------------------------------------------------------------

#[test]
fn a_bundle_carrying_tainted_exhaust_forces_the_structural_placeholder_only() {
    let (_tmp, vault) = temp_vault();
    register(&vault, SECRET, VALUE_V1);

    let tainted = artifact_id(0x61);
    put_artifact(
        &vault,
        &tainted,
        &BlobArtifactBody::new("build.log", "text/plain")
            .with_secret_taint_refs(vec![taint(SECRET, 0)]),
    );
    let clean = artifact_id(0x62);
    put_artifact(
        &vault,
        &clean,
        &BlobArtifactBody::new("readme.txt", "text/plain"),
    );

    assert!(!export_bundle_carries_tainted_exhaust(&vault, &[clean]).expect("clean bundle"));
    assert!(
        export_bundle_carries_tainted_exhaust(&vault, &[clean, tainted]).expect("mixed bundle")
    );

    let base = ExportSecretsNulledManifest::from_redacted(false);
    let clean_bundle =
        secrets_nulled_for_export_bundle(&vault, base, &[clean]).expect("clean bundle manifest");
    assert!(!clean_bundle.structural_placeholders());
    assert!(!clean_bundle.payloads());

    let tainted_bundle = secrets_nulled_for_export_bundle(&vault, base, &[clean, tainted])
        .expect("tainted bundle manifest");
    assert!(
        tainted_bundle.structural_placeholders(),
        "tainted exhaust serializes nulled with the structural placeholder"
    );
    assert!(
        !tainted_bundle.payloads(),
        "the new ctor does NOT force payload nulling: one tainted artifact must not redact a whole export"
    );
    assert!(
        ExportManifest::from_secrets_nulled(tainted_bundle).structurally_secret_nulled(),
        "the manifest reflects the placeholders"
    );

    // A caller who ASKED for a redacted export still gets one.
    let redacted = secrets_nulled_for_export_bundle(
        &vault,
        ExportSecretsNulledManifest::from_redacted(true),
        &[clean],
    )
    .expect("redacted bundle");
    assert!(redacted.payloads() && redacted.structural_placeholders());

    // State-INDEPENDENT: rotating does not change the bundle's shape.
    vault
        .rotate_secret(SECRET, VALUE_V2, AT_ROTATED)
        .expect("rotate");
    assert_eq!(
        vault.artifact_taint_state(&tainted).expect("state"),
        ArtifactTaintState::TaintedStale
    );
    assert!(
        secrets_nulled_for_export_bundle(&vault, base, &[tainted])
            .expect("still nulled")
            .structural_placeholders(),
        "stale taint nulls exactly as live taint does — an export leaves the vault either way"
    );

    whole_vault_export_manifest_artifact_for_bundle(&vault, base, &[clean, tainted])
        .expect("the bundle manifest assembles");
}

// ---------------------------------------------------------------------------
// The grep-guard (S1 idiom): no value bytes in this plane, anywhere
// ---------------------------------------------------------------------------

#[test]
fn no_value_bytes_reach_the_receipt_or_the_taint_ref() {
    let (_tmp, vault) = temp_vault();
    register(&vault, SECRET, VALUE_V1);
    let receipt = vault
        .rotate_secret(SECRET, VALUE_V2, AT_ROTATED)
        .expect("rotate");

    let value_v1 = String::from_utf8_lossy(VALUE_V1).into_owned();
    let value_v2 = String::from_utf8_lossy(VALUE_V2).into_owned();

    // Debug output.
    let debug = format!("{receipt:?}");
    assert!(!debug.contains(&value_v1), "receipt Debug: {debug}");
    assert!(!debug.contains(&value_v2), "receipt Debug: {debug}");
    assert!(!debug.contains("value_bytes"), "receipt Debug: {debug}");

    let taint_debug = format!("{:?}", taint(SECRET, 1));
    assert!(!taint_debug.contains(&value_v1));
    assert!(!taint_debug.contains(&value_v2));
    assert!(!taint_debug.contains("value_bytes"));

    // The durable wire bodies.
    let receipt_row = row_bytes(
        &vault,
        format!(
            "{SECRET_ROTATION_RECEIPT_PREFIX}{}",
            receipt.receipt_id.to_hex()
        )
        .as_bytes(),
    )
    .expect("receipt row");
    for needle in [VALUE_V1, VALUE_V2, b"value_bytes".as_slice()] {
        assert!(
            !receipt_row.windows(needle.len()).any(|w| w == needle),
            "the receipt row carries no value bytes"
        );
    }

    let id = artifact_id(0x71);
    vault
        .mark_artifact_tainted(&id, &[taint(SECRET, 1)])
        .expect("attach");
    let taint_row = row_bytes(
        &vault,
        format!("{SECRET_EXHAUST_TAINT_PREFIX}{}", id.to_hex()).as_bytes(),
    )
    .expect("taint row");
    for needle in [VALUE_V1, VALUE_V2, b"value_bytes".as_slice()] {
        assert!(
            !taint_row.windows(needle.len()).any(|w| w == needle),
            "the taint row carries no value bytes"
        );
    }
}
