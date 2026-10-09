use super::*;
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::config::VaultConfig;
use crate::edge::EdgeActorClass;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::secret_custody::{
    CustodyClass, CustodyTier, SECRET_CUSTODY_SCHEMA_VERSION, SecretBinding, SecretCustodyFloor,
    SecretCustodyRecord, SecretCustodyStatus,
};
use crate::secret_lease::SecretTaintRef;
use crate::secret_rotation::mark_exhaust_tainted_in_txn;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

mod hit_metadata;

fn path(value: &str) -> DeclaredOutputPath {
    DeclaredOutputPath::parse(value).expect("canonical path")
}

fn key(action: &BuildAction) -> ActionKey {
    action.action_key().expect("key")
}

fn action() -> BuildAction {
    BuildAction::new(
        FrozenBuildCommand::new(vec!["cc".into(), "main.c".into()], [("A", "1"), ("B", "2")])
            .expect("command"),
        BuildInputRoot {
            repo_ref: RepoRef::parse(&format!("local:/source#{}", "a".repeat(40))).expect("repo"),
            fork_hash: [1; 32],
            extra_inputs: vec![
                ExtraInputDigest::new([2; 32]),
                ExtraInputDigest::new([3; 32]),
            ],
        },
        BuildPlatform::new([("arch", "arm64"), ("os", "linux")]).expect("platform"),
        vec![path("out/a"), path("out/b")],
    )
    .expect("action")
}

fn result(reference: ArtifactVersionRef) -> ActionResult {
    ActionResult {
        exit_code: 7,
        outputs: BTreeMap::from([(path("out/a"), reference.clone())]),
        stdout_ref: Some(reference),
        stderr_ref: None,
        produced_at: 42,
        producer_ref: "executor:first".into(),
    }
}

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

fn artifact(vault: &Vault, bytes: &[u8]) -> ArtifactVersionRef {
    let id = EntityId::now();
    let at = TimeRange { start: 10, end: 10 };
    vault
        .put_blob_artifact(
            &id,
            &BlobArtifactBody::new("build.bin", "application/octet-stream"),
            at,
            10,
        )
        .expect("put artifact");
    let actor_id = EntityId::now();
    vault
        .put_entity(&actor_id, ENTITY_TYPE_PERSON, at, 10, b"uploader")
        .expect("put actor");
    let version = vault
        .append_blob_artifact_version(
            &id,
            bytes,
            &BlobVersionProvenance::UserUpload,
            WriteActor::new(actor_id, EdgeActorClass::Human),
            at,
            11,
        )
        .expect("append version");
    ArtifactVersionRef::new(id, version.version).expect("version ref")
}

fn sample_record() -> CachedActionResult {
    let id = EntityId::from_bytes([0x12; 16]).expect("id");
    CachedActionResult {
        action_key: action().action_key().expect("key"),
        result: result(ArtifactVersionRef::new(id, 1).expect("ref")),
        referenced_bytes: 5,
    }
}

fn raw_row(vault: &Vault, key: &ActionKey) -> Option<Vec<u8>> {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    vault
        .store
        .vault_meta
        .get(&rtxn, &BUILD_CACHE_REAPI_ROW.key_bytes(key.as_bytes()))
        .expect("read row")
        .map(|bytes| bytes.to_vec())
}

fn forge_row(record: &CachedActionResult, change: impl FnOnce(&mut BuildCacheRowV1)) -> Vec<u8> {
    let encoded = encode_build_cache_row(record).expect("encode row");
    let mut row: BuildCacheRowV1 = rmp_serde::from_slice(&encoded[1..]).expect("row body");
    change(&mut row);
    let mut bytes = vec![BUILD_CACHE_SCHEMA_VERSION_V1];
    bytes.extend(rmp_serde::to_vec(&row).expect("forge body"));
    bytes
}

fn mark_live(vault: &Vault, reference: &ArtifactVersionRef) {
    vault
        .register_secret(SecretCustodyRecord {
            schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
            name: "build-token".into(),
            class: CustodyClass::CustodyPortable,
            device_only: false,
            value_bytes: b"wave6-rotation-test-value-v1".to_vec(),
            status: SecretCustodyStatus::Active,
            registered_at: 1_700_000_000,
            rotated_at: None,
            rotation_generation: 0,
            bindings: vec![SecretBinding {
                effector: "connector:test".into(),
                tier_ceiling: CustodyTier::T1Leased,
                scopes: vec!["read".into()],
            }],
            manifest_ref: "secrets.toml".into(),
            declared_paths: vec![".secrets/api.key".into()],
            policy_floor_snapshot: SecretCustodyFloor::default(),
        })
        .expect("register secret");
    let mut wtxn = vault.store.env.write_txn().expect("write txn");
    mark_exhaust_tainted_in_txn(
        &vault.store,
        &mut wtxn,
        reference.artifact_id(),
        &[SecretTaintRef {
            secret_ref: "build-token".into(),
            generation: 0,
        }],
    )
    .expect("mark taint");
    wtxn.commit().expect("commit taint");
    assert_eq!(
        vault
            .artifact_taint_state(reference.artifact_id())
            .expect("state"),
        ArtifactTaintState::TaintedLive
    );
}

#[test]
fn artifact_ref_round_trip_is_canonical() {
    let id = "1234567890abcdef1234567890abcdef";
    let canonical = format!("{id}@1");
    let reference = ArtifactVersionRef::parse(&canonical).expect("ref");
    assert_eq!(reference.to_result_ref(), canonical);
    assert_eq!(reference.version(), 1);
    assert_eq!(reference.artifact_id().to_hex(), id);
    for bad in [
        format!("blob:{id}@1"),
        format!("{}@1", id.to_uppercase()),
        format!("{id}@0"),
        format!(" {id}@1"),
        format!("{id}@1 "),
        format!("{id}@@1"),
        format!("{id}@1@2"),
        format!("{id}@01"),
        format!("{id}@+1"),
        format!("{id}@-1"),
        format!("{id}@1x"),
        format!("{id}@18446744073709551616"),
        format!("{id}@"),
        format!("{}@1", "0".repeat(32)),
    ] {
        assert!(
            matches!(
                ArtifactVersionRef::parse(&bad),
                Err(BuildCacheError::InvalidArtifactRef(_))
            ),
            "{bad}"
        );
    }
    assert!(matches!(
        ArtifactVersionRef::new(*reference.artifact_id(), 0),
        Err(BuildCacheError::InvalidArtifactRef(_))
    ));
    let maximum = format!("{id}@{}", u64::MAX);
    let parsed = ArtifactVersionRef::parse(&maximum).expect("max version");
    assert_eq!(parsed.to_result_ref(), maximum);
}

#[test]
fn row_starts_with_schema_version() {
    let record = sample_record();
    let bytes = encode_build_cache_row(&record).expect("encode");
    assert_eq!(bytes[0], 2);
    let decoded = decode_build_cache_row(&bytes).expect("decode");
    assert_eq!(decoded, record);
    let key = BUILD_CACHE_REAPI_ROW.key_bytes(record.action_key.as_bytes());
    assert_eq!(
        &key[..BUILD_CACHE_KEY_PREFIX_V1.len()],
        b"build_cache:reapi:v2:"
    );
    assert_eq!(
        &key[BUILD_CACHE_KEY_PREFIX_V1.len()..],
        record.action_key.as_bytes()
    );
}

#[test]
fn unknown_schema_version_is_typed() {
    let record = sample_record();
    let mut bytes = encode_build_cache_row(&record).expect("encode");
    bytes[0] = 3;
    assert!(matches!(
        decode_build_cache_row(&bytes),
        Err(BuildCacheError::UnknownSchemaVersion { found: 3 })
    ));
}

#[test]
fn row_key_mismatch_is_corrupt() {
    let record = sample_record();
    let bytes = encode_build_cache_row(&record).expect("encode");
    let decoded = decode_build_cache_row(&bytes).expect("decode");
    assert!(matches!(
        verify_action_key(&ActionKey([9; 32]), &decoded),
        Err(BuildCacheError::CorruptRecord(_))
    ));
}

#[test]
fn tainted_live_result_is_refused() {
    let (_dir, vault) = temp_vault();
    let reference = artifact(&vault, b"tainted build");
    let action = action();
    let cache = BuildCache::new(&vault);
    cache
        .put(&action, result(reference.clone()))
        .expect("store clean");
    mark_live(&vault, &reference);
    assert!(matches!(cache.get(&key(&action)),
        Err(BuildCacheError::TaintedResult { artifact_ref }) if artifact_ref == reference.to_result_ref()));
    let mut other_action = action;
    other_action.input_root.fork_hash[0] ^= 1;
    assert!(matches!(
        cache.put(&other_action, result(reference)),
        Err(BuildCacheError::TaintedResult { .. })
    ));
    assert!(raw_row(&vault, &key(&other_action)).is_none());
}

#[test]
fn tainted_stale_result_is_refused() {
    let (_dir, vault) = temp_vault();
    let reference = artifact(&vault, b"stale build");
    let action = action();
    let cache = BuildCache::new(&vault);
    cache
        .put(&action, result(reference.clone()))
        .expect("store clean");
    mark_live(&vault, &reference);
    vault
        .rotate_secret(
            "build-token",
            b"wave6-rotation-test-value-v2",
            1_700_000_500,
        )
        .expect("rotate");
    assert_eq!(
        vault
            .artifact_taint_state(reference.artifact_id())
            .expect("state"),
        ArtifactTaintState::TaintedStale
    );
    assert!(matches!(
        cache.get(&key(&action)),
        Err(BuildCacheError::TaintedResult { .. })
    ));
    let mut other_action = action;
    other_action.input_root.fork_hash[0] ^= 1;
    assert!(matches!(
        cache.put(&other_action, result(reference)),
        Err(BuildCacheError::TaintedResult { .. })
    ));
    assert!(raw_row(&vault, &key(&other_action)).is_none());
}

#[test]
fn taint_after_insert_tombstones_get_and_put() {
    let (_dir, vault) = temp_vault();
    let reference = artifact(&vault, b"initially clean");
    let action = action();
    let key = key(&action);
    let cache = BuildCache::new(&vault);
    assert_eq!(
        vault
            .artifact_taint_state(reference.artifact_id())
            .expect("state"),
        ArtifactTaintState::Clean
    );
    cache
        .put(&action, result(reference.clone()))
        .expect("store");
    let before = raw_row(&vault, &key).expect("row");
    mark_live(&vault, &reference);
    assert!(matches!(
        cache.get(&key),
        Err(BuildCacheError::TaintedResult { .. })
    ));
    let clean_proposal = result(artifact(&vault, b"replacement cannot repair tombstone"));
    assert!(matches!(
        cache.put(&action, clean_proposal),
        Err(BuildCacheError::TaintedResult { .. })
    ));
    assert_eq!(raw_row(&vault, &key).expect("row"), before);
}

#[test]
fn action_key_encoding_golden_vector() {
    let mut action = action();
    action.command =
        FrozenBuildCommand::new(vec!["true".into()], BTreeMap::<String, String>::new()).unwrap();
    action.platform = BuildPlatform::new(BTreeMap::<String, String>::new()).unwrap();
    action.declared_outputs.clear();
    action = action.with_reapi_input_root(ReapiDigest::of(b""));
    assert_eq!(action.reapi_command_bytes(), b"\x0a\x04true");
    assert_eq!(
        action.action_key().unwrap().to_hex(),
        "054435d0a7573cc13cb737477406ab0e34801a7563531631746e21edead1a3e8"
    );
}

#[test]
fn noncanonical_output_order_is_rejected() {
    let record = sample_record();
    let bytes = forge_row(&record, |row| {
        let reference = row.outputs[0].1.clone();
        row.outputs = vec![
            ("out/b".into(), reference.clone()),
            ("out/a".into(), reference),
        ];
    });
    assert!(matches!(
        decode_build_cache_row(&bytes),
        Err(BuildCacheError::CorruptRecord(_))
    ));
}

#[test]
fn duplicate_output_key_is_rejected() {
    let record = sample_record();
    let bytes = forge_row(&record, |row| row.outputs.push(row.outputs[0].clone()));
    assert!(matches!(
        decode_build_cache_row(&bytes),
        Err(BuildCacheError::CorruptRecord(_))
    ));
}

#[test]
fn malformed_rows_fail_typed_including_integer_overflow() {
    let record = sample_record();
    let valid = encode_build_cache_row(&record).expect("encode");
    let mut trailing = valid.clone();
    trailing.push(0);
    let mut malformed = vec![vec![], vec![2], vec![2, 0xc1], trailing];
    for end in 2..valid.len() {
        malformed.push(valid[..end].to_vec());
    }
    malformed.push(forge_row(&record, |row| row.producer_ref.clear()));
    malformed.push(forge_row(&record, |row| row.outputs[0].0 = "out//a".into()));
    malformed.push(forge_row(&record, |row| {
        row.outputs[0].1 = "invalid@1".into();
    }));
    malformed.push(forge_row(&record, |row| {
        row.stdout_ref = Some("invalid@1".into());
    }));
    malformed.push(forge_row(&record, |row| {
        row.stderr_ref = Some("invalid@1".into());
    }));
    // Forge integers outside each Rust field's range, without narrowing casts.
    for (index, value) in [
        (1, rmpv::Value::from(i64::MAX)),
        (5, rmpv::Value::from(-1)),
        (7, rmpv::Value::from(-1)),
    ] {
        let mut body = rmpv::decode::read_value(&mut Cursor::new(&valid[1..])).expect("body");
        let rmpv::Value::Array(fields) = &mut body else {
            panic!("array");
        };
        fields[index] = value;
        let mut bytes = vec![2];
        rmpv::encode::write_value(&mut bytes, &body).expect("encode malformed integer");
        malformed.push(bytes);
    }
    for bytes in malformed {
        assert!(
            matches!(
                decode_build_cache_row(&bytes),
                Err(BuildCacheError::CorruptRecord(_))
            ),
            "{bytes:?}"
        );
    }
}

#[test]
fn deleted_artifact_tombstones_get_and_put_without_changing_row() {
    let (_dir, vault) = temp_vault();
    let reference = artifact(&vault, b"deleted output");
    let action = action();
    let cache = BuildCache::new(&vault);
    let key = key(&action);
    cache
        .put(&action, result(reference.clone()))
        .expect("store");
    let before = raw_row(&vault, &key).expect("row");
    vault
        .delete_entity_with_options(
            reference.artifact_id(),
            crate::deletion::DeleteEntityOptions { purge: true },
        )
        .expect("delete artifact");
    assert!(matches!(
        cache.get(&key),
        Err(BuildCacheError::ArtifactUnavailable { .. })
    ));
    assert!(matches!(
        cache.put(&action, result(artifact(&vault, b"replacement"))),
        Err(BuildCacheError::ArtifactUnavailable { .. })
    ));
    assert_eq!(raw_row(&vault, &key).expect("row"), before);
}

#[test]
fn account_members_share_hits_with_provenance_but_other_tenants_refuse() {
    let (_a, a) = temp_vault();
    let (_b, b) = temp_vault();
    let (_c, account) = temp_vault();
    for vault in [&a, &b, &account] {
        BuildCache::bind_account(vault, "account-A").unwrap();
    }
    let first = BuildCache::for_account(&a, &account, "account-A").unwrap();
    let second = BuildCache::for_account(&b, &account, "account-A").unwrap();
    let output = result(artifact(first.artifact_vault(), b"shared"));
    first.put(&action(), output.clone()).unwrap();
    assert_eq!(second.get(&key(&action())).unwrap().unwrap().result, output);
    assert!(matches!(
        BuildCache::for_account(&b, &account, "account-B"),
        Err(BuildCacheError::AccountMismatch)
    ));
    assert!(matches!(
        BuildCache::bind_account(&b, "account-B"),
        Err(BuildCacheError::AccountMismatch)
    ));
}
