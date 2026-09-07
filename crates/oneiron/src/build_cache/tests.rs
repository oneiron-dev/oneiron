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
        .get(&rtxn, &build_cache_key(key))
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
fn action_key_is_deterministic() {
    let action = action();
    let expected = key(&action);
    assert_eq!(expected.as_bytes().len(), 32);
    for _ in 0..8 {
        assert_eq!(
            ActionKey::derive(&action.clone()).expect("cloned key"),
            expected
        );
    }
}

#[test]
fn env_allowlist_order_is_not_semantic() {
    let original = action();
    let mut reversed = original.clone();
    reversed.command =
        FrozenBuildCommand::new(original.command.argv().to_vec(), [("B", "2"), ("A", "1")])
            .expect("command");
    assert_eq!(key(&original), key(&reversed));
}

#[test]
fn platform_property_order_is_not_semantic() {
    let original = action();
    let mut reversed = original.clone();
    reversed.platform = BuildPlatform::new([("os", "linux"), ("arch", "arm64")]).expect("platform");
    assert_eq!(key(&original), key(&reversed));
}

#[test]
fn declared_output_order_is_not_semantic() {
    let original = action();
    let reversed = BuildAction::new(
        original.command.clone(),
        original.input_root.clone(),
        original.platform.clone(),
        vec![path("out/b"), path("out/a")],
    )
    .expect("action");
    assert_eq!(reversed.declared_outputs(), &[path("out/a"), path("out/b")]);
    assert_eq!(key(&original), key(&reversed));
}

#[test]
fn argv_order_is_semantic() {
    let original = action();
    let mut swapped = original.clone();
    let mut argv = swapped.command.argv().to_vec();
    argv.swap(0, 1);
    swapped.command =
        FrozenBuildCommand::new(argv, original.command.env_allowlist().clone()).expect("command");
    assert_ne!(key(&original), key(&swapped));
}

#[test]
fn each_action_field_changes_the_key() {
    let original = action();
    let expected = key(&original);
    let mut variants = Vec::new();
    let mut changed = original.clone();
    changed.command = FrozenBuildCommand::new(
        vec!["clang".into(), "main.c".into()],
        original.command.env_allowlist().clone(),
    )
    .expect("command");
    variants.push(changed);
    let mut changed = original.clone();
    changed.command = FrozenBuildCommand::new(
        original.command.argv().to_vec(),
        [("A", "different"), ("B", "2")],
    )
    .expect("command");
    variants.push(changed);
    let mut changed = original.clone();
    changed.input_root.repo_ref =
        RepoRef::parse(&format!("local:/other-clone#{}", "a".repeat(40))).expect("repo");
    variants.push(changed);
    let mut changed = original.clone();
    changed.input_root.fork_hash[0] ^= 1;
    variants.push(changed);
    let mut changed = original.clone();
    changed.input_root.extra_inputs[0] = ExtraInputDigest::new([4; 32]);
    variants.push(changed);
    let mut changed = original.clone();
    changed.input_root.extra_inputs.swap(0, 1);
    variants.push(changed);
    let mut changed = original.clone();
    changed.platform = BuildPlatform::new([("arch", "x86_64"), ("os", "linux")]).expect("platform");
    variants.push(changed);
    variants.push(
        BuildAction::new(
            original.command,
            original.input_root,
            original.platform,
            vec![path("out/a"), path("out/c")],
        )
        .expect("action"),
    );
    for changed in variants {
        assert_ne!(key(&changed), expected);
    }
}

#[test]
fn invalid_action_shapes_fail_before_hashing() {
    assert!(matches!(
        FrozenBuildCommand::new(Vec::new(), [("A", "1")]),
        Err(BuildCacheError::InvalidAction(_))
    ));
    assert!(matches!(
        FrozenBuildCommand::new(vec!["cc".into()], [("A", "1"), ("A", "2")]),
        Err(BuildCacheError::InvalidAction(_))
    ));
    assert!(matches!(
        BuildPlatform::new([("os", "a"), ("os", "a")]),
        Err(BuildCacheError::InvalidAction(_))
    ));
    for value in [
        "",
        "/out",
        "out//bin",
        "out/./bin",
        "out\\bin",
        "out/",
        "C:/x",
        "//unc/x",
        ".",
        "..",
        "out/../bin",
        "out/\0bin",
        "drive:x",
    ] {
        assert!(
            matches!(
                DeclaredOutputPath::parse(value),
                Err(BuildCacheError::InvalidOutputPath(_))
            ),
            "{value:?}"
        );
    }
    assert_eq!(path("out/a:b").as_str(), "out/a:b");
    let action = action();
    assert!(matches!(
        BuildAction::new(
            action.command,
            action.input_root,
            action.platform,
            vec![path("out/a"), path("out/a")]
        ),
        Err(BuildCacheError::InvalidAction(_))
    ));
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
    assert_eq!(bytes[0], 1);
    let decoded = decode_build_cache_row(&record.action_key, &bytes).expect("decode");
    assert_eq!(decoded, record);
    let key = build_cache_key(&record.action_key);
    assert_eq!(&key[..BUILD_CACHE_KEY_PREFIX_V1.len()], b"build_cache:v1:");
    assert_eq!(
        &key[BUILD_CACHE_KEY_PREFIX_V1.len()..],
        record.action_key.as_bytes()
    );
}

#[test]
fn unknown_schema_version_is_typed() {
    let record = sample_record();
    let mut bytes = encode_build_cache_row(&record).expect("encode");
    bytes[0] = 2;
    assert!(matches!(
        decode_build_cache_row(&record.action_key, &bytes),
        Err(BuildCacheError::UnknownSchemaVersion { found: 2 })
    ));
}

#[test]
fn row_key_mismatch_is_corrupt() {
    let record = sample_record();
    let bytes = encode_build_cache_row(&record).expect("encode");
    assert!(matches!(
        decode_build_cache_row(&ActionKey([9; 32]), &bytes),
        Err(BuildCacheError::CorruptRecord("action key mismatch"))
    ));
}

#[test]
fn referenced_bytes_are_deduplicated() {
    let (_dir, vault) = temp_vault();
    let reference = artifact(&vault, b"five!");
    let result = result(reference);
    assert_eq!(result.artifact_refs().len(), 1);
    let cache = BuildCache::new(&vault);
    let BuildCachePutOutcome::Stored(record) = cache.put(&action(), result).expect("store") else {
        panic!("expected Stored");
    };
    assert_eq!(record.referenced_bytes, 5);
    assert_eq!(cache.get(&record.action_key).expect("get"), Some(record));
}

#[test]
fn second_put_leaves_raw_row_bytes_unchanged() {
    let (_dir, vault) = temp_vault();
    let cache = BuildCache::new(&vault);
    let action = action();
    let first = result(artifact(&vault, b"first result"));
    cache.put(&action, first.clone()).expect("store");
    let key = key(&action);
    let before = raw_row(&vault, &key).expect("row");
    let mut candidate = result(artifact(&vault, b"second result"));
    candidate.producer_ref = "executor:second".into();
    let BuildCachePutOutcome::Existing(existing) = cache.put(&action, candidate).expect("existing")
    else {
        panic!("expected Existing");
    };
    assert_eq!(existing.result, first);
    assert_eq!(raw_row(&vault, &key).expect("row"), before);
}

#[test]
fn referenced_byte_sum_overflow_is_typed() {
    assert_eq!(
        sum_referenced_bytes([u64::MAX, 0]).expect("exact limit"),
        u64::MAX
    );
    assert_eq!(sum_referenced_bytes([]).expect("empty"), 0);
    assert!(matches!(
        sum_referenced_bytes([u64::MAX, 1]),
        Err(BuildCacheError::ReferencedBytesOverflow)
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
    let action = BuildAction::new(
        FrozenBuildCommand::new(vec!["x".into()], [("A", "b")]).expect("command"),
        BuildInputRoot {
            repo_ref: RepoRef::LocalFolder {
                path: "r".into(),
                commit: "0".repeat(40),
            },
            fork_hash: [0x11; 32],
            extra_inputs: vec![ExtraInputDigest::new([0x22; 32])],
        },
        BuildPlatform::new([("p", "v")]).expect("platform"),
        vec![path("o")],
    )
    .expect("action");
    // Hand-derived grammar, not encoder-captured bytes. RepoRef is 48 bytes.
    let expected = [
        0x01, 0x01, 0x02, 0, 0, 0, 1, 0, 0, 0, 1, b'x', 0x03, 0, 0, 0, 1, 0, 0, 0, 1, b'A', 0, 0,
        0, 1, b'b', 0x04, 0, 0, 0, 48, b'l', b'o', b'c', b'a', b'l', b':', b'r', b'#', b'0', b'0',
        b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0',
        b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0',
        b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', 0x05, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x06, 0, 0, 0, 1, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x07, 0, 0, 0, 1, 0, 0, 0, 1, b'p', 0, 0, 0, 1, b'v', 0x08, 0, 0, 0, 1, 0, 0, 0, 1,
        b'o',
    ];
    let mut bytes = Vec::new();
    encode_action_v1(&mut bytes, &action).expect("encode");
    assert_eq!(bytes, expected);
    assert_eq!(
        ActionKey::derive(&action).expect("key").to_hex(),
        "ddefb27ce842230e9d925d84b4e07252e74d57f59c8b2d2b4d8800b012568745"
    );
}

#[test]
fn undeclared_output_is_rejected() {
    let (_dir, vault) = temp_vault();
    let cache = BuildCache::new(&vault);
    let action = action();
    let reference = artifact(&vault, b"output");
    let mut proposed = result(reference.clone());
    proposed.outputs.insert(path("undeclared"), reference);
    assert!(matches!(cache.put(&action, proposed.clone()),
        Err(BuildCacheError::UndeclaredOutput { path }) if path == "undeclared"));
    assert!(raw_row(&vault, &key(&action)).is_none());
    proposed.outputs.clear();
    assert!(matches!(
        cache.put(&action, proposed),
        Ok(BuildCachePutOutcome::Stored(_))
    ));
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
        decode_build_cache_row(&record.action_key, &bytes),
        Err(BuildCacheError::CorruptRecord(
            "noncanonical output ordering"
        ))
    ));
}

#[test]
fn duplicate_output_key_is_rejected() {
    let record = sample_record();
    let bytes = forge_row(&record, |row| row.outputs.push(row.outputs[0].clone()));
    assert!(matches!(
        decode_build_cache_row(&record.action_key, &bytes),
        Err(BuildCacheError::CorruptRecord(
            "noncanonical output ordering"
        ))
    ));
}

#[test]
fn noncanonical_repo_ref_is_rejected() {
    let original = action();
    let mut input_root = original.input_root.clone();
    input_root.repo_ref = RepoRef::LocalFolder {
        path: "/source".into(),
        commit: "A".repeat(40),
    };
    assert!(matches!(
        BuildAction::new(
            original.command.clone(),
            input_root.clone(),
            original.platform.clone(),
            original.declared_outputs().to_vec(),
        ),
        Err(BuildCacheError::InvalidAction("noncanonical repo_ref"))
    ));
    let mut mutated = original;
    mutated.input_root = input_root;
    assert!(matches!(
        mutated.action_key(),
        Err(BuildCacheError::InvalidAction("noncanonical repo_ref"))
    ));
    assert!(matches!(
        ActionKey::derive(&mutated),
        Err(BuildCacheError::InvalidAction("noncanonical repo_ref"))
    ));
    mutated.input_root.repo_ref = RepoRef::GitHubAtCommit {
        owner: "owner".into(),
        repo: "repo".into(),
        commit: "not-a-commit".into(),
    };
    assert!(matches!(
        mutated.action_key(),
        Err(BuildCacheError::InvalidAction("noncanonical repo_ref"))
    ));
}

#[test]
fn empty_producer_ref_is_rejected_before_store() {
    let (_dir, vault) = temp_vault();
    let mut proposed = result(artifact(&vault, b"output"));
    proposed.producer_ref.clear();
    assert!(matches!(
        proposed.validate(),
        Err(BuildCacheError::CorruptRecord("empty producer_ref"))
    ));
    let action = action();
    assert!(matches!(
        BuildCache::new(&vault).put(&action, proposed),
        Err(BuildCacheError::CorruptRecord("empty producer_ref"))
    ));
    assert!(raw_row(&vault, &key(&action)).is_none());
}

#[test]
fn malformed_rows_fail_typed_including_integer_overflow() {
    let record = sample_record();
    let valid = encode_build_cache_row(&record).expect("encode");
    let mut trailing = valid.clone();
    trailing.push(0);
    let mut malformed = vec![vec![], vec![1], vec![1, 0xc1], trailing];
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
        let mut bytes = vec![1];
        rmpv::encode::write_value(&mut bytes, &body).expect("encode malformed integer");
        malformed.push(bytes);
    }
    for bytes in malformed {
        assert!(
            matches!(
                decode_build_cache_row(&record.action_key, &bytes),
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
        .delete_entity(reference.artifact_id())
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
