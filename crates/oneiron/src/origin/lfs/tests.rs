//! Inline contract suite: digest/round-trip, put/dedup/refusal, fail-closed corruption, ref attach/detach, admission mapping.

use super::*;

use crate::error::ErrorKind;

use crate::test_util::{embedding_test_config, open_test_vault_with};

const LEARNED_AT: u64 = 1_700_000_000;

fn test_time() -> TimeRange {
    TimeRange {
        start: LEARNED_AT,
        end: LEARNED_AT,
    }
}

fn repo_id() -> EntityId {
    lfs_repo_id("a".repeat(64).as_str()).expect("repo id")
}

fn pointer_lines(oid: LfsOid, size: u64) -> Vec<Vec<u8>> {
    vec![
        b"version https://git-lfs.github.com/spec/v1".to_vec(),
        format!("oid sha256:{}", oid.to_hex()).into_bytes(),
        format!("size {size}").into_bytes(),
    ]
}

/// Replaces one ASSET entity's stored bytes THROUGH the raw store, which is
/// what real corruption looks like: no write path validated it, and the
/// lookup row still claims the original digest and length.
fn overwrite_stored_bytes(vault: &Vault, asset_id: EntityId, body: &[u8]) {
    let payload = crate::test_util::entity_record(ENTITY_TYPE_ASSET, test_time(), LEARNED_AT, body);
    vault
        .with_write_txn(|wtxn| {
            vault
                .store
                .entities
                .put(wtxn, asset_id.as_bytes(), &payload)?;
            Ok(())
        })
        .expect("overwrite stored asset bytes");
}

/// A policy that answers one fixed class, so an admission row proves the
/// mapping and not the default.
struct FixedPolicy(LfsAssetClass);

impl LfsPathPolicy for FixedPolicy {
    fn classify(&self, _repo_id: EntityId, _path: &str) -> Result<LfsAssetClass> {
        Ok(self.0)
    }
}

#[test]
fn lfs_oid_digest_matches_sha256() {
    let bytes = b"vault lfs object bytes";
    let expected = Sha256::digest(bytes);
    let oid = LfsOid::digest(bytes);
    assert_eq!(
        oid.as_bytes().as_slice(),
        AsRef::<[u8]>::as_ref(&expected),
        "digest is plain SHA-256"
    );

    let hex = oid.to_hex();
    assert_eq!(hex.len(), VAULT_LFS_OID_HEX_LEN);
    assert!(
        hex.chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character)),
        "to_hex is 64 lowercase hex characters"
    );
    assert_eq!(LfsOid::parse_hex(&hex).expect("round trip"), oid);
    assert_eq!(
        LfsOid::parse_hex(&hex.to_uppercase()).expect("uppercase parses"),
        oid
    );

    assert_eq!(
        LfsOid::parse_hex(&hex[..VAULT_LFS_OID_HEX_LEN - 1])
            .expect_err("short oid is refused")
            .kind(),
        ErrorKind::InvalidLfsObject
    );
    let mut non_hex = hex;
    non_hex.replace_range(0..1, "z");
    assert_eq!(
        LfsOid::parse_hex(&non_hex)
            .expect_err("non-hex oid is refused")
            .kind(),
        ErrorKind::InvalidLfsObject
    );
}

#[test]
fn lfs_put_writes_asset_and_lookup_row_once() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let bytes = b"one upload writes one object".to_vec();
    let oid = LfsOid::digest(&bytes);

    let outcome = vault
        .put_lfs_object(oid, &bytes, test_time(), LEARNED_AT)
        .expect("first upload");
    assert!(!outcome.deduplicated, "the first upload stores bytes");
    assert_eq!(outcome.object.oid, oid);
    assert_eq!(
        outcome.object.size_bytes,
        u64::try_from(bytes.len()).expect("length fits u64")
    );
    assert_eq!(outcome.object.created_at, LEARNED_AT);
    assert_eq!(
        outcome.object.asset_id,
        lfs_asset_entity_id(&oid).expect("deterministic asset id"),
        "the asset id is derived from the oid under the LFS domain"
    );

    let record = vault.lfs_object(oid).expect("record read").expect("record");
    assert_eq!(record, outcome.object, "the row carries the whole record");
    assert_eq!(
        vault
            .entities_by_type(ENTITY_TYPE_ASSET)
            .expect("scan assets"),
        vec![record.asset_id],
        "exactly one ASSET entity exists, and it is this object's"
    );
    assert_eq!(
        vault.get(&record.asset_id).expect("asset read"),
        Some(bytes.clone()),
        "the bytes are an ordinary ASSET entity"
    );
    assert_eq!(
        vault.get_lfs_object(oid).expect("download"),
        Some(bytes),
        "the object reads back byte-exact"
    );
}

#[test]
fn lfs_put_rejects_expected_oid_mismatch_without_writing() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let bytes = b"the bytes that were actually sent".to_vec();
    let claimed = LfsOid::digest(b"different bytes entirely");

    let refused = vault
        .put_lfs_object(claimed, &bytes, test_time(), LEARNED_AT)
        .expect_err("a body that is not the declared oid is refused");
    assert_eq!(refused.kind(), ErrorKind::InvalidLfsObject);

    assert_eq!(
        vault.lfs_object(claimed).expect("record read"),
        None,
        "no lookup row exists after the refusal"
    );
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_ASSET)
            .expect("scan assets")
            .is_empty(),
        "no ASSET entity exists after the refusal"
    );
    assert_eq!(
        vault
            .lfs_object(LfsOid::digest(&bytes))
            .expect("record read"),
        None,
        "and the real digest was not stored either"
    );
}

#[test]
fn lfs_put_rejects_size_mismatch_without_writing() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let bytes = b"twenty nine bytes of body ok!".to_vec();
    let oid = LfsOid::digest(&bytes);
    let declared = u64::try_from(bytes.len()).expect("length fits u64") + 1;

    // The shared gate the HTTP upload route runs before it ever calls the
    // engine: a declared size that disagrees with the body fails here.
    let refused = check_lfs_expectation(oid, Some(declared), &bytes)
        .expect_err("a declared size that disagrees is refused");
    assert_eq!(refused.kind(), ErrorKind::InvalidLfsObject);
    assert!(
        check_lfs_expectation(
            oid,
            Some(u64::try_from(bytes.len()).expect("length fits u64")),
            &bytes
        )
        .is_ok(),
        "the agreeing size passes the same gate"
    );

    assert_eq!(
        vault.lfs_object(oid).expect("record read"),
        None,
        "the refusal happened before any write"
    );
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_ASSET)
            .expect("scan assets")
            .is_empty(),
        "and no ASSET entity was created"
    );
}

#[test]
fn lfs_put_dedup_second_upload_is_one_object() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let bytes = b"identical bytes uploaded twice".to_vec();
    let oid = LfsOid::digest(&bytes);

    let first = vault
        .put_lfs_object(oid, &bytes, test_time(), LEARNED_AT)
        .expect("first upload");
    let second = vault
        .put_lfs_object(oid, &bytes, test_time(), LEARNED_AT + 60)
        .expect("second upload");

    assert!(!first.deduplicated);
    assert!(second.deduplicated, "the second upload stores nothing");
    assert_eq!(first.object, second.object, "one durable record survives");
    assert_eq!(
        vault
            .entities_by_type(ENTITY_TYPE_ASSET)
            .expect("scan assets"),
        vec![first.object.asset_id],
        "two identical uploads are one ASSET entity"
    );
    assert_eq!(
        second.object.created_at, LEARNED_AT,
        "the record keeps its original first-seen stamp"
    );
    assert_eq!(
        vault.get_lfs_object(oid).expect("download"),
        Some(bytes),
        "and the bytes are still exactly the uploaded bytes"
    );
}

#[test]
fn lfs_get_and_verify_fail_closed_on_corrupt_body() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let bytes = b"bytes that will be tampered with".to_vec();
    let size = u64::try_from(bytes.len()).expect("length fits u64");
    let oid = LfsOid::digest(&bytes);
    let record = vault
        .put_lfs_object(oid, &bytes, test_time(), LEARNED_AT)
        .expect("upload")
        .object;
    assert!(vault.verify_lfs_object(oid, size).expect("verify"));

    // Same length, one flipped byte: only a re-hash can catch this.
    let mut flipped = bytes.clone();
    flipped[0] ^= 0xff;
    overwrite_stored_bytes(&vault, record.asset_id, &flipped);
    assert_eq!(
        vault
            .get_lfs_object(oid)
            .expect_err("a flipped body never reads back as success")
            .kind(),
        ErrorKind::CorruptedIndex
    );
    assert_eq!(
        vault
            .verify_lfs_object(oid, size)
            .expect_err("and verify refuses it too")
            .kind(),
        ErrorKind::CorruptedIndex
    );

    // Truncated: the length check catches it before the hash does.
    overwrite_stored_bytes(&vault, record.asset_id, &bytes[..bytes.len() - 1]);
    assert_eq!(
        vault
            .get_lfs_object(oid)
            .expect_err("a truncated body never reads back as success")
            .kind(),
        ErrorKind::CorruptedIndex
    );
    assert_eq!(
        vault
            .verify_lfs_object(oid, size)
            .expect_err("and verify refuses it too")
            .kind(),
        ErrorKind::CorruptedIndex
    );
}

#[test]
fn lfs_attach_and_detach_ref_rows() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let bytes = b"bytes two refs both reference".to_vec();
    let oid = LfsOid::digest(&bytes);
    vault
        .put_lfs_object(oid, &bytes, test_time(), LEARNED_AT)
        .expect("upload");
    let repo = repo_id();

    vault
        .attach_lfs_object_to_git_ref(repo, "refs/heads/main", oid, LEARNED_AT)
        .expect("attach to main");
    vault
        .attach_lfs_object_to_git_ref(repo, "refs/heads/release", oid, LEARNED_AT)
        .expect("attach to release");
    assert_eq!(
        vault
            .lfs_git_ref_objects(repo, "refs/heads/main")
            .expect("read main rows"),
        vec![oid]
    );

    assert_eq!(
        vault
            .detach_lfs_objects_from_git_ref(repo, "refs/heads/main")
            .expect("detach main"),
        1,
        "detach reports the rows it removed"
    );
    assert!(
        vault
            .lfs_git_ref_objects(repo, "refs/heads/main")
            .expect("read main rows")
            .is_empty(),
        "that ref's rows are gone"
    );
    assert_eq!(
        vault
            .lfs_git_ref_objects(repo, "refs/heads/release")
            .expect("read release rows"),
        vec![oid],
        "another ref's attachment survives"
    );
    assert_eq!(
        vault.get_lfs_object(oid).expect("download"),
        Some(bytes),
        "and detaching never deletes shared bytes"
    );

    assert_eq!(
        vault
            .detach_lfs_objects_from_git_ref(repo, "refs/heads/release")
            .expect("detach release"),
        1
    );
    assert!(
        vault.lfs_object(oid).expect("record read").is_some(),
        "the object outlives its last attachment: this is not a collector"
    );
}

#[test]
fn lfs_admission_build_required_returns_keep_in_git() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let repo = repo_id();
    let bytes = b"a build input that stays in git".to_vec();
    let oid = LfsOid::digest(&bytes);
    let size = u64::try_from(bytes.len()).expect("length fits u64");
    let pointer =
        LfsPushedPointer::from_pointer_lines("tools/toolchain.tar.gz", &pointer_lines(oid, size))
            .expect("a pointer file parses");
    let intent = pointer.intent(repo);

    assert_eq!(
        vault
            .admit_lfs_pointer(&FixedPolicy(LfsAssetClass::BuildRequired), &intent)
            .expect("classify"),
        LfsAdmission::KeepInGit
    );
    assert_eq!(LfsAssetClass::BuildRequired.as_str(), "build-required");
    assert_eq!(LfsAdmission::KeepInGit.as_str(), "keep-in-git");
    assert!(
        vault
            .lfs_git_ref_objects(repo, "refs/heads/main")
            .expect("read rows")
            .is_empty(),
        "classification alone never writes a durable ref attachment"
    );
}

#[test]
fn lfs_admission_repository_large_returns_store_in_lfs() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let repo = repo_id();
    // A one-byte body and a large declared size classify the SAME way:
    // there is no size threshold anywhere in this module.
    let small = LfsPushedPointer::from_pointer_lines(
        "assets/tiny.bin",
        &pointer_lines(LfsOid::digest(b"x"), 1),
    )
    .expect("pointer parses")
    .intent(repo);
    let large = LfsPushedPointer::from_pointer_lines(
        "assets/huge.bin",
        &pointer_lines(LfsOid::digest(b"y"), 8_000_000_000),
    )
    .expect("pointer parses")
    .intent(repo);

    let policy = DefaultRepositoryLargeLfsPathPolicy;
    for intent in [&small, &large] {
        assert_eq!(
            vault.admit_lfs_pointer(&policy, intent).expect("classify"),
            LfsAdmission::StoreInLfs
        );
    }
    assert_eq!(LfsAssetClass::RepositoryLarge.as_str(), "repository-large");
    assert_eq!(LfsAdmission::StoreInLfs.as_str(), "store-in-lfs");

    // The pointer grammar is a conjunction: ordinary content that merely
    // mentions an oid is not a pointer, and neither is a truncated one.
    assert!(
        LfsPushedPointer::from_pointer_lines(
            "src/main.rs",
            &[
                format!("oid sha256:{}", LfsOid::digest(b"x").to_hex()).into_bytes(),
                b"fn main() {}".to_vec(),
            ],
        )
        .is_none(),
        "a source file that mentions an oid is not a pointer"
    );
    assert!(
        LfsPushedPointer::from_pointer_lines(
            "assets/tiny.bin",
            &[b"version https://git-lfs.github.com/spec/v1".to_vec()],
        )
        .is_none(),
        "a pointer without oid and size is not a pointer"
    );
    assert_eq!(
        LfsPushedPointer::from_pointer_lines(
            "assets/tiny.bin",
            &[
                format!("oid sha256:{}", LfsOid::digest(b"x").to_hex()).into_bytes(),
                b"size 1".to_vec(),
            ],
        )
        .expect("a modified pointer parses from its changed fields alone")
        .size_bytes,
        1
    );
}
