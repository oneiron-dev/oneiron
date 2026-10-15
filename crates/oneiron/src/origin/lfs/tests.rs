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

#[cfg(unix)]
#[test]
fn lfs_staging_symlink_never_spools_outside_the_vault() {
    use std::os::unix::fs::symlink;
    let (dir, vault) = open_test_vault_with(embedding_test_config());
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), dir.path().join("lfs-staging")).unwrap();
    let bytes = b"staging symlink containment";
    assert!(
        vault
            .put_lfs_object(LfsOid::digest(bytes), bytes, test_time(), LEARNED_AT)
            .is_err()
    );
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn lfs_staging_follows_the_open_root_after_rename_not_its_old_path() {
    let (dir, vault) = open_test_vault_with(embedding_test_config());
    let original = dir.path().to_path_buf();
    let moved = original.with_extension("moved-vault");
    std::fs::rename(&original, &moved).unwrap();
    std::fs::create_dir(&original).unwrap();
    let bytes = b"root replacement containment";
    let result = vault.put_lfs_object(LfsOid::digest(bytes), bytes, test_time(), LEARNED_AT);
    let inside = moved.join("lfs-staging").is_dir();
    let outside = original.join("lfs-staging").exists();
    std::fs::remove_dir_all(&original).unwrap();
    std::fs::rename(&moved, &original).unwrap();
    assert!(
        result.is_ok(),
        "upload remains bound to opened root: {result:?}"
    );
    assert!(inside);
    assert!(!outside);
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
