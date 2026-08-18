use super::*;
use crate::codebase::{CodebaseFileEntry, CodebaseSnapshot, RepoRef};
use crate::secret_custody::{
    CustodyClass, CustodyTier, SECRET_CUSTODY_SCHEMA_VERSION, SecretBinding, SecretCustodyFloor,
    SecretCustodyRecord, SecretCustodyStatus,
};

fn snapshot(files: Vec<CodebaseFileEntry>) -> CodebaseSnapshot {
    CodebaseSnapshot::new(
        "project.alpha",
        RepoRef::parse("github:oneiron-dev/oneiron#9d561405a81ffbf29d1369cd848e0ef9fca4f277")
            .unwrap(),
        Some("9d561405a81ffbf29d1369cd848e0ef9fca4f277".to_owned()),
        files,
    )
    .unwrap()
}

#[test]
fn unreadable_files_are_quarantined() -> crate::Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let snap = snapshot(vec![CodebaseFileEntry::new("src/lib.rs", [1; 32], 1)]);
    let txn = vault.store.env.read_txn()?;
    let (files, report) = vault.apply_custody_to_snapshot(&txn, &snap, &|_| None)?;
    assert!(files.is_empty());
    assert_eq!(report.quarantined_paths, ["src/lib.rs"]);
    Ok(())
}

#[test]
fn detected_files_are_quarantined_without_value() -> crate::Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let token = b"ghp_0123456789abcdefghijklmnopqrstuvwxyz".to_vec();
    let snap = snapshot(vec![CodebaseFileEntry::new(
        ".env",
        *blake3::hash(&token).as_bytes(),
        token.len() as u64,
    )]);
    let txn = vault.store.env.read_txn()?;
    let (files, report) = vault.apply_custody_to_snapshot(&txn, &snap, &|_| Some(token.clone()))?;
    assert!(files.is_empty());
    assert_eq!(report.quarantined_paths, [".env"]);
    assert_eq!(
        report.proposals[0].detector_reason,
        "gate.secret_scan.github_token"
    );
    assert!(!format!("{report:?}").contains("ghp_"));
    Ok(())
}

#[test]
fn universal_raw_put_retains_a_hash_bound_safe_fixture() -> crate::Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let content = b"pub fn safe() {}".to_vec();
    let snap = snapshot(vec![CodebaseFileEntry::new(
        "src/lib.rs",
        *blake3::hash(&content).as_bytes(),
        content.len() as u64,
    )]);
    let txn = vault.store.env.read_txn()?;
    let (files, report) =
        vault.apply_custody_to_snapshot(&txn, &snap, &|_| Some(content.clone()))?;
    assert_eq!(files, snap.files);
    assert_eq!(report, SnapshotCustodyReport::default());
    Ok(())
}

#[test]
fn hash_mismatch_is_quarantined_without_proposal() -> crate::Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let snap = snapshot(vec![CodebaseFileEntry::new("src/lib.rs", [1; 32], 1)]);
    let txn = vault.store.env.read_txn()?;
    let (files, report) = vault.apply_custody_to_snapshot(&txn, &snap, &|_| Some(vec![2]))?;
    assert!(files.is_empty());
    assert_eq!(report.quarantined_paths, ["src/lib.rs"]);
    assert!(report.proposals.is_empty());
    Ok(())
}

#[test]
fn relative_declared_path_does_not_suffix_match_root_file() {
    let mut exclusions = SnapshotExclusionSet::default();
    exclusions.declared_paths.insert("src/lib.rs".to_owned());

    assert!(!exclusions.excludes("lib.rs", &[0; 32], Some("/workspace/repo")));
}

#[test]
fn relative_declared_path_does_not_suffix_match_root_dotenv() {
    let mut exclusions = SnapshotExclusionSet::default();
    exclusions.declared_paths.insert("config/.env".to_owned());

    assert!(!exclusions.excludes(".env", &[0; 32], Some("/workspace/repo")));
}

#[test]
fn absolute_declared_path_excludes_repo_relative_manifest_entry() -> crate::Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let content = b"registered secret bytes".to_vec();
    let snap = snapshot(vec![CodebaseFileEntry::new(
        ".secrets/api.key",
        *blake3::hash(&content).as_bytes(),
        content.len() as u64,
    )]);
    let mut exclusions = SnapshotExclusionSet::default();
    exclusions
        .declared_paths
        .insert("/workspace/repo/.secrets/api.key".to_owned());
    assert!(exclusions.excludes(
        ".secrets/api.key",
        &snap.files[0].content_hash,
        Some("/workspace/repo")
    ));
    let txn = vault.store.env.read_txn()?;
    let (files, report) =
        vault.apply_custody_to_snapshot(&txn, &snap, &|_| Some(content.clone()))?;
    assert_eq!(
        files, snap.files,
        "unregistered paths remain materializable"
    );
    assert!(report.excluded_secret_paths.is_empty());
    Ok(())
}

#[test]
fn absolute_declared_path_from_another_root_is_inert() {
    let mut exclusions = SnapshotExclusionSet::default();
    // A same-named file in an unrelated checkout, and a root whose name merely
    // shares a prefix, must both stop matching: no bare suffix matching.
    exclusions
        .declared_paths
        .insert("/elsewhere/other-repo/.secrets/api.key".to_owned());
    exclusions
        .declared_paths
        .insert("/workspace/repository/.secrets/api.key".to_owned());

    assert!(!exclusions.excludes(".secrets/api.key", &[0; 32], Some("/workspace/repo")));
}

#[test]
fn absolute_declared_paths_anchor_files_and_directories_under_root() {
    let mut exclusions = SnapshotExclusionSet::default();
    exclusions
        .declared_paths
        .insert("/workspace/repo/.secrets".to_owned());
    exclusions
        .declared_paths
        .insert("/workspace/repo/config/prod.env".to_owned());

    let root = Some("/workspace/repo");
    assert!(exclusions.excludes(".secrets", &[0; 32], root), "directory");
    assert!(
        exclusions.excludes(".secrets/api.key", &[0; 32], root),
        "declared directory excludes its children"
    );
    assert!(
        exclusions.excludes("config/prod.env", &[0; 32], root),
        "anchored file"
    );
    assert!(
        !exclusions.excludes(".secretsx/api.key", &[0; 32], root),
        "directory match stops at a path boundary"
    );
}

#[test]
fn unanchored_absolute_declaration_falls_back_to_hash_only() {
    let mut exclusions = SnapshotExclusionSet::default();
    exclusions
        .declared_paths
        .insert("/workspace/repo/.secrets/api.key".to_owned());

    // No local root (hosted repo_ref): the absolute declaration cannot be
    // resolved against this manifest, so only the registered hash excludes.
    assert!(!exclusions.excludes(".secrets/api.key", &[0; 32], None));
    exclusions.registered_hashes.insert([7; 32]);
    assert!(exclusions.excludes(".secrets/api.key", &[7; 32], None));
}

#[test]
fn absolute_t2_registration_excludes_relative_snapshot_entry_after_recovery() -> crate::Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = crate::Vault::open(temp_dir.path(), crate::config::VaultConfig::default())?;
    let target_path = temp_dir.path().join(".secrets/api.key");
    std::fs::create_dir_all(target_path.parent().expect("target parent"))?;
    let content = b"t2-registered-secret-fixture".to_vec();
    vault.register_secret(SecretCustodyRecord {
        schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
        name: "snapshot-t2".to_owned(),
        class: CustodyClass::CustodyPortable,
        device_only: false,
        value_bytes: content.clone(),
        status: SecretCustodyStatus::Active,
        registered_at: 1,
        rotated_at: None,
        rotation_generation: 0,
        bindings: vec![SecretBinding {
            effector: "connector:snapshot-test".to_owned(),
            tier_ceiling: CustodyTier::T2LocalRegistered,
            scopes: vec!["read".to_owned()],
        }],
        manifest_ref: "secrets.toml".to_owned(),
        declared_paths: vec![target_path.to_string_lossy().into_owned()],
        policy_floor_snapshot: SecretCustodyFloor::default(),
    })?;
    let lease = vault.materialize_secret_lease("snapshot-t2", "connector:snapshot-test", 60)?;
    vault.register_secret_local(&lease.lease.lease_id, &target_path, "project.alpha")?;

    // Recovery re-materializes the same absolute registration, which must
    // still exclude the repository-relative manifest entry by path and hash.
    std::fs::remove_file(&target_path)?;
    vault.register_secret_local(&lease.lease.lease_id, &target_path, "project.alpha")?;
    let snap = snapshot(vec![CodebaseFileEntry::new(
        ".secrets/api.key",
        *blake3::hash(&content).as_bytes(),
        content.len() as u64,
    )]);
    let txn = vault.store.env.read_txn()?;
    let (files, report) =
        vault.apply_custody_to_snapshot(&txn, &snap, &|_| Some(content.clone()))?;
    assert!(files.is_empty());
    assert_eq!(report.excluded_secret_paths, [".secrets/api.key"]);
    Ok(())
}
