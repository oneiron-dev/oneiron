//! ONE-218: `Vault::open_existing`, the fail-closed existing-only open door,
//! exercised strictly through the public API.
//!
//! `Vault::open` remains the only door that creates a vault. This one refuses
//! anything that is not already an initialized vault root — and refuses it
//! without bringing one into existence — then serves the ordinary vault APIs
//! once every persisted identity comparison has passed.
//!
//! Linux-only, and deliberately so: the door binds the root as a directory
//! descriptor and opens LMDB through `/proc/self/fd/<dirfd>`, and it fails
//! closed rather than falling back to the pathname where that is unavailable.
//! The module is registered under the same target gate in `main.rs`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use oneiron::registry::ENTITY_TYPE_SUMMARY;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

use crate::common::entity as test_id;

/// Device-shaped, with a test-sized map so each fixture vault reserves a few
/// megabytes of address space rather than a gigabyte.
fn existing_only_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.max_readers = 16;
    config
}

fn entry_count(path: &Path) -> usize {
    std::fs::read_dir(path).expect("readable directory").count()
}

/// A trusted dictionary root: the Chinese analyzer probes
/// `<root>/zh/jieba.dict.utf8`, so these bytes are hashed into the vault's
/// persisted analyzer manifest and naming the root is the only way to reopen a
/// vault built over it.
fn trusted_dict_root(dir: &Path) -> PathBuf {
    let root = dir.join("trusted-dicts");
    std::fs::create_dir_all(root.join("zh")).expect("dict dir");
    let dict = root.join("zh").join("jieba.dict.utf8");
    std::fs::write(dict, "研究 100 n\n東京 90 n\n").expect("dict bytes");
    root
}

/// Creates the fixture vault and leaves one text-indexed entity behind, closed.
fn seed_vault(path: &Path, config: VaultConfig) -> EntityId {
    let vault = Vault::open(path, config).expect("fixture vault opens");
    let id = test_id(0x5B);
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_SUMMARY,
            TimeRange { start: 1, end: 1 },
            1,
            b"payload",
        )
        .text(&id, &[("body", "existing only open fixture")])
        .commit()
        .expect("fixture text commits");
    id
}

/// An absent path is refused without being brought into existence. The
/// create-capable door would have created the directory and a whole vault in
/// it, so "nothing is here afterwards" is the discriminating fact.
#[test]
fn open_existing_refuses_an_absent_path_and_creates_nothing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let absent = temp.path().join("absent-root");

    let refused = Vault::open_existing(&absent, existing_only_config());

    assert!(refused.is_err(), "an absent path must refuse");
    assert!(!absent.exists(), "the absent path must not be created");
    assert_eq!(entry_count(temp.path()), 0);
}

/// An empty directory — a mistyped or pre-created `--vault` — is refused and
/// keeps zero entries: no `data.mdb`, no `lock.mdb`, nothing.
#[test]
fn open_existing_refuses_an_empty_directory_and_leaves_it_empty() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("empty-root");
    std::fs::create_dir(&root).expect("empty directory");

    let refused = Vault::open_existing(&root, existing_only_config());

    assert!(refused.is_err(), "an empty directory must refuse");
    assert_eq!(entry_count(&root), 0, "nothing may be created in it");
}

/// An ordinary directory of unrelated files is never mistaken for a vault
/// root, and a half-written root — one LMDB file without its pair — is refused
/// rather than completed.
#[test]
fn open_existing_refuses_unrelated_and_half_written_roots() {
    let temp = tempfile::tempdir().expect("tempdir");
    let unrelated = temp.path().join("unrelated");
    std::fs::create_dir(&unrelated).expect("unrelated directory");
    std::fs::write(unrelated.join("notes.txt"), b"not a vault").expect("note file");
    let half = temp.path().join("half-written");
    std::fs::create_dir(&half).expect("half-written directory");
    std::fs::write(half.join("data.mdb"), b"").expect("lone data file");

    assert!(Vault::open_existing(&unrelated, existing_only_config()).is_err());
    assert_eq!(entry_count(&unrelated), 1);
    assert!(Vault::open_existing(&half, existing_only_config()).is_err());
    assert_eq!(entry_count(&half), 1, "the missing pair is not created");
}

/// The happy path: a valid vault reopens through the existing-only door and
/// serves the ordinary read APIs.
#[test]
fn open_existing_opens_a_valid_vault_and_serves_normal_apis() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("vault");
    let id = seed_vault(&root, existing_only_config());

    let vault = Vault::open_existing(&root, existing_only_config()).expect("existing vault opens");

    let hits = vault.search_text("existing", 10).expect("text search");
    assert!(
        hits.iter().any(|hit| hit.id == id),
        "the seeded doc is found"
    );
    assert!(vault.get(&id).expect("entity read").is_some());
    let doctor = vault.doctor().expect("doctor");
    assert!(doctor.storage_abi_version.is_some());
    assert!(doctor.db_manifest.missing_names.is_empty());
}

/// The custom-dictionary happy path: a vault whose analyzer identity comes from
/// operator-supplied dictionary bytes reopens when — and only when — those
/// exact roots are named again. The wrong-root leg proves the exact-match leg
/// is doing work rather than accepting anything.
#[test]
fn open_existing_opens_an_exact_match_custom_dictionary_vault() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("vault");
    let mut config = existing_only_config();
    config.dict_search_paths = vec![trusted_dict_root(temp.path())];
    let id = seed_vault(&root, config.clone());
    let mut wrong = config.clone();
    wrong.dict_search_paths = vec![temp.path().join("other-dicts")];
    std::fs::create_dir(temp.path().join("other-dicts")).expect("other dict dir");

    assert!(
        Vault::open_existing(&root, wrong).is_err(),
        "a dictionary root that is not this vault's must refuse"
    );
    let vault =
        Vault::open_existing(&root, config).expect("the exact dictionary roots reopen the vault");

    assert!(vault.get(&id).expect("entity read").is_some());
}

/// Every entry name in `root` with that entry's exact bytes.
fn root_snapshot(root: &Path) -> BTreeMap<std::ffi::OsString, Vec<u8>> {
    std::fs::read_dir(root)
        .expect("readable root")
        .map(|entry| {
            let entry = entry.expect("readable directory entry");
            let bytes = std::fs::read(entry.path()).expect("readable entry bytes");
            (entry.file_name(), bytes)
        })
        .collect()
}

/// A directory holding two PRE-CREATED ZERO-LENGTH LMDB files is refused, and
/// both files are still zero bytes afterwards.
///
/// This is the one shape a read-write LMDB open would quietly adopt: it
/// `ftruncate`s and initializes a zero-length `lock.mdb` and writes both meta
/// pages into a zero-length `data.mdb`. The door that must never create would
/// have created — so "both files are still empty, and the directory holds
/// nothing else" is the whole assertion.
#[test]
fn open_existing_refuses_a_precreated_empty_lmdb_pair_and_creates_nothing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("precreated-empty-pair");
    std::fs::create_dir(&root).expect("root");
    std::fs::write(root.join("data.mdb"), b"").expect("empty data file");
    std::fs::write(root.join("lock.mdb"), b"").expect("empty lock file");
    let before = root_snapshot(&root);
    assert_eq!(before.len(), 2);
    assert!(before.values().all(std::vec::Vec::is_empty));

    let refused = Vault::open_existing(&root, existing_only_config());

    assert!(refused.is_err(), "a pre-created empty pair must refuse");
    assert_eq!(
        root_snapshot(&root),
        before,
        "both files must be byte-identical and nothing may be added",
    );
    assert_eq!(entry_count(&root), 2);
}

/// A pair whose bytes are not an LMDB environment is refused just as firmly,
/// and each half is proved separately: one fixture pairs a headerless
/// `data.mdb` with a genuine `lock.mdb`, the other a genuine `data.mdb` with a
/// zero-length `lock.mdb`.
#[test]
fn open_existing_refuses_headerless_lmdb_pairs_and_creates_nothing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let real = temp.path().join("real-vault");
    seed_vault(&real, existing_only_config());

    let headerless_data = temp.path().join("headerless-data");
    std::fs::create_dir(&headerless_data).expect("root");
    std::fs::copy(real.join("lock.mdb"), headerless_data.join("lock.mdb")).expect("real lock file");
    std::fs::write(
        headerless_data.join("data.mdb"),
        b"not an lmdb data file".repeat(512),
    )
    .expect("headerless data file");

    let empty_lock = temp.path().join("empty-lock");
    std::fs::create_dir(&empty_lock).expect("root");
    std::fs::copy(real.join("data.mdb"), empty_lock.join("data.mdb")).expect("real data file");
    std::fs::write(empty_lock.join("lock.mdb"), b"").expect("empty lock file");

    for root in [&headerless_data, &empty_lock] {
        let before = root_snapshot(root);
        let refused = Vault::open_existing(root, existing_only_config());
        assert!(
            refused.is_err(),
            "{}: an incomplete LMDB pair must refuse",
            root.display(),
        );
        assert_eq!(
            root_snapshot(root),
            before,
            "{}: a refused root must be byte-identical afterwards",
            root.display(),
        );
    }
}
