//! FIX TEXT-READ-HANDLE-ANALYZER-MISMATCH: a handle refuses text reads, and
//! its rebuild pass indexes nothing, once another process has restamped the
//! text index under another analyzer.
//!
//! Since FIX ANALYZER-BUMP-AUTO-REINDEX an open whose analyzer differs from
//! the stored stamp clears the text index, stamps it with its own analyzer,
//! and its housekeeping pass indexes every document again. A handle that
//! another process opened before that keeps its own analyzer. Its queries
//! would then be tokenized under one analyzer against postings built under
//! another, with no error, and its own pass would index under its analyzer
//! into the other analyzer's index. Each text read and each rebuild page now
//! compares the handle's stamp with the stored one in its own transaction,
//! and refuses on any difference.
//!
//! The other analyzer here comes from a dictionary root: a Chinese jieba
//! dictionary turns the zh lane from portable to native, which changes the
//! analyzer manifest hash. One process holds one store per directory, so the
//! other handle runs in a second process.
#![cfg(oneiron_test_support)]

use oneiron::edge::EdgeActorClass;
use oneiron::housekeeping::HousekeepingBudget;
use oneiron::test_doors::text_index_rebuild as door;
use oneiron::write_envelope::WriteActor;
use oneiron::{EntityId, Error, Vault, VaultConfig};
use std::path::{Path, PathBuf};
use std::process::Command;

/// One NOTE per word: words no seeded text holds, so a search for one finds
/// its NOTE alone.
const WORDS: [&str; 3] = ["quillwort", "sandpiper", "tamarisk"];

/// The test [`open_under_other_analyzer`] runs in a second process.
const OTHER_ANALYZER_TEST: &str = "other_analyzer_process_opens_the_vault";
/// The vault directory the second process opens.
const OTHER_ANALYZER_VAULT_DIR: &str = "ONEIRON_TEST_OTHER_ANALYZER_VAULT_DIR";
/// The dictionary root the second process's analyzer loads.
const OTHER_ANALYZER_DICT_ROOT: &str = "ONEIRON_TEST_OTHER_ANALYZER_DICT_ROOT";
/// Set when the second process runs the housekeeping pass after its open.
const OTHER_ANALYZER_RUNS_PASS: &str = "ONEIRON_TEST_OTHER_ANALYZER_RUNS_PASS";

fn open(path: &Path) -> Vault {
    Vault::open(path, VaultConfig::default()).expect("open vault")
}

/// A dictionary root holding a jieba dictionary, under `dir`.
fn zh_dict_root(dir: &Path) -> PathBuf {
    let root = dir.join("dicts");
    std::fs::create_dir_all(root.join("zh")).expect("dictionary dir");
    std::fs::write(
        root.join("zh").join("jieba.dict.utf8"),
        "研究 100 n\n東京 90 n\n",
    )
    .expect("dictionary bytes");
    root
}

fn write_notes(vault: &Vault, words: &[&str]) -> Vec<EntityId> {
    let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let notes = words
        .iter()
        .map(|word| {
            vault
                .create_note("research", &format!("field notes on {word}"), actor)
                .expect("NOTE")
        })
        .collect();
    vault.set_indexed_idle_delay_ms(0).expect("idle delay row");
    let published = vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .expect("idle publication");
    assert!(
        published.failed.is_empty(),
        "the NOTEs publish at idle: {published:?}"
    );
    notes
}

fn assert_each_found_once(vault: &Vault, words: &[&str], notes: &[EntityId]) {
    for (word, note) in words.iter().zip(notes) {
        let found: Vec<EntityId> = vault
            .search_text(word, 10)
            .expect("text search")
            .into_iter()
            .map(|hit| hit.id)
            .collect();
        assert_eq!(
            found.iter().filter(|id| *id == note).count(),
            1,
            "{word:?} finds its NOTE once: {found:?}"
        );
    }
}

/// `read` refused because the stored stamp is another analyzer's.
fn assert_refused<T>(read: oneiron::Result<T>, what: &str) {
    match read {
        Err(Error::CorruptedIndex(reason)) => assert!(
            reason.contains("another analyzer"),
            "{what} names the other analyzer: {reason}"
        ),
        Err(error) => panic!("{what} refuses as CorruptedIndex, not {error:?}"),
        Ok(_) => panic!("{what} refuses as CorruptedIndex; it answered"),
    }
}

/// A text read and a recall run over the text arm on `vault`, both refused.
fn assert_text_reads_refused(vault: &Vault, when: &str) {
    assert_refused(
        vault.search_text(WORDS[0], 10),
        &format!("a text read {when}"),
    );
    assert_refused(
        vault
            .query()
            .search_text(WORDS[0], 10)
            .limit(10)
            .run_with_telemetry(),
        &format!("a recall run over the text arm {when}"),
    );
}

/// Opens the vault at `path` in a second process under the analyzer that
/// `dict_root` gives, which runs the housekeeping pass too with `run_pass`,
/// while this process keeps its own handle open.
fn open_under_other_analyzer(path: &Path, dict_root: &Path, run_pass: bool) {
    let mut command = Command::new(std::env::current_exe().expect("the test binary"));
    command
        .args([
            OTHER_ANALYZER_TEST,
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(OTHER_ANALYZER_VAULT_DIR, path)
        .env(OTHER_ANALYZER_DICT_ROOT, dict_root);
    if run_pass {
        command.env(OTHER_ANALYZER_RUNS_PASS, "1");
    } else {
        command.env_remove(OTHER_ANALYZER_RUNS_PASS);
    }
    let output = command.output().expect("start the second process");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "the second process ran its open: {}\nstdout:\n{stdout}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The second process [`open_under_other_analyzer`] starts. With no vault
/// named, in a normal run, it returns at once.
#[test]
fn other_analyzer_process_opens_the_vault() {
    let (Some(dir), Some(dict_root)) = (
        std::env::var_os(OTHER_ANALYZER_VAULT_DIR),
        std::env::var_os(OTHER_ANALYZER_DICT_ROOT),
    ) else {
        return;
    };
    let mut config = VaultConfig::default();
    config.dict_search_paths = vec![PathBuf::from(dict_root)];
    let vault = Vault::open(Path::new(&dir), config).expect("open under the other analyzer");
    if std::env::var_os(OTHER_ANALYZER_RUNS_PASS).is_none() {
        assert!(
            door::text_index_rebuild_progress(&vault)
                .expect("marker read")
                .is_some(),
            "the other analyzer's open restamped the index and started a rebuild"
        );
        return;
    }
    vault
        .housekeeping(HousekeepingBudget::unbounded())
        .expect("housekeeping pass");
    assert_eq!(
        door::text_index_rebuild_progress(&vault).expect("marker read"),
        None,
        "the other analyzer's pass ended the rebuild"
    );
    for word in WORDS {
        assert_eq!(
            vault.search_text(word, 10).expect("text search").len(),
            1,
            "the handle under the stamped analyzer finds the NOTE for {word:?}"
        );
    }
}

/// A handle opened before another analyzer's open restamped the index
/// refuses its text reads while that rebuild stands and after it ends.
/// Reopening it, as the refusal says, restores its reads.
#[test]
fn a_handle_refuses_text_reads_once_another_analyzer_restamps_the_index() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("vault");
    let dict_root = zh_dict_root(dir.path());
    let vault = open(&path);
    let notes = write_notes(&vault, &WORDS);
    assert_each_found_once(&vault, &WORDS, &notes);

    open_under_other_analyzer(&path, &dict_root, false);
    assert_text_reads_refused(&vault, "during the other analyzer's rebuild");

    open_under_other_analyzer(&path, &dict_root, true);
    assert_text_reads_refused(&vault, "after the other analyzer's pass");

    drop(vault);
    let vault = open(&path);
    vault
        .housekeeping(HousekeepingBudget::unbounded())
        .expect("housekeeping pass");
    assert_each_found_once(&vault, &WORDS, &notes);
}

/// A handle opened before another analyzer's open restamped the index
/// indexes nothing into it: its rebuild pass refuses and leaves the rebuild
/// to the stamped analyzer, whose pass then ends it.
#[test]
fn a_handle_under_another_analyzer_indexes_nothing_into_the_index() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("vault");
    let dict_root = zh_dict_root(dir.path());
    let vault = open(&path);
    write_notes(&vault, &WORDS);

    open_under_other_analyzer(&path, &dict_root, false);
    let standing = door::text_index_rebuild_progress(&vault)
        .expect("marker read")
        .expect("the other analyzer's rebuild stands");
    assert_eq!(standing.0, 0, "nothing is indexed again yet");

    assert_refused(
        door::run_text_index_rebuild_pages(&vault, 256, 1),
        "the rebuild pass of a handle under another analyzer",
    );
    vault
        .housekeeping(HousekeepingBudget::unbounded())
        .expect("housekeeping runs its other sweeps");
    assert_eq!(
        door::text_index_rebuild_progress(&vault).expect("marker read"),
        Some(standing),
        "the handle's housekeeping indexed nothing"
    );
    assert_eq!(
        door::text_index_row_counts(&vault).expect("row counts"),
        [0; 5],
        "no posting was written under this handle's analyzer"
    );

    open_under_other_analyzer(&path, &dict_root, true);
}
