//! FIX ANALYZER-BUMP-AUTO-REINDEX: an analyzer change no longer blocks text
//! search behind a manual recovery.
//!
//! An `ANALYZER_VERSION` bump or a `NormalizationPolicy` flag change moves the
//! analyzer manifest hash, and a BM25F field change moves the field-schema
//! hash. Before the fix a populated vault then failed closed at `Vault::open`
//! (`IncompatibleAnalyzer` / `Bm25FieldSchemaChanged`) until its host reopened
//! it with the manifest check skipped, cleared the text index, reopened and
//! indexed every document again. Now the open clears the index itself and
//! the housekeeping pass, the host's own tick, indexes every document again
//! from the text it was indexed with, the most recently written first. While
//! it runs, text reads answer from the documents indexed again so far and
//! say so (ruling ANALYZER-REINDEX-SEARCH-DURING-REBUILD = B).
#![cfg(oneiron_test_support)]

use oneiron::edge::EdgeActorClass;
use oneiron::housekeeping::HousekeepingBudget;
use oneiron::note::{NoteProgramEdit, NoteProgramEditOutcome};
use oneiron::retrieval_quality::RetrievalDegradation;
use oneiron::test_doors::text_index_rebuild as door;
use oneiron::write_envelope::WriteActor;
use oneiron::{EntityId, Vault, VaultConfig};
use std::path::Path;
use std::process::Command;

/// One NOTE per word: words no seeded text holds, so a search for one finds
/// its NOTE alone.
const WORDS: [&str; 5] = [
    "quillwort",
    "sandpiper",
    "tamarisk",
    "wolframite",
    "zeolitic",
];

fn open(path: &Path) -> Vault {
    Vault::open(path, VaultConfig::default()).expect("open vault")
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

/// The hits for `word`, by id.
fn hits(vault: &Vault, word: &str) -> Vec<EntityId> {
    vault
        .search_text(word, 10)
        .expect("text search")
        .into_iter()
        .map(|hit| hit.id)
        .collect()
}

fn assert_each_found_once(vault: &Vault, words: &[&str], notes: &[EntityId]) {
    for (word, note) in words.iter().zip(notes) {
        let found = hits(vault, word);
        assert_eq!(
            found.iter().filter(|id| *id == note).count(),
            1,
            "{word:?} finds its NOTE once: {found:?}"
        );
    }
}

/// A text read while a rebuild stands: it answers from the documents indexed
/// again so far, and its quality names the stale text arm. The hits for
/// `word`, by id.
fn partial_hits(vault: &Vault, word: &str) -> Vec<EntityId> {
    let read = vault
        .search_text_with_telemetry(word, 10)
        .expect("a text read answers while the rebuild stands");
    assert_eq!(
        read.retrieval_quality.degradation,
        [RetrievalDegradation::Bm25Stale],
        "a text read during the rebuild says its text arm is stale"
    );
    read.value.into_iter().map(|hit| hit.id).collect()
}

/// Whether a recall run over the text arm names that arm stale.
fn recall_marks_text_stale(vault: &Vault, word: &str) -> bool {
    vault
        .query()
        .search_text(word, 10)
        .limit(10)
        .run_with_telemetry()
        .expect("recall")
        .retrieval_quality
        .degradation
        .contains(&RetrievalDegradation::Bm25Stale)
}

/// The "rebuilding, N of M" the status and the doctor report show, in their
/// debug form: `Some(TextIndexRebuildProgress { .. })` or `None`.
fn shown_rebuild(vault: &Vault) -> (String, String) {
    let status = format!("{:?}", vault.text_index_status().expect("status"));
    let doctor = format!("{:?}", vault.doctor().expect("doctor"));
    let field = |debug: &str, name: &str| {
        let start = debug
            .find(name)
            .unwrap_or_else(|| panic!("{name} is shown: {debug}"));
        let rest = &debug[start + name.len()..];
        if rest.starts_with("None") {
            return "None".to_owned();
        }
        rest[..rest.find(')').map_or(rest.len(), |end| end + 1)].to_owned()
    };
    (
        field(&status, "rebuild: "),
        field(&doctor, "text_index_rebuild: "),
    )
}

fn progress(done: u64, total: u64) -> (String, String) {
    let shown = format!("Some(TextIndexRebuildProgress {{ done: {done}, total: {total} }})");
    (shown.clone(), shown)
}

/// Appends `words` to `note` as its owner and publishes it, so its content
/// changed last.
fn append_and_publish(vault: &Vault, note: EntityId, words: &str) {
    let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
    let document = vault
        .note_program_document(note)
        .expect("read document")
        .expect("NOTE document");
    let edit = NoteProgramEdit::InsertAfter {
        anchor: document
            .anchor(document.text().chars().count())
            .expect("end anchor"),
        text: words.to_owned(),
    };
    let outcome = vault
        .edit_note(note, &edit, WriteActor::new(owner, EdgeActorClass::Human))
        .expect("the owner edits the NOTE");
    assert!(
        matches!(outcome, NoteProgramEditOutcome::Edited { .. }),
        "the owner's edit lands in place: {outcome:?}"
    );
    let published = vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .expect("idle publication");
    assert!(
        published.failed.is_empty(),
        "the edit publishes at idle: {published:?}"
    );
}

/// A populated vault whose stored stamp says `restamp` built its index.
fn populated_then_restamped(path: &Path, restamp: impl FnOnce(&Vault)) -> Vec<EntityId> {
    let vault = open(path);
    let notes = write_notes(&vault, &WORDS);
    assert_each_found_once(&vault, &WORDS, &notes);
    restamp(&vault);
    notes
}

fn without_myanmar_zawgyi(vault: &Vault) {
    door::restamp_stored_analyzer_manifest(vault, |manifest| {
        assert!(
            manifest.normalization.myanmar_zawgyi,
            "this engine folds Zawgyi"
        );
        manifest.normalization.myanmar_zawgyi = false;
    })
    .expect("restamp the analyzer manifest");
}

#[test]
fn a_policy_flag_change_rebuilds_the_text_index_with_no_manual_step() {
    let dir = tempfile::tempdir().expect("temp dir");
    let notes = populated_then_restamped(dir.path(), without_myanmar_zawgyi);

    let vault = Vault::open(dir.path(), VaultConfig::default())
        .expect("a vault whose analyzer changed opens with no manual step");
    let (done, total) = door::text_index_rebuild_progress(&vault)
        .expect("marker read")
        .expect("the open started a rebuild");
    assert_eq!(done, 0, "nothing is indexed again before the pass");
    assert!(total >= WORDS.len() as u64, "every NOTE waits: {total}");
    assert_eq!(
        door::text_index_row_counts(&vault).expect("row counts"),
        [0; 5],
        "the open cleared every old-analyzer row"
    );
    assert!(
        partial_hits(&vault, WORDS[0]).is_empty(),
        "a text read answers, with no hit yet, before the pass"
    );
    assert!(
        recall_marks_text_stale(&vault, WORDS[0]),
        "recall names its text arm stale while the rebuild stands"
    );
    assert_eq!(
        shown_rebuild(&vault),
        progress(0, total),
        "the status and the doctor show the rebuild"
    );

    vault
        .housekeeping(HousekeepingBudget::unbounded())
        .expect("housekeeping pass");

    assert_eq!(
        door::text_index_rebuild_progress(&vault).expect("marker read"),
        None,
        "the pass ended the rebuild"
    );
    assert_each_found_once(&vault, &WORDS, &notes);
    assert!(
        vault
            .search_text_with_telemetry(WORDS[0], 10)
            .expect("text read")
            .retrieval_quality
            .degradation
            .is_empty(),
        "a text read after the rebuild is whole"
    );
    assert!(!recall_marks_text_stale(&vault, WORDS[0]));
    let none = ("None".to_owned(), "None".to_owned());
    assert_eq!(shown_rebuild(&vault), none, "nothing is shown once it ends");
}

/// The test [`open_in_second_process`] runs in a second process.
const SECOND_PROCESS_TEST: &str = "second_process_opens_the_vault";
/// The vault directory the second process opens.
const SECOND_PROCESS_VAULT_DIR: &str = "ONEIRON_TEST_SECOND_PROCESS_VAULT_DIR";
/// Set when the second process runs the housekeeping pass after its open.
const SECOND_PROCESS_RUNS_PASS: &str = "ONEIRON_TEST_SECOND_PROCESS_RUNS_PASS";

/// Opens the vault at `path` in a second process, which runs the
/// housekeeping pass too with `run_pass`, while this process keeps its own
/// handle open. One process holds one store per directory, so a second
/// handle on a live vault is another process's.
fn open_in_second_process(path: &Path, run_pass: bool) {
    let mut command = Command::new(std::env::current_exe().expect("the test binary"));
    command
        .args([
            SECOND_PROCESS_TEST,
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(SECOND_PROCESS_VAULT_DIR, path);
    if run_pass {
        command.env(SECOND_PROCESS_RUNS_PASS, "1");
    } else {
        command.env_remove(SECOND_PROCESS_RUNS_PASS);
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

/// The second process [`open_in_second_process`] starts. With no vault
/// named, in a normal run, it returns at once.
#[test]
fn second_process_opens_the_vault() {
    let Some(dir) = std::env::var_os(SECOND_PROCESS_VAULT_DIR) else {
        return;
    };
    let vault = open(Path::new(&dir));
    if std::env::var_os(SECOND_PROCESS_RUNS_PASS).is_some() {
        vault
            .housekeeping(HousekeepingBudget::unbounded())
            .expect("housekeeping pass");
        assert_eq!(
            door::text_index_rebuild_progress(&vault).expect("marker read"),
            None,
            "the second process's pass ended the rebuild"
        );
    } else {
        assert!(
            door::text_index_rebuild_progress(&vault)
                .expect("marker read")
                .is_some(),
            "the second process's open started a rebuild"
        );
    }
}

/// A rebuild another process's open starts reaches a handle this process
/// opened before it, at that handle's next text read: the read names its
/// text arm stale.
#[test]
fn a_rebuild_another_process_starts_holds_for_an_open_handle() {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = open(dir.path());
    let notes = write_notes(&vault, &WORDS);
    assert_each_found_once(&vault, &WORDS, &notes);
    without_myanmar_zawgyi(&vault);

    open_in_second_process(dir.path(), false);

    assert!(
        partial_hits(&vault, WORDS[0]).is_empty(),
        "the open handle answers from the cleared index and says so"
    );
    assert!(
        recall_marks_text_stale(&vault, WORDS[0]),
        "recall on the open handle names its text arm stale"
    );
}

/// A rebuild another process's pass ends no longer holds for a handle this
/// process opened while it stood: its next text read finds every document
/// and is whole.
#[test]
fn a_rebuild_another_process_ends_releases_an_open_handle() {
    let dir = tempfile::tempdir().expect("temp dir");
    let notes = populated_then_restamped(dir.path(), without_myanmar_zawgyi);
    open_in_second_process(dir.path(), false);
    let vault = open(dir.path());
    assert!(
        partial_hits(&vault, WORDS[0]).is_empty(),
        "a handle opened while the rebuild stands answers partly and says so"
    );

    open_in_second_process(dir.path(), true);

    assert_each_found_once(&vault, &WORDS, &notes);
    assert!(
        vault
            .search_text_with_telemetry(WORDS[0], 10)
            .expect("text read")
            .retrieval_quality
            .degradation
            .is_empty(),
        "a text read after the other process's pass is whole"
    );
    assert!(!recall_marks_text_stale(&vault, WORDS[0]));
}

#[test]
fn a_field_schema_change_rebuilds_the_text_index_too() {
    let dir = tempfile::tempdir().expect("temp dir");
    let notes = populated_then_restamped(dir.path(), |vault| {
        door::restamp_stored_bm25_field_schema_hash(vault, Some([0x5a; 32]))
            .expect("restamp the field-schema hash");
    });

    let vault = Vault::open(dir.path(), VaultConfig::default())
        .expect("a vault whose BM25F field schema changed opens with no manual step");
    let (done, total) = door::text_index_rebuild_progress(&vault)
        .expect("marker read")
        .expect("the open started a rebuild");
    assert_eq!(done, 0, "nothing is indexed again before the pass");
    assert!(total >= WORDS.len() as u64, "every NOTE waits: {total}");
    assert_eq!(
        door::text_index_row_counts(&vault).expect("row counts"),
        [0; 5],
        "the open cleared every row built under the old field schema"
    );
    vault
        .housekeeping(HousekeepingBudget::unbounded())
        .expect("housekeeping pass");

    assert_eq!(
        door::text_index_rebuild_progress(&vault).expect("marker read"),
        None
    );
    assert_each_found_once(&vault, &WORDS, &notes);
}

#[test]
fn a_rebuild_resumes_after_a_restart_and_keeps_the_writes_made_during_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    let notes = populated_then_restamped(dir.path(), without_myanmar_zawgyi);

    let done_before_restart = {
        let vault = open(dir.path());
        let (reindexed, complete) =
            door::run_text_index_rebuild_pages(&vault, 2, 1).expect("one page of the pass");
        assert!(
            reindexed <= 2,
            "one page indexes two documents again at most"
        );
        assert!(!complete, "the rebuild is left half done");
        let late = write_notes(&vault, &["vermiculite"]);
        assert_eq!(late.len(), 1);
        let (done, _) = door::text_index_rebuild_progress(&vault)
            .expect("marker read")
            .expect("the rebuild still stands");
        assert_eq!(done, 2);
        done
    };

    let vault = open(dir.path());
    let (done, _) = door::text_index_rebuild_progress(&vault)
        .expect("marker read")
        .expect("the reopen keeps the rebuild in flight");
    assert_eq!(
        done, done_before_restart,
        "the reopen resumes the rebuild and does not start it over"
    );
    assert_eq!(
        partial_hits(&vault, WORDS[4]),
        [notes[4]],
        "the page indexed before the restart stays searchable"
    );
    assert!(
        partial_hits(&vault, WORDS[0]).is_empty(),
        "the oldest NOTE waits for a later page"
    );

    vault
        .housekeeping(HousekeepingBudget::unbounded())
        .expect("housekeeping pass");

    assert_eq!(
        door::text_index_rebuild_progress(&vault).expect("marker read"),
        None
    );
    assert_each_found_once(&vault, &WORDS, &notes);
    assert_eq!(
        hits(&vault, "vermiculite").len(),
        1,
        "the NOTE written during the rebuild is found once"
    );
}

#[test]
fn the_rebuild_indexes_the_most_recently_written_documents_first() {
    let dir = tempfile::tempdir().expect("temp dir");
    let notes = {
        let vault = open(dir.path());
        // The order key is the wall-clock millisecond of a document's last
        // write: every row the open and the owner's creation wrote is older
        // than the NOTEs, to the millisecond, and the NOTEs than the edit.
        vault.ensure_embedded_owner_actor().expect("owner actor");
        std::thread::sleep(std::time::Duration::from_millis(50));
        let notes = write_notes(&vault, &WORDS);
        // The oldest NOTE, written again after the others, is now the most
        // recently written: the order is by last write, not by birth.
        std::thread::sleep(std::time::Duration::from_millis(50));
        append_and_publish(&vault, notes[0], " revisited");
        without_myanmar_zawgyi(&vault);
        notes
    };

    let vault = open(dir.path());
    let (reindexed, complete) =
        door::run_text_index_rebuild_pages(&vault, 2, 1).expect("one page of the pass");
    assert_eq!((reindexed, complete), (2, false), "one page of two");
    assert_eq!(
        partial_hits(&vault, WORDS[0]),
        [notes[0]],
        "the NOTE written last is searchable after one page"
    );
    assert_eq!(
        partial_hits(&vault, WORDS[4]),
        [notes[4]],
        "the newest NOTE is searchable after one page"
    );
    for word in &WORDS[1..4] {
        assert!(
            partial_hits(&vault, word).is_empty(),
            "{word:?}, written earlier, waits for a later page"
        );
    }
    let (done, total) = door::text_index_rebuild_progress(&vault)
        .expect("marker read")
        .expect("the rebuild stands");
    assert_eq!(done, 2);
    assert_eq!(shown_rebuild(&vault), progress(2, total));
}

#[test]
fn a_source_row_past_the_text_ceiling_does_not_hold_the_rebuild() {
    let dir = tempfile::tempdir().expect("temp dir");
    let notes = {
        let vault = open(dir.path());
        let notes = write_notes(&vault, &WORDS);
        without_myanmar_zawgyi(&vault);
        door::stretch_source_text_past_ceiling(&vault, &notes[0])
            .expect("stretch the first NOTE's source text");
        notes
    };

    let vault = open(dir.path());
    vault
        .housekeeping(HousekeepingBudget::unbounded())
        .expect("housekeeping pass");

    assert_eq!(
        door::text_index_rebuild_progress(&vault).expect("marker read"),
        None,
        "a document past the text ceiling does not hold the rebuild"
    );
    assert_each_found_once(&vault, &WORDS[1..], &notes[1..]);
    assert!(
        hits(&vault, WORDS[0]).is_empty(),
        "the NOTE past the ceiling stays out of search, as its write door would leave it"
    );
}

#[test]
fn an_unchanged_manifest_reopens_exactly_as_before() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (doctor, counts, notes) = {
        let vault = open(dir.path());
        let notes = write_notes(&vault, &WORDS);
        (
            vault.doctor().expect("doctor"),
            door::text_index_row_counts(&vault).expect("row counts"),
            notes,
        )
    };

    let vault = open(dir.path());
    assert_eq!(vault.doctor().expect("doctor"), doctor);
    assert_eq!(
        door::text_index_row_counts(&vault).expect("row counts"),
        counts,
        "the open cleared nothing"
    );
    assert_eq!(
        door::text_index_rebuild_progress(&vault).expect("marker read"),
        None,
        "the open started no rebuild"
    );
    assert_each_found_once(&vault, &WORDS, &notes);
}

#[test]
fn a_missing_field_schema_hash_still_refuses_the_open() {
    let dir = tempfile::tempdir().expect("temp dir");
    populated_then_restamped(dir.path(), |vault| {
        door::restamp_stored_bm25_field_schema_hash(vault, None)
            .expect("delete the field-schema hash");
    });

    let error = match Vault::open(dir.path(), VaultConfig::default()) {
        Ok(_) => panic!("a partly written stamp is not rebuilt over"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), oneiron::ErrorKind::IncompatibleAnalyzer);
}
