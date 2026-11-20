#![cfg(oneiron_test_support)]
//! `vault.files.sources.search` (census L2-16; ARCH-0027 #files-world:
//! "Search goes by name first and meaning second"). The owner searches the
//! Files world's sources: files whose name or path matches come first, by
//! match class, then files whose text matches in meaning, from the owner's
//! recall of the Files world mapped back to files through the ledger.
//!
//! The fixture is a rooted carrier install (test_doors::steward) that the
//! owner answers is his, so the Files world's "read on this install only"
//! setting has a live machine marked Yours to name; the folder's files are
//! handed to `rescan_folder_source` as a host's walk would, with no walk.
//!
//! The ask's read of the files a question names or a search finds
//! (`files_ask_read`, `vault.files.sources.ask`) is checked here on the same
//! fixture: it reads a file's note only while the note holds the file's text
//! at the revision the ledger names, which its citations name.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test files_search`.

use std::collections::HashMap;

use oneiron::authority::{ActSurface, MachineOwnership, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::MEMORY_CODE_NOT_FOUND;
use oneiron::note::{
    FileFacts, FileHandle, FileReadiness, FolderRescan, ImportedNote, NameMatch, NameOnlyFile,
    NameOnlyReason, NoteProgramEdit, NoteProgramEditOutcome,
};
use oneiron::task_verb::sdk::{
    FilesMeaningState, FilesSearchHit, FilesSearchMatch, FilesSourceAskRequest,
    FilesSourceSearchAnswer, FilesSourceSearchRequest, files_ask_read, search_files_sources_as,
};
use oneiron::test_doors::steward;
use oneiron::{EdgeActorClass, EntityId, Vault, WriteActor};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Maps any error into the test's error with the step that failed.
fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

/// A file the folder holds as text: its path, its Markdown and when it was
/// last written.
type TextFile<'a> = (&'a str, &'a str, u64);

/// A file the folder holds by its name only, and when it was last written.
type NamedFile<'a> = (&'a str, u64);

struct FilesVault {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: AuthenticatedOwner,
    source: EntityId,
    folder: String,
    kind: String,
}

/// A vault whose install is the owner's own machine, with one Files source
/// attached (`/srv/files`, a path the fixture never reads).
fn files_vault() -> TestResult<FilesVault> {
    let dir = tempfile::tempdir()?;
    let vault =
        steward::open_owner_carrier_vault(dir.path()).map_err(at("open the carrier vault"))?;
    let owner = steward::owner(&vault).map_err(at("owner proof"))?;
    let this_install = vault
        .local_machine()
        .map_err(at("read this install"))?
        .ok_or("fixture: this install has no machine id")?
        .id;
    vault
        .set_machine_role(
            &owner,
            ActSurface::ThisInstall,
            this_install,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .map_err(at("the owner answers this install is his"))?;
    let (_world, source) = vault
        .attach_files_source(
            &owner,
            ActSurface::ThisInstall,
            "/srv/files",
            Vec::new(),
            None,
            None,
        )
        .map_err(at("attach the Files source"))?;
    let placed = source
        .files
        .as_ref()
        .map(|files| files.source)
        .ok_or("fixture: no Files placement")?;
    Ok(FilesVault {
        _dir: dir,
        vault,
        owner,
        source: placed,
        folder: source.folder,
        kind: source.kind,
    })
}

impl FilesVault {
    /// One rescan, as a host's whole walk of the folder hands it over:
    /// `new` lands as notes, `named` is held by name only, `missing` left
    /// the folder. The new notes' text is published for search.
    fn rescan(
        &self,
        new: &[TextFile<'_>],
        named: &[NamedFile<'_>],
        missing: &[&str],
    ) -> TestResult {
        let report = self
            .vault
            .rescan_folder_source(
                &self.owner,
                FolderRescan {
                    folder: self.folder.clone(),
                    new: new
                        .iter()
                        .map(|(path, markdown, written_at)| ImportedNote {
                            path: (*path).to_owned(),
                            kind: self.kind.clone(),
                            title: Some((*path).to_owned()),
                            written_at: *written_at,
                            markdown: (*markdown).to_owned(),
                            original: None,
                        })
                        .collect(),
                    links: Vec::new(),
                    present: Vec::new(),
                    name_only: named
                        .iter()
                        .map(|(path, modified_at)| NameOnlyFile {
                            path: (*path).to_owned(),
                            why: NameOnlyReason::Unsupported,
                            facts: FileFacts {
                                bytes: 64,
                                modified_at: *modified_at,
                            },
                            original: None,
                        })
                        .collect(),
                    missing: missing.iter().map(|path| (*path).to_owned()).collect(),
                    raw_hashes: HashMap::new(),
                    facts: new
                        .iter()
                        .map(|(path, markdown, written_at)| {
                            (
                                (*path).to_owned(),
                                FileFacts {
                                    bytes: u64::try_from(markdown.len()).unwrap_or(u64::MAX),
                                    modified_at: *written_at,
                                },
                            )
                        })
                        .collect(),
                    whole: true,
                },
            )
            .map_err(at("rescan the Files source"))?;
        assert_eq!(report.failed, 0, "no file may be refused: {report:?}");
        assert_eq!(
            report.landed,
            new.len(),
            "every text file lands: {report:?}"
        );
        self.vault
            .set_indexed_idle_delay_ms(0)
            .map_err(at("idle delay"))?;
        let published = self
            .vault
            .refresh_staged_indexed_at_idle(u64::MAX)
            .map_err(at("publish the staged text"))?;
        assert!(
            published.failed.is_empty(),
            "every staged text publishes: {published:?}"
        );
        Ok(())
    }

    fn search(&self, query: &str) -> TestResult<FilesSourceSearchAnswer> {
        search_files_sources_as(
            &self.vault,
            &self.owner,
            FilesSourceSearchRequest {
                query: query.to_owned(),
                sources: None,
                limit: None,
                devices: None,
            },
        )
        .map_err(at("search the Files sources"))
    }
}

fn paths(answer: &FilesSourceSearchAnswer) -> Vec<&str> {
    answer
        .hits
        .iter()
        .map(|hit| hit.handle.path.as_str())
        .collect()
}

fn hit<'a>(answer: &'a FilesSourceSearchAnswer, path: &str) -> TestResult<&'a FilesSearchHit> {
    answer
        .hits
        .iter()
        .find(|hit| hit.handle.path == path)
        .ok_or_else(|| format!("no hit for {path}: {:?}", paths(answer)).into())
}

#[test]
fn files_search_ranks_name_first_then_meaning() -> TestResult {
    let files = files_vault()?;
    files.rescan(
        &[(
            "notes/plan.md",
            "# Plan\n\nWe set the budget for the quarter.\n",
            1_780_000_000,
        )],
        &[("reports/q3-budget.xlsx", 1_780_000_100)],
        &[],
    )?;

    let answer = files.search("budget")?;

    assert_eq!(answer.meaning, FilesMeaningState::Ran, "{answer:?}");
    assert_eq!(
        paths(&answer),
        vec!["reports/q3-budget.xlsx", "notes/plan.md"],
        "the name hit comes before the meaning hit: {answer:?}"
    );
    let named = &answer.hits[0];
    assert_eq!(
        named.matched,
        FilesSearchMatch::Name {
            class: NameMatch::NameWords
        }
    );
    assert_eq!(named.handle.source, files.source);
    let meant = &answer.hits[1];
    assert_eq!(meant.matched, FilesSearchMatch::Meaning { rank: 1 });
    assert!(
        meant.note.is_some(),
        "a meaning hit names its note: {meant:?}"
    );
    assert!(
        meant
            .snippet
            .as_deref()
            .is_some_and(|snippet| snippet.contains("budget")),
        "a meaning hit carries the words recall read: {meant:?}"
    );
    Ok(())
}

#[test]
fn files_search_finds_a_name_only_file_by_name() -> TestResult {
    let files = files_vault()?;
    files.rescan(
        &[(
            "notes/plan.md",
            "# Plan\n\nNothing about money.\n",
            1_780_000_000,
        )],
        &[("reports/q3-budget.xlsx", 1_780_000_100)],
        &[],
    )?;

    let answer = files.search("q3-budget")?;

    let found = hit(&answer, "reports/q3-budget.xlsx")?;
    assert_eq!(
        found.matched,
        FilesSearchMatch::Name {
            class: NameMatch::Exact
        },
        "the name without its extension is the query"
    );
    assert_eq!(
        found.readiness,
        FileReadiness::NameOnly {
            why: NameOnlyReason::Unsupported
        }
    );
    assert_eq!(found.note, None, "a name-only file has no note");
    assert_eq!(found.snippet, None, "a name hit carries no snippet");
    assert_eq!(found.modified_at, Some(1_780_000_100));
    assert_eq!(answer.hits[0].handle.path, "reports/q3-budget.xlsx");
    Ok(())
}

#[test]
fn files_search_lists_a_file_once() -> TestResult {
    let files = files_vault()?;
    files.rescan(
        &[(
            "notes/budget-review.md",
            "# Review\n\nThe budget review is on Friday.\n",
            1_780_000_000,
        )],
        &[],
        &[],
    )?;

    let answer = files.search("budget")?;

    let listed: Vec<&FilesSearchHit> = answer
        .hits
        .iter()
        .filter(|hit| hit.handle.path == "notes/budget-review.md")
        .collect();
    assert_eq!(
        listed.len(),
        1,
        "a file whose name and text both match is listed once: {answer:?}"
    );
    assert_eq!(
        listed[0].matched,
        FilesSearchMatch::Name {
            class: NameMatch::Prefix
        },
        "by its best tier, the name"
    );
    Ok(())
}

#[test]
fn files_search_orders_name_classes() -> TestResult {
    let files = files_vault()?;
    files.rescan(
        &[],
        &[
            ("budget/readme.txt", 1_780_000_400),
            ("q3-budget.md", 1_780_000_300),
            ("budget-old.md", 1_780_000_200),
            ("budget.md", 1_780_000_100),
            ("plan.md", 1_780_000_500),
        ],
        &[],
    )?;

    let answer = files.search("budget")?;

    assert_eq!(
        paths(&answer),
        vec![
            "budget.md",
            "budget-old.md",
            "q3-budget.md",
            "budget/readme.txt"
        ],
        "exact, then prefix, then the name's words, then the path's; plan.md matches nothing"
    );
    let classes: Vec<FilesSearchMatch> = answer.hits.iter().map(|hit| hit.matched).collect();
    assert_eq!(
        classes,
        vec![
            FilesSearchMatch::Name {
                class: NameMatch::Exact
            },
            FilesSearchMatch::Name {
                class: NameMatch::Prefix
            },
            FilesSearchMatch::Name {
                class: NameMatch::NameWords
            },
            FilesSearchMatch::Name {
                class: NameMatch::PathWords
            },
        ]
    );
    Ok(())
}

#[test]
fn files_search_skips_retracted_files() -> TestResult {
    let files = files_vault()?;
    files.rescan(
        &[],
        &[
            ("reports/q3-budget.xlsx", 1_780_000_100),
            ("reports/q4-budget.xlsx", 1_780_000_200),
        ],
        &[],
    )?;
    assert_eq!(
        paths(&files.search("budget")?),
        vec!["reports/q4-budget.xlsx", "reports/q3-budget.xlsx"],
        "both files are found, the one written last first"
    );

    files.rescan(
        &[],
        &[("reports/q4-budget.xlsx", 1_780_000_200)],
        &["reports/q3-budget.xlsx"],
    )?;

    assert_eq!(
        paths(&files.search("budget")?),
        vec!["reports/q4-budget.xlsx"],
        "a file that left its folder is not listed"
    );
    Ok(())
}

/// The ask cites a file at the revision the ledger names, so it reads the
/// file's note only while the note holds that revision's text (REVIEW-7726
/// P1): once the owner edits the note, neither the file the question names
/// nor the file a search finds is read, and no quote of the edit can be
/// certified as the file's.
#[test]
fn files_ask_reads_no_note_edited_since_its_file_was_read() -> TestResult {
    const PATH: &str = "notes/budget.md";
    let files = files_vault()?;
    files.rescan(&[(PATH, "Budget = 10\n", 1_780_000_000)], &[], &[])?;
    let named = FilesSourceAskRequest {
        query: "What is the budget?".to_owned(),
        file: Some(FileHandle {
            source: files.source,
            path: PATH.to_owned(),
        }),
        sources: None,
    };
    let before = files_ask_read(&files.vault, &files.owner, &named, None)
        .map_err(at("read the file before the edit"))?;
    assert_eq!(before.len(), 1, "the file is read: {before:?}");
    assert_eq!(
        before[0].text, "Budget = 10\n",
        "the note holds the file's text as the rescan took it"
    );
    let note = before[0].file.note;

    let owner = files
        .vault
        .ensure_embedded_owner_actor()
        .map_err(at("the owner's actor"))?;
    let base = files
        .vault
        .note_program_document(note)
        .map_err(at("read the note's document"))?
        .map(|doc| doc.version());
    let outcome = files
        .vault
        .edit_note(
            note,
            &NoteProgramEdit::WholeText {
                text: "Budget = 99\n".to_owned(),
                timeout_ms: 2_000,
                base,
            },
            WriteActor::new(owner, EdgeActorClass::Human),
        )
        .map_err(at("the owner edits the note"))?;
    assert!(
        matches!(outcome, NoteProgramEditOutcome::Edited { .. }),
        "the owner's edit lands: {outcome:?}"
    );

    let refused = match files_ask_read(&files.vault, &files.owner, &named, None) {
        Ok(read) => {
            return Err(format!("the edited note is read as the file's text: {read:?}").into());
        }
        Err(refused) => refused,
    };
    assert_eq!(refused.code, MEMORY_CODE_NOT_FOUND, "{refused:?}");

    let searched = files.search("budget")?;
    assert_eq!(
        paths(&searched),
        vec![PATH],
        "the search still finds the file by its name: {searched:?}"
    );
    let found = FilesSourceAskRequest {
        file: None,
        ..named
    };
    let read = files_ask_read(&files.vault, &files.owner, &found, Some(&searched))
        .map_err(at("read the files the search found"))?;
    assert!(
        read.is_empty(),
        "the edited note is not read as the file's text: {read:?}"
    );
    Ok(())
}

#[test]
fn files_search_finds_a_file_named_like_a_part() -> TestResult {
    // REVIEW-7705 P1: a real file named `#part<n>` in a folder has a
    // continuation part's path, but the ledger holds no file at the folder's
    // path, so it is a file of its own: found by its name and by its text,
    // under its own path.
    let files = files_vault()?;
    files.rescan(
        &[(
            "drafts/#part3",
            "# Draft\n\nThe invoice for the quarter is late.\n",
            1_780_000_000,
        )],
        &[("reports/#part2", 1_780_000_100)],
        &[],
    )?;

    let named = files.search("#part2")?;
    let found = hit(&named, "reports/#part2")?;
    assert_eq!(
        found.matched,
        FilesSearchMatch::Name {
            class: NameMatch::Exact
        },
        "its whole name is the query: {named:?}"
    );
    assert_eq!(named.hits[0].handle.path, "reports/#part2");

    let meant = files.search("invoice")?;
    assert_eq!(meant.meaning, FilesMeaningState::Ran, "{meant:?}");
    let found = hit(&meant, "drafts/#part3")?;
    assert!(
        matches!(found.matched, FilesSearchMatch::Meaning { .. }),
        "its text finds it: {meant:?}"
    );
    assert!(
        !paths(&meant).contains(&"drafts"),
        "no hit names the folder as a file: {meant:?}"
    );
    Ok(())
}

#[test]
fn files_search_lists_a_continuation_part_as_its_file() -> TestResult {
    let files = files_vault()?;
    files.rescan(
        &[
            (
                "notes/long.md",
                "# Long\n\nThe first part holds the plan.\n",
                1_780_000_000,
            ),
            (
                "notes/long.md/#part2",
                "The invoice closes the second part.\n",
                1_780_000_000,
            ),
        ],
        &[],
        &[],
    )?;

    let named = files.search("#part2")?;
    assert!(
        !paths(&named).contains(&"notes/long.md/#part2"),
        "a part is never listed by its own path: {named:?}"
    );

    let meant = files.search("invoice")?;
    assert_eq!(
        paths(&meant),
        vec!["notes/long.md"],
        "the part's text finds the file it is a part of: {meant:?}"
    );
    assert!(
        matches!(meant.hits[0].matched, FilesSearchMatch::Meaning { .. }),
        "{meant:?}"
    );
    Ok(())
}
