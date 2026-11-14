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
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test files_search`.

use std::collections::HashMap;

use oneiron::authority::{ActSurface, MachineOwnership, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::note::{
    FileFacts, FileReadiness, FolderRescan, ImportedNote, NameMatch, NameOnlyFile, NameOnlyReason,
};
use oneiron::task_verb::sdk::{
    FilesMeaningState, FilesSearchHit, FilesSearchMatch, FilesSourceSearchAnswer,
    FilesSourceSearchRequest, search_files_sources_as,
};
use oneiron::test_doors::steward;
use oneiron::{EntityId, Vault};

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
