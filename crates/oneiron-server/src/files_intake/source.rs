//! One rescan of an attached folder, as `oneiron import folder`, `oneiron
//! files`, the facade's `vault.files.sources.*` doors and `oneiron serve`'s
//! worker all run it (OF-554, FIX 6942). The folder is read as `import
//! notes` reads it, or as its Files source reads it, and each file the source
//! includes is judged against the vault and the ledger. Nothing is ever
//! written to the folder.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use oneiron::EntityId;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::MemoryResult;
use oneiron::note::{
    FileFacts, FileOriginal, FilesWorld, FolderFile, FolderFileState, FolderRescan,
    FolderRescanReport, FolderSource, FolderSourceFile, ImportedFile, ImportedNote,
    ImportedNoteStanding, NameOnlyFile,
};
use oneiron::task_verb::sdk::{
    self, FilesLimitCrossed, FilesOriginalsUnkept, FilesRescanView, FilesSourceAttachAnswer,
    FilesWorldView,
};
use serde::Serialize;

use super::ImportWarning;
use super::present_links::resolve_present_links;
use super::reader::{
    FILES_PART_MARK, Note, NoteCounts, PART_MARK, TitleCounts, choose_title, crossed_rows,
    earlier_titles, file_of, read_folder_rescan, resolve_links,
};

/// One rescan as stdout shows it: its counts, or why it read nothing.
#[derive(Serialize)]
pub(crate) struct Rescanned {
    pub(crate) folder: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) report: Option<FolderRescanReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
    /// The `[limits]` rows the folder's read crossed; it was read whole.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) warnings: Vec<ImportWarning>,
}

/// [`rescan`], its error kept as text beside the folder.
pub(crate) fn rescanned(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    source: &FolderSource,
) -> Rescanned {
    let (report, warnings, error) = match rescan(vault, owner, source) {
        Ok((report, warnings)) => (Some(report), warnings, None),
        Err(error) => (None, Vec::new(), Some(format!("{error:#}"))),
    };
    Rescanned {
        folder: source.folder.clone(),
        report,
        error,
        warnings,
    }
}

/// One rescan of the Files source `id` names, as `vault.files.sources.*`
/// and `oneiron files` answer it: its counts, the `[limits]` rows its read
/// crossed and the files whose original it could not keep, or why it read
/// nothing.
pub(crate) fn files_rescan(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    source: &FolderSource,
    id: EntityId,
) -> FilesRescanView {
    let (counts, limits_crossed, originals_unkept, error) = match rescan(vault, owner, source) {
        Ok((report, warnings)) => {
            let unkept = warnings.iter().find_map(|warning| match warning {
                ImportWarning::OriginalsUnkept { files, first_error } => {
                    Some(FilesOriginalsUnkept {
                        files: u64::try_from(*files).unwrap_or(u64::MAX),
                        first_error: first_error.clone(),
                    })
                }
                _ => None,
            });
            let crossed = warnings
                .iter()
                .filter_map(|warning| match warning {
                    ImportWarning::LimitCrossed {
                        row,
                        limit,
                        observed,
                    } => Some(FilesLimitCrossed {
                        row: (*row).to_owned(),
                        limit: *limit,
                        observed: *observed,
                    }),
                    ImportWarning::HardLinked { .. } | ImportWarning::OriginalsUnkept { .. } => {
                        None
                    }
                })
                .collect();
            (Some(report.into()), crossed, unkept, None)
        }
        Err(error) => (None, Vec::new(), None, Some(format!("{error:#}"))),
    };
    FilesRescanView {
        source: id,
        folder: source.folder.clone(),
        counts,
        error,
        limits_crossed,
        originals_unkept,
    }
}

/// `vault.files.sources.attach`'s answer for a source just attached to
/// `world`: its first rescan, run at once, and the source as it stands
/// after it.
///
/// # Errors
/// A source that is not a Files source, or a storage error. A rescan that
/// read nothing is said in the answer, never a refusal of the attach.
pub(crate) fn files_attached(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    world: FilesWorld,
    source: &FolderSource,
) -> MemoryResult<FilesSourceAttachAnswer> {
    let attached = sdk::files_source_view(vault, source)?;
    let rescan = files_rescan(vault, owner, source, attached.source);
    let source = match vault.folder_source(&source.folder)? {
        Some(rescanned) => sdk::files_source_view(vault, &rescanned)?,
        None => attached,
    };
    Ok(FilesSourceAttachAnswer {
        world: FilesWorldView {
            world: world.world,
            machine: world.machine,
        },
        source,
        rescan,
    })
}

/// Whether a rescan skips the read and hash of a file whose size and mtime
/// both match the last scan's record for that path (FIX 1365): an mtime
/// shortcut, never a watcher. A content change that keeps both size and
/// mtime is not seen until the next real change.
const RESCAN_MTIME_SHORTCUT: bool = true;

/// One rescan: the folder read as its source reads it, the files the
/// source includes, each against the vault and the ledger; and the
/// `[limits]` rows the read crossed. A file the last scan recorded with the
/// same size and mtime is not read again.
pub(crate) fn rescan(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    source: &FolderSource,
) -> anyhow::Result<(FolderRescanReport, Vec<ImportWarning>)> {
    let folder = Path::new(&source.folder);
    // An unmounted or moved folder retracts nothing.
    anyhow::ensure!(
        folder.is_dir(),
        "{} is not a folder now; nothing was rescanned",
        source.folder
    );
    // The notes' ids, titles and revisions derive from this, never from the
    // host's path when the source is a Files source's.
    let namespace = source.namespace();
    let mut counts = NoteCounts::default();
    let mark = if source.files.is_some() {
        FILES_PART_MARK
    } else {
        PART_MARK
    };
    // What the last scan recorded of each file still worth skipping: its
    // size and mtime. A retracted file is read again, so a returning file
    // restores its note; a file with no record is read as today.
    let ledger = vault.folder_source_files(&source.folder)?;
    let prior = prior_files(&ledger);
    let prior = RESCAN_MTIME_SHORTCUT.then_some(&prior);
    let (mut notes, mut name_only, mut facts, mut skipped) =
        read_for_rescan(source, folder, &mut counts, prior)?;
    let mut standings = standings_of(vault, &namespace, &notes)?;
    // A new note's inbound links, and a changed note's outbound ones, come
    // from the whole folder, skipped files included: with a new or changed
    // note the folder is read again, whole, so no live edge reads as dropped
    // when the rescan reconciles a superseded note's links (FIX 1363).
    if !skipped.is_empty()
        && standings.iter().any(|standing| {
            matches!(
                standing,
                ImportedNoteStanding::New | ImportedNoteStanding::Changed
            )
        })
    {
        counts = NoteCounts::default();
        (notes, name_only, facts, skipped) = read_for_rescan(source, folder, &mut counts, None)?;
        standings = standings_of(vault, &namespace, &notes)?;
    }
    let mut warnings = crossed_rows(vault, &counts);
    let raw_hashes = notes
        .iter()
        .filter_map(|note| Some((note.path.clone(), note.raw_hash.clone()?)))
        .collect::<HashMap<_, _>>();
    let seen = notes
        .iter()
        .map(|note| note.path.as_str())
        .chain(name_only.iter().map(|file| file.path.as_str()))
        .collect::<HashSet<_>>();
    // Only a file that is gone retracts: one the read passed over (blank,
    // hard-linked, unreadable) is still there. A continuation part names its
    // file in its path; it retracts too when that file was read and its text
    // no longer reaches the part.
    let missing = ledger
        .iter()
        .filter(|file| file.state != FolderFileState::Retracted)
        .filter(|file| !seen.contains(file.path.as_str()))
        .filter(|file| {
            let read_from = file_of(&file.path, mark);
            (read_from != file.path && seen.contains(read_from))
                || std::fs::symlink_metadata(folder.join(read_from)).is_err()
        })
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    // A folder emptied of its last file retracts that file too (ARCH-0027).
    // Retraction archives, and a returning file restores its note, so a
    // mount point read empty loses nothing.
    let earlier_titles = earlier_titles(vault, &namespace, &notes, &standings)?;
    let (links, _) = resolve_links(&notes, &standings, &earlier_titles);
    // Every present file's links as its text holds them now: the rescan
    // reconciles a superseded note's edges to them. Only a whole read
    // resolves them; a read that skipped files leaves every file's alone.
    let present_links = resolve_present_links(&notes, &standings);
    let mut present_targets: HashMap<&str, Vec<String>> = HashMap::new();
    for link in &present_links {
        present_targets
            .entry(link.from.as_str())
            .or_insert_with(Vec::new)
            .push(link.to.clone());
    }
    let links_complete = skipped.is_empty();
    let mut known_kinds = HashMap::new();
    let mut taken = HashSet::new();
    let mut titles = TitleCounts::default();
    let mut new = Vec::new();
    let mut present = Vec::new();
    for (note, standing) in notes.iter_mut().zip(&standings) {
        let markdown = std::mem::take(&mut note.markdown);
        if *standing != ImportedNoteStanding::New {
            present.push(FolderFile {
                path: note.path.clone(),
                markdown,
                links: links_complete
                    .then(|| present_targets.remove(note.path.as_str()).unwrap_or_default()),
            });
            continue;
        }
        let known = note.label.as_ref().is_some_and(|label| {
            *known_kinds
                .entry(label.clone())
                .or_insert_with(|| vault.note_kind(label).is_ok())
        });
        let kind = match &note.label {
            Some(label) if known => label.clone(),
            _ => source.kind.clone(),
        };
        let title = choose_title(vault, &namespace, note, &mut taken, &mut titles)?;
        // The host keeps a rescan's originals itself, once its notes land.
        new.push(ImportedNote {
            path: note.path.clone(),
            kind,
            title,
            written_at: note.written_at,
            markdown,
            original: None,
        });
    }
    // The name-only files' bytes, taken before their rows land: keeping
    // their originals needs no ledger row, naming them does (FIX 11276).
    let mut name_only_originals = Vec::new();
    for file in &mut name_only {
        if let Some(original) = file.original.take() {
            name_only_originals.push((file.path.clone(), original));
        }
    }
    let mut report = vault.rescan_folder_source(
        owner,
        FolderRescan {
            folder: source.folder.clone(),
            new,
            links,
            present,
            name_only,
            missing,
            raw_hashes,
            facts,
        },
    )?;
    // Skipped files keep what the ledger holds: each counts as unchanged,
    // as the reconcile counts the files it read and found the same.
    report.unchanged += skipped.len();
    // The notes have landed: what keeping their originals meets is said
    // beside the report, never in place of it.
    warnings.extend(keep_originals(
        vault,
        owner,
        source,
        &namespace,
        &notes,
        &name_only_originals,
    ));
    Ok((report, warnings))
}

/// What the last scan recorded of each file a rescan may skip: its size
/// and mtime, by path. Only a file the ledger still holds counts.
fn prior_files(ledger: &[FolderSourceFile]) -> HashMap<String, FileFacts> {
    ledger
        .iter()
        .filter(|file| !matches!(file.state, FolderFileState::Retracted))
        .filter_map(|file| {
            let meta = file.meta?;
            Some((
                file.path.clone(),
                FileFacts {
                    bytes: meta.bytes,
                    modified_at: meta.modified_at,
                },
            ))
        })
        .collect()
}

/// One read of `source`'s folder for a rescan: its notes, the files held by
/// name, the facts of every file read, and the included paths the shortcut
/// skipped.
fn read_for_rescan(
    source: &FolderSource,
    folder: &Path,
    counts: &mut NoteCounts,
    prior: Option<&HashMap<String, FileFacts>>,
) -> anyhow::Result<(
    Vec<Note>,
    Vec<NameOnlyFile>,
    HashMap<String, FileFacts>,
    Vec<String>,
)> {
    let (mut notes, mut name_only, facts, mut skipped) = match &source.files {
        Some(files) => {
            let read = super::files::read_files(folder, &files.exclude, counts, prior)?;
            (read.notes, read.name_only, read.facts, read.skipped)
        }
        None => read_folder_rescan(folder, counts, prior)?,
    };
    // A part goes with its file.
    notes.retain(|note| included(&source.include, note.file()));
    name_only.retain(|file| included(&source.include, &file.path));
    skipped.retain(|path| included(&source.include, path));
    Ok((notes, name_only, facts, skipped))
}

/// What the vault holds of each note read: new, changed or as it was.
fn standings_of(
    vault: &oneiron::Vault,
    namespace: &str,
    notes: &[Note],
) -> anyhow::Result<Vec<ImportedNoteStanding>> {
    Ok(vault.imported_note_standings(
        namespace,
        &notes
            .iter()
            .map(|note| ImportedFile {
                path: &note.path,
                markdown: &note.markdown,
                decoded: &note.decoded,
            })
            .collect::<Vec<_>>(),
    )?)
}

/// Keeps the original of each file the rescan read whose note the ledger
/// now holds (FIX 7779), and of each name-only file whose bytes the walk
/// read (FIX 11276), and names it on that file's ledger rows, a note's
/// parts' included. A file whose row already names the same bytes keeps no
/// second copy. A file whose original cannot be kept or named still has its
/// text imported: its rows name no original, and the warning counts it.
fn keep_originals(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    source: &FolderSource,
    namespace: &str,
    notes: &[Note],
    name_only: &[(String, oneiron::note::OriginalBytes)],
) -> Option<ImportWarning> {
    let unkept = |files: usize, error: &dyn std::fmt::Display| ImportWarning::OriginalsUnkept {
        files,
        first_error: error.to_string(),
    };
    let ledger = match vault.folder_source_files(&source.folder) {
        Ok(files) => files
            .into_iter()
            .map(|file| (file.path.clone(), file))
            .collect::<HashMap<_, _>>(),
        Err(error) => {
            let read =
                notes.iter().filter(|note| note.original.is_some()).count() + name_only.len();
            return Some(unkept(read, &error));
        }
    };
    let mut kept: HashMap<&str, Option<FileOriginal>> = HashMap::new();
    let (mut failed, mut first_error) = (0, None);
    let read = notes.iter().filter_map(|note| {
        note.original
            .as_ref()
            .map(|original| (note.path.as_str(), original))
    });
    let held = name_only
        .iter()
        .map(|(path, original)| (path.as_str(), original));
    for (path, original) in read.chain(held) {
        let Some(row) = ledger.get(path) else {
            continue;
        };
        let hash = original.content_hash();
        let same = row
            .original
            .as_ref()
            .filter(|kept| kept.content_hash == hash);
        let original = match same {
            Some(same) => Some(same.clone()),
            None => match vault.keep_folder_file_original(owner, namespace, path, original) {
                Ok(original) => Some(original),
                Err(error) => {
                    failed += 1;
                    first_error.get_or_insert_with(|| error.to_string());
                    None
                }
            },
        };
        kept.insert(path, original);
    }
    let mut originals = notes
        .iter()
        .filter_map(|note| Some((note.path.clone(), kept.get(note.file())?.clone())))
        .collect::<HashMap<_, _>>();
    for (path, _) in name_only {
        if let Some(original) = kept.get(path.as_str()) {
            originals.insert(path.clone(), original.clone());
        }
    }
    if let Err(error) = vault.link_folder_file_originals(owner, &source.folder, &originals) {
        return Some(unkept(kept.len(), &error));
    }
    first_error.map(|first_error| ImportWarning::OriginalsUnkept {
        files: failed,
        first_error,
    })
}

/// `path` as a source names it: canonical, a folder, UTF-8.
pub(crate) fn canonical_folder(path: &Path) -> anyhow::Result<String> {
    let folder = std::fs::canonicalize(path)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
    anyhow::ensure!(folder.is_dir(), "{} is not a folder", path.display());
    folder
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("{} is not a UTF-8 path", folder.display()))
}

/// Whether the source includes `path`: no patterns is every file; else one
/// pattern matches it.
fn included(patterns: &[String], path: &str) -> bool {
    patterns.is_empty() || patterns.iter().any(|pattern| matches(pattern, path))
}

/// Whether `pattern` matches all of `path`: `*` within a name, `**` across
/// folders, `?` one character.
pub(super) fn matches(pattern: &str, path: &str) -> bool {
    glob(
        &pattern.chars().collect::<Vec<_>>(),
        &path.chars().collect::<Vec<_>>(),
    )
}

fn glob(pattern: &[char], path: &[char]) -> bool {
    match pattern {
        [] => path.is_empty(),
        ['*', '*', '/', rest @ ..] => {
            glob(rest, path)
                || (0..path.len())
                    .filter(|&at| path[at] == '/')
                    .any(|at| glob(rest, &path[at + 1..]))
        }
        ['*', '*', rest @ ..] => (0..=path.len()).any(|at| glob(rest, &path[at..])),
        ['*', rest @ ..] => (0..=path.len())
            .take_while(|&at| at == 0 || path[at - 1] != '/')
            .any(|at| glob(rest, &path[at..])),
        ['?', rest @ ..] => path.first().is_some_and(|&c| c != '/') && glob(rest, &path[1..]),
        [c, rest @ ..] => path.first() == Some(c) && glob(rest, &path[1..]),
    }
}
