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
    FileOriginal, FilesWorld, FolderFile, FolderFileState, FolderRescan, FolderRescanReport,
    FolderSource, ImportedFile, ImportedNote, ImportedNoteStanding,
};
use oneiron::task_verb::sdk::{
    self, FilesLimitCrossed, FilesOriginalsUnkept, FilesRescanView, FilesSourceAttachAnswer,
    FilesWorldView,
};
use serde::Serialize;

use super::ImportWarning;
use super::reader::{
    FILES_PART_MARK, Note, NoteCounts, PART_MARK, TitleCounts, choose_title, crossed_rows,
    earlier_titles, file_of, read_folder, resolve_links,
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

/// One rescan: the folder read as its source reads it, the files the
/// source includes, each against the vault and the ledger; and the
/// `[limits]` rows the read crossed.
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
    let (mut notes, mut name_only, facts) = match &source.files {
        Some(files) => {
            let read = super::files::read_files(folder, &files.exclude, &mut counts)?;
            (read.notes, read.name_only, read.facts)
        }
        None => (
            read_folder(folder, &mut counts)?,
            Vec::new(),
            HashMap::new(),
        ),
    };
    let mut warnings = crossed_rows(vault, &counts);
    // A part goes with its file.
    notes.retain(|note| included(&source.include, note.file()));
    name_only.retain(|file| included(&source.include, &file.path));
    let raw_hashes = notes
        .iter()
        .filter_map(|note| Some((note.path.clone(), note.raw_hash.clone()?)))
        .collect::<HashMap<_, _>>();
    let ledger = vault.folder_source_files(&source.folder)?;
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
    let standings = vault.imported_note_standings(
        &namespace,
        &notes
            .iter()
            .map(|note| ImportedFile {
                path: &note.path,
                markdown: &note.markdown,
                decoded: &note.decoded,
            })
            .collect::<Vec<_>>(),
    )?;
    let earlier_titles = earlier_titles(vault, &namespace, &notes, &standings)?;
    let (links, _) = resolve_links(&notes, &standings, &earlier_titles);
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
    let report = vault.rescan_folder_source(
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
    // The notes have landed: what keeping their originals meets is said
    // beside the report, never in place of it.
    warnings.extend(keep_originals(vault, owner, source, &namespace, &notes));
    Ok((report, warnings))
}

/// Keeps the original of each file the rescan read whose note the ledger
/// now holds (FIX 7779), and names it on that file's ledger rows, its parts'
/// included. A file whose row already names the same bytes keeps no second
/// copy. A file whose original cannot be kept or named still has its text
/// imported: its rows name no original, and the warning counts it.
fn keep_originals(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    source: &FolderSource,
    namespace: &str,
    notes: &[Note],
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
            let read = notes.iter().filter(|note| note.original.is_some()).count();
            return Some(unkept(read, &error));
        }
    };
    let mut kept: HashMap<&str, Option<FileOriginal>> = HashMap::new();
    let (mut failed, mut first_error) = (0, None);
    for note in notes {
        let (Some(original), Some(row)) = (&note.original, ledger.get(&note.path)) else {
            continue;
        };
        let hash = original.content_hash();
        let same = row
            .original
            .as_ref()
            .filter(|kept| kept.content_hash == hash);
        let original = match same {
            Some(same) => Some(same.clone()),
            None => match vault.keep_folder_file_original(owner, namespace, &note.path, original) {
                Ok(original) => Some(original),
                Err(error) => {
                    failed += 1;
                    first_error.get_or_insert_with(|| error.to_string());
                    None
                }
            },
        };
        kept.insert(note.path.as_str(), original);
    }
    let originals = notes
        .iter()
        .filter_map(|note| Some((note.path.clone(), kept.get(note.file())?.clone())))
        .collect::<HashMap<_, _>>();
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
