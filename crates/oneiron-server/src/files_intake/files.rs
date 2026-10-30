//! A Files source's read (FIX 6942). The walk visits every regular file
//! under the folder, hidden ones too, and passes over what the source's
//! exclusions name before it opens it. Markdown and PDF read as an attached
//! folder reads them; a file whose extension is on the text list reads whole
//! as UTF-8. Every other file, one with another name (a hard link), and one
//! whose bytes hold no text, is held by its name, its bytes read whole all
//! the same, of any size (FIX 11588), and kept as its original once its
//! ledger row lands (FIX 11276). A file the walk could not open is opened
//! again once the walk is done; only one that still does not open is held
//! by its name with no bytes.

use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

use oneiron::note::{
    FILES_TEXT_EXTENSIONS, FileFacts, NameOnlyFile, NameOnlyReason, OriginalBytes,
};

use super::reader::{
    FILES_PART_MARK, Note, NoteCounts, TextKind, read_all, read_text, relative, written_at,
};

/// What one read of a Files source holds.
#[derive(Default)]
pub(super) struct FilesRead {
    /// Its notes, as an attached folder's read gives them.
    pub(super) notes: Vec<Note>,
    /// Its files with no text the vault takes.
    pub(super) name_only: Vec<NameOnlyFile>,
    /// By path, the facts of each note's file, a part's included.
    pub(super) facts: HashMap<String, FileFacts>,
    /// The paths the mtime shortcut skipped (FIX 1365): read by no one.
    pub(super) skipped: Vec<String>,
}

/// How the file at `path` holds its text, by its extension; none for a
/// format the source takes no text from.
fn text_kind(path: &str) -> Option<TextKind> {
    let extension = Path::new(path).extension()?.to_str()?;
    if extension.eq_ignore_ascii_case("md") {
        Some(TextKind::Markdown)
    } else if extension.eq_ignore_ascii_case("pdf") {
        Some(TextKind::Pdf)
    } else {
        FILES_TEXT_EXTENSIONS
            .iter()
            .any(|known| extension.eq_ignore_ascii_case(known))
            .then_some(TextKind::Plain)
    }
}

/// Whether one of `exclude` names the entry at `path` under the folder, by
/// its name or by its whole path.
fn excludes(exclude: &[String], path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    exclude.iter().any(|pattern| {
        super::source::matches(pattern, name) || super::source::matches(pattern, path)
    })
}

/// Every file under `folder` that `exclude` leaves, in path order: its
/// notes, a file past the note bound as its parts, and the files it holds
/// by name only. A file whose size and mtime both match `prior`'s record is
/// not read (FIX 1365).
pub(super) fn read_files(
    folder: &Path,
    exclude: &[String],
    counts: &mut NoteCounts,
    prior: Option<&HashMap<String, FileFacts>>,
) -> anyhow::Result<FilesRead> {
    let mut read = FilesRead::default();
    let excluded =
        |shown: &Path| relative(folder, shown).is_some_and(|path| excludes(exclude, &path));
    let mut unopened = Vec::new();
    let mut unopened_at = |shown: &Path| unopened.push(shown.to_path_buf());
    super::walk_files(folder, &excluded, &mut unopened_at, &mut |shown, file| {
        let Some(path) = relative(folder, shown) else {
            counts.unreadable_name += 1;
            return Ok(());
        };
        read_file(path, file, shown, counts, &mut read, prior)
    })?;
    // A file that did not open on the walk (no read permission then) is
    // opened again, never through a link (FIX 11588). One that still does
    // not open is held by its name, with what its metadata says.
    for shown in unopened {
        let Some(path) = relative(folder, &shown) else {
            counts.unreadable_name += 1;
            continue;
        };
        if let Some(file) = reopened(folder, &path) {
            read_file(path, file, &shown, counts, &mut read, prior)?;
            continue;
        }
        let facts = std::fs::symlink_metadata(&shown).map_or(
            FileFacts {
                bytes: 0,
                modified_at: 0,
            },
            |metadata| FileFacts {
                bytes: metadata.len(),
                modified_at: written_at(&metadata),
            },
        );
        read.name_only.push(NameOnlyFile {
            path,
            why: NameOnlyReason::Unreadable,
            facts,
            original: None,
        });
    }
    // A part carries its file's facts.
    for note in &read.notes {
        if let Some(file) = &note.part_of
            && let Some(facts) = read.facts.get(file).copied()
        {
            read.facts.insert(note.path.clone(), facts);
        }
    }
    Ok(read)
}

/// One open file of the source at `path`, shown as `shown`: its notes, or
/// its name with the reason it holds no text. Every file's bytes are read
/// whole, of any size (FIX 11588): a format the source takes no text from
/// and a file with another name keep theirs as their original, as a file
/// whose bytes hold no text does (FIX 11276). A file `prior` records with
/// the same size and mtime is not read at all (FIX 1365).
fn read_file(
    path: String,
    file: File,
    shown: &Path,
    counts: &mut NoteCounts,
    read: &mut FilesRead,
    prior: Option<&HashMap<String, FileFacts>>,
) -> anyhow::Result<()> {
    // Of the open file, so a name swapped after the walk listed it changes
    // nothing.
    let metadata = file.metadata()?;
    let facts = FileFacts {
        bytes: metadata.len(),
        modified_at: written_at(&metadata),
    };
    // A file with another name is passed over as today, never skipped:
    // that name may be outside the folder.
    let linked = super::hard_linked(&metadata);
    if linked {
        counts.hard_linked += 1;
    } else if prior.is_some_and(|prior| prior.get(&path) == Some(&facts)) {
        read.skipped.push(path);
        return Ok(());
    }
    let held = if linked {
        Some((NameOnlyReason::Linked, original(file, shown, &path)))
    } else {
        match text_kind(&path) {
            None => Some((NameOnlyReason::Unsupported, original(file, shown, &path))),
            Some(kind) => match read_all(file, shown) {
                Ok(bytes) => read_text(
                    (path.clone(), FILES_PART_MARK),
                    bytes,
                    facts.modified_at,
                    kind,
                    counts,
                    &mut read.notes,
                )
                .map(|(why, original)| (why, Some(original))),
                Err(_) => Some((NameOnlyReason::Unreadable, None)),
            },
        }
    };
    match held {
        Some((why, original)) => read.name_only.push(NameOnlyFile {
            path,
            why,
            facts,
            original,
        }),
        None => {
            read.facts.insert(path, facts);
        }
    }
    Ok(())
}

/// The bytes of a file held by its name, read whole as its original (FIX
/// 11588), under the media type its extension names, else
/// `application/octet-stream`. `None` when the read fails.
fn original(file: File, shown: &Path, path: &str) -> Option<OriginalBytes> {
    let bytes = read_all(file, shown).ok()?;
    let media_type = text_kind(path).map_or("application/octet-stream", TextKind::media_type);
    Some(OriginalBytes {
        media_type: media_type.to_owned(),
        bytes,
    })
}

/// The file at `path` below `folder`, opened again after the walk, every
/// folder on the way relative to the one above it and never through a link
/// (FIX 11588); `None` when it still does not open.
#[cfg(unix)]
fn reopened(folder: &Path, path: &str) -> Option<File> {
    super::confined::open_below(folder, Path::new(path))
        .ok()
        .map(|(_, file)| file)
}

#[cfg(not(unix))]
fn reopened(_folder: &Path, _path: &str) -> Option<File> {
    None
}
