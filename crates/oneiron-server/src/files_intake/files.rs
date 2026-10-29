//! A Files source's read (FIX 6942). The walk visits every regular file
//! under the folder, hidden ones too, and passes over what the source's
//! exclusions name before it opens it. Markdown and PDF read as an attached
//! folder reads them; a file whose extension is on the text list reads whole
//! as UTF-8. Every other file, and one whose bytes hold no text, is held by
//! its name only: its bytes are never read for a format the source takes no
//! text from. One whose bytes the walk read carries them, kept as its
//! original once its ledger row lands (FIX 11276).

use std::collections::HashMap;
use std::path::Path;

use oneiron::note::{FILES_TEXT_EXTENSIONS, FileFacts, NameOnlyFile, NameOnlyReason};

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
/// by name only.
pub(super) fn read_files(
    folder: &Path,
    exclude: &[String],
    counts: &mut NoteCounts,
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
        // Of the open file, so a name swapped after the walk listed it
        // changes nothing.
        let metadata = file.metadata()?;
        let facts = FileFacts {
            bytes: metadata.len(),
            modified_at: written_at(&metadata),
        };
        // The reason with the bytes the walk read, when it read them: a
        // format the source takes no text from, a file with another name and
        // one that did not open are held by name with none (FIX 11276).
        let held = if super::hard_linked(&metadata) {
            counts.hard_linked += 1;
            Some((NameOnlyReason::Linked, None))
        } else {
            match text_kind(&path) {
                None => Some((NameOnlyReason::Unsupported, None)),
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
    })?;
    // A file that did not open (no read permission) is held by its name,
    // with what its metadata says.
    for shown in unopened {
        let Some(path) = relative(folder, &shown) else {
            counts.unreadable_name += 1;
            continue;
        };
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
