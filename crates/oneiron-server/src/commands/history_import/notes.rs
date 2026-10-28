//! `oneiron import notes <folder> --out <batch>`: a folder of linked markdown
//! notes, as one batch the owner approves or declines whole (ARCH-0027,
//! ARCH-0032).
//!
//! This is the host's half. It reads the folder with the host's intake
//! (`crate::files_intake`): every `.md` and `.pdf` file under the
//! folder, never through a link and passing over hidden entries, takes each
//! note's title and kind from its frontmatter, and resolves its `[[links]]` to
//! the folder's other notes. It asks the vault where each file stands, writes the batch of
//! new notes and new links to `--out`, and prints counts and the digest that
//! `import approve` or `import decline` takes with the file. Nothing lands
//! before that. Stdout carries counts (per kind, per frontmatter `type`),
//! never note text, titles or link targets.
//!
//! A note keeps its file as written, frontmatter included. Its title is the
//! frontmatter `title` or `name`, else its file name; a title another note
//! already holds falls back to the note's path. Its kind is the frontmatter
//! `type` (or `metadata.type`) when that names a note kind the vault knows,
//! else `--kind`. A link resolves to a note by path, title or file name,
//! ignoring case; one that resolves to nothing stays text and is counted. A
//! note the vault's secret scan would refuse (its text, its path, or what its
//! frontmatter decodes to) is left out and counted, so the rest of the batch
//! can land. A file with another name (a hard link) is passed over: that
//! name may be outside the folder.
//!
//! A PDF's note is the text of its pages, read from its bytes: no frontmatter
//! and no links out, though a note's link can name it. Its title is its file
//! name and its kind `--kind`. A PDF with no text layer (a scan) reads as
//! blank; one that is encrypted or does not parse is passed over and counted.
//!
//! A file of any size is read (rule 5). Text past the note bound lands in
//! parts: the file's own note holds the first, and each next part is a note of
//! its own at `<path>#part<n>`, titled `<title> (part <n>)`, of the same kind,
//! with a link to the first. The frontmatter stays in the first part; each
//! part's links are those in its own text. A folder past one of its
//! `[limits]` rows (its notes' text, or how many there are) is read and
//! imported whole, and the row asks whether everything is okay (OF-520).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, Write};
use std::time::Instant;

use oneiron::EntityId;
use oneiron::note::{
    ImportedFile, ImportedNote, ImportedNoteBatch, ImportedNoteStanding, NOTES_IMPORT_SOURCE,
};
use serde::Serialize;

use crate::cli::ImportNotesArgs;
use crate::config::resolve_serve_config;
use crate::files_intake::{
    LinkCounts, NoteCounts, TitleCounts, choose_title, crossed_rows, earlier_titles, read_folder,
    resolve_links,
};
use crate::owner::note_imports::{self, NoteBatch};

pub(in crate::commands) mod folder;

#[derive(Serialize)]
struct BatchOut {
    file: String,
    request_id: String,
    digest: String,
    notes: usize,
    links: usize,
    approve: String,
    decline: String,
}

#[derive(Serialize)]
struct Outcome {
    source: &'static str,
    folder: String,
    notes: NoteCounts,
    warnings: Vec<super::ImportWarning>,
    /// New notes per kind.
    kinds: BTreeMap<String, usize>,
    /// New notes per frontmatter `type`: `""` when they have none,
    /// `(other)` when it is not a short name.
    types: BTreeMap<String, usize>,
    titles: TitleCounts,
    links: LinkCounts,
    /// The batch written to `--out`; none when nothing is new.
    batch: Option<BatchOut>,
    seconds: f64,
}

/// `oneiron import notes <folder> --out <batch> [--kind <kind>]`.
pub(in crate::commands) fn import_notes(args: ImportNotesArgs) -> anyhow::Result<()> {
    let ImportNotesArgs {
        path,
        out,
        kind,
        serve,
    } = args;
    let started = Instant::now();
    anyhow::ensure!(
        !out.exists(),
        "{} exists; the batch goes to a new file",
        out.display()
    );
    let config = resolve_serve_config(&serve)?;
    // The approve and decline lines name these; a lossy name is another path.
    for named in [Some(&out), serve.config.as_ref(), Some(&config.vault_path)]
        .into_iter()
        .flatten()
    {
        anyhow::ensure!(
            named.to_str().is_some(),
            "{} is not a UTF-8 path",
            named.display()
        );
    }
    let folder = std::fs::canonicalize(&path)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
    anyhow::ensure!(folder.is_dir(), "{} is not a folder", path.display());
    let mut counts = NoteCounts::default();
    let mut notes = read_folder(&folder, &mut counts)?;
    super::progress(&format!("read {} note(s)", notes.len()));
    let folder = folder
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("{} is not a UTF-8 path", folder.display()))?
        .to_owned();

    let vault = super::open_vault(&config)?;
    let owner = crate::owner::local_owner(&vault)?;
    vault
        .note_kind(&kind)
        .map_err(|_| anyhow::anyhow!("--kind {kind:?} is not a note kind this vault knows"))?;
    let standings = vault.imported_note_standings(
        &folder,
        &notes
            .iter()
            .map(|note| ImportedFile {
                path: &note.path,
                markdown: &note.markdown,
                decoded: &note.decoded,
            })
            .collect::<Vec<_>>(),
    )?;
    for standing in &standings {
        match standing {
            ImportedNoteStanding::New => counts.new += 1,
            ImportedNoteStanding::Unchanged => counts.unchanged += 1,
            ImportedNoteStanding::Changed => counts.changed += 1,
            ImportedNoteStanding::Removed => counts.removed += 1,
            ImportedNoteStanding::Refused => counts.refused += 1,
        }
    }

    let mut kinds = BTreeMap::new();
    let mut types = BTreeMap::new();
    let mut titles = TitleCounts::default();
    let mut known_kinds = HashMap::new();
    let mut taken = HashSet::new();
    let mut files = Vec::new();
    for (note, standing) in notes.iter_mut().zip(&standings) {
        // The batch takes a new note's text; the rest is not needed again.
        let markdown = std::mem::take(&mut note.markdown);
        if *standing != ImportedNoteStanding::New {
            continue;
        }
        let known = note.label.as_ref().is_some_and(|label| {
            *known_kinds
                .entry(label.clone())
                .or_insert_with(|| vault.note_kind(label).is_ok())
        });
        let kind = match &note.label {
            Some(label) if known => label.clone(),
            _ => kind.clone(),
        };
        *kinds.entry(kind.clone()).or_insert(0) += 1;
        *types
            .entry(shown_label(note.label.as_deref()).to_owned())
            .or_insert(0) += 1;
        let title = choose_title(&vault, &folder, note, &mut taken, &mut titles)?;
        files.push(ImportedNote {
            path: note.path.clone(),
            kind,
            title,
            written_at: note.written_at,
            markdown,
        });
    }
    let earlier_titles = earlier_titles(&vault, &folder, &notes, &standings)?;
    let (links, link_counts) = resolve_links(&notes, &standings, &earlier_titles);

    let batch = if files.is_empty() {
        None
    } else {
        let batch = ImportedNoteBatch {
            request_id: EntityId::now(),
            folder: folder.clone(),
            notes: files,
            links,
        };
        let digest = note_imports::digest(&vault, &owner, &batch)?;
        let (note_count, link_count) = (batch.notes.len(), batch.links.len());
        let batch = NoteBatch::from(batch);
        super::super::owner::write_new_file(&out, |file| {
            let mut writer = io::BufWriter::new(&mut *file);
            serde_json::to_writer(&mut writer, &batch).map_err(io::Error::other)?;
            writer.flush()?;
            drop(writer);
            file.sync_all()
        })?;
        // The vault this preview read, named outright: a config alone could
        // name another one.
        let config_flag = serve
            .config
            .as_ref()
            .map(|config| format!(" --config {}", quoted(&config.to_string_lossy())))
            .unwrap_or_default();
        let decision = |verb: &str| {
            format!(
                "oneiron import {verb} {} --digest {}{config_flag} --vault-path {}",
                quoted(&out.to_string_lossy()),
                digest,
                quoted(&config.vault_path.to_string_lossy()),
            )
        };
        Some(BatchOut {
            file: out.display().to_string(),
            approve: decision("approve"),
            decline: decision("decline"),
            request_id: batch.request_id,
            digest,
            notes: note_count,
            links: link_count,
        })
    };
    let mut warnings = crossed_rows(&vault, &counts);
    if counts.hard_linked > 0 {
        warnings.push(super::ImportWarning::HardLinked {
            files: counts.hard_linked,
        });
    }
    let outcome = Outcome {
        source: NOTES_IMPORT_SOURCE,
        folder,
        notes: counts,
        warnings,
        kinds,
        types,
        titles,
        links: link_counts,
        batch,
        seconds: started.elapsed().as_secs_f64(),
    };
    let mut stdout = io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, &outcome)?;
    writeln!(stdout)?;
    Ok(())
}

/// A frontmatter `type` as stdout shows it: a short name as it is, anything
/// else (prose, a long value) as `(other)`, so no note text reaches stdout.
/// A name the release filter reads as a credential is `(other)` too (FIX
/// 9475), whatever the vault's secret scan is set to.
fn shown_label(label: Option<&str>) -> &str {
    match label {
        None => "",
        Some(label)
            if label.len() <= 64
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
                && !oneiron::batch::export::redact_credentials(&mut serde_json::Value::from(
                    label,
                )) =>
        {
            label
        }
        Some(_) => "(other)",
    }
}

/// `text` as one shell word.
fn quoted(text: &str) -> String {
    if !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/-:=@+,".contains(&b))
    {
        text.to_owned()
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Astra 3 and Greptile (notes.rs:327): only the note count bounded a
    /// folder, so about 100 GiB of notes under the per-file cap were read
    /// into memory before any limit. Past its byte budget a folder is
    /// refused while it is read.
    #[test]
    fn a_folder_past_its_byte_budget_is_refused_while_it_is_read() {
        let dir = tempfile::tempdir().expect("test fixture");
        for name in ["a.md", "b.md", "c.md"] {
            std::fs::write(dir.path().join(name), "x".repeat(400)).expect("test fixture");
        }
        let mut counts = NoteCounts::default();
        let refused = read_folder(dir.path(), &mut counts, 1000)
            .err()
            .and_then(|error| error.downcast::<FolderRefused>().ok());
        assert!(
            matches!(
                refused,
                Some(FolderRefused::TooManyBytes { budget: 1000, .. })
            ),
            "{refused:?}"
        );
        assert_eq!(counts.found, 2, "refused at the file past the budget");
    }
}
