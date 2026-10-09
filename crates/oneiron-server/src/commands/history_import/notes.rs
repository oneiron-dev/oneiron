//! `oneiron import notes <folder> --out <batch>`: a folder of linked markdown
//! notes, as one batch the owner approves or declines whole (ARCH-0027,
//! ARCH-0032).
//!
//! This is the host's half. It reads every `.md` file under the folder, never
//! through a link and passing over hidden entries, takes each note's title and
//! kind from its frontmatter, and resolves its `[[links]]` to the folder's
//! other notes. It asks the vault where each file stands, writes the batch of
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
//! note the vault's secret scan would refuse is left out and counted, so the
//! rest of the batch can land.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, Write};
use std::path::{Component, Path};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use oneiron::EntityId;
use oneiron::consent::AuthenticatedOwner;
use oneiron::note::{ImportedNoteStanding, NOTES_IMPORT_SOURCE};
use serde::Serialize;

use crate::cli::ImportNotesArgs;
use crate::config::resolve_serve_config;
use crate::owner::note_imports::{self, NoteBatch, NoteFile, NoteLink};

mod markdown;
use markdown::{Front, Link};

/// The largest note the vault holds; a larger file is passed over and counted.
const MAX_NOTE_BYTES: u64 = 1024 * 1024;

/// The most notes one import reads.
const MAX_NOTES: usize = 100_000;

/// The longest title a note keeps.
const MAX_TITLE_BYTES: usize = 256;

/// One file, read and parsed.
struct Note {
    /// Under the folder, `/`-separated.
    path: String,
    markdown: String,
    written_at: u64,
    /// The frontmatter's `title` or `name`.
    title: Option<String>,
    /// The frontmatter's `type` or `metadata.type`.
    label: Option<String>,
    links: Vec<Link>,
}

#[derive(Serialize, Default)]
struct NoteCounts {
    /// Notes read from the folder.
    found: usize,
    new: usize,
    unchanged: usize,
    changed: usize,
    removed: usize,
    /// New, but the vault's secret scan would refuse their text; `oneiron
    /// secret-scan off` lets them in.
    refused: usize,
    /// Files passed over: larger than a note may be, or blank.
    too_large: usize,
    blank: usize,
    /// Files whose name is not UTF-8: it could not name its note.
    unreadable_name: usize,
    /// Notes whose frontmatter is not YAML: title from the file name, kind
    /// from `--kind`.
    unreadable_frontmatter: usize,
}

/// Where the new notes' titles came from.
#[derive(Serialize, Default)]
struct TitleCounts {
    frontmatter: usize,
    file_name: usize,
    /// Another note held the title: the note's path instead.
    path: usize,
    none: usize,
}

#[derive(Serialize, Default)]
struct LinkCounts {
    /// Every `[[link]]` outside code, in every note read.
    found: usize,
    resolved: usize,
    /// Resolve to no note of the folder; they stay text.
    unresolved: usize,
    /// Embeds of a file that is not a note (`![[photo.png]]`).
    attachments: usize,
    /// Resolve to the note itself (`[[#a heading]]`).
    to_itself: usize,
    /// Resolve to a note that is neither in the vault nor in this batch: it
    /// was erased or archived, or the secret scan refuses it.
    to_left_out: usize,
    /// Edges this batch adds.
    new: usize,
}

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
    let folder = std::fs::canonicalize(&path)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
    anyhow::ensure!(folder.is_dir(), "{} is not a folder", path.display());
    let mut counts = NoteCounts::default();
    let notes = read_folder(&folder, &mut counts)?;
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
            .map(|note| (note.path.as_str(), note.markdown.as_str()))
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
    for (note, standing) in notes.iter().zip(&standings) {
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
        let title = choose_title(&vault, &owner, note, &mut taken, &mut titles)?;
        files.push(NoteFile {
            path: note.path.clone(),
            kind,
            title,
            written_at: note.written_at,
            markdown: note.markdown.clone(),
        });
    }
    let (links, link_counts) = resolve_links(&notes, &standings);

    let batch = if files.is_empty() {
        None
    } else {
        let batch = NoteBatch {
            request_id: EntityId::now().to_hex(),
            source_id: NOTES_IMPORT_SOURCE.to_owned(),
            folder: folder.clone(),
            notes: files,
            links,
        };
        let preview = note_imports::preview(&vault, &owner, &batch)?;
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
                preview.digest,
                quoted(&config.vault_path.to_string_lossy()),
            )
        };
        Some(BatchOut {
            file: out.display().to_string(),
            request_id: preview.request_id.clone(),
            approve: decision("approve"),
            decline: decision("decline"),
            digest: preview.digest,
            notes: preview.notes,
            links: preview.links,
        })
    };
    let outcome = Outcome {
        source: NOTES_IMPORT_SOURCE,
        folder,
        notes: counts,
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

/// Every note under `folder`, in path order.
fn read_folder(folder: &Path, counts: &mut NoteCounts) -> anyhow::Result<Vec<Note>> {
    let mut notes = Vec::new();
    super::walk_notes(folder, &mut |shown, file| {
        let Some(path) = relative(folder, shown) else {
            counts.unreadable_name += 1;
            return Ok(());
        };
        let metadata = file.metadata()?;
        if metadata.len() > MAX_NOTE_BYTES {
            counts.too_large += 1;
            return Ok(());
        }
        let text = super::read_limited(file, shown, MAX_NOTE_BYTES)?;
        if text.trim().is_empty() {
            counts.blank += 1;
            return Ok(());
        }
        anyhow::ensure!(
            notes.len() < MAX_NOTES,
            "{} holds more than {MAX_NOTES} notes; nothing was imported. Import one \
             folder under it at a time",
            folder.display()
        );
        // A file whose time cannot be read was written by now at the latest.
        let written_at = metadata
            .modified()
            .unwrap_or_else(|_| SystemTime::now())
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        let (front, body) = markdown::split_frontmatter(&text);
        let Front { title, label } = match front.map(markdown::frontmatter) {
            Some(Some(found)) => found,
            unread => {
                counts.unreadable_frontmatter += usize::from(unread.is_some());
                Front {
                    title: None,
                    label: None,
                }
            }
        };
        let links = markdown::wikilinks(body);
        counts.found += 1;
        notes.push(Note {
            path,
            written_at,
            title,
            label,
            links,
            markdown: text,
        });
        Ok(())
    })?;
    Ok(notes)
}

/// A frontmatter `type` as stdout shows it: a short name as it is, anything
/// else (prose, a long value) as `(other)`, so no note text reaches stdout.
fn shown_label(label: Option<&str>) -> &str {
    match label {
        None => "",
        Some(label)
            if label.len() <= 64
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b)) =>
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

/// `shown` under `folder`, `/`-separated.
/// `None` when a part of it is not UTF-8: the path names the note, so it is
/// never read lossily.
fn relative(folder: &Path, shown: &Path) -> Option<String> {
    let parts = shown
        .strip_prefix(folder)
        .unwrap_or(shown)
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_str()),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    Some(parts.join("/"))
}

/// A title for a new note that no other note holds: the frontmatter's, else
/// the file name, else the path. Titles that differ only in case and spacing
/// are one title.
fn choose_title(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    note: &Note,
    taken: &mut HashSet<String>,
    counts: &mut TitleCounts,
) -> anyhow::Result<Option<String>> {
    let path = note.path.strip_suffix(".md").unwrap_or(&note.path);
    let stem = path.rsplit('/').next().unwrap_or(path);
    let candidates = [
        (note.title.as_deref(), &mut counts.frontmatter),
        (Some(stem), &mut counts.file_name),
        (Some(path), &mut counts.path),
    ];
    for (candidate, count) in candidates {
        let Some(candidate) = candidate else {
            continue;
        };
        let normalized = candidate
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();
        if candidate.trim().is_empty()
            || candidate.len() > MAX_TITLE_BYTES
            || candidate.chars().any(char::is_control)
            || taken.contains(&normalized)
            || !vault.note_title_free(owner, candidate)?
        {
            continue;
        }
        taken.insert(normalized);
        *count += 1;
        return Ok(Some(candidate.to_owned()));
    }
    counts.none += 1;
    Ok(None)
}

/// Resolves every note's links. The batch carries the links that start at a
/// new note, and those of an unchanged note that resolve only now, to a new
/// note: a link an earlier import resolved keeps its note. A changed note's
/// links wait with its text.
fn resolve_links(
    notes: &[Note],
    standings: &[ImportedNoteStanding],
) -> (Vec<NoteLink>, LinkCounts) {
    let now = Index::new(notes, |_| true);
    let before = Index::new(notes, |index| {
        matches!(
            standings[index],
            ImportedNoteStanding::Unchanged | ImportedNoteStanding::Changed
        )
    });
    let mut counts = LinkCounts::default();
    let mut batch = Vec::new();
    let mut seen = HashSet::new();
    for (from, note) in notes.iter().enumerate() {
        for link in &note.links {
            counts.found += 1;
            if link.target.is_empty() {
                counts.to_itself += 1;
                continue;
            }
            let Some(to) = now.resolve(&link.target) else {
                let attachment = link.embed
                    && Path::new(&link.target)
                        .extension()
                        .is_some_and(|extension| !extension.eq_ignore_ascii_case("md"));
                if attachment {
                    counts.attachments += 1;
                } else {
                    counts.unresolved += 1;
                }
                continue;
            };
            counts.resolved += 1;
            if to == from {
                counts.to_itself += 1;
                continue;
            }
            if matches!(
                standings[to],
                ImportedNoteStanding::Removed | ImportedNoteStanding::Refused
            ) {
                counts.to_left_out += 1;
                continue;
            }
            let lands = match standings[from] {
                ImportedNoteStanding::New => true,
                ImportedNoteStanding::Unchanged => {
                    standings[to] == ImportedNoteStanding::New
                        && before.resolve(&link.target).is_none()
                }
                ImportedNoteStanding::Changed
                | ImportedNoteStanding::Removed
                | ImportedNoteStanding::Refused => false,
            };
            if lands && seen.insert((from, to)) {
                batch.push(NoteLink {
                    from: note.path.clone(),
                    to: notes[to].path.clone(),
                });
            }
        }
    }
    counts.new = batch.len();
    (batch, counts)
}

/// The notes a link can name: by path, title or file name, ignoring case and
/// a `.md` ending; the first in path order wins a tie.
struct Index {
    by_path: HashMap<String, usize>,
    by_title: HashMap<String, usize>,
    by_stem: HashMap<String, usize>,
}

impl Index {
    fn new(notes: &[Note], include: impl Fn(usize) -> bool) -> Self {
        let mut index = Self {
            by_path: HashMap::new(),
            by_title: HashMap::new(),
            by_stem: HashMap::new(),
        };
        for (at, note) in notes.iter().enumerate().filter(|(at, _)| include(*at)) {
            index.by_path.entry(key(&note.path)).or_insert(at);
            if let Some(title) = &note.title {
                index.by_title.entry(key(title)).or_insert(at);
            }
            let stem = note.path.rsplit('/').next().unwrap_or(&note.path);
            index.by_stem.entry(key(stem)).or_insert(at);
        }
        index
    }

    fn resolve(&self, target: &str) -> Option<usize> {
        let wanted = key(target);
        [&self.by_path, &self.by_title, &self.by_stem]
            .into_iter()
            .find_map(|names| names.get(&wanted).copied())
    }
}

fn key(name: &str) -> String {
    let name = name.to_lowercase();
    match name.strip_suffix(".md") {
        Some(stem) => stem.to_owned(),
        None => name,
    }
}
