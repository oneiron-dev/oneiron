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
use std::time::{Instant, UNIX_EPOCH};

use oneiron::EntityId;
use oneiron::consent::AuthenticatedOwner;
use oneiron::note::{ImportedNoteStanding, NOTES_IMPORT_SOURCE};
use serde::Serialize;

use crate::cli::ImportNotesArgs;
use crate::config::resolve_serve_config;
use crate::owner::note_imports::{self, NoteBatch, NoteFile, NoteLink};

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

/// A `[[link]]` as written: its target, and whether it embeds (`![[...]]`).
struct Link {
    target: String,
    embed: bool,
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
    /// New notes per frontmatter `type`; `""` when they have none.
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
    let config = resolve_serve_config(&serve)?;
    let folder = std::fs::canonicalize(&path)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
    anyhow::ensure!(folder.is_dir(), "{} is not a folder", path.display());
    let mut counts = NoteCounts::default();
    let notes = read_folder(&folder, &mut counts)?;
    super::progress(&format!("read {} note(s)", notes.len()));
    let folder = folder.to_string_lossy().into_owned();

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
            .entry(note.label.clone().unwrap_or_default())
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
        let config_flag = serve
            .config
            .as_ref()
            .map(|config| format!(" --config {}", config.display()))
            .unwrap_or_default();
        let decision = |verb: &str| {
            format!(
                "oneiron import {verb} {} --digest {}{config_flag}",
                out.display(),
                preview.digest
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
        let written_at = metadata
            .modified()
            .ok()
            .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |since| since.as_secs());
        let (front, body) = split_frontmatter(&text);
        let (title, label) = match front.map(frontmatter) {
            Some(None) => {
                counts.unreadable_frontmatter += 1;
                (None, None)
            }
            Some(Some(found)) => found,
            None => (None, None),
        };
        let links = wikilinks(body);
        counts.found += 1;
        notes.push(Note {
            path: relative(folder, shown),
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

/// `shown` under `folder`, `/`-separated.
fn relative(folder: &Path, shown: &Path) -> String {
    shown
        .strip_prefix(folder)
        .unwrap_or(shown)
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// The YAML a note opens with, between a first line `---` and the next line
/// `---` or `...`, and the body after it.
fn split_frontmatter(text: &str) -> (Option<&str>, &str) {
    let rest = text.strip_prefix('\u{feff}').unwrap_or(text);
    let Some(after) = rest
        .strip_prefix("---\n")
        .or_else(|| rest.strip_prefix("---\r\n"))
    else {
        return (None, text);
    };
    let mut offset = 0;
    for line in after.split_inclusive('\n') {
        let bare = line.trim_end_matches(['\r', '\n']);
        if bare == "---" || bare == "..." {
            return (Some(&after[..offset]), &after[offset + line.len()..]);
        }
        offset += line.len();
    }
    (None, text)
}

/// The frontmatter's title (`title`, else `name`) and type (`type`, else
/// `metadata.type`); `None` when it is not YAML.
fn frontmatter(yaml: &str) -> Option<(Option<String>, Option<String>)> {
    let value: serde_yaml_ng::Value = serde_yaml_ng::from_str(yaml).ok()?;
    let text = |value: Option<&serde_yaml_ng::Value>| {
        value
            .and_then(serde_yaml_ng::Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_owned)
    };
    let title = text(value.get("title")).or_else(|| text(value.get("name")));
    let label = text(value.get("type")).or_else(|| {
        text(
            value
                .get("metadata")
                .and_then(|metadata| metadata.get("type")),
        )
    });
    Some((title, label))
}

/// Every `[[link]]` in `body` outside fenced code and inline code.
fn wikilinks(body: &str) -> Vec<Link> {
    let mut links = Vec::new();
    let mut fence: Option<(char, usize)> = None;
    for line in body.lines() {
        let trimmed = line.trim_start();
        let run = |mark: char| trimmed.chars().take_while(|&c| c == mark).count();
        if let Some((mark, opened)) = fence {
            if run(mark) >= opened && trimmed.trim_start_matches(mark).trim().is_empty() {
                fence = None;
            }
            continue;
        }
        if let Some(mark) = ['`', '~'].into_iter().find(|&mark| run(mark) >= 3) {
            fence = Some((mark, run(mark)));
            continue;
        }
        line_links(line, &mut links);
    }
    links
}

fn line_links(line: &str, links: &mut Vec<Link>) {
    let bytes = line.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'`' {
            // An inline code span runs to the next run of as many backticks.
            let ticks = bytes[at..].iter().take_while(|&&b| b == b'`').count();
            let fence = "`".repeat(ticks);
            let after = at + ticks;
            at = line[after..]
                .match_indices(&fence)
                .find(|(found, _)| {
                    bytes.get(after + found + ticks) != Some(&b'`')
                        && (*found == 0 || bytes[after + found - 1] != b'`')
                })
                .map_or(after, |(found, _)| after + found + ticks);
            continue;
        }
        if bytes[at..].starts_with(b"[[")
            && let Some(close) = line[at + 2..].find("]]")
        {
            let inner = &line[at + 2..at + 2 + close];
            if !inner.contains('[') {
                links.push(Link {
                    target: inner
                        .split('|')
                        .next()
                        .and_then(|target| target.split(['#', '^']).next())
                        .unwrap_or_default()
                        .trim()
                        .to_owned(),
                    embed: at > 0 && bytes[at - 1] == b'!',
                });
                at += close + 4;
                continue;
            }
        }
        at += 1;
    }
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

/// Resolves every note's links. The batch carries the links that end at a
/// new note or start at one; a changed note's links wait with its text.
fn resolve_links(
    notes: &[Note],
    standings: &[ImportedNoteStanding],
) -> (Vec<NoteLink>, LinkCounts) {
    let key = |text: &str| text.strip_suffix(".md").unwrap_or(text).to_lowercase();
    let mut by_path = HashMap::new();
    let mut by_title: HashMap<String, Vec<usize>> = HashMap::new();
    let mut by_stem: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, note) in notes.iter().enumerate() {
        by_path.insert(key(&note.path), index);
        if let Some(title) = &note.title {
            by_title
                .entry(title.to_lowercase())
                .or_default()
                .push(index);
        }
        let stem = note.path.rsplit('/').next().unwrap_or(&note.path);
        by_stem.entry(key(stem)).or_default().push(index);
    }
    let resolve = |target: &str| -> Option<usize> {
        let wanted = key(target);
        by_path.get(&wanted).copied().or_else(|| {
            [&by_title, &by_stem]
                .into_iter()
                .find_map(|index| index.get(&wanted))
                .and_then(|found| found.first().copied())
        })
    };
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
            let attachment = link.embed
                && Path::new(&link.target)
                    .extension()
                    .is_some_and(|extension| extension != "md");
            let Some(to) = resolve(&link.target) else {
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
                ImportedNoteStanding::Unchanged => standings[to] == ImportedNoteStanding::New,
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
