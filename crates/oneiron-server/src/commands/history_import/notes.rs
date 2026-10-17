//! `oneiron import notes <folder> --out <batch>`: a folder of linked markdown
//! notes, as one batch the owner approves or declines whole (ARCH-0027,
//! ARCH-0032).
//!
//! This is the host's half. It reads every `.md` and `.pdf` file under the
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
use std::io::{self, Read, Write};
use std::ops::Range;
use std::path::{Component, Path};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use oneiron::EntityId;
use oneiron::ingest::{PdfText, pdf_text};
use oneiron::limit_ask::EngineLimit;
use oneiron::note::{
    ImportedFile, ImportedNote, ImportedNoteBatch, ImportedNoteLink, ImportedNoteStanding,
    NOTES_IMPORT_SOURCE,
};
use serde::Serialize;

use crate::cli::ImportNotesArgs;
use crate::config::resolve_serve_config;
use crate::owner::note_imports::{self, NoteBatch};

pub(in crate::commands) mod folder;
mod markdown;
use markdown::{Front, Link};

/// The largest note the vault holds; a file's text past it lands in parts.
const MAX_NOTE_BYTES: usize = 1024 * 1024;

/// What joins a file's path to a continuation part's number in the part's
/// path: `<path>#part<n>`. No file the walk reads ends that way.
const PART_MARK: &str = "#part";

/// The longest title a note keeps.
const MAX_TITLE_BYTES: usize = 256;

/// One file, or one part of a file past the note bound, read and parsed.
struct Note {
    /// Under the folder, `/`-separated; a continuation part's is
    /// `<path>#part<n>`.
    path: String,
    /// The file as written; a PDF's text. A part's share of either.
    markdown: String,
    /// The hash of a PDF's bytes: its revision, which its text alone does
    /// not show.
    raw_hash: Option<String>,
    written_at: u64,
    /// The frontmatter's `title` or `name`.
    title: Option<String>,
    /// The frontmatter's `type` or `metadata.type`.
    label: Option<String>,
    /// The frontmatter as it decodes, for the secret scan.
    decoded: String,
    links: Vec<Link>,
    /// For a continuation part, its file's path: the first part's note.
    part_of: Option<String>,
}

impl Note {
    /// The file this note was read from, under the folder.
    fn file(&self) -> &str {
        self.part_of.as_deref().unwrap_or(&self.path)
    }
}

#[derive(Serialize, Default)]
struct NoteCounts {
    /// Notes read from the folder, continuation parts included.
    found: usize,
    /// Continuation parts of files whose text is past the note bound.
    parts: usize,
    /// Bytes of text the notes hold, decoded frontmatter included: what
    /// `limits.import_folder_text_bytes` measures.
    text_bytes: u64,
    new: usize,
    unchanged: usize,
    changed: usize,
    removed: usize,
    /// New, but the vault's secret scan would refuse their text; `oneiron
    /// secret-scan off` lets them in.
    refused: usize,
    /// Files passed over: blank.
    blank: usize,
    /// Files passed over because they have another name (a hard link),
    /// which may be outside the folder.
    hard_linked: usize,
    /// Files whose name is not UTF-8: it could not name its note.
    unreadable_name: usize,
    /// Notes whose frontmatter is not YAML: title from the file name, kind
    /// from `--kind`.
    unreadable_frontmatter: usize,
    /// PDFs passed over: encrypted, or not a PDF the reader parses.
    unreadable_pdf: usize,
    /// PDFs read in part: a page past the codec's bound, or a font the reader
    /// cannot map. The rest of their text lands.
    partly_read_pdf: usize,
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
    /// From a continuation part to its file's first part.
    parts: usize,
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

/// The title each changed note had when it landed: links resolved by it then.
fn earlier_titles(
    vault: &oneiron::Vault,
    folder: &str,
    notes: &[Note],
    standings: &[ImportedNoteStanding],
) -> anyhow::Result<Vec<Option<String>>> {
    notes
        .iter()
        .zip(standings)
        .map(|(note, standing)| {
            // A part's title is not in its text.
            if *standing != ImportedNoteStanding::Changed || note.part_of.is_some() {
                return Ok(None);
            }
            let id = oneiron::Vault::imported_note_id(folder, &note.path)?;
            Ok(vault.read_note(&id)?.and_then(|landed| {
                markdown::split_frontmatter(&landed.markdown)
                    .0
                    .and_then(markdown::frontmatter)
                    .and_then(|front| front.title)
            }))
        })
        .collect()
}

/// Measures what a folder's read held against its `[limits]` rows (OF-520):
/// past one, the vault's port asks whether everything is okay, and the folder
/// is imported whole all the same. Each crossing is a warning for stdout.
fn crossed_rows(vault: &oneiron::Vault, counts: &NoteCounts) -> Vec<super::ImportWarning> {
    [
        (EngineLimit::ImportFolderTextBytes, counts.text_bytes),
        (
            EngineLimit::ImportFolderNotes,
            u64::try_from(counts.found).unwrap_or(u64::MAX),
        ),
    ]
    .into_iter()
    .filter_map(|(row, observed)| {
        let limit = vault.measure_limit(row, observed)?;
        Some(super::ImportWarning::LimitCrossed {
            row: row.key(),
            limit,
            observed,
        })
    })
    .collect()
}

/// Every note under `folder`, in path order, a file past the note bound as
/// its parts.
fn read_folder(folder: &Path, counts: &mut NoteCounts) -> anyhow::Result<Vec<Note>> {
    let mut notes = Vec::new();
    super::walk_notes(folder, &mut |shown, file| {
        let Some(path) = relative(folder, shown) else {
            counts.unreadable_name += 1;
            return Ok(());
        };
        // Of the open file, so a name swapped after the walk listed it
        // changes nothing.
        let metadata = file.metadata()?;
        if super::hard_linked(&metadata) {
            counts.hard_linked += 1;
            return Ok(());
        }
        let pdf = Path::new(&path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("pdf"));
        let bytes = read_all(file, shown)?;
        let (text, raw_hash) = if pdf {
            // Bytes, never the lossy text read: a PDF is binary.
            match pdf_text(&bytes) {
                Ok(PdfText { text, unread }) => {
                    if unread > 0 {
                        if text.trim().is_empty() {
                            counts.unreadable_pdf += 1;
                            return Ok(());
                        }
                        counts.partly_read_pdf += 1;
                    }
                    (text, Some(blake3::hash(&bytes).to_hex().to_string()))
                }
                Err(_) => {
                    counts.unreadable_pdf += 1;
                    return Ok(());
                }
            }
        } else {
            let text = String::from_utf8(bytes)
                .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned());
            (text, None)
        };
        if text.trim().is_empty() {
            counts.blank += 1;
            return Ok(());
        }
        // A file whose time cannot be read was written by now at the latest.
        let written_at = metadata
            .modified()
            .unwrap_or_else(|_| SystemTime::now())
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        let (front, body) = if pdf {
            (None, text.as_str())
        } else {
            markdown::split_frontmatter(&text)
        };
        // The body is the text's tail.
        let body_at = text.len() - body.len();
        let Front {
            title,
            label,
            mut decoded,
        } = match front.map(markdown::frontmatter) {
            Some(Some(found)) => found,
            unread => {
                counts.unreadable_frontmatter += usize::from(unread.is_some());
                Front {
                    title: None,
                    label: None,
                    decoded: String::new(),
                }
            }
        };
        counts.text_bytes = counts
            .text_bytes
            .saturating_add(u64::try_from(text.len() + decoded.len()).unwrap_or(u64::MAX));
        let ranges = parts(&text, MAX_NOTE_BYTES);
        let links = ranges
            .iter()
            .map(|range| {
                if pdf {
                    Vec::new()
                } else {
                    markdown::wikilinks(&text[range.start.max(body_at)..range.end.max(body_at)])
                }
            })
            .collect::<Vec<_>>();
        let stem = without_extension(&path);
        let named = title
            .clone()
            .unwrap_or_else(|| stem.rsplit('/').next().unwrap_or(stem).to_owned());
        let texts = if ranges.len() == 1 && ranges[0].len() == text.len() {
            vec![text]
        } else {
            ranges
                .iter()
                .map(|range| text[range.clone()].to_owned())
                .collect()
        };
        for (at, (markdown, links)) in texts.into_iter().zip(links).enumerate() {
            counts.found += 1;
            notes.push(if at == 0 {
                Note {
                    path: path.clone(),
                    raw_hash: raw_hash.clone(),
                    written_at,
                    title: title.clone(),
                    label: label.clone(),
                    decoded: std::mem::take(&mut decoded),
                    links,
                    markdown,
                    part_of: None,
                }
            } else {
                counts.parts += 1;
                let number = at + 1;
                Note {
                    path: format!("{path}{PART_MARK}{number}"),
                    raw_hash: raw_hash.clone(),
                    written_at,
                    title: Some(format!("{named} (part {number})")),
                    label: label.clone(),
                    decoded: String::new(),
                    links,
                    markdown,
                    part_of: Some(path.clone()),
                }
            });
        }
        Ok(())
    })?;
    Ok(notes)
}

/// `text` in parts of at most `bound` bytes, in order. Each is cut on a
/// character boundary, at the last line break in its second half when it
/// has one, so a line stays whole where it can. A blank part holds nothing
/// and is left out. Text within the bound is one part.
fn parts(text: &str, bound: usize) -> Vec<Range<usize>> {
    let mut parts = Vec::new();
    let mut start = 0;
    while text.len() - start > bound {
        let mut end = start + bound;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        if let Some(line) = text.as_bytes()[start..end]
            .iter()
            .rposition(|&byte| byte == b'\n')
            .filter(|&line| line >= bound / 2)
        {
            end = start + line + 1;
        }
        parts.push(start..end);
        start = end;
    }
    parts.push(start..text.len());
    parts.retain(|part| !text[part.clone()].trim().is_empty());
    parts
}

/// The file a ledger path names: a continuation part's
/// (`<file>#part<n>`) file, else the path itself.
fn file_of(path: &str) -> &str {
    path.rsplit_once(PART_MARK)
        .filter(|(file, number)| {
            !number.is_empty()
                && number.bytes().all(|byte| byte.is_ascii_digit())
                && without_extension(file).len() < file.len()
        })
        .map_or(path, |(file, _)| file)
}

/// Reads all of `reader`, as it is.
fn read_all(mut reader: impl Read, path: &Path) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
    Ok(bytes)
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

/// A title for a new note that no other note of `folder`'s import holds: the
/// frontmatter's, else the file name, else the path. Titles that differ only
/// in case and spacing are one title.
fn choose_title(
    vault: &oneiron::Vault,
    folder: &str,
    note: &Note,
    taken: &mut HashSet<String>,
    counts: &mut TitleCounts,
) -> anyhow::Result<Option<String>> {
    let path = without_extension(&note.path);
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
            || !vault.imported_note_title_free(folder, candidate)?
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

/// `path` without its `.md` or `.pdf`, in any case.
fn without_extension(path: &str) -> &str {
    for extension in [".md", ".pdf"] {
        if let Some(at) = path.len().checked_sub(extension.len())
            && path
                .get(at..)
                .is_some_and(|end| end.eq_ignore_ascii_case(extension))
        {
            return &path[..at];
        }
    }
    path
}

/// Resolves every note's links. The batch carries the links that start at a
/// new note, and those of an unchanged note that resolve only now, to a new
/// note: a link an earlier import resolved keeps its note. What resolved
/// before is judged from the notes the folder still holds, a changed one by
/// the title it landed with, so a note whose file left the folder no longer
/// holds its name. A changed note's links wait with its text. A continuation
/// part links to its file's first part, which it continues.
fn resolve_links(
    notes: &[Note],
    standings: &[ImportedNoteStanding],
    earlier_titles: &[Option<String>],
) -> (Vec<ImportedNoteLink>, LinkCounts) {
    let now = Index::new(notes, |_| true, |at| notes[at].title.as_deref());
    let before = Index::new(
        notes,
        |at| {
            matches!(
                standings[at],
                ImportedNoteStanding::Unchanged | ImportedNoteStanding::Changed
            )
        },
        |at| match standings[at] {
            ImportedNoteStanding::Changed => earlier_titles[at].as_deref(),
            _ => notes[at].title.as_deref(),
        },
    );
    let first_parts = notes
        .iter()
        .enumerate()
        .filter(|(_, note)| note.part_of.is_none())
        .map(|(at, note)| (note.path.as_str(), at))
        .collect::<HashMap<_, _>>();
    let mut counts = LinkCounts::default();
    let mut batch = Vec::new();
    let mut seen = HashSet::new();
    for (from, note) in notes.iter().enumerate() {
        if let Some(&to) = note
            .part_of
            .as_deref()
            .and_then(|file| first_parts.get(file))
        {
            counts.parts += 1;
            let lands = !matches!(
                standings[to],
                ImportedNoteStanding::Removed | ImportedNoteStanding::Refused
            ) && match standings[from] {
                ImportedNoteStanding::New => true,
                ImportedNoteStanding::Unchanged => standings[to] == ImportedNoteStanding::New,
                ImportedNoteStanding::Changed
                | ImportedNoteStanding::Removed
                | ImportedNoteStanding::Refused => false,
            };
            if lands && seen.insert((from, to)) {
                batch.push(ImportedNoteLink {
                    from: note.path.clone(),
                    to: notes[to].path.clone(),
                });
            }
        }
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
                batch.push(ImportedNoteLink {
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
    fn new<'a>(
        notes: &'a [Note],
        include: impl Fn(usize) -> bool,
        title: impl Fn(usize) -> Option<&'a str>,
    ) -> Self {
        let mut index = Self {
            by_path: HashMap::new(),
            by_title: HashMap::new(),
            by_stem: HashMap::new(),
        };
        for (at, note) in notes.iter().enumerate().filter(|(at, _)| include(*at)) {
            index.by_path.entry(key(&note.path)).or_insert(at);
            if let Some(title) = title(at) {
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
