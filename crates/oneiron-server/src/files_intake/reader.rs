//! The host's reader of a folder of notes, shared by `oneiron import notes`,
//! an attached folder's rescans and a Files source's (OF-554, FIX 6942).
//!
//! It reads every `.md` and `.pdf` file under the folder, never through a
//! link and passing over hidden entries, takes each note's title and kind
//! from its frontmatter, and resolves its `[[links]]` to the folder's other
//! notes. A note keeps its file as written, frontmatter included. Its title
//! is the frontmatter `title` or `name`, else its file name; a title another
//! note already holds falls back to the note's path. A link resolves to a
//! note by path, title or file name, ignoring case; one that resolves to
//! nothing stays text and is counted. A file with another name (a hard link)
//! is passed over: that name may be outside the folder.
//!
//! A PDF's note is the text of its pages, read from its bytes: no frontmatter
//! and no links out, though a note's link can name it. A PDF with no text
//! layer (a scan) reads as blank; one that is encrypted or does not parse is
//! passed over and counted.
//!
//! A file of any size is read (rule 5). Text past the note bound lands in
//! parts: the file's own note holds the first, and each next part is a note of
//! its own at `<path>#part<n>`, titled `<title> (part <n>)`, of the same kind,
//! with a link to the first. The frontmatter stays in the first part; each
//! part's links are those in its own text.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::ops::Range;
use std::path::{Component, Path};
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::ingest::{PdfText, pdf_text};
use oneiron::limit_ask::EngineLimit;
use oneiron::note::{ImportedNoteLink, ImportedNoteStanding, NameOnlyReason};
use serde::Serialize;

use super::ImportWarning;
use super::markdown::{self, Front, Link};

/// The largest note the vault holds; a file's text past it lands in parts.
const MAX_NOTE_BYTES: usize = 1024 * 1024;

/// What joins a file's path to a continuation part's number in the part's
/// path: `<path>#part<n>`. No file the walk reads ends that way.
const PART_MARK: &str = "#part";

/// The longest title a note keeps.
const MAX_TITLE_BYTES: usize = 256;

/// One file, or one part of a file past the note bound, read and parsed.
pub(crate) struct Note {
    /// Under the folder, `/`-separated; a continuation part's is
    /// `<path>#part<n>`.
    pub(crate) path: String,
    /// The file as written; a PDF's text. A part's share of either.
    pub(crate) markdown: String,
    /// The hash of a PDF's bytes: its revision, which its text alone does
    /// not show.
    pub(crate) raw_hash: Option<String>,
    pub(crate) written_at: u64,
    /// The frontmatter's `title` or `name`.
    pub(crate) title: Option<String>,
    /// The frontmatter's `type` or `metadata.type`.
    pub(crate) label: Option<String>,
    /// The frontmatter as it decodes, for the secret scan.
    pub(crate) decoded: String,
    links: Vec<Link>,
    /// For a continuation part, its file's path: the first part's note.
    pub(crate) part_of: Option<String>,
}

impl Note {
    /// The file this note was read from, under the folder.
    pub(crate) fn file(&self) -> &str {
        self.part_of.as_deref().unwrap_or(&self.path)
    }
}

#[derive(Serialize, Default)]
pub(crate) struct NoteCounts {
    /// Notes read from the folder, continuation parts included.
    pub(crate) found: usize,
    /// Continuation parts of files whose text is past the note bound.
    pub(crate) parts: usize,
    /// Bytes of text the notes hold, decoded frontmatter included: what
    /// `limits.import_folder_text_bytes` measures.
    pub(crate) text_bytes: u64,
    pub(crate) new: usize,
    pub(crate) unchanged: usize,
    pub(crate) changed: usize,
    pub(crate) removed: usize,
    /// New, but the vault's secret scan would refuse their text; `oneiron
    /// secret-scan off` lets them in.
    pub(crate) refused: usize,
    /// Files passed over: blank.
    pub(crate) blank: usize,
    /// Files passed over because they have another name (a hard link),
    /// which may be outside the folder.
    pub(crate) hard_linked: usize,
    /// Files whose name is not UTF-8: it could not name its note.
    pub(crate) unreadable_name: usize,
    /// Notes whose frontmatter is not YAML: title from the file name, kind
    /// from `--kind`.
    pub(crate) unreadable_frontmatter: usize,
    /// PDFs passed over: encrypted, or not a PDF the reader parses.
    pub(crate) unreadable_pdf: usize,
    /// PDFs read in part: a page past the codec's bound, or a font the reader
    /// cannot map. The rest of their text lands.
    pub(crate) partly_read_pdf: usize,
}

/// Where the new notes' titles came from.
#[derive(Serialize, Default)]
pub(crate) struct TitleCounts {
    pub(crate) frontmatter: usize,
    pub(crate) file_name: usize,
    /// Another note held the title: the note's path instead.
    pub(crate) path: usize,
    pub(crate) none: usize,
}

#[derive(Serialize, Default)]
pub(crate) struct LinkCounts {
    /// Every `[[link]]` outside code, in every note read.
    pub(crate) found: usize,
    pub(crate) resolved: usize,
    /// Resolve to no note of the folder; they stay text.
    pub(crate) unresolved: usize,
    /// Embeds of a file that is not a note (`![[photo.png]]`).
    pub(crate) attachments: usize,
    /// Resolve to the note itself (`[[#a heading]]`).
    pub(crate) to_itself: usize,
    /// Resolve to a note that is neither in the vault nor in this batch: it
    /// was erased or archived, or the secret scan refuses it.
    pub(crate) to_left_out: usize,
    /// From a continuation part to its file's first part.
    pub(crate) parts: usize,
    /// Edges this batch adds.
    pub(crate) new: usize,
}

/// The title each changed note had when it landed: links resolved by it then.
pub(crate) fn earlier_titles(
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
pub(crate) fn crossed_rows(vault: &oneiron::Vault, counts: &NoteCounts) -> Vec<ImportWarning> {
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
        Some(ImportWarning::LimitCrossed {
            row: row.key(),
            limit,
            observed,
        })
    })
    .collect()
}

/// Every note under `folder`, in path order, a file past the note bound as
/// its parts.
pub(crate) fn read_folder(folder: &Path, counts: &mut NoteCounts) -> anyhow::Result<Vec<Note>> {
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
        let kind = if Path::new(&path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("pdf"))
        {
            TextKind::Pdf
        } else {
            TextKind::Markdown
        };
        let bytes = read_all(file, shown)?;
        // A file with no text is passed over, and counted.
        read_text(
            path,
            bytes,
            written_at(&metadata),
            kind,
            counts,
            &mut notes,
        );
        Ok(())
    })?;
    Ok(notes)
}

/// How a file's bytes hold its text.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum TextKind {
    /// Markdown: frontmatter and `[[links]]`, read lossily as UTF-8.
    Markdown,
    /// A PDF's text layer, read from its bytes.
    Pdf,
    /// UTF-8 text whole (a Files source's text and code): no frontmatter,
    /// no links out.
    Plain,
}

/// When a file was last written (seconds). A file whose time cannot be read
/// was written by now at the latest.
pub(super) fn written_at(metadata: &std::fs::Metadata) -> u64 {
    metadata
        .modified()
        .unwrap_or_else(|_| SystemTime::now())
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// The notes one file's `bytes` hold, pushed onto `notes` (a file past the
/// note bound as its parts), or why it holds none: no text, or none that
/// reads.
pub(super) fn read_text(
    path: String,
    bytes: Vec<u8>,
    written_at: u64,
    kind: TextKind,
    counts: &mut NoteCounts,
    notes: &mut Vec<Note>,
) -> Option<NameOnlyReason> {
    let (text, raw_hash) = match kind {
        // Bytes, never the lossy text read: a PDF is binary.
        TextKind::Pdf => match pdf_text(&bytes) {
            Ok(PdfText { text, unread }) => {
                if unread > 0 {
                    if text.trim().is_empty() {
                        counts.unreadable_pdf += 1;
                        return Some(NameOnlyReason::Unreadable);
                    }
                    counts.partly_read_pdf += 1;
                }
                (text, Some(blake3::hash(&bytes).to_hex().to_string()))
            }
            Err(_) => {
                counts.unreadable_pdf += 1;
                return Some(NameOnlyReason::Unreadable);
            }
        },
        TextKind::Markdown => (
            String::from_utf8(bytes)
                .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned()),
            None,
        ),
        TextKind::Plain => match String::from_utf8(bytes) {
            Ok(text) if !text.contains('\0') => (text, None),
            _ => return Some(NameOnlyReason::NotText),
        },
    };
    if text.trim().is_empty() {
        counts.blank += 1;
        return Some(NameOnlyReason::Empty);
    }
    let (front, body) = if kind == TextKind::Markdown {
        markdown::split_frontmatter(&text)
    } else {
        (None, text.as_str())
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
            if kind == TextKind::Markdown {
                markdown::wikilinks(&text[range.start.max(body_at)..range.end.max(body_at)])
            } else {
                Vec::new()
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
    None
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
/// (`<file>#part<n>`) file, else the path itself. A Files source's part may
/// continue a file of any name, its text or code as well as its notes.
pub(super) fn file_of(path: &str) -> &str {
    path.rsplit_once(PART_MARK)
        .filter(|(file, number)| {
            !file.is_empty()
                && !number.is_empty()
                && number.bytes().all(|byte| byte.is_ascii_digit())
        })
        .map_or(path, |(file, _)| file)
}

/// Reads all of `reader`, as it is.
pub(super) fn read_all(mut reader: impl Read, path: &Path) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
    Ok(bytes)
}

/// `shown` under `folder`, `/`-separated.
/// `None` when a part of it is not UTF-8: the path names the note, so it is
/// never read lossily.
pub(super) fn relative(folder: &Path, shown: &Path) -> Option<String> {
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
pub(crate) fn choose_title(
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
pub(crate) fn resolve_links(
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
