//! Resumable depth-first walks for `find` and `grep`. A walk's sealed
//! position names each directory still open and the listing page it reads,
//! which starts right after the last entry it reached, and the entry a page
//! ended inside with where its lines resume, so a page that its output or
//! scan limit cut picks up where it stopped. The next page finishes that
//! entry first, then the listing goes on after it. An entry written or
//! removed before the resume point shifts nothing (FIX 4885): the page
//! resumes by the listing's own cursor, not by a count into a page read
//! again, and no entry that comes in before the cut one takes its lines.

use crate::error::Result;
use oneiron_contracts::claim::ScopedReadReceipt;

use super::coreutils_text::{LinePosition, join_graph_path, page_lines};
use super::model::{GRAPH_FS_MAX_SCAN_ROWS, GraphFsEntryKind, GraphFsPage, GraphFsResolver};
use super::paging::{CommandOutputBuilder, SealedPosition};

/// A walk's rendered output and the folded receipt of the reads behind it.
pub(super) struct WalkOutput {
    pub(super) bytes: Vec<u8>,
    pub(super) next_cursor: Option<String>,
    pub(super) total: usize,
    pub(super) receipt: Option<ScopedReadReceipt>,
}

/// What a walk does at each visible path.
#[derive(Clone, Copy)]
enum WalkVerb<'a> {
    /// Prints the path.
    Find,
    /// Prints the file's lines that hold `pattern`.
    Grep { pattern: &'a str },
}

/// The first byte of a sealed walk position in this format: one sealed
/// before resume-by-cursor (FIX 4885) does not open.
const WALK_POSITION_FORMAT: u8 = 2;

/// Where a walk resumes.
#[derive(Debug, Default)]
struct WalkPosition {
    /// The walk root itself is behind it.
    root_done: bool,
    /// The directories still open, the root first.
    frames: Vec<WalkFrame>,
    /// The entry a page ended inside, by path, and where its lines resume:
    /// the next page finishes it before it reads any listing, as its frame
    /// has already passed it (a directory's own frame is open already).
    lines: Option<(String, LinePosition)>,
}

#[derive(Debug)]
struct WalkFrame {
    /// The directory's name in its parent; empty for the root.
    name: String,
    /// The listing page the frame reads: `None` for the first, else the
    /// cursor of the page that starts right after the last entry the walk
    /// finished, or the one the page before it handed out.
    page: Option<String>,
    /// How many entries of that page the walk has passed: none when `page`
    /// starts right after the last one it finished.
    passed: usize,
}

impl SealedPosition for WalkPosition {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![WALK_POSITION_FORMAT, u8::from(self.root_done)];
        match &self.lines {
            Some((path, lines)) => {
                bytes.push(1);
                put_field(&mut bytes, path.as_bytes());
                put_field(&mut bytes, &lines.to_bytes());
            }
            None => bytes.push(0),
        }
        for frame in &self.frames {
            put_field(&mut bytes, frame.name.as_bytes());
            put_optional(&mut bytes, frame.page.as_deref().map(str::as_bytes));
            bytes.extend_from_slice(&(frame.passed as u64).to_be_bytes());
        }
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut fields = Fields(bytes);
        if fields.take::<1>()? != [WALK_POSITION_FORMAT] {
            return None;
        }
        let root_done = match fields.take::<1>()? {
            [0] => false,
            [1] => true,
            _ => return None,
        };
        let lines = match fields.take::<1>()? {
            [0] => None,
            [1] => {
                let path = String::from_utf8(fields.field()?.to_vec()).ok()?;
                Some((path, LinePosition::from_bytes(fields.field()?)?))
            }
            _ => return None,
        };
        let mut frames = Vec::new();
        while !fields.0.is_empty() {
            let name = String::from_utf8(fields.field()?.to_vec()).ok()?;
            let page = match fields.optional()? {
                Some(page) => Some(String::from_utf8(page.to_vec()).ok()?),
                None => None,
            };
            let passed = usize::try_from(u64::from_be_bytes(fields.take::<8>()?)).ok()?;
            frames.push(WalkFrame { name, page, passed });
        }
        Some(Self {
            root_done,
            frames,
            lines,
        })
    }
}

fn put_field(bytes: &mut Vec<u8>, field: &[u8]) {
    bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
    bytes.extend_from_slice(field);
}

fn put_optional(bytes: &mut Vec<u8>, field: Option<&[u8]>) {
    match field {
        Some(field) => {
            bytes.push(1);
            put_field(bytes, field);
        }
        None => bytes.push(0),
    }
}

struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.0.split_first_chunk::<N>()?;
        self.0 = rest;
        Some(*head)
    }

    fn field(&mut self) -> Option<&'a [u8]> {
        let len = usize::try_from(u32::from_be_bytes(self.take::<4>()?)).ok()?;
        let (field, rest) = self.0.split_at_checked(len)?;
        self.0 = rest;
        Some(field)
    }

    fn optional(&mut self) -> Option<Option<&'a [u8]>> {
        match self.take::<1>()? {
            [0] => Some(None),
            [1] => self.field().map(Some),
            _ => None,
        }
    }
}

/// What one visit left: the walk goes on, or the page is full and the walk
/// resumes at this path (inside its lines, when it printed some).
enum Visited {
    Done,
    Cut(Option<LinePosition>),
}

/// The page a walk prints into, and what it read.
struct Walk {
    out: CommandOutputBuilder,
    total: usize,
    receipt: Option<ScopedReadReceipt>,
}

impl GraphFsResolver<'_, '_> {
    pub(super) fn find_walk(&self, path: &str, cursor: Option<&str>) -> Result<WalkOutput> {
        self.walk(path, true, WalkVerb::Find, &format!("find {path}"), cursor)
    }

    pub(super) fn grep_walk(
        &self,
        pattern: &str,
        path: &str,
        recursive: bool,
        cursor: Option<&str>,
    ) -> Result<WalkOutput> {
        let flag = if recursive { " -r" } else { "" };
        let listing = format!("grep{flag} {}:{pattern} {path}", pattern.len());
        self.walk(
            path,
            recursive,
            WalkVerb::Grep { pattern },
            &listing,
            cursor,
        )
    }

    /// Walks `root` as `find` does: the root, then each directory's entries
    /// in listing order, every page of the listing, a directory's own tree
    /// right after it. A page ends where its output or its scan limit cut it,
    /// and only then hands out a cursor, sealed to this walk.
    fn walk(
        &self,
        root: &str,
        recursive: bool,
        verb: WalkVerb<'_>,
        listing: &str,
        cursor: Option<&str>,
    ) -> Result<WalkOutput> {
        let scope = self.cursor_scope(listing);
        let mut at: WalkPosition = scope.open(cursor)?.unwrap_or_default();
        let mut walk = Walk {
            out: CommandOutputBuilder::new(self.options),
            total: 0,
            receipt: None,
        };
        let cut = self.walk_from(root, recursive, verb, &mut at, &mut walk)?;
        Ok(WalkOutput {
            bytes: walk.out.into_bytes(),
            next_cursor: cut.then(|| scope.seal(&at)),
            total: walk.total,
            receipt: walk.receipt,
        })
    }

    /// Walks on from `at`, leaving there where the next page resumes.
    /// Returns whether the page was cut before the walk ended.
    fn walk_from(
        &self,
        root: &str,
        recursive: bool,
        verb: WalkVerb<'_>,
        at: &mut WalkPosition,
        walk: &mut Walk,
    ) -> Result<bool> {
        let mut steps = 0;
        if !at.root_done {
            if !self.coreutils_path_visible(root)? {
                return Ok(false);
            }
            let lines = lines_of(&mut at.lines, root);
            if let Visited::Cut(lines) = self.visit(verb, root, false, lines, walk)? {
                at.lines = lines.map(|lines| (root.to_owned(), lines));
                return Ok(true);
            }
            if !recursive {
                return Ok(false);
            }
            at.root_done = true;
            at.frames.push(WalkFrame {
                name: String::new(),
                page: None,
                passed: 0,
            });
        } else if let Some((path, lines)) = at.lines.take() {
            // The entry the last page ended inside: finished first, whatever
            // came into its listing before it since.
            steps += 1;
            if self.coreutils_path_visible(&path)?
                && let Visited::Cut(lines) = self.visit(verb, &path, false, Some(lines), walk)?
            {
                at.lines = lines.map(|lines| (path, lines));
                return Ok(true);
            }
        }
        let mut dirs: Vec<String> = Vec::with_capacity(at.frames.len());
        for frame in &at.frames {
            let dir = match dirs.last() {
                Some(parent) => join_graph_path(parent, &frame.name),
                None => root.to_owned(),
            };
            dirs.push(dir);
        }
        // Each open directory's page as read this call, and the index of the
        // next entry in it.
        let mut pages: Vec<Option<(GraphFsPage, usize)>> = at.frames.iter().map(|_| None).collect();
        while let Some(depth) = at.frames.len().checked_sub(1) {
            if steps >= GRAPH_FS_MAX_SCAN_ROWS {
                return Ok(true);
            }
            let (page, index) = match pages[depth].take() {
                Some(read) => read,
                None => {
                    steps += 1;
                    let page = self.readdir(&dirs[depth], at.frames[depth].page.as_deref())?;
                    if let Some(read) = page.read_receipt() {
                        fold_receipt(&mut walk.receipt, read.clone());
                    }
                    (page, at.frames[depth].passed)
                }
            };
            let entry = page
                .entries()
                .get(index)
                .filter(|entry| entry.kind() != GraphFsEntryKind::Cursor)
                .cloned();
            let after = page.entry_cursor(index).map(str::to_owned);
            let next_page = page.next_cursor().map(str::to_owned);
            pages[depth] = Some((page, index));
            let Some(entry) = entry else {
                // This page is walked: on to the listing's next page, or back up.
                if let Some(next_page) = next_page {
                    let frame = &mut at.frames[depth];
                    frame.page = Some(next_page);
                    frame.passed = 0;
                    pages[depth] = None;
                } else {
                    at.frames.pop();
                    pages.pop();
                    dirs.pop();
                }
                continue;
            };
            steps += 1;
            let child = join_graph_path(&dirs[depth], entry.name());
            let is_dir = entry.kind() == GraphFsEntryKind::Directory;
            if self.coreutils_path_visible(&child)? {
                if let Visited::Cut(lines) = self.visit(verb, &child, is_dir, None, walk)? {
                    // The next page finishes this entry, then goes on after
                    // it: the frame passes it now, and a directory's own
                    // frame opens, so its tree still follows it.
                    if let Some(lines) = lines {
                        pass(&mut at.frames[depth], &mut pages[depth], after);
                        if is_dir {
                            at.frames.push(WalkFrame {
                                name: entry.name().to_owned(),
                                page: None,
                                passed: 0,
                            });
                        }
                        at.lines = Some((child, lines));
                    }
                    return Ok(true);
                }
                if is_dir {
                    pass(&mut at.frames[depth], &mut pages[depth], after);
                    at.frames.push(WalkFrame {
                        name: entry.name().to_owned(),
                        page: None,
                        passed: 0,
                    });
                    pages.push(None);
                    dirs.push(child);
                    continue;
                }
            }
            pass(&mut at.frames[depth], &mut pages[depth], after);
        }
        Ok(false)
    }

    fn visit(
        &self,
        verb: WalkVerb<'_>,
        path: &str,
        is_dir: bool,
        lines: Option<LinePosition>,
        walk: &mut Walk,
    ) -> Result<Visited> {
        match verb {
            WalkVerb::Find => {
                let mut line = path.to_owned();
                line.push('\n');
                let from = lines.map_or(0, |lines| lines.printed);
                match walk.out.push_line(&line, from) {
                    None => {
                        walk.total += 1;
                        Ok(Visited::Done)
                    }
                    Some(printed) => Ok(Visited::Cut(Some(LinePosition { line: 0, printed }))),
                }
            }
            WalkVerb::Grep { .. } if is_dir => Ok(Visited::Done),
            WalkVerb::Grep { pattern } => {
                let read = self.read_file(path)?;
                if let Some(receipt) = read.receipt {
                    fold_receipt(&mut walk.receipt, receipt);
                }
                let Some(file) = read.value else {
                    return Ok(Visited::Done);
                };
                let (matched, next) = page_lines(
                    file.bytes(),
                    lines.unwrap_or_default(),
                    &mut walk.out,
                    usize::MAX,
                    |line| line.contains(pattern).then(|| format!("{path}:{line}\n")),
                );
                walk.total += matched;
                Ok(next.map_or(Visited::Done, |lines| Visited::Cut(Some(lines))))
            }
        }
    }
}

/// The lines to resume in the walk root at `path`: the saved ones, when they
/// belong to it.
fn lines_of(saved: &mut Option<(String, LinePosition)>, path: &str) -> Option<LinePosition> {
    saved
        .take()
        .and_then(|(owner, lines)| (owner == path).then_some(lines))
}

/// Marks the entry at `read`'s index finished: the walk goes on to the next
/// one in the page it read, and a later call resumes right after this one,
/// by its listing's own cursor when it gives one (FIX 4885), else by count.
fn pass(frame: &mut WalkFrame, read: &mut Option<(GraphFsPage, usize)>, after: Option<String>) {
    if let Some((_, index)) = read {
        *index += 1;
    }
    match after {
        Some(after) => {
            frame.page = Some(after);
            frame.passed = 0;
        }
        None => frame.passed += 1,
    }
}

fn fold_receipt(into: &mut Option<ScopedReadReceipt>, later: ScopedReadReceipt) {
    match into {
        Some(receipt) => receipt.restrict_with(&later),
        None => *into = Some(later),
    }
}
