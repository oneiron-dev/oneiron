//! Resumable depth-first walks for `find` and `grep`. A walk's sealed
//! position names each directory still open, the listing page it reads and
//! how far into that page it got, and where the next file's lines resume, so
//! a page that its output or scan limit cut picks up exactly where it stopped.

use oneiron_base::error::Result;
use oneiron_contracts::claim::ScopedReadReceipt;

use crate::graph_fs::coreutils_text::LinePosition;
use crate::graph_fs::coreutils_text::join_graph_path;
use crate::graph_fs::model::GRAPH_FS_MAX_SCAN_ROWS;
use crate::graph_fs::model::GraphFsEntryKind;
use crate::graph_fs::model::GraphFsPage;
use crate::graph_fs::paging::SealedPosition;

/// A walk's rendered output and the folded receipt of the reads behind it.
pub struct WalkOutput {
    pub bytes: Vec<u8>,
    pub next_cursor: Option<String>,
    pub total: usize,
    pub receipt: Option<ScopedReadReceipt>,
}

/// What a walk does at each visible path.
#[derive(Clone, Copy)]
pub enum WalkVerb<'a> {
    /// Prints the path.
    Find,
    /// Prints the file's lines that hold `pattern`.
    Grep { pattern: &'a str },
}

/// Where a walk resumes.
#[derive(Debug, Default)]
pub struct WalkPosition {
    /// The walk root itself is behind it.
    pub root_done: bool,
    /// The directories still open, the root first.
    pub frames: Vec<WalkFrame>,
    /// Where the next file's lines resume, when a page ended inside it.
    pub lines: Option<LinePosition>,
}

#[derive(Debug)]
pub struct WalkFrame {
    /// The directory's name in its parent; empty for the root.
    pub name: String,
    /// The listing page the frame reads: `None` for the first, else the
    /// cursor the page before it handed out.
    pub page: Option<String>,
    /// How many entries of that page the walk has passed.
    pub passed: usize,
}

impl SealedPosition for WalkPosition {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![u8::from(self.root_done)];
        put_optional(
            &mut bytes,
            self.lines.map(|lines| lines.to_bytes()).as_deref(),
        );
        for frame in &self.frames {
            put_field(&mut bytes, frame.name.as_bytes());
            put_optional(&mut bytes, frame.page.as_deref().map(str::as_bytes));
            bytes.extend_from_slice(&(frame.passed as u64).to_be_bytes());
        }
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut fields = Fields(bytes);
        let root_done = match fields.take::<1>()? {
            [0] => false,
            [1] => true,
            _ => return None,
        };
        let lines = match fields.optional()? {
            Some(lines) => Some(LinePosition::from_bytes(lines)?),
            None => None,
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
pub enum Visited {
    Done,
    Cut(Option<LinePosition>),
}

pub fn fold_receipt(into: &mut Option<ScopedReadReceipt>, later: ScopedReadReceipt) {
    match into {
        Some(receipt) => receipt.restrict_with(&later),
        None => *into = Some(later),
    }
}
