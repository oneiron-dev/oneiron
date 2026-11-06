//! Graph-FS public projection types: caps, host imports, mount and options, entry, page and file, coreutils verb, decision and output, and the resolver with its ScopedRead constructor.

use crate::sandbox_import::SandboxImportClass;
use oneiron_contracts::entity_id::bytes_to_hex_lower;

pub const GRAPH_FS_PROJECTION_VERSION: &str = "graph-fs.v1";
pub const GRAPH_FS_DEFAULT_PAGE_BYTE_CAP: usize = 16 * 1024;
pub const GRAPH_FS_MIN_PAGE_BYTE_CAP: usize = 256;
pub const GRAPH_FS_MAX_PAGE_BYTE_CAP: usize = 256 * 1024;
pub const GRAPH_FS_DEFAULT_MAX_ENTRIES: usize = 512;
pub const GRAPH_FS_MAX_PAGE_ENTRIES: usize = 4096;
pub const GRAPH_FS_MORE_ENTRY: &str = "_more";
pub const GRAPH_FS_COREUTILS_DEFAULT_RESULT_CAP: usize = 512;
pub const GRAPH_FS_COREUTILS_MAX_RESULT_CAP: usize = 4096;

pub const GRAPH_FS_MAX_SCAN_ROWS: usize = 100_000;
/// Room a page keeps for its `_more` entry, sealed cursor included.
pub const GRAPH_FS_MORE_RESERVE_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum GraphFsMount {
    #[default]
    LiveHead,
    ForkHash([u8; 32]),
}

impl GraphFsMount {
    #[must_use]
    pub fn stable_label(self) -> String {
        match self {
            Self::LiveHead => "live-head".to_owned(),
            Self::ForkHash(hash) => format!("forkHash:{}", bytes_to_hex_lower(&hash)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraphFsOptions {
    pub mount: GraphFsMount,
    pub page_byte_cap: usize,
    pub max_entries: usize,
}

impl Default for GraphFsOptions {
    fn default() -> Self {
        Self {
            mount: GraphFsMount::LiveHead,
            page_byte_cap: GRAPH_FS_DEFAULT_PAGE_BYTE_CAP,
            max_entries: GRAPH_FS_DEFAULT_MAX_ENTRIES,
        }
    }
}

impl GraphFsOptions {
    #[must_use]
    pub fn mount(self) -> GraphFsMount {
        self.mount
    }

    #[must_use]
    pub fn page_byte_cap(self) -> usize {
        self.page_byte_cap
    }

    #[must_use]
    pub fn max_entries(self) -> usize {
        self.max_entries
    }

    #[must_use]
    pub fn with_mount(mut self, mount: GraphFsMount) -> Self {
        self.mount = mount;
        self
    }

    #[must_use]
    pub fn with_page_byte_cap(mut self, page_byte_cap: usize) -> Self {
        self.page_byte_cap =
            page_byte_cap.clamp(GRAPH_FS_MIN_PAGE_BYTE_CAP, GRAPH_FS_MAX_PAGE_BYTE_CAP);
        self
    }

    #[must_use]
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries.clamp(1, GRAPH_FS_MAX_PAGE_ENTRIES);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphFsEntryKind {
    Directory,
    File,
    Symlink,
    Cursor,
}

impl GraphFsEntryKind {
    pub fn stable_label(self) -> &'static str {
        match self {
            Self::Directory => "dir",
            Self::File => "file",
            Self::Symlink => "symlink",
            Self::Cursor => "cursor",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphFsEntry {
    pub name: String,
    pub kind: GraphFsEntryKind,
    pub target: Option<String>,
    pub cursor: Option<String>,
    pub byte_len: Option<usize>,
}

impl GraphFsEntry {
    #[must_use]
    pub fn directory(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: GraphFsEntryKind::Directory,
            target: None,
            cursor: None,
            byte_len: None,
        }
    }

    #[must_use]
    pub fn file(name: impl Into<String>, byte_len: Option<usize>) -> Self {
        Self {
            name: name.into(),
            kind: GraphFsEntryKind::File,
            target: None,
            cursor: None,
            byte_len,
        }
    }

    #[must_use]
    pub fn symlink(name: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: GraphFsEntryKind::Symlink,
            target: Some(target.into()),
            cursor: None,
            byte_len: None,
        }
    }

    #[must_use]
    pub fn cursor(cursor: impl Into<String>) -> Self {
        Self {
            name: GRAPH_FS_MORE_ENTRY.to_owned(),
            kind: GraphFsEntryKind::Cursor,
            target: None,
            cursor: Some(cursor.into()),
            byte_len: None,
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn kind(&self) -> GraphFsEntryKind {
        self.kind
    }

    #[must_use]
    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    #[must_use]
    pub fn cursor_token(&self) -> Option<&str> {
        self.cursor.as_deref()
    }

    #[must_use]
    pub fn byte_len(&self) -> Option<usize> {
        self.byte_len
    }

    pub fn byte_cost(&self) -> usize {
        self.kind.stable_label().len()
            + self.name.len()
            + self.target.as_ref().map_or(0, String::len)
            + self.cursor.as_ref().map_or(0, String::len)
            + self.byte_len.map_or(0, decimal_len)
            + 8
    }

    pub fn render_line(&self, out: &mut String) {
        out.push_str("entry\t");
        out.push_str(self.kind.stable_label());
        out.push('\t');
        out.push_str(&self.name);
        if let Some(target) = &self.target {
            out.push_str("\ttarget=");
            out.push_str(target);
        }
        if let Some(cursor) = &self.cursor {
            out.push_str("\tcursor=");
            out.push_str(cursor);
        }
        if let Some(byte_len) = self.byte_len {
            out.push_str("\tbytes=");
            out.push_str(&byte_len.to_string());
        }
        out.push('\n');
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphFsPage {
    pub path: String,
    pub mount: GraphFsMount,
    pub entries: Vec<GraphFsEntry>,
    pub next_cursor: Option<String>,
    pub byte_count: usize,
    pub read_receipt: Option<oneiron_contracts::claim::ScopedReadReceipt>,
    /// Per entry, the cursor of the page that starts right after it in the
    /// listing's own order, for a walk to resume after the last entry it
    /// finished (FIX 4885). Empty for a listing that gives none; never
    /// rendered.
    pub entry_cursors: Vec<Option<String>>,
}

impl GraphFsPage {
    /// Receipt for the scoped point reads behind this listing: an entity
    /// directory's body, or each claim a claims listing names. `None` for a
    /// fixed or policy-scanned listing, which makes no point read.
    #[must_use]
    pub fn read_receipt(&self) -> Option<&oneiron_contracts::claim::ScopedReadReceipt> {
        self.read_receipt.as_ref()
    }

    pub fn with_read_receipt(
        mut self,
        receipt: oneiron_contracts::claim::ScopedReadReceipt,
    ) -> Self {
        self.read_receipt = Some(receipt);
        self
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn mount(&self) -> GraphFsMount {
        self.mount
    }

    #[must_use]
    pub fn entries(&self) -> &[GraphFsEntry] {
        &self.entries
    }

    #[must_use]
    pub fn next_cursor(&self) -> Option<&str> {
        self.next_cursor.as_deref()
    }

    /// The cursor of the page that starts right after entry `index`, when
    /// its listing gives one.
    #[must_use]
    pub fn entry_cursor(&self, index: usize) -> Option<&str> {
        self.entry_cursors.get(index).and_then(Option::as_deref)
    }

    #[must_use]
    pub fn byte_count(&self) -> usize {
        self.byte_count
    }

    #[must_use]
    pub fn render_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str(GRAPH_FS_PROJECTION_VERSION);
        out.push('\n');
        out.push_str("path\t");
        out.push_str(&self.path);
        out.push('\n');
        out.push_str("mount\t");
        out.push_str(&self.mount.stable_label());
        out.push('\n');
        for entry in &self.entries {
            entry.render_line(&mut out);
        }
        out.into_bytes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphFsFile {
    pub path: String,
    pub mount: GraphFsMount,
    pub bytes: Vec<u8>,
}

impl GraphFsFile {
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn mount(&self) -> GraphFsMount {
        self.mount
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphFsCoreutilsVerb {
    Grep,
    Ls,
    Find,
    Cat,
    Head,
    Wc,
}

impl GraphFsCoreutilsVerb {
    pub fn stable_label(self) -> &'static str {
        match self {
            Self::Grep => "grep",
            Self::Ls => "ls",
            Self::Find => "find",
            Self::Cat => "cat",
            Self::Head => "head",
            Self::Wc => "wc",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphFsCoreutilsDecision {
    Pushdown,
    Walk,
}

impl GraphFsCoreutilsDecision {
    pub fn stable_label(self) -> &'static str {
        match self {
            Self::Pushdown => "pushdown",
            Self::Walk => "walk",
        }
    }
}

fn decimal_len(mut value: usize) -> usize {
    let mut len = 1;
    while value >= 10 {
        value /= 10;
        len += 1;
    }
    len
}
