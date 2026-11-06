//! Core half of `graph_fs::paging`: its store-layer items live in `oneiron_store::graph_fs::paging` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::graph_fs::paging::*;

use super::model::{
    GRAPH_FS_MORE_RESERVE_BYTES, GraphFsEntry, GraphFsEntryKind, GraphFsMount, GraphFsOptions,
    GraphFsPage, GraphFsResolver,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use rand_core::{OsRng, RngCore};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TemporalCursor {
    pub(super) learned_at: u64,
    pub(super) id: EntityId,
}

impl TemporalCursor {
    pub(super) fn port_position(self) -> crate::ports::EntityTime {
        crate::ports::EntityTime {
            id: self.id,
            timestamp: self.learned_at,
        }
    }
}

impl SealedPosition for TemporalCursor {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.learned_at.to_be_bytes().to_vec();
        bytes.extend_from_slice(self.id.as_bytes());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (learned_at, id) = bytes.split_first_chunk::<8>()?;
        Some(Self {
            learned_at: u64::from_be_bytes(*learned_at),
            id: entity_id(id)?,
        })
    }
}

/// Where the day listing resumes: after a timeline row, and whether that
/// row's day is already listed (every later row is in that day or after it,
/// so this is all the listing needs to pass over the days it listed). Sealed,
/// it fits the page's `_more` reserve.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct DayPosition {
    pub(super) after: Option<TemporalCursor>,
    pub(super) day_listed: bool,
}

impl SealedPosition for DayPosition {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![u8::from(self.day_listed)];
        if let Some(after) = self.after {
            bytes.extend_from_slice(&after.to_bytes());
        }
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (flag, after) = bytes.split_first()?;
        Some(Self {
            after: match after {
                [] => None,
                after => Some(TemporalCursor::from_bytes(after)?),
            },
            day_listed: match flag {
                0 => false,
                1 => true,
                _ => return None,
            },
        })
    }
}

impl GraphFsResolver<'_, '_> {
    /// The scope of one listing's cursors: this vault, this reader, and the
    /// listing named by `listing` (its path and any parameter it walks by).
    pub(super) fn cursor_scope(&self, listing: &str) -> CursorScope {
        let mut hasher = blake3::Hasher::new_keyed(position_key());
        hasher.update(b"oneiron.graph-fs.cursor.v1");
        hasher.update(self.scoped_read.vault().vault_id().as_bytes());
        let reference = self.options.mount.stable_label();
        hasher.update(&(reference.len() as u64).to_be_bytes());
        hasher.update(reference.as_bytes());
        if let Some((repo, _)) = self.snapshot {
            hasher.update(repo.as_bytes());
        }
        hasher.update(&(self.options.max_entries as u64).to_be_bytes());
        hasher.update(&(self.options.page_byte_cap as u64).to_be_bytes());
        for field in [self.scoped_read.actor_key().actor_ref(), listing] {
            hasher.update(&(field.len() as u64).to_be_bytes());
            hasher.update(field.as_bytes());
        }
        CursorScope(*hasher.finalize().as_bytes())
    }
}

pub(super) struct PageBuilder {
    path: String,
    mount: GraphFsMount,
    byte_cap: usize,
    max_entries: usize,
    entries: Vec<GraphFsEntry>,
    /// Per entry, the cursor of the page right after it
    /// ([`Self::try_push_after`]); `None` for the `_more` entry.
    entry_cursors: Vec<Option<String>>,
    byte_count: usize,
    last_temporal_cursor: Option<TemporalCursor>,
}

impl PageBuilder {
    pub(super) fn new(path: &str, options: GraphFsOptions) -> Self {
        Self {
            path: path.to_owned(),
            mount: options.mount,
            byte_cap: options.page_byte_cap,
            max_entries: options.max_entries,
            entries: Vec::new(),
            entry_cursors: Vec::new(),
            byte_count: 0,
            last_temporal_cursor: None,
        }
    }

    /// Pushes `entry` when it fits, with `after`, the cursor of the page that
    /// starts right after it in the listing's own order: a walk resumes there
    /// once it has finished the entry, so a write before it shifts nothing
    /// (FIX 4885).
    pub(super) fn try_push_after(&mut self, entry: GraphFsEntry, after: String) -> bool {
        if self.entries.len() >= self.max_entries {
            return false;
        }
        let cost = entry.byte_cost();
        let entry_cap = if self.entries.is_empty() {
            self.byte_cap
        } else {
            self.byte_cap.saturating_sub(GRAPH_FS_MORE_RESERVE_BYTES)
        };
        if self.byte_count + cost > entry_cap {
            return false;
        }
        self.byte_count += cost;
        self.entries.push(entry);
        self.entry_cursors.push(Some(after));
        true
    }

    pub(super) fn last_entry_name(&self) -> Option<String> {
        self.entries
            .iter()
            .rev()
            .find(|entry| entry.kind != GraphFsEntryKind::Cursor)
            .map(|entry| entry.name.clone())
    }

    pub(super) fn set_last_temporal_cursor(&mut self, cursor: TemporalCursor) {
        self.last_temporal_cursor = Some(cursor);
    }

    pub(super) fn last_temporal_cursor(&self) -> Option<TemporalCursor> {
        self.last_temporal_cursor
    }

    pub(super) fn finish(mut self, mut next_cursor: Option<String>) -> GraphFsPage {
        if let Some(cursor) = next_cursor.clone() {
            let mut more = GraphFsEntry::cursor(cursor);
            // The first entry always stays: dropping it would hand out a
            // cursor past an entry no page shows. When it and the cursor
            // together pass the cap, the page goes without its `_more` line
            // and still hands its cursor out.
            while self.byte_count + more.byte_cost() > self.byte_cap && self.entries.len() > 1 {
                let Some(removed) = self.entries.pop() else {
                    break;
                };
                self.entry_cursors.pop();
                self.byte_count = self.byte_count.saturating_sub(removed.byte_cost());
                // The page now ends at the entry before: it resumes after
                // that one, when its listing says where that is.
                if let Some(Some(after)) = self.entry_cursors.last() {
                    next_cursor = Some(after.clone());
                    more = GraphFsEntry::cursor(after.clone());
                }
            }
            if self.byte_count + more.byte_cost() <= self.byte_cap {
                self.byte_count += more.byte_cost();
                self.entries.push(more);
                self.entry_cursors.push(None);
            }
        }
        if self.entry_cursors.iter().all(Option::is_none) {
            self.entry_cursors.clear();
        }
        GraphFsPage {
            path: self.path,
            mount: self.mount,
            entries: self.entries,
            next_cursor,
            byte_count: self.byte_count,
            read_receipt: None,
            entry_cursors: self.entry_cursors,
        }
    }
}

pub(super) struct CommandOutputBuilder {
    bytes: Vec<u8>,
    byte_cap: usize,
    max_entries: usize,
    entries: usize,
    full: bool,
}

impl CommandOutputBuilder {
    pub(super) fn new(options: GraphFsOptions) -> Self {
        Self {
            bytes: Vec::new(),
            byte_cap: options.page_byte_cap,
            max_entries: options.max_entries,
            entries: 0,
            full: false,
        }
    }

    pub(super) fn try_push(&mut self, bytes: &[u8]) -> bool {
        if self.entries >= self.max_entries
            || self.bytes.len().saturating_add(bytes.len()) > self.byte_cap
        {
            self.full = true;
            return false;
        }
        self.bytes.extend_from_slice(bytes);
        self.entries += 1;
        true
    }

    /// Pushes `line` from byte `printed` on (what earlier pages printed of
    /// it). Returns `None` once all of it is in, else how much of it has
    /// printed when the page filled: no more, on a page holding other lines;
    /// as much as fits, cut on a character boundary, on an empty one, so a
    /// line longer than any page prints across pages.
    pub(super) fn push_line(&mut self, line: &str, printed: usize) -> Option<usize> {
        let printed = if line.is_char_boundary(printed) {
            printed
        } else {
            0
        };
        let rest = &line[printed..];
        if self.try_push(rest.as_bytes()) {
            return None;
        }
        if self.entries > 0 {
            return Some(printed);
        }
        let mut end = self.byte_cap.min(rest.len());
        while !rest.is_char_boundary(end) {
            end -= 1;
        }
        self.bytes.extend_from_slice(&rest.as_bytes()[..end]);
        self.entries += 1;
        Some(printed + end)
    }

    pub(super) fn entries(&self) -> usize {
        self.entries
    }

    pub(super) fn is_full(&self) -> bool {
        self.full
    }

    pub(super) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
