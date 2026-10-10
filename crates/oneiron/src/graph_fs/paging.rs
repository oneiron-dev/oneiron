//! Cursor codecs, page and output builders with byte-cap logic, and day-shard civil-date math.

use std::sync::OnceLock;

use rand_core::{OsRng, RngCore};

use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};

use super::model::{
    GRAPH_FS_MORE_RESERVE_BYTES, GraphFsEntry, GraphFsEntryKind, GraphFsMount, GraphFsOptions,
    GraphFsPage, GraphFsResolver,
};

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

    fn to_bytes(self) -> Vec<u8> {
        let mut bytes = self.learned_at.to_be_bytes().to_vec();
        bytes.extend_from_slice(self.id.as_bytes());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (learned_at, id) = bytes.split_first_chunk::<8>()?;
        Some(Self {
            learned_at: u64::from_be_bytes(*learned_at),
            id: EntityId::from_bytes(id.try_into().ok()?).ok()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct EdgeCursor {
    kind: u8,
    source: EntityId,
}

impl EdgeCursor {
    pub(super) fn port_position(self) -> (u8, EntityId) {
        (self.kind, self.source)
    }
    pub(super) fn from_port(edge: &crate::edge::EdgeInfo) -> Self {
        Self {
            kind: edge.kind as u8,
            source: edge.target,
        }
    }

    fn to_bytes(self) -> Vec<u8> {
        let mut bytes = vec![self.kind];
        bytes.extend_from_slice(self.source.as_bytes());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (kind, source) = bytes.split_first()?;
        Some(Self {
            kind: *kind,
            source: EntityId::from_bytes(source.try_into().ok()?).ok()?,
        })
    }
}

/// A sealed position is its nonce, its tag, then the position's own bytes:
/// 52 bytes for a temporal one, 104 hex characters, which the page's `_more`
/// reserve holds.
const SEALED_NONCE_LEN: usize = 12;
const SEALED_TAG_LEN: usize = 16;

/// This process's key for sealing walk positions. A restart retires every
/// position it sealed, and a listing given one starts again from the top.
fn position_key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut key = [0; 32];
        OsRng.fill_bytes(&mut key);
        key
    })
}

/// Where a scan-bounded walk resumes, as the page hands it out: sealed, so
/// the token names no row. A walk can stop at its scan limit on a row it
/// passed over (sealed custody, a row the reader may not see); its resume
/// point then is that row, and a plain cursor would publish its time and id
/// (ARCH-0051: what a walk withholds stays absent, paging included). A sealed
/// position opens only in this process, for the vault, reader and listing
/// that sealed it.
pub(super) struct CursorScope([u8; 32]);

impl GraphFsResolver<'_, '_> {
    /// The scope of one listing's cursors: this vault, this reader, and the
    /// listing named by `listing` (its path and any parameter it walks by).
    pub(super) fn cursor_scope(&self, listing: &str) -> CursorScope {
        let mut hasher = blake3::Hasher::new_keyed(position_key());
        hasher.update(b"oneiron.graph-fs.cursor.v1");
        hasher.update(self.scoped_read.vault().vault_id().as_bytes());
        for field in [self.scoped_read.actor_key().actor_ref(), listing] {
            hasher.update(&(field.len() as u64).to_be_bytes());
            hasher.update(field.as_bytes());
        }
        CursorScope(*hasher.finalize().as_bytes())
    }
}

impl CursorScope {
    pub(super) fn seal_temporal(&self, cursor: TemporalCursor) -> String {
        self.seal(&cursor.to_bytes())
    }

    pub(super) fn open_temporal(&self, token: Option<&str>) -> Result<Option<TemporalCursor>> {
        token
            .map(|token| {
                self.open(token)
                    .as_deref()
                    .and_then(TemporalCursor::from_bytes)
                    .ok_or_else(invalid_cursor)
            })
            .transpose()
    }

    pub(super) fn seal_edge(&self, cursor: EdgeCursor) -> String {
        self.seal(&cursor.to_bytes())
    }

    pub(super) fn open_edge(&self, token: Option<&str>) -> Result<Option<EdgeCursor>> {
        token
            .map(|token| {
                self.open(token)
                    .as_deref()
                    .and_then(EdgeCursor::from_bytes)
                    .ok_or_else(invalid_cursor)
            })
            .transpose()
    }

    /// Authenticated encryption under a fresh nonce: the tag is a keyed hash
    /// of the nonce and the position, and the position travels XORed with a
    /// stream keyed by that tag. Two tokens never compare equal, even for one
    /// position, so comparing them says nothing about where a walk stopped.
    fn seal(&self, position: &[u8]) -> String {
        let mut nonce = [0; SEALED_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let tag = self.tag(&nonce, position);
        let mut token = nonce.to_vec();
        token.extend_from_slice(&tag);
        token.extend_from_slice(position);
        self.xor_stream(&tag, &mut token[SEALED_NONCE_LEN + SEALED_TAG_LEN..]);
        bytes_to_hex_lower(&token)
    }

    fn open(&self, token: &str) -> Option<Vec<u8>> {
        if !token.len().is_multiple_of(2) || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let bytes = (0..token.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&token[at..at + 2], 16).ok())
            .collect::<Option<Vec<u8>>>()?;
        let (nonce, rest) = bytes.split_first_chunk::<SEALED_NONCE_LEN>()?;
        let (tag, sealed) = rest.split_first_chunk::<SEALED_TAG_LEN>()?;
        let mut position = sealed.to_vec();
        self.xor_stream(tag, &mut position);
        let expected = self.tag(nonce, &position);
        let mismatch = expected
            .iter()
            .zip(tag)
            .fold(0, |acc, (left, right)| acc | (left ^ right));
        (mismatch == 0).then_some(position)
    }

    fn tag(&self, nonce: &[u8], position: &[u8]) -> [u8; SEALED_TAG_LEN] {
        let mut hasher = blake3::Hasher::new_keyed(&self.0);
        hasher.update(b"tag");
        hasher.update(nonce);
        hasher.update(position);
        let mut tag = [0; SEALED_TAG_LEN];
        tag.copy_from_slice(&hasher.finalize().as_bytes()[..SEALED_TAG_LEN]);
        tag
    }

    fn xor_stream(&self, tag: &[u8], bytes: &mut [u8]) {
        let mut hasher = blake3::Hasher::new_keyed(&self.0);
        hasher.update(b"stream");
        hasher.update(tag);
        let mut stream = vec![0; bytes.len()];
        hasher.finalize_xof().fill(&mut stream);
        for (byte, key) in bytes.iter_mut().zip(stream) {
            *byte ^= key;
        }
    }
}

fn invalid_cursor() -> Error {
    Error::InvalidConfig("invalid graph-fs cursor; list again without one".to_owned())
}

pub(super) struct PageBuilder {
    path: String,
    mount: GraphFsMount,
    byte_cap: usize,
    max_entries: usize,
    entries: Vec<GraphFsEntry>,
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
            byte_count: 0,
            last_temporal_cursor: None,
        }
    }

    pub(super) fn try_push(&mut self, entry: GraphFsEntry) -> bool {
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

    pub(super) fn finish(mut self, next_cursor: Option<String>) -> GraphFsPage {
        if let Some(cursor) = next_cursor.clone() {
            let more = GraphFsEntry::cursor(cursor);
            while self.byte_count + more.byte_cost() > self.byte_cap {
                let Some(removed) = self.entries.pop() else {
                    break;
                };
                self.byte_count = self.byte_count.saturating_sub(removed.byte_cost());
            }
            if self.byte_count + more.byte_cost() <= self.byte_cap {
                self.byte_count += more.byte_cost();
                self.entries.push(more);
            }
        }
        GraphFsPage {
            path: self.path,
            mount: self.mount,
            entries: self.entries,
            next_cursor,
            byte_count: self.byte_count,
            read_receipt: None,
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

pub(super) fn format_day_shard(day: u64) -> String {
    let (year, month, day_of_month) = civil_from_days(day as i64);
    format!("{year:04}-{month:02}-{day_of_month:02}")
}

pub(super) fn parse_day_shard(value: &str) -> Result<u64> {
    let mut parts = value.split('-');
    let Some(year) = parts.next() else {
        return Err(Error::InvalidConfig(
            "invalid graph-fs day shard".to_owned(),
        ));
    };
    let Some(month) = parts.next() else {
        return Err(Error::InvalidConfig(
            "invalid graph-fs day shard".to_owned(),
        ));
    };
    let Some(day) = parts.next() else {
        return Err(Error::InvalidConfig(
            "invalid graph-fs day shard".to_owned(),
        ));
    };
    if parts.next().is_some() {
        return Err(Error::InvalidConfig(
            "invalid graph-fs day shard".to_owned(),
        ));
    }
    let year = year
        .parse::<i32>()
        .map_err(|_| Error::InvalidConfig("invalid graph-fs day shard".to_owned()))?;
    let month = month
        .parse::<u32>()
        .map_err(|_| Error::InvalidConfig("invalid graph-fs day shard".to_owned()))?;
    let day = day
        .parse::<u32>()
        .map_err(|_| Error::InvalidConfig("invalid graph-fs day shard".to_owned()))?;
    let days = days_from_civil(year, month, day)
        .ok_or_else(|| Error::InvalidConfig("invalid graph-fs day shard".to_owned()))?;
    u64::try_from(days).map_err(|_| Error::InvalidConfig("invalid graph-fs day shard".to_owned()))
}

fn civil_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year as i32, m as u32, d as u32)
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let year = i64::from(year) - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month = i64::from(month);
    let day = i64::from(day);
    let mp = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    if !(0..=365).contains(&doy) {
        return None;
    }
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let (roundtrip_year, roundtrip_month, roundtrip_day) = civil_from_days(days);
    if roundtrip_year == year as i32 + i32::from(month <= 2)
        && roundtrip_month == month as u32
        && roundtrip_day == day as u32
    {
        Some(days)
    } else {
        None
    }
}
