//! Cursor codecs, page and output builders with byte-cap logic, and day-shard civil-date math.

use crate::edge::EDGE_KEY_LEN;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::store::Store;

use super::model::{
    GRAPH_FS_MORE_RESERVE_BYTES, GraphFsEntry, GraphFsEntryKind, GraphFsMount, GraphFsOptions,
    GraphFsPage,
};

use super::readdir::parse_entity_id;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TemporalCursor {
    pub(super) learned_at: u64,
    pub(super) id: EntityId,
}

impl TemporalCursor {
    pub(super) fn parse_optional(value: Option<&str>) -> Result<Option<Self>> {
        value.map(Self::parse).transpose()
    }

    pub(super) fn parse(value: &str) -> Result<Self> {
        let Some((learned, id)) = value.split_once(':') else {
            return Err(Error::InvalidConfig(
                "invalid graph-fs temporal cursor".to_owned(),
            ));
        };
        let learned_at = learned
            .parse::<u64>()
            .map_err(|_| Error::InvalidConfig("invalid graph-fs temporal cursor".to_owned()))?;
        Ok(Self {
            learned_at,
            id: parse_entity_id(id)?,
        })
    }

    pub(super) fn encode(self) -> String {
        format!("{}:{}", self.learned_at, self.id.to_hex())
    }

    pub(super) fn temporal_key(self) -> [u8; 24] {
        Store::encode_temporal_key(self.learned_at, &self.id)
    }

    pub(super) fn next_temporal_key(self) -> [u8; 24] {
        let mut key = self.temporal_key();
        increment_lexicographic_key(&mut key);
        key
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct EdgeCursor {
    kind: u8,
    source: EntityId,
}

impl EdgeCursor {
    pub(super) fn encode(self) -> String {
        format!("{}:{}", self.kind, self.source.to_hex())
    }
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

    pub(super) fn last_temporal_cursor(&self) -> Option<String> {
        self.last_temporal_cursor.map(TemporalCursor::encode)
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

pub(super) fn temporal_cursor_from_key(key: &[u8]) -> Result<TemporalCursor> {
    if key.len() != 24 {
        return Err(Error::CorruptedIndex("temporal learned key"));
    }
    let learned_at = u64::from_be_bytes(
        key[..8]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("temporal learned key"))?,
    );
    let id = EntityId::from_bytes(
        key[8..24]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("temporal learned key"))?,
    )
    .map_err(|_| Error::CorruptedIndex("temporal learned key"))?;
    Ok(TemporalCursor { learned_at, id })
}

pub(super) fn edge_cursor_from_key(key: &[u8]) -> Result<EdgeCursor> {
    if key.len() != EDGE_KEY_LEN {
        return Err(Error::CorruptedIndex("edge record"));
    }
    let kind = key[ENTITY_ID_LEN];
    let source = EntityId::from_bytes(
        key[ENTITY_ID_LEN + 1..]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("edge record"))?,
    )
    .map_err(|_| Error::CorruptedIndex("edge record"))?;
    Ok(EdgeCursor { kind, source })
}

pub(super) fn parse_edge_cursor(value: &str) -> Result<EdgeCursor> {
    let Some((kind, source)) = value.split_once(':') else {
        return Err(Error::InvalidConfig(
            "invalid graph-fs edge cursor".to_owned(),
        ));
    };
    let kind = kind
        .parse::<u8>()
        .map_err(|_| Error::InvalidConfig("invalid graph-fs edge cursor".to_owned()))?;
    Ok(EdgeCursor {
        kind,
        source: parse_entity_id(source)?,
    })
}

pub(super) fn edge_cursor_key(target: &EntityId, cursor: EdgeCursor) -> Vec<u8> {
    let mut key = Vec::with_capacity(EDGE_KEY_LEN);
    key.extend_from_slice(target.as_bytes());
    key.push(cursor.kind);
    key.extend_from_slice(cursor.source.as_bytes());
    key
}

fn increment_lexicographic_key(key: &mut [u8]) {
    for byte in key.iter_mut().rev() {
        if *byte == u8::MAX {
            *byte = 0;
        } else {
            *byte += 1;
            return;
        }
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
