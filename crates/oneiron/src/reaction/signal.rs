//! The agent signal feed: new reactions to a person's own messages since a
//! time, read from the reaction claims themselves so a replica answers the
//! same as the writer. A put signals at its learned time, a removal at its
//! retraction time.
//!
//! The feed reads every record the person authored, however many: the count
//! only feeds the advisory [`EngineScan::EdgePeerRows`] check for the person's
//! `AuthoredBy` edges, which never refuses the read.
use std::collections::BTreeMap;

use super::chain::{admission_in, reactions_on_in};
use crate::conversation::AudienceCache;
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::scan_check::{EngineScan, ScanCount};
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};

/// Largest page one call returns. A larger ask is served in pages of this
/// size, each with the cursor of the next.
pub const MAX_REACTION_SIGNAL_PAGE: usize = 1000;
const CURSOR_BYTES: usize = 25;

/// A put or a removal of a reaction to one of the reader's messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactionSignal {
    pub reaction: EntityId,
    pub message: EntityId,
    pub by: EntityId,
    pub glyph: String,
    pub occurred_at: u64,
    pub recorded_at: u64,
    pub revoked: bool,
}

impl ReactionSignal {
    /// `reaction.put` or `reaction.revoked`.
    #[must_use]
    pub const fn event(&self) -> &'static str {
        if self.revoked {
            "reaction.revoked"
        } else {
            "reaction.put"
        }
    }

    fn key(&self) -> [u8; CURSOR_BYTES] {
        let mut key = [0u8; CURSOR_BYTES];
        key[..8].copy_from_slice(&self.recorded_at.to_be_bytes());
        key[8..24].copy_from_slice(self.reaction.as_bytes());
        key[24] = u8::from(self.revoked);
        key
    }
}

/// One bounded page. `next` is the exclusive cursor of its last signal; it
/// disambiguates several events recorded in the same second.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionSignalPage {
    pub signals: Vec<ReactionSignal>,
    pub next: Option<String>,
}

fn bad_cursor() -> Error {
    Error::InvalidConfig("invalid reaction signal cursor".into())
}

fn parse_cursor(cursor: &str) -> Result<[u8; CURSOR_BYTES]> {
    if cursor.len() != CURSOR_BYTES * 2
        || !cursor
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(bad_cursor());
    }
    let mut key = [0u8; CURSOR_BYTES];
    for (slot, pair) in key.iter_mut().zip(cursor.as_bytes().chunks_exact(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| bad_cursor())?;
        *slot = u8::from_str_radix(pair, 16).map_err(|_| bad_cursor())?;
    }
    Ok(key)
}

fn cursor_hex(key: &[u8; CURSOR_BYTES]) -> String {
    key.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The page size a `limit` asks for: at most [`MAX_REACTION_SIGNAL_PAGE`],
/// with the rest reached through the page's cursor.
fn page_size(limit: usize) -> Result<usize> {
    if limit == 0 {
        return Err(Error::InvalidConfig(
            "reaction signal limit must be at least 1".into(),
        ));
    }
    Ok(limit.min(MAX_REACTION_SIGNAL_PAGE))
}

/// Pages signals already in feed order: at most `limit` (up to
/// [`MAX_REACTION_SIGNAL_PAGE`]), strictly after the `after` cursor. A caller
/// that withholds some signals pages what it keeps, so a cursor never names a
/// signal the reader was not shown.
pub fn page_reaction_signals(
    signals: Vec<ReactionSignal>,
    after: Option<&str>,
    limit: usize,
) -> Result<ReactionSignalPage> {
    let limit = page_size(limit)?;
    let after = after.map(parse_cursor).transpose()?;
    let mut signals: Vec<_> = signals
        .into_iter()
        .filter(|signal| after.is_none_or(|cursor| signal.key() > cursor))
        .collect();
    let next = (signals.len() > limit).then(|| cursor_hex(&signals[limit - 1].key()));
    signals.truncate(limit);
    Ok(ReactionSignalPage { signals, next })
}

impl Vault {
    /// Every reaction signal for `person` recorded at or after `since`, in
    /// feed order: reactions by others to the records `person` authored. A
    /// signal never broadens its message's audience: the reactor must have
    /// been in the room at the reaction's time and the reader must be able
    /// to read the reaction.
    pub fn reactions_since(&self, person: EntityId, since: u64) -> Result<Vec<ReactionSignal>> {
        let mut signals = Vec::new();
        self.each_reaction_signal_since(person, since, |signal| signals.push(signal))?;
        signals.sort_by_key(ReactionSignal::key);
        Ok(signals)
    }

    /// One page of [`Vault::reactions_since`]. Only the page and the one
    /// signal after it are held while the person's records are read.
    pub fn reactions_since_page(
        &self,
        person: EntityId,
        since: u64,
        after: Option<&str>,
        limit: usize,
    ) -> Result<ReactionSignalPage> {
        let limit = page_size(limit)?;
        let after = after.map(parse_cursor).transpose()?;
        let mut kept = BTreeMap::new();
        self.each_reaction_signal_since(person, since, |signal| {
            let key = signal.key();
            if after.is_some_and(|cursor| key <= cursor) {
                return;
            }
            kept.insert(key, signal);
            if kept.len() > limit + 1 {
                kept.pop_last();
            }
        })?;
        let mut signals: Vec<ReactionSignal> = kept.into_values().collect();
        let next = (signals.len() > limit).then(|| cursor_hex(&signals[limit - 1].key()));
        signals.truncate(limit);
        Ok(ReactionSignalPage { signals, next })
    }

    /// Hands each signal of [`Vault::reactions_since`] to `each`, in no
    /// particular order. A signal recorded before `since` is never built.
    fn each_reaction_signal_since(
        &self,
        person: EntityId,
        since: u64,
        mut each: impl FnMut(ReactionSignal),
    ) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        let fold = admission_in(self, &txn)?;
        let mut audience = AudienceCache::default();
        let direction = EdgeDirection::In;
        let kind = EdgeKind::AuthoredBy;
        let scope = [&[direction as u8][..], person.as_bytes(), &[kind as u8][..]].concat();
        let mut count = ScanCount::start(&self.store, &txn, EngineScan::EdgePeerRows, &scope)?;
        for edge in self
            .store
            .port_edges(&txn, &person, direction, Some(kind), None)?
        {
            count.row();
            let record = edge?.target;
            if !matches!(
                self.get_entity_type_in_txn(&txn, &record)?,
                Some(ENTITY_TYPE_MESSAGE | ENTITY_TYPE_TURN)
            ) {
                continue;
            }
            for row in reactions_on_in(self, &txn, &fold, record)? {
                let removed_at = row.retracted_at().filter(|at| *at >= since);
                let put_since = row.learned_at >= since;
                if row.value.by == person
                    || (removed_at.is_none() && !put_since)
                    || !audience.readable(self, &txn, row.id, &[row.value.by])?
                    || !audience.readable(self, &txn, row.id, &[person])?
                {
                    continue;
                }
                let put = ReactionSignal {
                    reaction: row.id,
                    message: record,
                    by: row.value.by,
                    glyph: row.value.glyph.clone(),
                    occurred_at: row.value.occurred_at,
                    recorded_at: row.learned_at,
                    revoked: false,
                };
                if let Some(removed_at) = removed_at {
                    each(ReactionSignal {
                        recorded_at: removed_at,
                        revoked: true,
                        ..put.clone()
                    });
                }
                if put_since {
                    each(put);
                }
            }
        }
        count.finish(self);
        Ok(())
    }
}
