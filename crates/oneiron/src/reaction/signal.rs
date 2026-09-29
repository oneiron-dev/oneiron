//! The agent signal feed: new reactions to a person's own messages since a
//! time, read from the reaction claims themselves so a replica answers the
//! same as the writer. A put signals at its learned time, a removal at its
//! retraction time.
use super::chain::{admission_in, reactions_on_in};
use crate::conversation::AudienceCache;
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};

/// Records one person may have authored before the feed refuses loudly.
const MAX_AUTHORED_RECORDS: usize = 100_000;
/// Largest page a caller may ask for.
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

/// Pages signals already in feed order: at most `limit`, strictly after the
/// `after` cursor. A caller that withholds some signals pages what it keeps,
/// so a cursor never names a signal the reader was not shown.
pub fn page_reaction_signals(
    signals: Vec<ReactionSignal>,
    after: Option<&str>,
    limit: usize,
) -> Result<ReactionSignalPage> {
    if !(1..=MAX_REACTION_SIGNAL_PAGE).contains(&limit) {
        return Err(Error::InvalidConfig(
            "reaction signal limit must be 1..=1000".into(),
        ));
    }
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
        let txn = self.store.env.read_txn()?;
        let fold = admission_in(self, &txn)?;
        let mut audience = AudienceCache::default();
        let mut signals = Vec::new();
        for (scanned, edge) in self
            .store
            .port_edges(
                &txn,
                &person,
                EdgeDirection::In,
                Some(EdgeKind::AuthoredBy),
                None,
            )?
            .enumerate()
        {
            if scanned >= MAX_AUTHORED_RECORDS {
                return Err(Error::IndexOverflow("reaction signal authored records"));
            }
            let record = edge?.target;
            if !matches!(
                self.get_entity_type_in_txn(&txn, &record)?,
                Some(ENTITY_TYPE_MESSAGE | ENTITY_TYPE_TURN)
            ) {
                continue;
            }
            for row in reactions_on_in(self, &txn, &fold, record)? {
                if row.value.by == person
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
                if let Some(removed_at) = row.retracted_at() {
                    signals.push(ReactionSignal {
                        recorded_at: removed_at,
                        revoked: true,
                        ..put.clone()
                    });
                }
                signals.push(put);
            }
        }
        signals.retain(|signal| signal.recorded_at >= since);
        signals.sort_by_key(ReactionSignal::key);
        Ok(signals)
    }

    /// One page of [`Vault::reactions_since`].
    pub fn reactions_since_page(
        &self,
        person: EntityId,
        since: u64,
        after: Option<&str>,
        limit: usize,
    ) -> Result<ReactionSignalPage> {
        page_reaction_signals(self.reactions_since(person, since)?, after, limit)
    }
}
