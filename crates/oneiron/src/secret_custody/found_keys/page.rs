//! The found-key notices a page at a time (FIX 8204): the order
//! [`Vault::found_keys`] reads, newest key first and then the record id, cut
//! into pages a cursor continues. Every retained notice stays reachable: an
//! older one needs no newer one settled, and a cursor never expires. A
//! record that finds a newer key after a page was read moves ahead of that
//! page's cursor, so the next page does not repeat it.

use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::vault::Vault;

use super::{FOUND, FoundKeyNotice, actions};

/// Where a page of found-key notices ends: the newest key time and the
/// record of its last notice. As text, `<found_at>.<record as 32 hex>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoundKeyCursor {
    pub latest: u64,
    pub record: EntityId,
}

impl FoundKeyCursor {
    /// The cursor's text form.
    #[must_use]
    pub fn to_text(self) -> String {
        format!("{}.{}", self.latest, self.record.to_hex())
    }

    /// The cursor `text` names, or `None` when it names none.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let (latest, record) = text.trim().split_once('.')?;
        Some(Self {
            latest: latest.parse().ok()?,
            record: EntityId::from_hex(record).ok()?,
        })
    }

    /// Whether a notice at `latest` for `record` comes after this cursor in
    /// newest-first, then record-id order.
    fn precedes(self, latest: u64, record: &EntityId) -> bool {
        latest < self.latest || (latest == self.latest && *record > self.record)
    }
}

/// One page of found-key notices, newest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundKeyNoticePage {
    pub notices: Vec<FoundKeyNotice>,
    /// The cursor the next page starts after; `None` once `done`.
    pub next_cursor: Option<FoundKeyCursor>,
    /// No notice under this filter is left after this page.
    pub done: bool,
}

impl Vault {
    /// [`Self::found_keys`] a page at a time: at most `limit` notices after
    /// `after` (from the newest when `None`), with the cursor of the next
    /// page. `open_only` keeps the records with a key the owner has not
    /// acted on. A zero `limit` reads none, and its next page starts where
    /// `after` did. No value is read.
    ///
    /// # Errors
    /// As [`Self::found_keys`].
    pub fn found_keys_page(
        &self,
        owner: &AuthenticatedOwner,
        open_only: bool,
        after: Option<FoundKeyCursor>,
        limit: usize,
    ) -> Result<FoundKeyNoticePage> {
        owner.revalidate(self)?;
        let txn = self.store.env.read_txn()?;
        let mut rows = Vec::new();
        for row in FOUND.iter_from(&self.store, &txn, &[])? {
            let (record, found) = row?;
            if open_only && found.keys.iter().all(|key| key.settled.is_some()) {
                continue;
            }
            let latest = found.keys.iter().map(|key| key.found_at).max().unwrap_or(0);
            if after.is_some_and(|cursor| !cursor.precedes(latest, &record)) {
                continue;
            }
            rows.push((latest, record, found));
        }
        rows.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
        let done = rows.len() <= limit;
        rows.truncate(limit);
        let next_cursor = if done {
            None
        } else {
            rows.last()
                .map(|(latest, record, _)| FoundKeyCursor {
                    latest: *latest,
                    record: *record,
                })
                .or(after)
        };
        let notices = rows
            .into_iter()
            .map(|(_, record, found)| {
                let keys = found
                    .keys
                    .iter()
                    .map(|key| actions::card_in_txn(self, &txn, &record, key))
                    .collect::<Result<Vec<_>>>()?;
                Ok(FoundKeyNotice { record, keys })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(FoundKeyNoticePage {
            notices,
            next_cursor,
            done,
        })
    }
}
