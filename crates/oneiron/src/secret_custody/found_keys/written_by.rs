//! A person's own found keys, a page at a time (L6-03-WRITER-FOUND-KEY-LIST;
//! Engine RULING 11:39 = A): each key a mask lifted out of a value that
//! person wrote in their own name, which they may answer not a secret or
//! kept as text ([`Vault::rule_found_key_not_a_secret`]). The list is what
//! makes that answer usable for a person who does not own the vault: the
//! owner's list ([`Vault::found_keys_page`]) and the found-key notices are
//! the owner's alone.
//!
//! The card is value-free and names only what the writer may use: the
//! handle, the scan kind, where it sat, when it was found, what was done
//! about it and when, and the two answers still open to them. It names no
//! custody record, display label, receipt or grant, and none of the owner's
//! own answers. A card names its record and its place there only while the
//! person can still read that record; otherwise both are left out, so the
//! list never shows a record the person's read scope hides, or that it
//! exists.

use std::cmp::Ordering;

use heed::RoTxn;

use super::{FOUND, FoundKey, FoundKeyAction, actions};
use crate::claim::{ClaimReadStatus, ScopedReadActorKey};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{ClaimError, Error, Result};
use crate::secret_custody::doors::read_secret_custody_admission_in_txn;
use crate::vault::Vault;

/// What was done about a person's found key, and when; the receipt and any
/// grant stay on the owner's card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrittenFoundKeySettled {
    pub action: FoundKeyAction,
    pub at: u64,
}

/// One found key as the person who wrote its value reads it. It holds no
/// value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenFoundKeyCard {
    /// The handle the record holds, such as `sc12`; the answer doors take it.
    pub handle: String,
    /// The scan rule's word for the key, such as `openai_key`.
    pub kind: String,
    /// The record it was found in, or the file's ASSET; `None` when the
    /// person can no longer read it.
    pub record: Option<EntityId>,
    /// Where it sat in that record: `body`, `claim`, `text:<field>`,
    /// `file`, or a row outside the entity tables; `None` when the record
    /// is left out.
    pub place: Option<String>,
    pub found_at: u64,
    pub settled: Option<WrittenFoundKeySettled>,
    /// The answers still open to the writer: not a secret and kept as text,
    /// as the owner's card offers them.
    pub actions: Vec<FoundKeyAction>,
}

/// Where a page of a person's found keys ends: the last card's find time
/// and handle. As text, `<found_at>.<handle>`. It names no record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenFoundKeyCursor {
    pub found_at: u64,
    pub handle: String,
}

impl WrittenFoundKeyCursor {
    /// The cursor's text form.
    #[must_use]
    pub fn to_text(&self) -> String {
        format!("{}.{}", self.found_at, self.handle)
    }

    /// The cursor `text` names, or `None` when it names none.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let (found_at, handle) = text.trim().split_once('.')?;
        if handle.is_empty() {
            return None;
        }
        Some(Self {
            found_at: found_at.parse().ok()?,
            handle: handle.to_owned(),
        })
    }

    /// Whether a key found at `found_at` under `handle` comes after this
    /// cursor in newest-first, then handle order.
    fn precedes(&self, found_at: u64, handle: &str) -> bool {
        found_at < self.found_at || (found_at == self.found_at && handle > self.handle.as_str())
    }
}

/// One page of a person's found keys, newest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenFoundKeyPage {
    pub keys: Vec<WrittenFoundKeyCard>,
    /// The cursor the next page starts after; `None` once `done`.
    pub next_cursor: Option<WrittenFoundKeyCursor>,
    /// No key under this filter is left after this page.
    pub done: bool,
}

impl Vault {
    /// The found keys whose values the proof's person wrote in their own
    /// name, a page at a time: at most `limit` keys after `after` (from the
    /// newest when `None`), newest first and then by handle, with the cursor
    /// of the next page. Only that person's keys are read: a record that
    /// holds another writer's key, or an agent's, shows none of them, and
    /// their times move no cursor here. `open_only` keeps the keys no one
    /// has answered yet. A zero `limit` reads none, and its next page starts
    /// where `after` did. No value is read.
    ///
    /// The person is rechecked live in the reading transaction, owner of
    /// this vault or not; an owner reads the keys they wrote themselves
    /// here, and every key through [`Self::found_keys_page`]. A writer's
    /// keys carry one custody record each, minted once per distinct value
    /// and noted on the one record it was written in (a moved row's keys
    /// merge by custody; a known value's file note names no writer), so a
    /// handle names one card in this list.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// when the proof is not a live person's of this vault.
    /// [`ClaimError::ScopedReadOwnerNotLive`] when the owner binding cannot
    /// be read. Storage errors.
    pub fn found_keys_written_by_page(
        &self,
        person: &AuthenticatedOwner,
        open_only: bool,
        after: Option<&WrittenFoundKeyCursor>,
        limit: usize,
    ) -> Result<WrittenFoundKeyPage> {
        let txn = self.store.env.read_txn()?;
        let writer = person.revalidate_person_in_txn(self, &txn)?;
        let mut rows: Vec<(EntityId, FoundKey)> = Vec::new();
        for row in FOUND.iter_from(&self.store, &txn, &[])? {
            let (record, found) = row?;
            for key in found.keys {
                if key.writer != Some(writer) || (open_only && key.settled.is_some()) {
                    continue;
                }
                if after.is_some_and(|cursor| !cursor.precedes(key.found_at, &key.handle)) {
                    continue;
                }
                rows.push((record, key));
            }
        }
        rows.sort_by(|left, right| newest_first(&left.1, &right.1));
        let done = rows.len() <= limit;
        rows.truncate(limit);
        let next_cursor = if done {
            None
        } else {
            rows.last()
                .map(|(_, key)| WrittenFoundKeyCursor {
                    found_at: key.found_at,
                    handle: key.handle.clone(),
                })
                .or_else(|| after.cloned())
        };
        let records: Vec<EntityId> = rows.iter().map(|(record, _)| *record).collect();
        let readable = readable_records_in_txn(self, &txn, &writer, &records)?;
        let keys = rows
            .iter()
            .zip(readable)
            .map(|((record, key), readable)| {
                written_card_in_txn(self, &txn, readable.then_some(*record), key)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(WrittenFoundKeyPage {
            keys,
            next_cursor,
            done,
        })
    }
}

/// Newest find first, then handle ascending: the order the cursor reads.
fn newest_first(left: &FoundKey, right: &FoundKey) -> Ordering {
    right
        .found_at
        .cmp(&left.found_at)
        .then_with(|| left.handle.cmp(&right.handle))
}

/// One key as its writer reads it. `record` is the record it was found in
/// while the writer can still read it, else `None`, and the card then names
/// no place either.
fn written_card_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    record: Option<EntityId>,
    key: &FoundKey,
) -> Result<WrittenFoundKeyCard> {
    let actions = if key.kept_by_owner() {
        Vec::new()
    } else {
        let status = read_secret_custody_admission_in_txn(&vault.store, txn, &key.custody)?
            .map(|rec| rec.status);
        actions::text_answers(key, status).to_vec()
    };
    Ok(WrittenFoundKeyCard {
        handle: key.handle.clone(),
        kind: key.kind().to_owned(),
        place: record.map(|_| key.place.clone()),
        record,
        found_at: key.found_at,
        settled: key.settled.as_ref().map(|settled| WrittenFoundKeySettled {
            action: settled.action,
            at: settled.at,
        }),
        actions,
    })
}

/// Which of `records` `person` can read now, in `txn`, one answer each: the
/// lane `get_entity` opens for a person with no credential bound
/// (`Memory::read_lane`). The vault owner's own key goes to the person the
/// Memory facade's owner test passes (the embedded owner, or a human whose
/// owner binding verifies), the test the owner key's own recheck runs;
/// anyone else reads as a human, admitted only through their grants. Each
/// record is judged as a point read of a record verb admits it, a claim of
/// any status included. An id that names no entity, such as a side row's,
/// is not readable.
fn readable_records_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    person: &EntityId,
    records: &[EntityId],
) -> Result<Vec<bool>> {
    if records.is_empty() {
        return Ok(Vec::new());
    }
    let owner =
        crate::memory::actor_is_vault_owner_in_txn(vault, txn, *person, EdgeActorClass::Human)
            .map_err(|error| Error::Claim(ClaimError::ScopedReadOwnerNotLive(Box::new(error))))?;
    let key = if owner {
        ScopedReadActorKey::vault_owner(*person)
    } else {
        let Some(key) = ScopedReadActorKey::with_actor_class(
            person.to_hex(),
            EdgeActorClass::Human.gate_actor_class(),
        ) else {
            return Ok(vec![false; records.len()]);
        };
        key.require_access_grants(Some(*person))
    };
    vault
        .scoped_read(key)
        .with_claim_status(ClaimReadStatus::Recorded)
        .entities_readable_in_txn(txn, records)
}
