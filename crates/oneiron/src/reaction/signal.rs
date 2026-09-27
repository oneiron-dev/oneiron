//! Derived per-author event index. The record/tombstone remains the authority.
use super::{ReactionBody, ReactionSignal};
use crate::conversation::{AudienceCache, member_at_in, room_for_record_in, visible_at_in};
use crate::error::{Error, RecordError, Result};
use crate::registry::ENTITY_TYPE_REACTION;
use crate::store::{ManifestDbs, Store};
use crate::{EdgeKind, EntityId, Vault};
use serde::{Deserialize, Serialize};

const PREFIX: &[u8] = b"reaction_inbox:v1:";
const PENDING: &[u8] = b"reaction:pending_signal:v1:";
const PENDING_BY: &[u8] = b"reaction:pending_by:v1:";

/// One bounded author-signal page. `next` is the exclusive full-key cursor;
/// it disambiguates multiple puts/revocations in the same second.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionSignalPage {
    pub signals: Vec<ReactionSignal>,
    pub next: Option<String>,
}
impl std::ops::Deref for ReactionSignalPage {
    type Target = [ReactionSignal];
    fn deref(&self) -> &Self::Target {
        &self.signals
    }
}
impl IntoIterator for ReactionSignalPage {
    type Item = ReactionSignal;
    type IntoIter = std::vec::IntoIter<ReactionSignal>;
    fn into_iter(self) -> Self::IntoIter {
        self.signals.into_iter()
    }
}
fn cursor_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(HEX[usize::from(byte >> 4)] as char);
        value.push(HEX[usize::from(byte & 15)] as char);
    }
    value
}
fn parse_cursor(cursor: &str) -> Result<[u8; 25]> {
    if cursor.len() != 50 {
        return Err(Error::InvalidConfig("invalid reaction cursor".into()));
    }
    let mut value = [0u8; 25];
    for (i, chunk) in cursor.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk)
            .map_err(|_| Error::InvalidConfig("invalid reaction cursor".into()))?;
        if !text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(Error::InvalidConfig("invalid reaction cursor".into()));
        }
        value[i] = u8::from_str_radix(text, 16)
            .map_err(|_| Error::InvalidConfig("invalid reaction cursor".into()))?;
    }
    Ok(value)
}

#[derive(Debug, Serialize, Deserialize)]
struct PendingSignal {
    body: ReactionBody,
    learned_at: u64,
    revoked_at: Option<u64>,
}
fn pending_key(msg: EntityId, id: EntityId) -> Vec<u8> {
    [PENDING, msg.as_bytes(), id.as_bytes()].concat()
}
fn pending_by_key(person: EntityId, id: EntityId) -> Vec<u8> {
    [PENDING_BY, person.as_bytes(), id.as_bytes()].concat()
}
fn sole_edge(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
) -> Result<Option<EntityId>> {
    let mut prefix = src.as_bytes().to_vec();
    prefix.push(kind as u8);
    let mut entries = store.edges_out().prefix_iter(txn, &prefix)?;
    let Some((key, _)) = entries.next().transpose()? else {
        return Ok(None);
    };
    if entries.next().transpose()?.is_some() {
        return Ok(None);
    }
    if key.len() != 33 {
        return Err(Error::CorruptedIndex("reaction edge key"));
    }
    EntityId::from_bytes(
        key[17..33]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("reaction edge target"))?,
    )
    .map(Some)
}
fn author_in(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    msg: EntityId,
) -> Result<Option<EntityId>> {
    sole_edge(store, txn, msg, EdgeKind::AuthoredBy)
}
fn has_type(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kinds: &[u8],
) -> Result<bool> {
    let Some(raw) = store.entities().get(txn, id.as_bytes())? else {
        return Ok(false);
    };
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("reaction dependency header"))?;
    Ok(kinds.contains(&header.entity_type))
}
/// A body is not an event until its two bindings and typed references exist.
fn ready(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    body: &ReactionBody,
) -> Result<bool> {
    Ok(has_type(store, txn, id, &[ENTITY_TYPE_REACTION])?
        && has_type(
            store,
            txn,
            body.msg,
            &[
                crate::registry::ENTITY_TYPE_MESSAGE,
                crate::registry::ENTITY_TYPE_TURN,
            ],
        )?
        && has_type(store, txn, body.by, &[crate::registry::ENTITY_TYPE_PERSON])?
        && sole_edge(store, txn, id, EdgeKind::About)? == Some(body.msg)
        && sole_edge(store, txn, id, EdgeKind::AuthoredBy)? == Some(body.by))
}
fn key(author: EntityId, at: u64, reaction: EntityId, revoked: bool) -> Vec<u8> {
    let mut result = Vec::with_capacity(PREFIX.len() + 41);
    result.extend_from_slice(PREFIX);
    result.extend_from_slice(author.as_bytes());
    result.extend_from_slice(&at.to_be_bytes());
    result.extend_from_slice(reaction.as_bytes());
    result.push(u8::from(revoked));
    result
}
fn encode(row: &ReactionSignal) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(row)
        .map_err(|_| Error::Record(RecordError::InvalidReactionBody("signal encode")))
}
fn append_for_author(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    author: EntityId,
    id: EntityId,
    body: &ReactionBody,
    revoked: bool,
    recorded_at: u64,
) -> Result<()> {
    let row = ReactionSignal {
        reaction: id,
        message: body.msg,
        by: body.by,
        glyph: body.glyph.clone(),
        occurred_at: body.at,
        recorded_at,
        revoked,
    };
    store
        .vault_meta()
        .put(txn, &key(author, recorded_at, id, revoked), &encode(&row)?)?;
    Ok(())
}
fn append_or_defer(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    body: &ReactionBody,
    revoked: bool,
    at: u64,
) -> Result<()> {
    let pending_key = pending_key(body.msg, id);
    if let Some(bytes) = store.vault_meta.get(txn, &pending_key)? {
        let mut pending: PendingSignal = rmp_serde::from_slice(&bytes)
            .map_err(|_| Error::CorruptedIndex("reaction pending signal"))?;
        if pending.body != *body {
            return Err(Error::CorruptedIndex("reaction pending body"));
        }
        if revoked {
            pending.revoked_at = Some(at);
        }
        store.vault_meta.put(
            txn,
            &pending_key,
            &rmp_serde::to_vec_named(&pending)
                .map_err(|_| Error::CorruptedIndex("reaction pending encode"))?,
        )?;
        store
            .vault_meta
            .put(txn, &pending_by_key(body.by, id), body.msg.as_bytes())?;
        if ready(store, txn, id, body)? {
            flush_pending_for_message(store, txn, body.msg)?;
        }
        return Ok(());
    }
    if ready(store, txn, id, body)?
        && let Some(author) = author_in(store, txn, body.msg)?
    {
        append_for_author(store, txn, author, id, body, revoked, at)?;
    } else {
        let learned_at = if revoked {
            let raw = store
                .entities
                .get(txn, id.as_bytes())?
                .ok_or(Error::CorruptedIndex("reaction pending source"))?;
            crate::batch::EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("reaction pending header"))?
                .learned_at
        } else {
            at
        };
        let pending = PendingSignal {
            body: body.clone(),
            learned_at,
            revoked_at: revoked.then_some(at),
        };
        store.vault_meta.put(
            txn,
            &pending_key,
            &rmp_serde::to_vec_named(&pending)
                .map_err(|_| Error::CorruptedIndex("reaction pending encode"))?,
        )?;
        store
            .vault_meta
            .put(txn, &pending_by_key(body.by, id), body.msg.as_bytes())?;
    }
    Ok(())
}

/// A reaction binding or target author edge can complete a deferred put in
/// either replay order. Incomplete rows remain pending, never user-visible.
pub(crate) fn flush_pending_after_edge(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
    _target: EntityId,
) -> Result<()> {
    if !matches!(kind, EdgeKind::About | EdgeKind::AuthoredBy) {
        return Ok(());
    }
    let message = if let Some(raw) = store.entities().get(txn, src.as_bytes())? {
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("reaction edge source"))?;
        if header.entity_type == ENTITY_TYPE_REACTION
            && raw.len() > crate::batch::ENTITY_METADATA_HEADER_LEN
        {
            Some(
                ReactionBody::from_bytes(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
                    .map_err(|_| Error::CorruptedIndex("reaction edge body"))?
                    .msg,
            )
        } else if kind == EdgeKind::AuthoredBy {
            Some(src)
        } else {
            None
        }
    } else if kind == EdgeKind::AuthoredBy {
        Some(src)
    } else {
        None
    };
    if let Some(message) = message {
        flush_pending_for_message(store, txn, message)?;
    }
    Ok(())
}

fn flush_pending_for_message(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    message: EntityId,
) -> Result<()> {
    let Some(author) = author_in(store, txn, message)? else {
        return Ok(());
    };
    let prefix = [PENDING, message.as_bytes()].concat();
    let mut pending = Vec::new();
    for (n, entry) in store.vault_meta().prefix_iter(txn, &prefix)?.enumerate() {
        if n >= 100_000 {
            return Err(Error::IndexOverflow("reaction_pending_signal"));
        }
        let (key, value) = entry?;
        if key.len() != prefix.len() + 16 {
            return Err(Error::CorruptedIndex("reaction pending key"));
        }
        let id = EntityId::from_bytes(
            key[prefix.len()..]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("reaction pending key"))?,
        )?;
        let row: PendingSignal = rmp_serde::from_slice(&value)
            .map_err(|_| Error::CorruptedIndex("reaction pending signal"))?;
        if row.body.msg != message {
            return Err(Error::CorruptedIndex("reaction pending target"));
        }
        pending.push((key.to_vec(), id, row));
    }
    for (key, id, row) in pending {
        if !ready(store, txn, id, &row.body)? {
            continue;
        }
        append_for_author(store, txn, author, id, &row.body, false, row.learned_at)?;
        if let Some(at) = row.revoked_at {
            append_for_author(store, txn, author, id, &row.body, true, at)?;
        }
        store.vault_meta().delete(txn, &key)?;
        store
            .vault_meta()
            .delete(txn, &pending_by_key(row.body.by, id))?;
    }
    Ok(())
}

/// A referenced target can arrive after the reaction and all its edges.
pub(crate) fn flush_pending_after_dependency(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    kind: u8,
) -> Result<()> {
    if matches!(
        kind,
        crate::registry::ENTITY_TYPE_MESSAGE | crate::registry::ENTITY_TYPE_TURN
    ) {
        flush_pending_for_message(store, txn, id)?;
    } else if kind == crate::registry::ENTITY_TYPE_PERSON {
        let prefix = [PENDING_BY, id.as_bytes()].concat();
        let mut messages = std::collections::BTreeSet::new();
        for (n, entry) in store.vault_meta().prefix_iter(txn, &prefix)?.enumerate() {
            if n >= 100_000 {
                return Err(Error::IndexOverflow("reaction_pending_by"));
            }
            let (key, value) = entry?;
            if key.len() != prefix.len() + 16 || value.len() != 16 {
                return Err(Error::CorruptedIndex("reaction pending reactor index"));
            }
            messages.insert(EntityId::from_bytes(value.as_ref().try_into().map_err(
                |_| Error::CorruptedIndex("reaction pending reactor target"),
            )?)?);
        }
        for message in messages {
            flush_pending_for_message(store, txn, message)?;
        }
    }
    Ok(())
}

/// The generic entity-put chokepoint sees typed puts and sync replay alike.
pub(crate) fn record_put_in_store(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    body: &[u8],
    learned_at: u64,
) -> Result<()> {
    let body = ReactionBody::from_bytes(body)?;
    append_or_defer(store, txn, id, &body, false, learned_at)
}

/// The generic soft-delete door also reaches here: direct deletion of a
/// reaction is revocation, not an unannounced disappearance from an inbox.
pub(crate) fn record_revoke(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    queue_outbound: bool,
) -> Result<()> {
    let Some(raw) = vault.store.entities.get(txn, id.as_bytes())? else {
        return Ok(());
    };
    let h = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("reaction revoke header"))?;
    if h.entity_type != ENTITY_TYPE_REACTION {
        return Ok(());
    }
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &id)?.is_live() {
        return Ok(());
    }
    let body = ReactionBody::from_bytes(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
        .map_err(|_| Error::CorruptedIndex("reaction stored body"))?;
    append_or_defer(
        &vault.store,
        txn,
        id,
        &body,
        true,
        vault.store.clock.now_recorded_at(),
    )?;
    if queue_outbound {
        super::outbound::enqueue(vault, txn, id, &body, true)?;
    }
    super::admission::clear_triple(&vault.store, txn, id, &body)
}

/// A remote soft tombstone must not enqueue an outbound provider echo.
pub(crate) fn record_replayed_revoke(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    deleted_at: u64,
) -> Result<()> {
    let Some(raw) = vault.store.entities.get(txn, id.as_bytes())? else {
        return Ok(());
    };
    let h = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("reaction replay header"))?;
    if h.entity_type != ENTITY_TYPE_REACTION
        || !crate::vault::live_entity_row_in_txn(&vault.store, txn, &id)?.is_live()
    {
        return Ok(());
    }
    let body = ReactionBody::from_bytes(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
        .map_err(|_| Error::CorruptedIndex("reaction stored body"))?;
    append_or_defer(&vault.store, txn, id, &body, true, deleted_at)?;
    super::admission::clear_triple(&vault.store, txn, id, &body)
}

impl Vault {
    /// Signals since a recorded-time cursor, including revocations. A signal
    /// cannot broaden its target MESSAGE's audience.
    pub fn reactions_since(&self, person: EntityId, since: u64) -> Result<ReactionSignalPage> {
        self.reactions_since_page(person, since, None, 1000)
    }

    /// Continue after an exact previous key, with a bounded physical scan.
    /// A page can be empty when its examined rows were withheld; its cursor
    /// still advances, so a large hidden backlog cannot wedge the reader.
    pub fn reactions_since_page(
        &self,
        person: EntityId,
        since: u64,
        after: Option<&str>,
        limit: usize,
    ) -> Result<ReactionSignalPage> {
        if !(1..=1000).contains(&limit) {
            return Err(Error::InvalidConfig(
                "reaction signal limit must be 1..=1000".into(),
            ));
        }
        let after = after.map(parse_cursor).transpose()?;
        let txn = self.store.env.read_txn()?;
        let prefix = [PREFIX, person.as_bytes()].concat();
        let mut rows = Vec::new();
        let mut scanned = 0;
        let mut last = None;
        let mut next = None;
        let mut audience = AudienceCache::default();
        for entry in self.store.vault_meta.prefix_iter(&txn, &prefix)? {
            let (k, v) = entry?;
            if k.len() != prefix.len() + 25 {
                return Err(Error::CorruptedIndex("reaction inbox key"));
            }
            let at = u64::from_be_bytes(
                k[prefix.len()..prefix.len() + 8]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("reaction inbox time"))?,
            );
            // Inclusive timestamp start, then an exclusive full-key cursor.
            let suffix: [u8; 25] = k[prefix.len()..]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("reaction inbox cursor"))?;
            if at < since || after.is_some_and(|cursor| suffix <= cursor) {
                continue;
            }
            if scanned >= limit {
                next = last.map(|key: [u8; 25]| cursor_hex(&key));
                break;
            }
            scanned += 1;
            last = Some(suffix);
            let row: ReactionSignal = rmp_serde::from_slice(&v)
                .map_err(|_| Error::CorruptedIndex("reaction inbox value"))?;
            if row.recorded_at != at
                || row.reaction.as_bytes() != &k[prefix.len() + 8..prefix.len() + 24]
                || row.revoked != (k[prefix.len() + 24] == 1)
            {
                return Err(Error::CorruptedIndex("reaction inbox mismatch"));
            }
            // A soft shell still carries the put/revoked audit signal. A
            // hard-erased or archived source must never release its copied
            // glyph from a stale derived index, even if cleanup was missed.
            let source = crate::vault::live_entity_row_in_txn(&self.store, &txn, &row.reaction)?;
            if self.local_hard_delete_marker_exists_in_txn(&txn, &row.reaction)?
                || self
                    .archive_tombstone_in_txn(&txn, &row.reaction)?
                    .is_some()
                || !matches!(
                    source,
                    crate::vault::LiveEntityRow::Live {
                        entity_type: ENTITY_TYPE_REACTION,
                        ..
                    } | crate::vault::LiveEntityRow::DeletedShell
                )
            {
                continue;
            }
            if !ready(
                &self.store,
                &txn,
                row.reaction,
                &ReactionBody {
                    v: 1,
                    msg: row.message,
                    by: row.by,
                    glyph: row.glyph.clone(),
                    at: row.occurred_at,
                    ext: None,
                },
            )? {
                continue;
            }
            if audience.readable(self, &txn, row.message, &[person])? {
                let room =
                    room_for_record_in(self, &txn, row.message)?.ok_or(Error::EntityNotFound)?;
                let event_at = if row.revoked {
                    row.recorded_at
                } else {
                    row.occurred_at
                };
                if visible_at_in(self, &txn, room, person, event_at)?
                    && member_at_in(self, &txn, room, row.by, row.occurred_at)?
                {
                    rows.push(row);
                }
            }
        }
        Ok(ReactionSignalPage {
            signals: rows,
            next,
        })
    }
}
