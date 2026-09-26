//! Derived per-author event index. The record/tombstone remains the authority.
use super::{ReactionBody, ReactionSignal};
use crate::conversation::{AudienceCache, member_at_in, room_for_record_in, visible_at_in};
use crate::conversation_dag::edge_ids;
use crate::error::{Error, RecordError, Result};
use crate::registry::ENTITY_TYPE_REACTION;
use crate::store::{ManifestDbs, Store};
use crate::{EdgeKind, EntityId, Vault};
use serde::{Deserialize, Serialize};

const PREFIX: &[u8] = b"reaction_inbox:v1:";
const PENDING: &[u8] = b"reaction:pending_signal:v1:";

#[derive(Debug, Serialize, Deserialize)]
struct PendingSignal {
    body: ReactionBody,
    learned_at: u64,
    revoked_at: Option<u64>,
}
fn pending_key(msg: EntityId, id: EntityId) -> Vec<u8> {
    [PENDING, msg.as_bytes(), id.as_bytes()].concat()
}
fn author_in(store: &Store, txn: &heed::RoTxn<'_>, msg: EntityId) -> Result<Option<EntityId>> {
    let authors = edge_ids(store, txn, &msg, EdgeKind::AuthoredBy, false, 2)?;
    if authors.len() > 1 {
        return Err(Error::CorruptedIndex("reaction target authors"));
    }
    Ok(authors.first().copied())
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
        if let Some(author) = author_in(store, txn, body.msg)? {
            flush_pending_for_author_edge(store, txn, body.msg, EdgeKind::AuthoredBy, author)?;
        }
        return Ok(());
    }
    if let Some(author) = author_in(store, txn, body.msg)? {
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
    }
    Ok(())
}

/// A MESSAGE/TURN author edge arriving after the reaction put or tombstone
/// resolves deferred events without losing their original timestamps.
pub(crate) fn flush_pending_for_author_edge(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
    author: EntityId,
) -> Result<()> {
    if kind != EdgeKind::AuthoredBy {
        return Ok(());
    }
    let prefix = [PENDING, src.as_bytes()].concat();
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
        if row.body.msg != src {
            return Err(Error::CorruptedIndex("reaction pending target"));
        }
        pending.push((key.to_vec(), id, row));
    }
    for (key, id, row) in pending {
        append_for_author(store, txn, author, id, &row.body, false, row.learned_at)?;
        if let Some(at) = row.revoked_at {
            append_for_author(store, txn, author, id, &row.body, true, at)?;
        }
        store.vault_meta().delete(txn, &key)?;
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
    pub fn reactions_since(&self, person: EntityId, since: u64) -> Result<Vec<ReactionSignal>> {
        let txn = self.store.env.read_txn()?;
        let prefix = [PREFIX, person.as_bytes()].concat();
        let mut rows = Vec::new();
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
            // Inclusive second-granularity cursor: two events can share a
            // second, so replay at the boundary is safer than losing one.
            if at < since {
                continue;
            }
            if rows.len() >= 1000 {
                return Err(Error::IndexOverflow("reaction_inbox"));
            }
            let row: ReactionSignal = rmp_serde::from_slice(&v)
                .map_err(|_| Error::CorruptedIndex("reaction inbox value"))?;
            if row.recorded_at != at
                || row.reaction.as_bytes() != &k[prefix.len() + 8..prefix.len() + 24]
                || row.revoked != (k[prefix.len() + 24] == 1)
            {
                return Err(Error::CorruptedIndex("reaction inbox mismatch"));
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
        Ok(rows)
    }
}
