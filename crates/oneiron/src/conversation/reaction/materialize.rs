//! Shared admission and rebuildable inbox projection across local and replay writes.
use super::codec::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::{EdgeKind, encode_edge_value, parse_strict_edge_record};
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_REACTION};
use crate::store::Store;

pub(super) fn invalid(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidReactionBody(reason))
}

pub(crate) fn validate_put(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    data: &[u8],
    learned_at: u64,
) -> Result<()> {
    let body = decode_reaction_body(data)?;
    for (endpoint, expected) in [
        (body.msg, ENTITY_TYPE_MESSAGE),
        (body.by, crate::registry::ENTITY_TYPE_PERSON),
    ] {
        if let Some(raw) = store.entities.get(txn, endpoint.as_bytes())? {
            let h = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("reaction endpoint header"))?;
            if h.entity_type != expected {
                return Err(invalid("reaction endpoint has wrong type"));
            }
        }
    }

    if let Some(old) = store.entities.get(txn, id.as_bytes())? {
        let h =
            EntityMetadataHeader::parse(&old).ok_or(Error::CorruptedIndex("reaction header"))?;
        if h.entity_type != ENTITY_TYPE_REACTION
            || old.get(ENTITY_METADATA_HEADER_LEN..) != Some(data)
            || h.learned_at != learned_at
        {
            return Err(invalid("reaction identity and recorded time are immutable"));
        }
    }
    let old_keys: Vec<Vec<u8>> = store
        .edges_out
        .prefix_iter(txn, id.as_bytes())?
        .map(|entry| entry.map(|(k, _)| k.to_vec()))
        .collect::<std::result::Result<_, _>>()?;
    for key in old_keys {
        let (_, kind, target) = crate::edge::parse_strict_edge_record_key(&key)?;
        if !((kind == EdgeKind::About && target == body.msg)
            || (kind == EdgeKind::AuthoredBy && target == body.by))
        {
            return Err(invalid("preexisting edge conflicts with reaction body"));
        }
    }
    let incoming_revoked = store.entity_deletion_present_in_txn(txn, id, learned_at)?;
    // Validate against rows rather than edges: a replay may put the row before
    // its edge delta, and an adversary cannot hide a duplicate by removing an edge.
    for entry in store.entities.iter(txn)? {
        let (key, raw) = entry?;
        let Some(h) = EntityMetadataHeader::parse(&raw) else {
            continue;
        };
        if h.entity_type != ENTITY_TYPE_REACTION || key.as_ref() == id.as_bytes() {
            continue;
        }
        let other_id = EntityId::from_bytes(
            key.as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("reaction id"))?,
        )?;
        let other = decode_reaction_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if body.ext.is_some() && body.ext == other.ext {
            return Err(invalid("external reaction id already exists"));
        }
        if !incoming_revoked
            && body.msg == other.msg
            && body.by == other.by
            && body.glyph == other.glyph
            && !store.entity_deletion_present_in_txn(txn, &other_id, h.learned_at)?
        {
            return Err(invalid("reaction triple already has a live record"));
        }
    }
    Ok(())
}

pub(crate) fn validate_edge(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    source: &EntityId,
    kind: EdgeKind,
    target: &EntityId,
    deleting: bool,
) -> Result<()> {
    let Some(raw) = store.entities.get(txn, source.as_bytes())? else {
        return Ok(());
    };
    let h = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if h.entity_type != ENTITY_TYPE_REACTION {
        return Ok(());
    }
    let body = decode_reaction_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    if deleting
        || !matches!((kind, target), (EdgeKind::About, t) if *t == body.msg)
            && !matches!((kind, target), (EdgeKind::AuthoredBy, t) if *t == body.by)
    {
        return Err(invalid(
            "reaction edges are immutable About/message and AuthoredBy/person",
        ));
    }
    Ok(())
}

pub(crate) fn stage_put(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    data: &[u8],
    learned_at: u64,
) -> Result<()> {
    let body = decode_reaction_body(data)?;
    // Primary edges are mechanically regenerated from the pinned record body.
    for (kind, target) in [(EdgeKind::About, body.msg), (EdgeKind::AuthoredBy, body.by)] {
        let value = encode_edge_value(kind, 1.0, learned_at, crate::affect::Vad::NEUTRAL, None)?;
        store
            .edges_out
            .put(txn, &Store::encode_edge_key(id, kind, &target), &value)?;
        store
            .edges_in
            .put(txn, &Store::encode_edge_key(&target, kind, id), &value)?;
    }
    index_record(store, txn, id, &body, learned_at, None)
}

pub(super) fn message_author(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    message: &EntityId,
) -> Result<Option<EntityId>> {
    let mut prefix = message.as_bytes().to_vec();
    prefix.push(EdgeKind::AuthoredBy as u8);
    let mut author = None;
    for entry in store.edges_out.prefix_iter(txn, &prefix)? {
        let (key, value) = entry?;
        if author.is_some() {
            return Ok(None);
        }
        author = Some(parse_strict_edge_record(&key, &value)?.target);
    }
    Ok(author)
}

fn index_record(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: &ReactionBody,
    learned_at: u64,
    revoked: Option<u64>,
) -> Result<()> {
    let Some(author) = message_author(store, txn, &body.msg)? else {
        return Ok(());
    };
    // System messages have no person author and therefore no person inbox.
    let mut events = vec![(ReactionSignalKind::Put, body.at, learned_at, 0u8)];
    if let Some(at) = revoked {
        events.push((ReactionSignalKind::Revoked, at, at, 1));
    }
    for (kind, at, recorded_at, tag) in events {
        let signal = ReactionSignal {
            kind,
            reaction: id.to_hex(),
            message: body.msg.to_hex(),
            by: body.by.to_hex(),
            glyph: body.glyph.clone(),
            at,
            recorded_at,
        };
        let mut key = REACTION_INBOX_KEY_PREFIX.to_vec();
        key.extend_from_slice(author.as_bytes());
        key.extend_from_slice(&at.to_be_bytes());
        key.extend_from_slice(id.as_bytes());
        key.push(tag);
        let value = serde_json::to_vec(&signal)
            .map_err(|_| Error::InvariantViolation("reaction signal encode"))?;
        store.vault_meta.put(txn, &key, &value)?;
    }
    Ok(())
}

pub(crate) fn stage_revoked(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    at: u64,
) -> Result<()> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(());
    };
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("reaction header"))?;
    if header.entity_type != ENTITY_TYPE_REACTION {
        return Ok(());
    }
    let body = decode_reaction_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    index_record(store, txn, id, &body, header.learned_at, Some(at))
}

pub(crate) fn rebuild_inbox_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>) -> Result<()> {
    let keys: Vec<Vec<u8>> = store
        .vault_meta
        .prefix_iter(txn, REACTION_INBOX_KEY_PREFIX)?
        .map(|e| e.map(|(k, _)| k.to_vec()))
        .collect::<std::result::Result<_, _>>()?;
    for key in keys {
        store.vault_meta.delete(txn, &key)?;
    }
    let mut rows = Vec::new();
    for entry in store.entities.iter(txn)? {
        let (key, raw) = entry?;
        let Some(h) = EntityMetadataHeader::parse(&raw) else {
            continue;
        };
        if h.entity_type != ENTITY_TYPE_REACTION {
            continue;
        }
        let id = EntityId::from_bytes(
            key.as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("reaction id"))?,
        )?;
        let body = decode_reaction_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        let revoked = revocation_time(store, txn, &id, h.learned_at)?;
        rows.push((id, body, h.learned_at, revoked));
    }
    for (id, body, learned, revoked) in rows {
        index_record(store, txn, &id, &body, learned, revoked)?;
    }
    Ok(())
}

pub(super) fn revocation_time(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    learned_at: u64,
) -> Result<Option<u64>> {
    if let Some(raw) = store
        .sync_state
        .get(txn, crate::deletion::archive_tombstone_key(id).as_str())?
    {
        return Ok(Some(
            crate::deletion::decode_tombstone_value(&raw).deleted_at,
        ));
    }
    let key = crate::deletion::pending_tombstone_key(
        &crate::deletion::window_label_from_timestamp(learned_at),
        id,
    );
    if let Some(raw) = store.sync_state.get(txn, key.as_str())? {
        return Ok(Some(
            crate::deletion::decode_tombstone_value(&raw).deleted_at,
        ));
    }
    #[cfg(feature = "sync")]
    {
        use crate::sync::loro_support::{doc_from_snapshot, import_doc, tombstone_values_for_id};
        let window = crate::deletion::window_label_from_timestamp(learned_at);
        if let Some(snapshot) = store
            .sync_state
            .get(txn, format!("d:w:{window}").as_str())?
        {
            let doc = doc_from_snapshot(&snapshot)?;
            for entry in store
                .sync_state
                .prefix_iter(txn, format!("u:w:{window}:").as_str())?
            {
                let (_, bytes) = entry?;
                import_doc(&doc, &bytes)?;
            }
            if let Some(raw) = tombstone_values_for_id(&doc.get_map("tombstones"), id).first() {
                return Ok(Some(
                    crate::deletion::decode_tombstone_value(raw).deleted_at,
                ));
            }
        }
    }
    Ok(None)
}

/// Only batches changing authorship or message rows need a full inbox rejoin.
pub(crate) fn batch_needs_inbox_rejoin(ops: &[crate::batch::BatchOp]) -> bool {
    ops.iter().any(|op| {
        matches!(
            op,
            crate::batch::BatchOp::Put {
                entity_type: ENTITY_TYPE_MESSAGE,
                ..
            } | crate::batch::BatchOp::Edge {
                kind: EdgeKind::AuthoredBy,
                ..
            } | crate::batch::BatchOp::PublicEdgeWithCreatedAt {
                kind: EdgeKind::AuthoredBy,
                ..
            } | crate::batch::BatchOp::EdgeWithCreatedAt {
                kind: EdgeKind::AuthoredBy,
                ..
            } | crate::batch::BatchOp::DeleteEdge {
                kind: EdgeKind::AuthoredBy,
                ..
            }
        )
    })
}

pub(crate) fn purge_signals(store: &Store, txn: &mut heed::RwTxn<'_>, id: &EntityId) -> Result<()> {
    let hex = id.to_hex();
    let mut keys = Vec::new();
    for entry in store
        .vault_meta
        .prefix_iter(txn, REACTION_INBOX_KEY_PREFIX)?
    {
        let (key, value) = entry?;
        let signal: ReactionSignal =
            serde_json::from_slice(&value).map_err(|_| Error::CorruptedIndex("reaction inbox"))?;
        let author_matches = key
            .get(REACTION_INBOX_KEY_PREFIX.len()..REACTION_INBOX_KEY_PREFIX.len() + 16)
            == Some(id.as_bytes().as_slice());
        if author_matches || signal.reaction == hex || signal.message == hex || signal.by == hex {
            keys.push(key.to_vec());
        }
    }
    for key in keys {
        store.vault_meta.delete(txn, &key)?;
    }
    Ok(())
}
