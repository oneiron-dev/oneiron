//! Message visibility shared by reaction writes, reads, and room listing.
//!
//! Membership is PERSON --ParticipatesIn--> CONVERSATION; the edge creation
//! time is the history boundary. PERSON creation is never room membership.
//! Missing membership fails closed. A thread follows ChildOf to its room.
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::{EdgeKind, parse_strict_edge_record};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON};
use crate::store::Store;
use std::collections::BTreeSet;

pub(crate) fn live_header(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<EntityMetadataHeader>> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if raw.len() == ENTITY_METADATA_HEADER_LEN
        || store.entity_deletion_present_in_txn(txn, id, header.learned_at)?
    {
        return Ok(None);
    }
    Ok(Some(header))
}

pub(crate) fn message_room(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    message: &EntityId,
) -> Result<Option<EntityId>> {
    let mut prefix = message.as_bytes().to_vec();
    prefix.push(EdgeKind::BelongsTo as u8);
    let mut room = None;
    for entry in store.edges_out.prefix_iter(txn, &prefix)? {
        let (key, value) = entry?;
        let edge = parse_strict_edge_record(&key, &value)?;
        if live_header(store, txn, &edge.target)?
            .is_some_and(|h| h.entity_type == ENTITY_TYPE_CONVERSATION)
        {
            if room.is_some() {
                return Ok(None);
            }
            room = Some(edge.target);
        }
    }
    Ok(room)
}

pub(crate) fn message_visible_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    message: &EntityId,
    viewer: &EntityId,
) -> Result<bool> {
    if live_header(store, txn, viewer)?.is_none_or(|h| h.entity_type != ENTITY_TYPE_PERSON) {
        return Ok(false);
    }
    let Some(header) = live_header(store, txn, message)? else {
        return Ok(false);
    };
    if header.entity_type != ENTITY_TYPE_MESSAGE {
        return Ok(false);
    }
    let raw = store
        .entities
        .get(txn, message.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let mut bytes = &raw[ENTITY_METADATA_HEADER_LEN..];
    let Ok(rmpv::Value::Map(entries)) = rmpv::decode::read_value(&mut bytes) else {
        return Ok(false);
    };
    if !bytes.is_empty()
        || !entries
            .iter()
            .any(|(k, v)| k.as_str() == Some("is_visible") && v.as_bool() == Some(true))
    {
        return Ok(false);
    }
    let Some(mut room) = message_room(store, txn, message)? else {
        return Ok(false);
    };
    let mut seen = BTreeSet::new();
    loop {
        if !seen.insert(room) || seen.len() > 64 {
            return Ok(false);
        }
        let mut prefix = room.as_bytes().to_vec();
        prefix.push(EdgeKind::ChildOf as u8);
        let mut parent = None;
        for entry in store.edges_out.prefix_iter(txn, &prefix)? {
            let (key, value) = entry?;
            let edge = parse_strict_edge_record(&key, &value)?;
            if live_header(store, txn, &edge.target)?
                .is_none_or(|h| h.entity_type != ENTITY_TYPE_CONVERSATION)
                || parent.is_some()
            {
                return Ok(false);
            }
            parent = Some(edge.target);
        }
        if let Some(id) = parent {
            room = id;
            continue;
        }
        let key = Store::encode_edge_key(viewer, EdgeKind::ParticipatesIn, &room);
        if let Some(value) = store.edges_out.get(txn, &key)? {
            let edge = parse_strict_edge_record(&key, &value)?;
            return Ok(edge.decoded.created_at <= header.learned_at);
        }
        return Ok(false);
    }
}

impl Vault {
    /// Message visibility from live room membership at the message's record time.
    pub fn conversation_message_visible_to(
        &self,
        message: &EntityId,
        viewer: &EntityId,
    ) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        message_visible_in_txn(&self.store, &txn, message, viewer)
    }

    /// A message page filtered by the same membership rule as its reactions.
    pub fn visible_conversation_messages(
        &self,
        conversation: &EntityId,
        viewer: &EntityId,
        after: Option<EntityId>,
        limit: usize,
    ) -> Result<Vec<EntityId>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let txn = self.store.env.read_txn()?;
        let mut prefix = conversation.as_bytes().to_vec();
        prefix.push(EdgeKind::BelongsTo as u8);
        let mut out = Vec::new();
        for entry in self.store.edges_in.prefix_iter(&txn, &prefix)? {
            let (key, value) = entry?;
            let id = parse_strict_edge_record(&key, &value)?.target;
            if after.is_some_and(|a| id <= a) {
                continue;
            }
            if message_visible_in_txn(&self.store, &txn, &id, viewer)? {
                out.push(id);
            }
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }
}
