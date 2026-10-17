//! The entity table. A record's body and the text it was indexed with are
//! read by the door's rules, and a record that holds a hit is written again
//! through its own door: an ordinary record through the batch door, which
//! masks its body and its index text with one plan; a NOTE through its
//! document's door; a file through the batch door's file mark, which keeps
//! its bytes. An entity document's text is its own op history, which no door
//! rewrites.

use std::ops::Bound;

use heed::{RoTxn, RwTxn};

use super::super::write_payload_hit;
use super::{Done, LiftCause, Page};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{
    ENTITY_TYPE_ASSET, ENTITY_TYPE_NOTE, ENTITY_TYPE_SECRET_CUSTODY, ENTITY_TYPE_WORLD_KEY_PAD,
};
use crate::side_table::{self, Named, SideTable};
use crate::{TimeRange, Vault};

/// The text each record was indexed with, by field.
const INDEX_SOURCE_TEXT: SideTable<EntityId, Vec<(String, String)>, Named> =
    SideTable::new(&side_table::INDEX_SOURCE_TEXT);

/// The records after `after` (a record id; empty at the start), up to
/// `limit`.
pub(super) fn census(vault: &Vault, txn: &RoTxn<'_>, after: &[u8], limit: usize) -> Result<Page> {
    let start = if after.is_empty() {
        Bound::Unbounded
    } else {
        Bound::Excluded(after)
    };
    let mut page = Page {
        read: 0,
        hits: Vec::new(),
        next: None,
    };
    let mut read = 0;
    for row in vault
        .store
        .entities
        .range(txn, &(start, Bound::Unbounded))?
    {
        let (key, raw) = row?;
        read += 1;
        if let Some(id) = record_id(&key)
            && hit(vault, txn, &id, &raw)?.is_some()
        {
            page.hits.push(key.to_vec());
        }
        if read == limit {
            page.next = Some(key.into_owned());
            break;
        }
    }
    page.read = u64::try_from(read).unwrap_or(u64::MAX);
    Ok(page)
}

/// Reads record `key` again in the writer's transaction and writes it again
/// through its door when it still holds a hit.
pub(super) fn lift(vault: &Vault, txn: &mut RwTxn<'_>, key: &[u8]) -> Result<Done> {
    let Some(id) = record_id(key) else {
        return Ok(Done::Clean);
    };
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)? else {
        return Ok(Done::Clean);
    };
    // A record a writer has cleaned since the census read it is done.
    let Some(reason) = hit(vault, txn, &id, &raw)? else {
        return Ok(Done::Clean);
    };
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("lift sweep entity header"))?;
    if crate::store::legal_hold::held_in_txn(&vault.store, txn, id.as_bytes())? {
        return Ok(Done::Propose(LiftCause::Held, reason));
    }
    // A record's prose lives in its document, whose history no door
    // rewrites: its keys are marked through the document's own door.
    #[cfg(feature = "sync")]
    if header.entity_type != ENTITY_TYPE_NOTE
        && crate::entity_doc::has_record_head(&vault.store, txn, &id)?
    {
        return crate::entity_doc::lift_entity_text_in_txn(vault, txn, &id)
            .map(super::retained::text_done);
    }
    match header.entity_type {
        ENTITY_TYPE_NOTE => {
            crate::note::lift_note_in_txn(vault, txn, id)?;
            after_rewrite(vault, txn, &id, reason, false)
        }
        ENTITY_TYPE_ASSET => {
            mark_file(vault, txn, &id, &header, &raw)?;
            Ok(Done::Propose(LiftCause::File, reason))
        }
        _ => rewrite(vault, txn, &id, &header, &raw, reason),
    }
}

/// `record:<id>`.
pub(super) fn path(key: &[u8]) -> String {
    record_id(key).map_or_else(
        || "record:".to_owned(),
        |id| format!("record:{}", id.to_hex()),
    )
}

fn record_id(key: &[u8]) -> Option<EntityId> {
    EntityId::from_bytes(key.try_into().ok()?).ok()
}

/// The door's reason for a hit in `raw`'s body or in the text it was indexed
/// with; `None` for a clean record and for one the sweep leaves: a custody
/// record, the value's home, and a world key's pad.
fn hit(vault: &Vault, txn: &RoTxn<'_>, id: &EntityId, raw: &[u8]) -> Result<Option<&'static str>> {
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return Ok(None);
    };
    if matches!(
        header.entity_type,
        ENTITY_TYPE_SECRET_CUSTODY | ENTITY_TYPE_WORLD_KEY_PAD
    ) {
        return Ok(None);
    }
    if let Some(reason) = raw
        .get(ENTITY_METADATA_HEADER_LEN..)
        .and_then(write_payload_hit)
    {
        return Ok(Some(reason));
    }
    Ok(index_text(vault, txn, id)?
        .iter()
        .find_map(|(_, text)| write_payload_hit(text.as_bytes())))
}

fn index_text(vault: &Vault, txn: &RoTxn<'_>, id: &EntityId) -> Result<Vec<(String, String)>> {
    Ok(INDEX_SOURCE_TEXT
        .get_lenient(&vault.store, txn, id)?
        .unwrap_or_default())
}

fn occurred(header: &EntityMetadataHeader) -> TimeRange {
    TimeRange {
        start: header.occurred_start,
        end: header.occurred_end,
    }
}

/// An ordinary record: its old text leaves the index first, and a body that
/// holds a hit drops the vector made from it, so the put schedules a new
/// one. The batch door then masks the body and the index text with one plan
/// and indexes the masked text. The record's revision ledger keeps the body
/// it replaced.
fn rewrite(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    header: &EntityMetadataHeader,
    raw: &[u8],
    reason: &'static str,
) -> Result<Done> {
    let body = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
    let body_hit = write_payload_hit(body).is_some();
    let fields = index_text(vault, txn, id)?;
    crate::bm25::deindex_text(&vault.store, txn, id)?;
    let mut batch = vault.batch_in();
    if body_hit {
        crate::vault::entity_revision::drop_vector_state(vault, txn, id)?;
        batch = batch.put_internal(
            id,
            header.entity_type,
            occurred(header),
            header.learned_at,
            body,
        );
    }
    if !fields.is_empty() {
        let fields = fields
            .iter()
            .map(|(name, text)| (name.as_str(), text.as_str()))
            .collect::<Vec<_>>();
        batch = batch.text(id, &fields);
    }
    batch.apply(txn)?;
    after_rewrite(vault, txn, id, reason, body_hit)
}

/// A file keeps its bytes. Put again as they are, the batch door marks each
/// key in them with its custody record and raises the file's band; a file
/// already marked is left as it is.
fn mark_file(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    header: &EntityMetadataHeader,
    raw: &[u8],
) -> Result<()> {
    let bytes = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
    let hash = *blake3::hash(bytes).as_bytes();
    if crate::secret_custody::masked_file_in_txn(&vault.store, txn, &hash)?.is_some() {
        return Ok(());
    }
    vault
        .batch_in()
        .put_internal(
            id,
            ENTITY_TYPE_ASSET,
            occurred(header),
            header.learned_at,
            bytes,
        )
        .apply(txn)
}

/// The record as its door left it: still holding a hit is one no rule
/// placed; else masked, with `history` when its ledger kept what it replaced.
fn after_rewrite(
    vault: &Vault,
    txn: &RwTxn<'_>,
    id: &EntityId,
    reason: &'static str,
    history: bool,
) -> Result<Done> {
    let left = match crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)? {
        Some(raw) => hit(vault, txn, id, &raw)?,
        None => None,
    };
    Ok(match left {
        Some(left) => Done::Propose(LiftCause::Unplaceable, left),
        None => Done::Masked { history, reason },
    })
}
