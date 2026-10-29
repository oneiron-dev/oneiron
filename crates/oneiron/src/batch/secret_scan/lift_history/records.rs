//! The entity table. A record's body and the text it was indexed with are
//! read by the door's rules, and a record that holds a hit is written again
//! through its own door: an ordinary record through the batch door, which
//! masks its body and its index text with one plan; a NOTE through its
//! document's door; a file through the batch door's file mark, which keeps
//! its bytes. An entity document's text is its own op history, which no door
//! rewrites. A file-plane ASSET is read as its body, never its manifest, and
//! its body is what a lift puts again (FIX 5395).

use std::borrow::Cow;
use std::ops::Bound;

use heed::{RoTxn, RwTxn};

use super::super::mask::REASON_KNOWN_VALUE;
use super::super::mask::known_marks::{holds_unmarked_known, remark_known_file_in_txn};
use super::super::write_payload_hit;
use super::{Done, LiftCause, LiftFamily, Page, proposals, record_text};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{
    ENTITY_TYPE_ASSET, ENTITY_TYPE_NOTE, ENTITY_TYPE_SECRET_CUSTODY, ENTITY_TYPE_WORLD_KEY_PAD,
};
use crate::secret_custody::{KeptValues, KnownValues, masked_file_in_txn};
use crate::side_table::{self, Named, SideTable};
use crate::{TimeRange, Vault};

/// The text each record was indexed with, by field.
const INDEX_SOURCE_TEXT: SideTable<EntityId, Vec<(String, String)>, Named> =
    SideTable::new(&side_table::INDEX_SOURCE_TEXT);

/// The records after `after` (a record id; empty at the start), up to
/// `limit`: each that holds a hit, or a file holding a value `known` knows
/// that its mark does not cover yet (FIX 2781). A known-value pass
/// (`known_only`) reads the files alone.
pub(super) fn census(
    vault: &Vault,
    txn: &RoTxn<'_>,
    after: &[u8],
    limit: usize,
    known: Option<&KnownValues>,
    known_only: bool,
) -> Result<Page> {
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
            && census_hit(vault, txn, &id, &raw, known, known_only)?
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

/// Whether record `id`'s stored row `raw` is one the walk settles: a hit
/// the door's rules place (a known-value pass reads none), or a file holding
/// a value `known` knows that its mark does not cover yet.
fn census_hit(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
    known: Option<&KnownValues>,
    known_only: bool,
) -> Result<bool> {
    let file = EntityMetadataHeader::parse(raw)
        .is_some_and(|header| header.entity_type == ENTITY_TYPE_ASSET);
    if known_only && (!file || known.is_none()) {
        return Ok(false);
    }
    let raw = materialized(vault, txn, id, raw)?;
    if !known_only && hit(vault, txn, id, &raw)?.is_some() {
        return Ok(true);
    }
    match known.filter(|_| file) {
        Some(known) => known_hit(vault, txn, id, &raw, known),
        None => Ok(false),
    }
}

/// Whether the file ASSET `id` stores (its row `raw`, as its readers read
/// it) holds a value `known` knows that its mark does not cover yet, past
/// the owner's rulings in the record (FIX 2781). A file whose members the
/// read fails on reads as one: its writer tries it, and keeps the failure
/// to try again.
fn known_hit(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
    known: &KnownValues,
) -> Result<bool> {
    if proposals::owner_kept_in_txn(vault, txn, LiftFamily::Records, id.as_bytes())? {
        return Ok(false);
    }
    let bytes = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
    let kept = KeptValues::for_records_in_txn(&vault.store, txn, [*id])?;
    let prior = masked_file_in_txn(&vault.store, txn, blake3::hash(bytes).as_bytes())?;
    Ok(
        holds_unmarked_known(bytes, known, |value| kept.holds(id, value), prior.as_ref())
            .unwrap_or(true),
    )
}

/// A known-value pass over record `key` (FIX 2781): a file's mark takes
/// each value custody knows that it does not cover yet, past the owner's
/// rulings, in the writer's transaction. Its bytes, its index text and its
/// proposals stay as they are; any other record is passed over, and a file
/// a legal hold keeps files a proposal as a lift does.
pub(super) fn remark(vault: &Vault, txn: &mut RwTxn<'_>, key: &[u8]) -> Result<Done> {
    let Some(id) = record_id(key) else {
        return Ok(Done::Clean);
    };
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)? else {
        return Ok(Done::Clean);
    };
    if EntityMetadataHeader::parse(&raw)
        .is_none_or(|header| header.entity_type != ENTITY_TYPE_ASSET)
    {
        return Ok(Done::Clean);
    }
    let raw = vault.materialized_row_in_txn(txn, &id, raw)?;
    if proposals::owner_kept_in_txn(vault, txn, LiftFamily::Records, key)? {
        return Ok(Done::Clean);
    }
    if crate::store::legal_hold::held_in_txn(&vault.store, txn, id.as_bytes())? {
        return Ok(Done::Propose(LiftCause::Held, REASON_KNOWN_VALUE));
    }
    let bytes = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
    Ok(if remark_file(vault, txn, &id, bytes)? {
        Done::Marked
    } else {
        Done::Clean
    })
}

/// The values custody knows in the file `bytes` ASSET `id` stores, marked
/// beside its marks, past the owner's rulings in the record; `true` when
/// one was added.
fn remark_file(vault: &Vault, txn: &mut RwTxn<'_>, id: &EntityId, bytes: &[u8]) -> Result<bool> {
    let Some(known) = KnownValues::load_in_writer(&vault.store, txn)? else {
        return Ok(false);
    };
    let kept = KeptValues::for_records_in_txn(&vault.store, txn, [*id])?;
    let added = remark_known_file_in_txn(&vault.store, txn, id, bytes, &known, &kept)?;
    // New spans on a repo blob refresh the index copies it derives, in this
    // writer (FIX 7608 slice 3).
    if added {
        crate::origin::secret_projection::index::refresh_repo_index_projection_in_txn(
            vault,
            txn,
            &[*blake3::hash(bytes).as_bytes()],
        )?;
    }
    Ok(added)
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
    let raw = vault.materialized_row_in_txn(txn, &id, raw)?;
    // A record a writer has cleaned since the census read it is done; a
    // file still settles a known-value hit (FIX 8647).
    let Some(reason) = hit(vault, txn, &id, &raw)? else {
        return remark(vault, txn, key);
    };
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("lift sweep entity header"))?;
    if crate::store::legal_hold::held_in_txn(&vault.store, txn, id.as_bytes())? {
        return Ok(Done::Propose(LiftCause::Held, reason));
    }
    // A record's prose lives in its document, whose history no door
    // rewrites: its keys are marked through the document's own door.
    if header.entity_type != ENTITY_TYPE_NOTE
        && crate::entity_doc::has_record_head(&vault.store, txn, &id)?
    {
        return crate::entity_doc::lift_entity_text_in_txn(vault, txn, &id)
            .map(super::retained::text_done);
    }
    match header.entity_type {
        ENTITY_TYPE_NOTE => {
            // Its document's history no door rewrites either: each text the
            // census reads is marked where it is kept (FIX 2967).
            let body = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
            let mut kept = vec![body.to_vec()];
            for (_, text) in index_text(vault, txn, &id)?
                .into_iter()
                .chain(record_text::staged(vault, txn, &id)?)
            {
                kept.push(text.into_bytes());
            }
            crate::note::lift_note_in_txn(vault, txn, id, &kept).map(super::retained::text_done)
        }
        ENTITY_TYPE_ASSET => {
            mark_file(vault, txn, &id, &header, &raw)?;
            // A file whose only hit was in its index text reads clean now.
            match raw
                .get(ENTITY_METADATA_HEADER_LEN..)
                .and_then(write_payload_hit)
            {
                Some(_) => Ok(Done::Propose(LiftCause::File, reason)),
                None => after_rewrite(vault, txn, &id, reason, false),
            }
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

pub(super) fn record_id(key: &[u8]) -> Option<EntityId> {
    EntityId::from_bytes(key.try_into().ok()?).ok()
}

/// The stored row `raw` of `id` as its readers read it: a file-plane ASSET
/// with its body in place of its manifest (FIX 5395); any other row as it
/// is.
fn materialized<'r>(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: &EntityId,
    raw: &'r [u8],
) -> Result<Cow<'r, [u8]>> {
    if EntityMetadataHeader::parse(raw).is_none_or(|header| header.entity_type != ENTITY_TYPE_ASSET)
    {
        return Ok(Cow::Borrowed(raw));
    }
    Ok(Cow::Owned(vault.materialized_row_in_txn(
        txn,
        id,
        raw.to_vec(),
    )?))
}

/// The door's reason for a hit in `raw`'s body, in the text it was indexed
/// with, or in the text it keeps beside them ([`record_text`]); `None` for a
/// clean record and for one the sweep leaves: a custody record, the value's
/// home, and a world key's pad.
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
    // A NOTE's text its lift marked is done (FIX 2967).
    let note = header.entity_type == ENTITY_TYPE_NOTE;
    let body = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
    if let Some(reason) = record_text::unmarked_hit(vault, txn, note, body)? {
        return Ok(Some(reason));
    }
    for (_, text) in index_text(vault, txn, id)? {
        if let Some(reason) = record_text::unmarked_hit(vault, txn, note, text.as_bytes())? {
            return Ok(Some(reason));
        }
    }
    record_text::hit(vault, txn, id, header.entity_type)
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
    let fields = index_inputs(vault, txn, id)?;
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
/// already marked keeps its marks, and takes beside them each value custody
/// came to know since, past the owner's rulings (FIX 2781). Its index text
/// is text, not its bytes, and is lifted first ([`lift_file_text`]).
fn mark_file(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    header: &EntityMetadataHeader,
    raw: &[u8],
) -> Result<()> {
    lift_file_text(vault, txn, id)?;
    let bytes = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
    let hash = *blake3::hash(bytes).as_bytes();
    if masked_file_in_txn(&vault.store, txn, &hash)?.is_some() {
        if !proposals::owner_kept_in_txn(vault, txn, LiftFamily::Records, id.as_bytes())? {
            remark_file(vault, txn, id, bytes)?;
        }
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
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    reason: &'static str,
    history: bool,
) -> Result<Done> {
    record_text::settle_staged(vault, txn, id)?;
    let left = match crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)? {
        Some(raw) => hit(vault, txn, id, &materialized(vault, txn, id, &raw)?)?,
        None => None,
    };
    Ok(match left {
        Some(left) => Done::Propose(LiftCause::Unplaceable, left),
        None => Done::Masked { history, reason },
    })
}

/// Whether record `key` is still live.
pub(super) fn exists(vault: &Vault, txn: &RoTxn<'_>, key: &[u8]) -> Result<bool> {
    match record_id(key) {
        Some(id) => Ok(crate::vault::live_entity_row_in_txn(&vault.store, txn, &id)?.is_live()),
        None => Ok(false),
    }
}

/// The text a record's index reads next: what it staged for its live
/// revision's idle publication, which that publication indexes, else the
/// text it was indexed with.
fn index_inputs(vault: &Vault, txn: &RoTxn<'_>, id: &EntityId) -> Result<Vec<(String, String)>> {
    match record_text::staged_live(vault, txn, id)? {
        Some(staged) => Ok(staged),
        None => index_text(vault, txn, id),
    }
}

/// A file's index text that holds a hit goes through the batch door again,
/// masked, as an ordinary record's does; staged text that still holds one is
/// dropped. The file's bytes are [`mark_file`]'s.
fn lift_file_text(vault: &Vault, txn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
    let fields = index_inputs(vault, txn, id)?;
    if fields
        .iter()
        .any(|(_, text)| write_payload_hit(text.as_bytes()).is_some())
    {
        crate::bm25::deindex_text(&vault.store, txn, id)?;
        let fields = fields
            .iter()
            .map(|(name, text)| (name.as_str(), text.as_str()))
            .collect::<Vec<_>>();
        vault.batch_in().text(id, &fields).apply(txn)?;
    }
    record_text::settle_staged(vault, txn, id)
}
