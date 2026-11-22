//! The owner's notice of a refused setting projection keeps its seen and acknowledged marks
//! between a vault's machines (row SETTING-PROJECTED-ROW-REFUSING-HOOKS, REVIEW-10294 round 2).
//!
//! Each machine whose pass refuses a row raises that notice alone, under one id: its producer and
//! event name the acts it is about (`setting::project::refusal`). A window carries a row body as
//! one value, so of two machines that raised the same notice while apart, the window keeps one
//! body, and an owner's mark on the other copy would go. Ingest lands such a carried body with
//! the marks of both copies: a reader either copy marks seen or acknowledged stays so, as no door
//! takes a mark back. Every other key lands as carried. Where the merge holds marks the carried
//! body lacks, the window owes the merged body: the import leaves a pending-mirror marker, and the
//! live mirror writes the stored body over the carrier, so the machine that sent it learns this
//! machine's marks.
//!
//! Only a body that decodes and encodes back to its own bytes is merged; any other lands as it
//! came. A row a federation peer's import brought ([`super::peer_row_in_txn`]) lands as it came.

use std::borrow::Cow;
use std::collections::BTreeMap;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::inbox::{NotificationBody, decode_notification_body, encode_notification_body};
use crate::registry::ENTITY_TYPE_NOTIFICATION;
use crate::setting::SETTING_REFUSAL_NOTIFICATION_PRODUCER;

/// `bytes` as a refusal notice's body, where they decode to one and encode back to themselves.
fn refusal_notice(bytes: &[u8]) -> Option<NotificationBody> {
    let body = decode_notification_body(bytes).ok()?;
    (body.source.producer == SETTING_REFUSAL_NOTIFICATION_PRODUCER
        && encode_notification_body(&body).ok()? == bytes)
        .then_some(body)
}

/// Whether `row` is a NOTIFICATION row.
fn is_notification_row(row: &[u8]) -> bool {
    EntityMetadataHeader::parse(row)
        .is_some_and(|header| header.entity_type == ENTITY_TYPE_NOTIFICATION)
}

/// Adds every mark of `held` to `carried`; whether that added one.
fn merge_marks(carried: &mut BTreeMap<String, bool>, held: &BTreeMap<String, bool>) -> bool {
    let mut added = false;
    for (reader, marked) in held {
        if *marked && carried.get(reader) != Some(&true) {
            carried.insert(reader.clone(), true);
            added = true;
        }
    }
    added
}

/// The body `data` of the carried row `blob` at `id`, in `window_key`, as this vault admits it: a
/// refusal notice whose seen or acknowledged marks lack one the notice held here holds lands
/// with both copies' marks, and the window that carries it owes the merged body. Any other row,
/// a body the merge does not change, and a row a federation peer's import brought land as they
/// came.
///
/// # Errors
///
/// Storage errors, or a merged body that does not encode.
pub(in crate::sync) fn carried_notification_marks_in_txn<'a>(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    id: &EntityId,
    blob: &[u8],
    data: Cow<'a, [u8]>,
) -> Result<Cow<'a, [u8]>> {
    if !is_notification_row(blob) {
        return Ok(data);
    }
    let Some(held) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, wtxn, id)? else {
        return Ok(data);
    };
    if !is_notification_row(&held) {
        return Ok(data);
    }
    let (Some(held), Some(mut carried)) = (
        held.get(ENTITY_METADATA_HEADER_LEN..)
            .and_then(refusal_notice),
        refusal_notice(&data),
    ) else {
        return Ok(data);
    };
    let seen = merge_marks(&mut carried.seen_by, &held.seen_by);
    let acked = merge_marks(&mut carried.acked_by, &held.acked_by);
    if !(seen || acked) {
        return Ok(data);
    }
    if super::peer_row_in_txn(vault, wtxn, window_key, id, blob)? {
        return Ok(data);
    }
    let merged = encode_notification_body(&carried)?;
    vault.mark_merged_carrier_in_txn(wtxn, window_key, id, blob)?;
    Ok(Cow::Owned(merged))
}
