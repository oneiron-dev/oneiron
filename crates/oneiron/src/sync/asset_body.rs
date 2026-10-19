//! File-plane ASSET rows at sync (FIX 5393 cut 1): no export ships a manifest without its bytes.
//!
//! A file-plane ASSET row holds a manifest in place of its body, and sync
//! copies rows raw, so a peer would take the manifest for the body. Until a
//! body transport lands (cut 2), every egress withholds such a row, and an
//! echo of its body inline is the same row. Each helper asks
//! [`ASSET_FILE_PLANE`] first: off, no row is a file row, and every caller
//! keeps its exact behaviour without reading a descriptor.
//!
//! The descriptor decides, never the bytes: a row is a file row only when
//! the ASSET owns a complete body file for the manifest it stores
//! ([`asset_body_file_of_row`]). A peer's bytes are never read as a manifest.

use std::collections::BTreeSet;

use heed::RoTxn;
use loro::LoroMap;

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::{ASSET_FILE_PLANE, ManifestDbs, asset_body_file_of_row};
use crate::sync::loro_support::map_for_each_value_bytes;

/// Whether the stored row `raw` of `id` is a file-plane ASSET's. Always
/// `false` while the file plane is off.
///
/// # Errors
///
/// [`asset_body_file_of_row`]'s errors.
pub(crate) fn file_row_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<bool> {
    if !ASSET_FILE_PLANE {
        return Ok(false);
    }
    Ok(asset_body_file_of_row(store, txn, id.as_bytes(), raw)?.is_some())
}

/// [`file_row_in_txn`] for the row stored at `id`, read in place.
///
/// # Errors
///
/// Storage errors, and [`file_row_in_txn`]'s.
pub(in crate::sync) fn file_row_at(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    if !ASSET_FILE_PLANE {
        return Ok(false);
    }
    Ok(
        crate::ports::EntityStoreRead::port_entity_with_raw(store, txn, id, |raw| {
            file_row_in_txn(store, txn, id, raw)
        })?
        .unwrap_or(false),
    )
}

/// The ids `entities` carries whose stored rows are file-plane ASSETs': a
/// selector export withholds them before it picks a candidate, so no edge,
/// birth or epoch summary leaves as if they shipped.
///
/// # Errors
///
/// [`file_row_at`]'s errors.
pub(in crate::sync) fn file_rows_in(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    entities: &LoroMap,
) -> Result<BTreeSet<EntityId>> {
    let mut rows = BTreeSet::new();
    if !ASSET_FILE_PLANE {
        return Ok(rows);
    }
    let mut carried = Vec::new();
    map_for_each_value_bytes(entities, |raw_key, blob| {
        if blob.is_some()
            && let Ok(id) = EntityId::from_hex(raw_key)
        {
            carried.push(id);
        }
    });
    for id in carried {
        if file_row_at(store, txn, &id)? {
            rows.insert(id);
        }
    }
    Ok(rows)
}

/// The logical echo test: whether `carried` holds inline the body the
/// file-plane ASSET row `stored` of `id` keeps in its file. The metadata
/// header must be the same bytes, and the carried body's BLAKE3 and length
/// those of the stored manifest. `false` for any row that is not a file row,
/// whose callers keep their exact-byte test, and always while the file plane
/// is off.
///
/// # Errors
///
/// [`asset_body_file_of_row`]'s errors.
pub(in crate::sync) fn file_echo_equal(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    stored: &[u8],
    carried: &[u8],
) -> Result<bool> {
    if !ASSET_FILE_PLANE
        || stored.len() < ENTITY_METADATA_HEADER_LEN
        || carried.get(..ENTITY_METADATA_HEADER_LEN) != stored.get(..ENTITY_METADATA_HEADER_LEN)
    {
        return Ok(false);
    }
    let Some((digest, len)) = asset_body_file_of_row(store, txn, id.as_bytes(), stored)? else {
        return Ok(false);
    };
    let body = &carried[ENTITY_METADATA_HEADER_LEN..];
    Ok(body.len() as u64 == len && *blake3::hash(body).as_bytes() == digest)
}
