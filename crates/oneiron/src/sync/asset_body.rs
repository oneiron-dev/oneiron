//! File-plane ASSET rows at sync (FIX 5393): no export ships a manifest as a body.
//!
//! A file-plane ASSET row holds a manifest in place of its body. A window
//! carries it by reference (FIX 5489, [`references`]): the row's bytes are
//! the carrier, its reference rides beside it in the same commit, and the
//! body moves outside Loro, by the frames of `sync::transport` a socket's
//! [`session::AssetBodySession`] drives. An echo of a body, inline or by
//! reference, is the same row. Each helper asks
//! [`ASSET_FILE_PLANE`] first: off, no row is a file row, no reference is
//! read, and every caller keeps its exact behaviour.
//!
//! The descriptor decides, never the bytes: a row is a file row only when
//! the ASSET owns a complete body file for the manifest it stores
//! ([`asset_body_file_of_row`]). A peer's bytes are read as a manifest only
//! where a reference binds them.

pub(crate) mod client;
mod landing;
pub(crate) mod references;
mod send;
pub(crate) mod session;

use std::collections::BTreeSet;

use heed::RoTxn;
use loro::{LoroDoc, LoroMap};

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_ASSET;
use crate::store::{
    ASSET_FILE_PLANE, AssetBodyFacts, ManifestDbs, asset_body_file_of_row, asset_file_in_txn,
};
use crate::sync::loro_support::map_for_each_value_bytes;
use references::AssetBodyRef;

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

/// The row a point read serves for `blob`, what `doc` carries for `id`
/// (FIX 5532): an ordinary body as it is, and a carrier `doc` binds by
/// reference as the body it names under its header, read whole from the row
/// stored here, inline or in its file, as the read was served before the
/// file plane. `None` while that body is not here.
///
/// # Errors
///
/// Storage errors, and a body file that is missing or disagrees with its
/// manifest.
pub(in crate::sync) fn served_row(
    vault: &crate::Vault,
    doc: &LoroDoc,
    id: &EntityId,
    blob: Vec<u8>,
) -> Result<Option<Vec<u8>>> {
    let Some(body) = references::bound_in(doc, id, &blob) else {
        return Ok(Some(blob));
    };
    let txn = vault.store.env.read_txn()?;
    let Some(stored) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, id)?
    else {
        return Ok(None);
    };
    if !ref_echo_equal(&vault.store, &txn, id, &body, &stored, &blob)? {
        return Ok(None);
    }
    vault.materialized_row_in_txn(&txn, id, stored).map(Some)
}

/// Whether the stored row `stored` of `id` is an ASSET whose body, inline or
/// in its file, has exactly `facts`. An inline body is measured only when
/// its length is the one `facts` names.
///
/// # Errors
///
/// [`asset_file_in_txn`]'s errors.
pub(in crate::sync) fn stored_body_is(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    stored: &[u8],
    facts: &AssetBodyFacts,
) -> Result<bool> {
    if EntityMetadataHeader::parse(stored).is_none_or(|h| h.entity_type != ENTITY_TYPE_ASSET) {
        return Ok(false);
    }
    let body = &stored[ENTITY_METADATA_HEADER_LEN..];
    if let Some(manifest) = asset_file_in_txn(store, txn, id, body)? {
        return Ok(manifest.facts == *facts);
    }
    Ok(body.len() as u64 == facts.len && AssetBodyFacts::of(body) == *facts)
}

/// The echo test of a carrier `body` binds: `carried` is the row `stored` of
/// `id` when the two hold the same metadata header and the stored body,
/// inline or in its file, is the one the reference names. Identical
/// manifest bytes alone prove nothing. `false` while the file plane is off.
///
/// # Errors
///
/// [`stored_body_is`]'s errors.
pub(in crate::sync) fn ref_echo_equal(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    body: &AssetBodyRef,
    stored: &[u8],
    carried: &[u8],
) -> Result<bool> {
    if !ASSET_FILE_PLANE
        || stored.len() < ENTITY_METADATA_HEADER_LEN
        || carried.get(..ENTITY_METADATA_HEADER_LEN) != stored.get(..ENTITY_METADATA_HEADER_LEN)
    {
        return Ok(false);
    }
    stored_body_is(store, txn, id, stored, &body.facts())
}

/// Both logical echo tests, for a parity site that holds the window `doc`
/// `carried` comes from: [`file_echo_equal`], and [`ref_echo_equal`] when a
/// reference of `doc` binds `carried`.
///
/// # Errors
///
/// Their errors.
pub(in crate::sync) fn doc_echo_equal(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    doc: &LoroDoc,
    id: &EntityId,
    stored: &[u8],
    carried: &[u8],
) -> Result<bool> {
    if file_echo_equal(store, txn, id, stored, carried)? {
        return Ok(true);
    }
    match references::bound_in(doc, id, carried) {
        Some(body) => ref_echo_equal(store, txn, id, &body, stored, carried),
        None => Ok(false),
    }
}
