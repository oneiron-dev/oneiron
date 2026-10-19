//! Which records hold one record's bytes, read for a delete's impact preview.
//!
//! Read-only. The answers use the release rule of the delete lifecycle and nothing of their own:
//! bytes stay while an `asset_ref` row or a live artifact's version claim holds them.

use heed::RoTxn;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_BLOB_ARTIFACT};
use crate::store::Store;

use super::references::{claimed_hashes, live_claim_holders};
use super::store_keys::{ASSET_REF, BLOB_ARTIFACT_CONTENT_HASH_LEN};
use super::versions::{VERSIONS, blob_artifact_asset_entity_id};

type ContentHash = [u8; BLOB_ARTIFACT_CONTENT_HASH_LEN];

/// The distinct content hashes `artifact` holds: its chain's hashes, then every hash its
/// replicated `blob.version` claims name. A replica has no chain of its own. Those claims count
/// only for an artifact row, or for an id with no row here (an artifact whose delete arrived
/// first), never for another kind of row a claim names.
pub(super) fn artifact_hashes(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
) -> Result<Vec<ContentHash>> {
    let mut hashes = Vec::new();
    for entry in VERSIONS.iter_from(store, txn, artifact.as_bytes())? {
        let (_, record) = entry?;
        if !hashes.contains(&record.content_hash) {
            hashes.push(record.content_hash);
        }
    }
    let claims_count = crate::ports::EntityStoreRead::port_entity_raw(store, txn, artifact)?
        .is_none_or(|raw| raw.first() == Some(&ENTITY_TYPE_BLOB_ARTIFACT));
    if claims_count {
        for content_hash in claimed_hashes(store, txn, artifact)? {
            if !hashes.contains(&content_hash) {
                hashes.push(content_hash);
            }
        }
    }
    Ok(hashes)
}

/// The content hashes the stored record `raw` at `id` holds: an artifact's own bytes, or the one
/// hash a byte carrier stores ([`carrier_content_hash`]). Any other record holds none.
pub(crate) fn held_content_hashes_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<Vec<ContentHash>> {
    if EntityMetadataHeader::parse(raw).map(|header| header.entity_type)
        == Some(ENTITY_TYPE_BLOB_ARTIFACT)
    {
        return artifact_hashes(store, txn, id);
    }
    Ok(carrier_content_hash(store, txn, id, raw)?
        .into_iter()
        .collect())
}

/// The hash whose bytes the stored record `raw` at `id` carries, when it is a content-addressed
/// version ASSET: its id is derived from the hash of its body. Every holder of those bytes reads
/// them through it, so deleting it takes them from all of them. A file-plane ASSET's row holds
/// its body's manifest, not the body, so the hash is the one that manifest names, read through
/// the file plane; an inline body is hashed as its row holds it (FIX 5394).
pub(crate) fn carrier_content_hash(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<Option<ContentHash>> {
    if EntityMetadataHeader::parse(raw).map(|header| header.entity_type) != Some(ENTITY_TYPE_ASSET)
    {
        return Ok(None);
    }
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    let hash: ContentHash = match crate::store::asset_file_in_txn(store, txn, id, body)? {
        Some(manifest) => manifest.facts.blake3,
        None => *blake3::hash(body).as_bytes(),
    };
    Ok((blob_artifact_asset_entity_id(&hash)? == *id).then_some(hash))
}

/// Every record that keeps the bytes under `hash` from release, sorted: each `asset_ref` row's
/// artifact and each live artifact a version claim names.
pub(crate) fn content_holders_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    hash: &ContentHash,
) -> Result<Vec<EntityId>> {
    let mut holders = live_claim_holders(store, txn, hash)?;
    for row in ASSET_REF.iter_from(store, txn, hash)? {
        let ((_, artifact), ()) = row?;
        holders.push(artifact);
    }
    holders.sort_unstable();
    holders.dedup();
    Ok(holders)
}

/// The actor who wrote every version of `artifact` here, read from the authenticated write
/// envelope of each version's `blob.version` claim (ARCH-0043: the actor is read, never claimed).
///
/// `None` when it does not resolve to one actor: no version on this vault's chain, a version
/// claim gone, deleted or unauthenticated, versions by different actors, or bytes held only
/// through a claim that arrived from another vault, whose writer this vault cannot prove.
pub(crate) fn artifact_author_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
) -> Result<Option<EntityId>> {
    let mut author = None;
    let mut chain = Vec::new();
    for entry in VERSIONS.iter_from(&vault.store, txn, artifact.as_bytes())? {
        let (_, record) = entry?;
        if !claim_is_live(&vault.store, txn, &record.claim_id)? {
            return Ok(None);
        }
        let Some(body) = vault.get_claim_in_txn(txn, &record.claim_id)? else {
            return Ok(None);
        };
        let Some(writer) = crate::batch::authenticated_claim_author_in_txn(
            &vault.store,
            txn,
            &record.claim_id,
            &body,
        )?
        else {
            return Ok(None);
        };
        if author.is_some_and(|seen| seen != writer.entity_ref()) {
            return Ok(None);
        }
        author = Some(writer.entity_ref());
        chain.push(record.content_hash);
    }
    if claimed_hashes(&vault.store, txn, artifact)?
        .iter()
        .any(|hash| !chain.contains(hash))
    {
        return Ok(None);
    }
    Ok(author)
}

/// A stored claim row with its body, under no delete this vault holds. A soft delete leaves a
/// header-only shell, which names no author.
fn claim_is_live(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)? else {
        return Ok(false);
    };
    if raw.len() <= ENTITY_METADATA_HEADER_LEN {
        return Ok(false);
    }
    crate::deletion::row_deletion_marked(store, txn, id, Some(raw.as_slice())).map(|marked| !marked)
}
