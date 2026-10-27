//! An ASSET's bytes in the canonical BlobStore (FIX 9949).
//! Entry: land_asset_blob_in_txn.
//! Definitions: this module owns the listed types and functions; the body fields stay in the parent.
//!
//! An uploaded or generated ASSET row is metadata: its kind, media type, size,
//! source, model, and the BLAKE3 hash that names its bytes. The bytes are a
//! blob the ASSET holds by a stable reference, its own id, landed in the same
//! actor-authorized transaction as the row and its ASSET_TEXT, read in the
//! snapshot of the lane that admitted the row, and released with the row at
//! its delete and its erase. The blob's own content-addressed row and its
//! reference rows are the BlobStore's; nothing here counts holders.

use heed::{RoTxn, RwTxn};
use rmpv::Value;

use super::{BODY_BLAKE3, BODY_MEDIA_TYPE, EntityId, MemoryError, MemoryResult, TimeRange};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::ports::{BlobStore, EntityStoreRead};
use crate::registry::ENTITY_TYPE_ASSET;
use crate::store::Store;

/// The ASSET body field that holds the bytes' size.
const BODY_BYTE_SIZE: &str = "byte_size";

/// What an ASSET's metadata names of its bytes: the hash their blob is
/// stored under, their media type and their size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AssetBlobRef {
    pub(crate) hash: [u8; 32],
    pub(crate) media_type: String,
    pub(crate) byte_size: u64,
}

impl AssetBlobRef {
    /// The reference an ASSET's metadata body names; `None` for a body that
    /// names no blob (a document of another shape, or no map at all).
    pub(crate) fn of_body(body: &[u8]) -> Option<Self> {
        let Some(Value::Map(entries)) = super::decode_whole(body) else {
            return None;
        };
        let field = |name: &str| {
            entries
                .iter()
                .find(|(key, _)| key.as_str() == Some(name))
                .map(|(_, value)| value)
        };
        let hash = blake3::Hash::from_hex(field(BODY_BLAKE3)?.as_str()?).ok()?;
        let media_type = field(BODY_MEDIA_TYPE)?.as_str()?.to_owned();
        let byte_size = field(BODY_BYTE_SIZE)?.as_u64()?;
        Some(Self {
            hash: *hash.as_bytes(),
            media_type,
            byte_size,
        })
    }

    /// `bytes` when they are the ones this reference names: its hash and
    /// its size.
    fn names(&self, bytes: &[u8]) -> bool {
        bytes.len() as u64 == self.byte_size && blake3::hash(bytes).as_bytes() == &self.hash
    }
}

/// Lands `bytes` as the blob ASSET `asset` holds, in `txn`, the transaction
/// the actor's write of `asset` itself is in, after that write: a supporting
/// effect of the row, never a write of its own. The reference is the ASSET's
/// id. A fence an earlier release left on the same bytes is lifted, as a new
/// artifact holding them lifts it.
pub(super) fn land_asset_blob_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    asset: &EntityId,
    bytes: &[u8],
    occurred: TimeRange,
    learned_at: u64,
) -> MemoryResult<[u8; 32]> {
    let hash = vault.port_blob_put(txn, asset, bytes, occurred, learned_at)?;
    crate::blob_artifact::hold_asset_reference_in_txn(&vault.store, txn, &hash)?;
    Ok(hash)
}

/// The media type and bytes `body`, an ASSET row a lane admitted, names,
/// read in `txn`, the snapshot that lane admitted it in. `None` for a body
/// that names no blob. A blob the store does not hold, or bytes that are not
/// the ones the body names, are a corrupt index: an admitted ASSET's
/// reference holds its bytes for as long as the row stands.
pub(super) fn resolve_asset_blob_in_lane(
    vault: &Vault,
    txn: &RoTxn<'_>,
    body: &[u8],
) -> MemoryResult<Option<(String, Vec<u8>)>> {
    let Some(blob) = AssetBlobRef::of_body(body) else {
        return Ok(None);
    };
    let bytes = vault
        .port_blob_get(txn, &blob.hash)?
        .filter(|bytes| blob.names(bytes))
        .ok_or_else(|| MemoryError::from(crate::error::Error::CorruptedIndex("asset blob")))?;
    Ok(Some((blob.media_type, bytes)))
}

/// [`resolve_asset_blob_in_lane`] for a reader that holds a store rather
/// than a lane (the media backfill): `read` reads one stored row's body by
/// id in the reader's own snapshot. A blob that is absent, or bytes that are
/// not the ones the body names, read as no media.
pub(crate) fn asset_media_in(
    body: &[u8],
    read: impl FnOnce(&EntityId) -> crate::error::Result<Option<Vec<u8>>>,
) -> crate::error::Result<Option<(String, Vec<u8>)>> {
    let Some(blob) = AssetBlobRef::of_body(body) else {
        return Ok(None);
    };
    let id = crate::blob_artifact::blob_artifact_asset_entity_id(&blob.hash)?;
    Ok(read(&id)?
        .filter(|bytes| !bytes.is_empty() && blob.names(bytes))
        .map(|bytes| (blob.media_type, bytes)))
}

/// The deletion eraser for an ASSET's blob reference (FIX 9949): at the
/// ASSET's delete or erase, in that transaction and before its body goes,
/// the reference it holds on its bytes is released, and the bytes go with
/// their last holder by the BlobStore's own rule. A row that is no ASSET, or
/// whose body names no blob it holds, releases nothing.
pub(crate) fn release_asset_blob_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> crate::error::Result<()> {
    let Some(raw) = store.port_entity_raw(wtxn, id)? else {
        return Ok(());
    };
    if EntityMetadataHeader::parse(&raw).map(|header| header.entity_type) != Some(ENTITY_TYPE_ASSET)
    {
        return Ok(());
    }
    let Some(blob) = raw
        .get(ENTITY_METADATA_HEADER_LEN..)
        .and_then(AssetBlobRef::of_body)
    else {
        return Ok(());
    };
    crate::blob_artifact::release_asset_reference_in_txn(store, wtxn, id, &blob.hash)
}
