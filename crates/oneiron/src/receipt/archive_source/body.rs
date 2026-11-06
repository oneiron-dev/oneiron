//! Canonical archives through the original inline body or verified ASSET file.
use std::io::{Seek, SeekFrom};

use super::{
    codec::{ReceiptArchive, decode, id_of_bytes, invalid},
    reader::{BodyRangeReader, decode_reader, id_of_reader},
};
use crate::{
    entity_id::EntityId,
    error::Result,
    store::{AssetBodyFacts, AssetFileManifest, CheckedAssetBody, Store},
};

pub(super) struct DecodedArchive {
    pub(super) row: ReceiptArchive,
    pub(super) id: EntityId,
}

/// `file` is the original put's storage fact, not a guess from its row bytes.
/// Its staging pin must remain held through the caller's write transaction.
pub(super) fn decode_put(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    body: &[u8],
    file: Option<AssetBodyFacts>,
) -> Result<Option<DecodedArchive>> {
    let Some(facts) = file else {
        return decode(body)?
            .map(|row| {
                Ok(DecodedArchive {
                    row,
                    id: id_of_bytes(body)?,
                })
            })
            .transpose();
    };
    if AssetFileManifest::decode(body).is_none_or(|manifest| manifest.facts != facts) {
        return Err(invalid());
    }
    let key = crate::store::body_key_row_in_txn(store, txn, &facts.blake3)?;
    let file =
        CheckedAssetBody::open(&store.body_dir()?, &facts, key.as_ref())?.into_verified_file()?;
    let mut reader = BodyRangeReader::new(&file, 0, facts.len);
    let Some(row) = decode_reader(&mut reader)? else {
        return Ok(None);
    };
    reader.seek(SeekFrom::Start(0))?;
    let id = id_of_reader(reader)?;
    Ok(Some(DecodedArchive { row, id }))
}

/// Stored rows use their SAME-snapshot native descriptor. A manifest-shaped
/// inline body stays inline. Callers hold the file pin before opening `txn`.
pub(super) fn decode_stored(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<Option<DecodedArchive>> {
    let file =
        crate::store::asset_file_in_txn(store, txn, id, body)?.map(|manifest| manifest.facts);
    decode_put(store, txn, body, file)
}
