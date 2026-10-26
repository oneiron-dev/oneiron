//! The vault-meta rows a declared space keeps for a record's media vector
//! (FIX 7608 S3F, FIX 10407): their exact keys, which a room stages under
//! too, so a mask change drops a room's cached vectors of a record by the
//! same keys base drops its own by ([`super::delete_media_vectors_in_txn`]).

use std::collections::BTreeSet;

use heed::RoTxn;

use super::{EMBEDDING_SPACE, media_vector_row_key};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::SideTableDbs;

/// The keys of the media vector and device rows each space declared in
/// `txn` keeps, or a room stages, for one of `ids`.
///
/// # Errors
/// A store failure.
pub(crate) fn media_row_keys_in(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    ids: &BTreeSet<EntityId>,
) -> Result<BTreeSet<Vec<u8>>> {
    let mut keys = BTreeSet::new();
    for (space_id, _) in EMBEDDING_SPACE.scan(store, txn)? {
        for id in ids {
            keys.insert(media_vector_row_key(&space_id, id));
            keys.insert(super::super::device::media_device_row_key(&space_id, id));
        }
    }
    Ok(keys)
}
