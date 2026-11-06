//! The vault-meta rows a declared space keeps for a record's media vector
//! (FIX 7608 S3F, FIX 10407): their side-table prefixes, which a room stages
//! under too, so a mask change or a delete drops a room's cached vectors of a
//! record by the same rows base drops its own by
//! ([`super::delete_media_vectors_in_txn`]).

use crate::side_table;

/// The prefixes of the media vector and device rows a space keeps, or a
/// room stages, for a record. Each row key is one of them and a
/// `(space key, record)` side-table key, so a room's copies of a record are
/// found in every space it staged them under, one retired since included
/// (FIX 9398).
pub(crate) fn media_row_prefixes() -> [&'static [u8]; 2] {
    [
        side_table::EMBEDDING_MEDIA_VECTOR.prefix,
        side_table::EMBEDDING_MEDIA_DEVICE.prefix,
    ]
}
