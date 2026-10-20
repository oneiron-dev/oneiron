//! One row's read that tells its own value's damage from the store's failure
//! (FIX 6482). [`SideTable::get`] returns both as one error; a reader that
//! must let one damaged row wait alone, and still fail on the store, reads
//! through [`SideTable::get_classified`] instead.

use heed::RoTxn;

use super::{SideCodec, SideKey, SideTable, SideTableDbs};
use crate::error::Error;

/// What one row read to.
#[derive(Debug)]
pub(crate) enum SideGet<V> {
    /// No row under the key.
    Missing,
    /// The row, decoded.
    Decoded(V),
    /// The row is there, but its bytes do not decode as the table's value:
    /// this one row's damage.
    DecodeError(Error),
    /// The store failed to read the row.
    StoreError(Error),
}

impl<K: SideKey, V, C: SideCodec<V>> SideTable<K, V, C> {
    /// [`Self::get`], with the store's own failure apart from one row's value
    /// that does not decode.
    pub(crate) fn get_classified(
        &self,
        dbs: &impl SideTableDbs,
        txn: &RoTxn<'_>,
        key: &K,
    ) -> SideGet<V> {
        match self.get_raw(dbs, txn, &self.key_bytes(key)) {
            Err(error) => SideGet::StoreError(error),
            Ok(None) => SideGet::Missing,
            Ok(Some(bytes)) => match self.decode_value(&bytes) {
                Ok(value) => SideGet::Decoded(value),
                Err(error) => SideGet::DecodeError(error),
            },
        }
    }
}
