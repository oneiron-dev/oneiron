//! Original decoded scans with their canonical stored bytes retained.

use super::{SideCodec, SideKey, SideTable, SideTableDbs};
use crate::Result;

impl<K: SideKey, V, C: SideCodec<V>> SideTable<K, V, C> {
    /// The same eager key/value decode as `scan`, in the same order. The full
    /// physical key and original body are returned only after that row decodes.
    pub(crate) fn scan_with_bytes(
        &self,
        dbs: &impl SideTableDbs,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<(K, V, Vec<u8>, Vec<u8>)>> {
        self.raw_rows(dbs, txn, &[], false)?
            .map(|row| {
                let (key, body) = row?;
                let decoded_key = self.decode_row_key(&key)?;
                let value = self.decode_value(&body)?;
                Ok((decoded_key, value, key, body))
            })
            .collect()
    }
}
