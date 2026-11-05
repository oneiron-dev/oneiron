//! Descending raw side rows for readers that retain malformed values as facts.
use heed::RoTxn;

use super::{SideCodec, SideKey, SideTable, SideTableDbs};
use crate::Result;

impl<K: SideKey, V, C: SideCodec<V>> SideTable<K, V, C> {
    /// [`Self::iter_raw_from`] in descending key order. Key and value validation
    /// remain with the caller, using the table's native key and value codecs.
    pub(crate) fn iter_raw_rev_from<'txn>(
        &self,
        dbs: &impl SideTableDbs,
        txn: &'txn RoTxn<'_>,
        key_prefix: &[u8],
    ) -> Result<impl Iterator<Item = Result<(Vec<u8>, Vec<u8>)>> + 'txn> {
        let prefix_len = self.decl.prefix.len();
        Ok(self
            .raw_rows(dbs, txn, key_prefix, true)?
            .map(move |row| row.map(|(key, value)| (key[prefix_len..].to_vec(), value))))
    }
}
