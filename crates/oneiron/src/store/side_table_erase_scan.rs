//! The scan an erase's scrub makes of one side table: every row whose key
//! and value decode, with any row whose value no longer decodes deleted and
//! counted. The skill attribution ledgers and the resident skill rows scrub
//! an erased entity with it.
use crate::Vault;
use crate::error::Result;
use crate::side_table::{SideCodec, SideKey, SideTable};

/// Every row of `table` whose key and value decode, in key order, for an
/// erase's scrub (FIX 8988). A row whose value no longer decodes is deleted
/// by its key and counted, so an erase never fails on it; a key that does
/// not decode names nothing a scrub can match, and is left as it is.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_scan_in_txn<K: SideKey, V, C: SideCodec<V>>(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    table: SideTable<K, V, C>,
) -> Result<Vec<(K, V)>> {
    let raw = table
        .iter_raw_from(&vault.store, wtxn, &[])?
        .collect::<Result<Vec<_>>>()?;
    let mut rows = Vec::with_capacity(raw.len());
    let mut dropped = 0_usize;
    for (key, value) in raw {
        let Some(key) = K::decode_key(&key) else {
            continue;
        };
        match table.decode_value(&value) {
            Ok(value) => rows.push((key, value)),
            Err(_) => {
                table.delete(&vault.store, wtxn, &key)?;
                dropped += 1;
            }
        }
    }
    if dropped > 0 {
        tracing::warn!(
            dropped,
            table = table.decl().name,
            "an erase deleted rows that no longer decode"
        );
    }
    Ok(rows)
}
