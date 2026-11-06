//! Carriers the historical lift sweep marked (OF-067, Engine ruling D = a).
//! A carrier whose bytes a receipt, an op log or a content address binds
//! keeps them as they are. Where its new write is refused or withheld, the
//! sweep marks the row instead: the bytes it read, by their hash, the
//! detector's reason, and the parts its readers keep back. Each reader of
//! the carrier reads the mark before it hands the bytes on. A mark holds no
//! value and no digest of one.
//!
//! The mark is bound to the bytes it was made over: a later write that
//! changes them leaves it behind, and the next run reads them again.

use heed::{RoTxn, RwTxn};

use crate::error::Result;
use crate::side_table::{self, Named, SideTable, SideTableDbs, SideTableDecl};

const MARKS: SideTable<Vec<u8>, CarrierMark, Named> = SideTable::new(&side_table::SECRET_LIFT_MARK);

/// One marked carrier row. It holds no value.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct CarrierMark {
    /// The blake3 hash of the bytes the mark was made over, or the content
    /// address the row is keyed by.
    pub(crate) version: [u8; 32],
    /// The detector's reason for the first hit.
    pub(crate) reason: String,
    /// The parts the carrier's readers withhold, by path, in order; empty
    /// when the whole carrier is withheld.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) withheld: Vec<String>,
    pub(crate) marked_at: u64,
}

fn mark_key(table: &SideTableDecl, row: &[u8]) -> Vec<u8> {
    [table.name.as_bytes(), b":", row].concat()
}

/// The mark on `table`'s row `row` (the key after the table's prefix), when
/// one was made over `version`.
pub(crate) fn carrier_mark_in_txn(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    table: &SideTableDecl,
    row: &[u8],
    version: &[u8; 32],
) -> Result<Option<CarrierMark>> {
    Ok(MARKS
        .get(store, txn, &mark_key(table, row))?
        .filter(|mark| mark.version == *version))
}

/// Marks `table`'s row `row`, replacing any mark it had.
pub(crate) fn put_carrier_mark_in_txn(
    store: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    table: &SideTableDecl,
    row: &[u8],
    mark: &CarrierMark,
) -> Result<()> {
    MARKS.put(store, txn, &mark_key(table, row), mark)
}
