//! A NOTE document's sizes, measured where a store-aware entrance loads or a
//! room projects one (rule 5; FIX 4280). Its body bytes, its pins and its
//! authorship entries once refused a load or a birth past fixed bounds; now
//! each is counted against its threshold row
//! ([`EngineScan::NoteDocumentBytes`], [`EngineScan::NoteDocumentPinRows`],
//! [`EngineScan::NoteDocumentAuthorshipRows`]), scoped by the NOTE's id, and a
//! crossing raises a check while the document serves. A malformed shape, a
//! wrong id or a corrupt document still refuses where it always did.
//!
//! A room's measurements wait with the room (`pending`), never with the vault,
//! so no check the vault keeps names a room's NOTE.

use crate::scan_check::{EngineScan, PendingScanChecks, ScanCount};
use crate::store::ManifestDbs;
use crate::{EntityId, Result};

/// Counts `doc`, the document of NOTE `note` as `txn` reads it through
/// `store`, against its three threshold rows; each crossing waits in
/// `pending`.
///
/// # Errors
///
/// Storage errors reading a threshold row.
pub(super) fn measure_document(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    doc: &loro::LoroDoc,
    pending: &PendingScanChecks,
) -> Result<()> {
    let [bytes, pins, authorship] = super::document::document_sizes(doc);
    for (scan, rows) in [
        (EngineScan::NoteDocumentBytes, bytes),
        (EngineScan::NoteDocumentPinRows, pins),
        (EngineScan::NoteDocumentAuthorshipRows, authorship),
    ] {
        measure(store, txn, scan, note, rows, pending)?;
    }
    Ok(())
}

/// Counts `rows` of `scan` for NOTE `note` against its threshold row, as
/// `txn` reads it through `store`; a crossing waits in `pending`.
///
/// # Errors
///
/// Storage errors reading the threshold row.
pub(crate) fn measure(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    scan: EngineScan,
    note: EntityId,
    rows: usize,
    pending: &PendingScanChecks,
) -> Result<()> {
    let mut count = ScanCount::start(store, txn, scan, note.as_bytes())?;
    count.rows(rows);
    count.defer_to(pending);
    Ok(())
}
