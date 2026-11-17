//! The checkpoint-pins door's office source writer (UC-10 PR 5). Compiled
//! only under `--cfg oneiron_test_support`; never API.

use super::*;

/// Puts an office source row for the checkpoint-pins door: `key`'s artifact
/// imported as `kind` at `source_version` with `source_hash`'s bytes.
pub(crate) fn put_pins_office_source_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    key: &crate::entity_id::EntityId,
    kind: OfficeBodyKind,
    source_version: u64,
    source_hash: &[u8; 32],
) -> crate::error::Result<()> {
    SOURCES.put(
        store,
        txn,
        key,
        &OfficeBodySource {
            kind,
            source_version,
            source_hash: *source_hash,
        },
    )
}
