//! The found-key notice for a known value in a file (FIX 2780): a file's key
//! custody already holds is marked with its existing record, and the owner's
//! found-key list names that file the same way it does for a minted key. No
//! custody record is minted.

use heed::RwTxn;

use super::FoundFile;
use crate::error::Result;
use crate::ports::ShortIdStoreRead;
use crate::secret_custody::{FoundNote, note_found_keys_in_txn};
use crate::store::Store;

/// Records each key `files` marks that custody already holds, in the write's
/// own transaction, with its existing record and handle.
pub(super) fn note_known_file_keys_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    files: &[FoundFile],
    at: u64,
) -> Result<()> {
    let mut notes = Vec::new();
    for file in files {
        for key in &file.keys {
            let Some(custody) = key.custody else {
                continue;
            };
            // A record with no handle leaves no note rather than refusing
            // the write.
            let Some((handle, _)) = store.port_short_id_reference(&*wtxn, &custody)? else {
                continue;
            };
            notes.push(FoundNote {
                record: file.record,
                custody,
                handle,
                reason: key.reason,
                place: "file".to_owned(),
            });
        }
    }
    note_found_keys_in_txn(store, wtxn, &notes, at)
}
