//! The export supplement import marks this install still owes the owner's
//! other machines (FIX 12291): one value-free row per export secret request
//! whose supplement the owner imported here while this install could not
//! sign his mark. The import's own writer files it, and the writer the mark
//! counts in, or the one that finds nothing owed any more, drops it
//! (`secret_custody::holder_export`); an erase of the owner drops his.

use serde::{Deserialize, Serialize};

use crate::authority::{ActSurface, AuthorityEntryHash};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::vault::Vault;

/// Each import mark this install still owes, by the entry hash of the
/// export secret request it marks.
pub(crate) const PENDING_IMPORT_MARK: SideTable<AuthorityEntryHash, PendingImportMark, Named> =
    SideTable::new(&side_table::SECRET_CUSTODY_PENDING_IMPORT_MARK);

/// One import mark this install has not signed yet. It holds no secret
/// byte, ciphertext, secret name, proof, credential or key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingImportMark {
    /// The owner PERSON whose export the request carries, as the import
    /// revalidated him.
    pub(crate) owner: EntityId,
    /// Where he imported the supplement: audit only.
    pub(crate) surface: ActSurface,
    /// The second the import was at: audit only. The mark carries the
    /// second it is signed at.
    pub(crate) imported_at: u64,
}

/// Erasing `actor` (FIX 3520): an import mark still owed for him is
/// dropped, so no act is carried in his name. One-way, in the erase's own
/// transaction; the import stands.
///
/// # Errors
///
/// Storage errors, or a row that cannot be read.
pub(crate) fn erase_pending_import_mark_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    for (request, pending) in PENDING_IMPORT_MARK.scan(&vault.store, wtxn)? {
        if pending.owner == *actor {
            PENDING_IMPORT_MARK.delete(&vault.store, wtxn, &request)?;
        }
    }
    Ok(())
}
