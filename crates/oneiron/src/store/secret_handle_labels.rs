//! The owner-set labels on custody handles: one stored label per custody
//! record, with the Gate receipt of the set that wrote it. Custody's label
//! door (`secret_custody::handle_labels`) sets and reads them; the side-row
//! wall admits each one as it does a purpose (SECRET-HANDLE-LABEL-UNWALLED);
//! an erase drops a record's label with its row.

use heed::RwTxn;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

/// One handle's owner-set label. Key: id16 (the custody record id).
pub(crate) const LABEL: SideTable<EntityId, SecretHandleLabel, Named> =
    SideTable::new(&side_table::SECRET_HANDLE_LABEL);

#[doc(hidden)]
pub use oneiron_records::store::secret_handle_labels::SecretHandleLabel;

/// Whether a masked copy of a label row still reads as one, for the wall.
pub(crate) fn accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<SecretHandleLabel, Named>(bytes)
}

/// Drops the label on the custody record `custody`, cleared or whose row is
/// being erased: the label must not survive it, nor any custody record the
/// wall minted for a secret in it.
pub(crate) fn erase_secret_handle_label_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    custody: &EntityId,
) -> Result<()> {
    let place = format!("side:{}", LABEL.decl().name);
    let origin = crate::batch::secret_scan::side_row_origin(&place, &LABEL.key_bytes(custody))?;
    crate::secret_custody::revoke_side_row_custody_in_txn(vault, wtxn, &origin, None)?;
    LABEL.delete(&vault.store, wtxn, custody)?;
    Ok(())
}
