//! Owner-authored purpose text on a custody handle. The authored side-row
//! wall masks values before storage; the receipt is a native Gate id.

use heed::RwTxn;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

pub(crate) const PURPOSE: SideTable<EntityId, SecretHandlePurpose, Named> =
    SideTable::new(&side_table::SECRET_HANDLE_PURPOSE);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SecretHandlePurpose {
    pub purpose: String,
    pub receipt: [u8; 16],
}

pub(crate) fn accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<SecretHandlePurpose, Named>(bytes)
}

pub(crate) fn erase_secret_handle_purpose_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    custody: &EntityId,
) -> Result<()> {
    let place = format!("side:{}", PURPOSE.decl().name);
    let origin = crate::batch::secret_scan::side_row_origin(&place, &PURPOSE.key_bytes(custody))?;
    crate::secret_custody::revoke_side_row_custody_in_txn(vault, txn, &origin, None)?;
    PURPOSE.delete(&vault.store, txn, custody)?;
    Ok(())
}
