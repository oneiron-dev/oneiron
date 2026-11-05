//! Core half of `store::secret_handle_purpose`: its store-layer items live in `oneiron_store::secret_handle_purpose` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::secret_handle_purpose::*;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use heed::RwTxn;
use serde::{Deserialize, Serialize};

pub(crate) const PURPOSE: SideTable<EntityId, SecretHandlePurpose, Named> =
    SideTable::new(&side_table::SECRET_HANDLE_PURPOSE);

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
