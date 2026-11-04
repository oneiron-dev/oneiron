//! Late owner obligations of an already bound captured request.

use heed::{RoTxn, RwTxn};

use super::{RESPONSE_OWNERS, ResponseBinding, Rows};
use crate::side_table::SideTableDbs;
use crate::{EntityId, Result};

/// Whether the instance already has an obligation for each proved owner.
pub(crate) fn response_owners_bound_in_txn<D: SideTableDbs>(
    dbs: &D,
    txn: &RoTxn<'_>,
    instance: &[u8; 16],
    owners: &[EntityId],
) -> Result<bool> {
    for owner in owners {
        if !RESPONSE_OWNERS.contains(dbs, txn, &(*owner, *instance))? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Adds newly proved owners of the current bound instance, without replacing its binding
/// or any existing obligation. The caller validates the current row and binding in this
/// writer and journals only the returned new obligation rows before committing.
pub(crate) fn bind_missing_response_owners_in_txn<D: SideTableDbs>(
    dbs: &D,
    wtxn: &mut RwTxn<'_>,
    carrier: &[u8],
    binding: ResponseBinding,
    owners: &[EntityId],
) -> Result<Rows> {
    let carrier = carrier.to_vec();
    let mut owners = owners.to_vec();
    owners.sort_unstable();
    owners.dedup();
    let mut history = Vec::new();
    for owner in owners {
        let key = (owner, binding.instance);
        if RESPONSE_OWNERS.contains(dbs, wtxn, &key)? {
            continue;
        }
        RESPONSE_OWNERS.put(dbs, wtxn, &key, &carrier)?;
        history.push((
            RESPONSE_OWNERS.key_bytes(&key),
            RESPONSE_OWNERS.encode_value(&carrier)?,
        ));
    }
    Ok(history)
}
