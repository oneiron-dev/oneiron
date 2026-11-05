//! Late owner obligations of an already bound captured request.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use super::{RESPONSE_OWNERS, ResponseBinding, Rows, response_binding_in_txn};
use crate::side_table::{SideKey, SideTableDbs};
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
    bind_missing_instance_owners_in_txn(dbs, wtxn, carrier, binding.instance, owners)
}

/// Adds a proved owner to every retained instance of the selected carriers.
/// The current binding and exact historical obligations supply the instances;
/// the caller supplies the carrier ownership and journals only the new rows.
pub(crate) fn bind_retained_response_owner_in_txn<D: SideTableDbs>(
    dbs: &D,
    wtxn: &mut RwTxn<'_>,
    carriers: &[Vec<u8>],
    owner: EntityId,
) -> Result<Rows> {
    if carriers.is_empty() {
        return Ok(Vec::new());
    }
    let carriers: BTreeSet<_> = carriers.iter().cloned().collect();
    let mut instances = BTreeSet::new();
    for carrier in &carriers {
        if let Some(binding) = response_binding_in_txn(dbs, wtxn, carrier)? {
            instances.insert((carrier.clone(), binding.instance));
        }
    }
    for row in RESPONSE_OWNERS.iter_raw_from(dbs, wtxn, b"")? {
        let (key, carrier) = row?;
        if carriers.contains(&carrier) {
            if let Some((_, instance)) = <(EntityId, [u8; 16]) as SideKey>::decode_key(&key) {
                instances.insert((carrier, instance));
            }
        }
    }
    let mut history = Vec::new();
    for (carrier, instance) in instances {
        history.extend(bind_missing_instance_owners_in_txn(
            dbs,
            wtxn,
            &carrier,
            instance,
            &[owner],
        )?);
    }
    Ok(history)
}

fn bind_missing_instance_owners_in_txn<D: SideTableDbs>(
    dbs: &D,
    wtxn: &mut RwTxn<'_>,
    carrier: &[u8],
    instance: [u8; 16],
    owners: &[EntityId],
) -> Result<Rows> {
    let carrier = carrier.to_vec();
    let mut owners = owners.to_vec();
    owners.sort_unstable();
    owners.dedup();
    let mut history = Vec::new();
    for owner in owners {
        let key = (owner, instance);
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
