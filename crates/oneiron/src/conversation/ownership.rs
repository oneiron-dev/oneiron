//! Local, explicit topology ownership; selector families never auto-adopt each other.
use crate::store::Store;
use crate::{EntityId, Result};
use heed::{RoTxn, RwTxn};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Owner {
    Room,
    Dag,
}
const PREFIX: &[u8] = b"conversation:topology_owner:v1:";

pub(crate) fn owner_in(store: &Store, txn: &RoTxn<'_>, id: EntityId) -> Result<Option<Owner>> {
    let stored = store.vault_meta.get(txn, &super::key(PREFIX, id))?;
    let explicit = match stored.as_deref() {
        None => None,
        Some(b"room") => Some(Owner::Room),
        Some(b"dag") => Some(Owner::Dag),
        _ => return Err(super::state("invalid conversation topology owner")),
    };
    let mut inferred = None;
    for (prefix, owner) in [
        (b"conversation_dag:initialized:v1:".as_slice(), Owner::Room),
        (b"conversation_dag:migrated:v1:".as_slice(), Owner::Dag),
    ] {
        if let Some(marker) = store.vault_meta.get(txn, &super::key(prefix, id))? {
            if marker.as_ref() != [1]
                || inferred.is_some_and(|found| found != owner)
                || explicit.is_some_and(|found| found != owner)
            {
                return Err(super::state("ambiguous conversation topology owner"));
            }
            inferred = Some(owner);
        }
    }
    Ok(explicit.or(inferred))
}

pub(crate) fn require_in(store: &Store, txn: &RoTxn<'_>, id: EntityId, owner: Owner) -> Result<()> {
    if owner_in(store, txn, id)?.is_some_and(|found| found != owner) {
        return Err(super::state(
            "conversation belongs to another topology family",
        ));
    }
    Ok(())
}

pub(crate) fn claim_in(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: EntityId,
    owner: Owner,
) -> Result<()> {
    require_in(store, txn, id, owner)?;
    store.vault_meta.put(
        txn,
        &super::key(PREFIX, id),
        match owner {
            Owner::Room => b"room",
            Owner::Dag => b"dag",
        },
    )
}
