//! Which owner created an agent definition through the owner's create door
//! (OWNER-MADE-AGENT-DEF-UNPLACED). Only that door writes the stamp, in the
//! write that creates the definition, from the owner proof it revalidated
//! there; a body's `provenance` names an author a caller supplies, so no
//! reader takes it as this fact. The stamp is not the definition's subject
//! anchor, so an owner-made agent stays an independent agent in rooms and is
//! not the owner's pen.
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

/// The creating owner of a definition. Key: the definition's id; value: the
/// owner's id.
const CREATING_OWNER: SideTable<EntityId, EntityId, Raw> =
    SideTable::new(&side_table::AGENT_DEF_CREATING_OWNER);

/// Stamps `owner` as the creator of the definition at `id`, in the write
/// that creates it.
pub(super) fn record_creating_owner_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    owner: &EntityId,
) -> Result<()> {
    CREATING_OWNER.put(store, txn, id, owner)
}

/// Whether the definition at `id` was created by `owner` through the
/// owner's create door. Compared as stored bytes: a damaged row matches no
/// owner.
pub(crate) fn created_by_owner_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    owner: &EntityId,
) -> Result<bool> {
    Ok(CREATING_OWNER.get_bytes(store, txn, id)?.as_deref() == Some(owner.as_bytes().as_slice()))
}

/// Removes the stamp of the definition at `id` with its row, so a later row
/// at the id is not taken as the owner's.
pub(super) fn remove_creating_owner_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    CREATING_OWNER.delete(store, txn, id).map(|_| ())
}
