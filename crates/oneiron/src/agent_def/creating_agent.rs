//! Which agent created an agent definition (AGENT-DEF-PROVENANCE-AUTHOR-FORGEABLE).
//! The engine writes the stamp in the write that creates the definition
//! through an agent-authored create door, from the author that door
//! authenticated: `vault.agents.put`, the credential setup door, an agent's
//! own travelling pack, and the generic row doors an agent's batch commits
//! through. A body's `provenance` names an author a caller supplies, and a
//! later put of the row may rewrite it, so no reader takes it as this fact:
//! what an agent made (`made_by`) and the owner's `vault.agents.pause_tree`
//! read this stamp. A proposed change, and an imported, replicated or seeded
//! row, has none.
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

/// The creating agent of a definition. Key: the definition's id; value: the
/// author's id.
const CREATING_AGENT: SideTable<EntityId, EntityId, Raw> =
    SideTable::new(&side_table::AGENT_DEF_CREATING_AGENT);

/// Stamps `author` as the creator of the definition at `id`, in the write
/// that creates it.
pub(crate) fn record_creating_agent_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    author: &EntityId,
) -> Result<()> {
    CREATING_AGENT.put(store, txn, id, author)
}

/// The agent that created the definition at `id`, if an agent-authored
/// create door stamped one. A damaged row names no agent.
pub(super) fn creating_agent_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<EntityId>> {
    CREATING_AGENT.get_lenient(store, txn, id)
}

/// Removes the stamp of the definition at `id` with its row, so a later row
/// at the id is not taken as the agent's.
pub(super) fn remove_creating_agent_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    CREATING_AGENT.delete(store, txn, id).map(|_| ())
}
