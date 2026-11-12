//! The pack hook selector types and the agent hook proposal rows
//! (ARCH-0080 §3, §10): when a hook fires, how it may spend model time, the
//! outcome set, the HOOK.md selector, and each agent hook's ask wider than
//! its own ceiling, with the erase and the actor scrub a deletion makes of
//! them. The pack catalog (`skill_hub::pack_catalog::hooks`) parses,
//! binds, lists and settles them; the derived-row erase and the side-table
//! declaration's actor scrub call the store functions.
use serde::{Deserialize, Serialize};

use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::store::pack_hook_actor_class::HookActorClass;
use crate::{EntityId, Result, Vault};

#[doc(hidden)]
pub use oneiron_verb_wire::store::pack_hook_proposal::{
    HookOutcomeKind, HookPhase, HookRenderClass, HookSelector, HookWidening, PackHookProposal,
    PackHookProposalStatus,
};

/// Each agent hook's ask, by the binding claim it widens.
pub(crate) const PROPOSALS: SideTable<EntityId, PackHookProposal, Named> =
    SideTable::new(&side_table::SKILL_HUB_PACK_HOOK_PROPOSAL);

/// Drops the proposal keyed by the binding claim `binding`: a deleted or
/// erased binding takes its proposal with it.
pub(crate) fn erase_hook_proposal_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    binding: &EntityId,
) -> Result<()> {
    PROPOSALS.delete(store, txn, binding)?;
    Ok(())
}

/// An erased actor leaves no id in the proposals: an ask it made as the
/// agent goes with it, and where it settled one as the owner the settlement
/// stays and its `settled_by` is blanked.
pub(crate) fn scrub_hook_proposal_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    for (binding, mut proposal) in PROPOSALS.scan(&vault.store, txn)? {
        if proposal.agent == *actor {
            PROPOSALS.delete(&vault.store, txn, &binding)?;
        } else if proposal.settled_by == Some(*actor) {
            proposal.settled_by = None;
            PROPOSALS.put(&vault.store, txn, &binding, &proposal)?;
        }
    }
    Ok(())
}
