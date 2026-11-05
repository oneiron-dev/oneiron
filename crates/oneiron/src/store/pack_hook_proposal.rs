//! Core half of `store::pack_hook_proposal`: its store-layer items live in `oneiron_store::pack_hook_proposal` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::pack_hook_proposal::*;

use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::store::pack_hook_actor_class::HookActorClass;
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};

/// When a hook fires (ARCH-0080 §2).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum HookPhase {
    /// Before a verb, inside the call; it may stop the act.
    Pre,
    /// After a verb, inside the call.
    Post,
    /// After a write commits, on its own runner.
    Fact,
}

/// The one outcome set; the phase decides which kinds apply.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum HookOutcomeKind {
    Continue,
    Rewrite,
    Skip,
    Ask,
    AddBlock,
    Annotate,
    Redact,
    Propose,
    Enqueue,
    Effect,
    Nothing,
}

/// What a HOOK.md declares: the selector table of ARCH-0080 §3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HookSelector {
    /// Globs over row names and SelfEffect labels; for a fact hook, over
    /// predicates.
    pub verbs: Vec<String>,
    /// Empty selects every class.
    pub actors: Vec<HookActorClass>,
    /// A world, facet, room or project as `<axis>:<32 hex id>`; a scope
    /// only narrows.
    pub scope: Option<String>,
    pub phase: HookPhase,
    /// Higher runs first; ties break on the content hash.
    pub priority: i32,
    pub budget_ms: u32,
    /// The owner's narrowing dial. Off by default.
    pub blocking: bool,
    /// The engine refuses any other kind from this hook.
    pub outcomes: Vec<HookOutcomeKind>,
    /// A post-hook's served-row filter: it runs only on a call that served
    /// rows (a recall's pack, a deadline's cut pack included) when one of
    /// them matches, and reads only those. An entry is `<kind glob>:<predicate
    /// glob>`, or a bare predicate glob over served claims.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub served: Vec<String>,
    /// `generative` lets a fact hook call `ai.verdict`.
    #[serde(default, skip_serializing_if = "HookRenderClass::is_deterministic")]
    pub render_class: HookRenderClass,
}

/// Each agent hook's ask, by the binding claim it widens.
pub(crate) const PROPOSALS: SideTable<EntityId, PackHookProposal, Named> =
    SideTable::new(&side_table::SKILL_HUB_PACK_HOOK_PROPOSAL);

/// One agent hook's ask for the binding its HOOK.md declares, where the
/// agent's put bound it narrower.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackHookProposal {
    /// The binding claim the agent's put wrote at its ceiling.
    #[serde(with = "crate::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub binding: EntityId,
    /// The agent that wrote the hook and asks.
    #[serde(with = "crate::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub agent: EntityId,
    pub pack: String,
    pub hook: String,
    /// The pack source the agent's latest put bound.
    #[serde(with = "crate::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub source: EntityId,
    /// BLAKE3 of `body.js`, lowercase hex.
    pub body_hash: String,
    /// The selector as the hook declares it; an approval binds this.
    pub asked: HookSelector,
    /// What `asked` holds beyond the agent's ceiling.
    pub widening: Vec<HookWidening>,
    pub status: PackHookProposalStatus,
    pub proposed_at: u64,
    pub settled_at: Option<u64>,
    /// The owner who approved or discarded it.
    #[serde(with = "crate::serialize::entity_ref::optional")]
    #[schemars(with = "Option<String>")]
    pub settled_by: Option<EntityId>,
}

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
