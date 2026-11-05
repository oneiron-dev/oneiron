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

/// How a hook's body may spend model time (ARCH-0035 render classes;
/// ARCH-0080 §4 Its shape).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum HookRenderClass {
    /// No model call: the body stays deterministic inside its budget.
    #[default]
    DeterministicEager,
    /// A fact hook that may call `ai.verdict`, paid from its pack's budget
    /// line.
    Generative,
}

impl HookRenderClass {
    pub(crate) const fn is_deterministic(&self) -> bool {
        matches!(self, Self::DeterministicEager)
    }
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

/// What an agent's hook asks beyond its own ceiling.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum HookWidening {
    /// Fail safe before the verb runs; only the owner marks a hook blocking.
    Blocking,
    /// A pre-hook's Skip of the verbs it selects.
    Skip,
    /// A pre-hook's Ask before the verbs it selects.
    Ask,
    /// A pre-hook's Rewrite of the verbs it selects.
    Rewrite,
}

/// Where a proposal stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PackHookProposalStatus {
    /// Waiting for the owner; the binding runs at the agent's ceiling.
    Proposed,
    /// The owner bound the hook as asked.
    Approved,
    /// The owner declined; the binding stays at the agent's ceiling.
    Discarded,
    /// The agent's later put no longer asks it, or stopped the hook.
    Withdrawn,
}

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
