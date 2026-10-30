//! An agent's hook that asks wider than its own ceiling (ARCH-0080 §10):
//! Skip, Ask or Rewrite on another actor's verbs, or blocking. The agent's
//! put binds it at the agent's ceiling, and records in the same write a
//! proposal for the binding it asked for; the owner lists, approves or
//! discards it.
//! Entry: `Vault::pack_hook_proposals`. Defines its own items; the binding
//! scan and row codecs stay in `hooks`, the agent's bind in `install`.

use super::*;
use crate::side_table::{self, Named, SideTable};

/// Each agent hook's ask, by the binding claim it widens.
const PROPOSALS: SideTable<EntityId, PackHookProposal, Named> =
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

/// What `selector` asks beyond an agent's own ceiling (ARCH-0080 §10). A
/// selector names actor classes, never one actor, so a pre-hook's Skip, Ask
/// or Rewrite always reaches another actor's verbs.
fn agent_widening(selector: &HookSelector) -> Vec<HookWidening> {
    let mut widening = Vec::new();
    if selector.blocking {
        widening.push(HookWidening::Blocking);
    }
    for (kind, wider) in [
        (HookOutcomeKind::Skip, HookWidening::Skip),
        (HookOutcomeKind::Ask, HookWidening::Ask),
        (HookOutcomeKind::Rewrite, HookWidening::Rewrite),
    ] {
        if selector.outcomes.contains(&kind) && kind.applies_in(selector.phase) {
            widening.push(wider);
        }
    }
    widening
}

impl Vault {
    /// The agent's put bound `row` at its ceiling for a hook that declares
    /// `asked`: a wider ask becomes the owner's proposal. A standing ask the
    /// owner already settled stays settled; a new ask replaces it, and a put
    /// that asks nothing wider withdraws an open one.
    pub(in crate::skill_hub::pack_catalog) fn propose_wider_hook_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        row: &PackHookBinding,
        asked: &HookSelector,
        at: u64,
    ) -> Result<()> {
        let agent = row.author_id();
        let widening = agent_widening(asked);
        if widening.is_empty() {
            return self.withdraw_hook_proposal_in_txn(txn, id, at);
        }
        let proposed_at = match PROPOSALS.get(&self.store, txn, &id)? {
            Some(standing) if standing.agent == agent && standing.asked == *asked => {
                match standing.status {
                    PackHookProposalStatus::Proposed => standing.proposed_at,
                    PackHookProposalStatus::Approved | PackHookProposalStatus::Discarded => {
                        return Ok(());
                    }
                    PackHookProposalStatus::Withdrawn => at,
                }
            }
            _ => at,
        };
        let proposal = PackHookProposal {
            binding: id,
            agent,
            pack: row.pack.clone(),
            hook: row.hook.clone(),
            source: row.source,
            body_hash: row.body_hash.clone(),
            asked: asked.clone(),
            widening,
            status: PackHookProposalStatus::Proposed,
            proposed_at,
            settled_at: None,
            settled_by: None,
        };
        PROPOSALS.put(&self.store, txn, &id, &proposal)
    }

    /// An open proposal at `id` is withdrawn: the agent no longer asks it.
    pub(in crate::skill_hub::pack_catalog) fn withdraw_hook_proposal_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        at: u64,
    ) -> Result<()> {
        match PROPOSALS.get(&self.store, txn, &id)? {
            Some(mut open) if open.status == PackHookProposalStatus::Proposed => {
                open.status = PackHookProposalStatus::Withdrawn;
                open.settled_at = Some(at);
                PROPOSALS.put(&self.store, txn, &id, &open)
            }
            _ => Ok(()),
        }
    }

    /// The owner's own bind of the binding at `id`, at `selector`: an open
    /// proposal that asked exactly that is approved by the same act.
    pub(in crate::skill_hub::pack_catalog) fn settle_hook_proposal_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        selector: &HookSelector,
        owner: EntityId,
        at: u64,
    ) -> Result<()> {
        match PROPOSALS.get(&self.store, txn, &id)? {
            Some(mut open)
                if open.status == PackHookProposalStatus::Proposed && open.asked == *selector =>
            {
                open.status = PackHookProposalStatus::Approved;
                open.settled_at = Some(at);
                open.settled_by = Some(owner);
                PROPOSALS.put(&self.store, txn, &id, &open)
            }
            _ => Ok(()),
        }
    }

    /// Whether the owner approved the binding at `id` as `selector` asks it:
    /// the agent's next put leaves that binding standing.
    pub(in crate::skill_hub::pack_catalog) fn hook_proposal_approved_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        selector: &HookSelector,
    ) -> Result<bool> {
        Ok(PROPOSALS.get(&self.store, txn, id)?.is_some_and(|row| {
            row.status == PackHookProposalStatus::Approved && row.asked == *selector
        }))
    }

    /// Every agent hook proposal, settled or not, by binding.
    pub fn pack_hook_proposals(&self) -> Result<Vec<PackHookProposal>> {
        let txn = self.store.env.read_txn()?;
        Ok(PROPOSALS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, row)| row)
            .collect())
    }

    /// The owner approves an agent's wider hook: its binding is written again
    /// at the selector the agent asked, under the owner's envelope, as the
    /// owner's own act. The hook still runs as its agent, at the grant it
    /// reads under. A binding that moved since the ask is refused; the owner
    /// discards that proposal.
    pub fn approve_pack_hook_proposal(
        &self,
        owner: &AuthenticatedOwner,
        binding: EntityId,
    ) -> Result<PackHookProposal> {
        let approved = self.with_write_txn_grouped(|txn| {
            let owner_id = owner.revalidate_in_txn(self, txn)?;
            let mut proposal = open_proposal_in_txn(self, txn, &binding)?;
            let (_, previous) = bindings_in_txn(&self.store, txn)?
                .into_iter()
                .find(|(id, _)| *id == binding)
                .ok_or_else(|| invalid("the hook this proposal asks for is no longer bound"))?;
            let ceiling = HookSelector {
                blocking: false,
                ..proposal.asked.clone()
            };
            if previous.author
                != (HookAuthor::Agent {
                    agent: proposal.agent,
                })
                || previous.body_hash != proposal.body_hash
                || previous.selector != ceiling
            {
                return Err(invalid(
                    "the hook changed since the agent asked; discard this proposal",
                ));
            }
            let mut row = previous.clone();
            row.selector = proposal.asked.clone();
            row.owner = owner_id;
            let envelope = owner_envelope(owner, owner_id, &row.pack, &row.source)?;
            let at = crate::unix_seconds_now();
            self.batch_in()
                .claim_candidate(
                    &binding,
                    binding_candidate(&row)?,
                    &envelope,
                    TimeRange { start: at, end: at },
                    at,
                )
                .apply(txn)?;
            crate::runtime_hooks::sync_binding_cursor_in_txn(
                self,
                txn,
                binding,
                Some(&previous),
                &row,
            )?;
            proposal.status = PackHookProposalStatus::Approved;
            proposal.settled_at = Some(at);
            proposal.settled_by = Some(owner_id);
            PROPOSALS.put(&self.store, txn, &binding, &proposal)?;
            Ok(proposal)
        })?;
        self.verb_hook_bindings_changed();
        Ok(approved)
    }

    /// The owner discards an agent's wider ask. Its binding stays at the
    /// agent's ceiling, as the agent's put bound it.
    pub fn discard_pack_hook_proposal(
        &self,
        owner: &AuthenticatedOwner,
        binding: EntityId,
    ) -> Result<PackHookProposal> {
        self.with_write_txn_grouped(|txn| {
            let owner_id = owner.revalidate_in_txn(self, txn)?;
            let mut proposal = open_proposal_in_txn(self, txn, &binding)?;
            proposal.status = PackHookProposalStatus::Discarded;
            proposal.settled_at = Some(crate::unix_seconds_now());
            proposal.settled_by = Some(owner_id);
            PROPOSALS.put(&self.store, txn, &binding, &proposal)?;
            Ok(proposal)
        })
    }
}

/// The open proposal at `binding`; one the owner or the agent settled is
/// refused.
fn open_proposal_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    binding: &EntityId,
) -> Result<PackHookProposal> {
    let proposal = PROPOSALS
        .get(&vault.store, txn, binding)?
        .ok_or(Error::EntityNotFound)?;
    if proposal.status != PackHookProposalStatus::Proposed {
        return Err(invalid("the hook proposal is already settled"));
    }
    Ok(proposal)
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
