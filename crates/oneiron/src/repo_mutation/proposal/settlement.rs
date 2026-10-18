//! Review decisions are retained separately from execution. Approval never
//! fabricates a checker result or advances head: the tested merge queue lands it.
use super::{PROPOSAL, RepoProposal, RepoProposalOperation, RepoProposalStatus, invalid, store};
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject};
use crate::consent::AuthenticatedOwner;
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepoProposalDecision {
    Approve,
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoProposalSettlement {
    pub receipt: EntityId,
    pub actor: EntityId,
    pub decision: RepoProposalDecision,
    pub settled_at: u64,
}

impl Vault {
    /// Approve or reject one immutable proposal as an independent owner. Every
    /// check authorizing the decision and its receipt runs in the same writer.
    pub(crate) fn settle_repo_proposal_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        id: EntityId,
        decision: RepoProposalDecision,
    ) -> Result<RepoProposal> {
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_in_txn(self, &txn)?;
        super::guards::require_entity_kind(self, &txn, id, crate::registry::ENTITY_TYPE_CLAIM)?;
        let mut row = PROPOSAL.get(&self.store, &txn, &id)?.ok_or(crate::Error::EntityNotFound)?;
        require_independent(self, &txn, &row, actor)?;
        if let Some(settled) = &row.settlement {
            return if settled.actor == actor && settled.decision == decision {
                Ok(row)
            } else {
                Err(invalid("proposal already has a different settlement"))
            };
        }
        if row.status != RepoProposalStatus::Proposed || row.operation_seq.is_some()
            || row.merge_stack.is_some()
        {
            return Err(invalid("only an unconsumed open proposal can be settled"));
        }
        if decision == RepoProposalDecision::Approve {
            super::validate_conflict_in_txn(self, &txn, &row)?;
            if !row.eligible()? {
                return Err(invalid("approval requires unanimous independent multi-critic acceptance"));
            }
        }
        let receipt = self.store.clock.entity_id()?;
        let now = super::super::support::now_secs();
        let mut body = ClaimBody::new(
            "repo.proposal_settlement", ClaimSubject::Entity(id),
            rmpv::Value::Map(vec![
                ("proposal".into(), id.to_hex().into()),
                ("actor".into(), actor.to_hex().into()),
                ("decision".into(), match decision {
                    RepoProposalDecision::Approve => "approve".into(),
                    RepoProposalDecision::Reject => "reject".into(),
                }),
            ]), 1.0, ClaimApprovalStatus::Auto, ClaimLifecycleStatus::Active,
        )?;
        body.source = Some(ClaimSource::Observed);
        self.put_reserved_claim_in_txn(
            &mut txn, &receipt, &body, crate::temporal::TimeRange { start: now, end: now }, now,
        )?;
        row.status = match decision {
            RepoProposalDecision::Approve => RepoProposalStatus::Approved,
            RepoProposalDecision::Reject => RepoProposalStatus::Rejected,
        };
        row.settlement = Some(RepoProposalSettlement { receipt, actor, decision, settled_at: now });
        store(self, &mut txn, &row)?;
        txn.commit()?;
        Ok(row)
    }
}

/// A resolution's own producer and either original producer cannot review or
/// settle it. Only independently authenticated humans reach these owner doors;
/// an agent or a descendant credential cannot borrow the owner's proof.
pub(super) fn require_independent(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &RepoProposal,
    actor: EntityId,
) -> Result<()> {
    if row.actor.id().is_none() || row.actor.is(actor) {
        return Err(invalid("a proposal producer cannot settle or review its own work"));
    }
    if let RepoProposalOperation::ResolveConflictFile { open_conflict_claim_id, .. } = &row.operation {
        let body = vault.get_claim_in_txn(txn, open_conflict_claim_id)?
            .ok_or(crate::Error::EntityNotFound)?;
        let conflict = super::super::conflict_value::decode_repo_conflict_open_value(&body.value)?;
        for source in conflict.proposals {
            let source = PROPOSAL.get(&vault.store, txn, &source)?.ok_or(crate::Error::EntityNotFound)?;
            if source.actor.id().is_none() || source.actor.is(actor) {
                return Err(invalid("a conflict producer cannot review or settle its resolution"));
            }
        }
    }
    Ok(())
}
