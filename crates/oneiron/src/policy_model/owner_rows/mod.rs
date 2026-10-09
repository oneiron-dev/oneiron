//! Holder-governed owner-policy row edits, proposals, events and change log.
mod authority;
mod ledger;
mod notifications;
mod secret_scan_switch;

pub(crate) use authority::is_live_vault_owner_in_txn;
pub use ledger::{PolicyChangedEvent, PolicyProposalStatus, PolicyRowProposal, PolicyRowReceipt};
pub use notifications::{
    PolicyNotificationFailure, PolicyNotificationMode, PolicyNotificationRule,
    PolicyNotificationTarget,
};
pub use secret_scan_switch::SecretScanReceipt;

use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::gate::PolicyRowChange;
use crate::memory::{Memory, MemoryResult};
use crate::{EntityId, Vault};

fn denied() -> Error {
    Error::InvalidConfig("a live policy-power holder is required".to_owned())
}

/// Exact action-grant target for one owner-policy row key and scope.
/// An Owner can pass this value to `ActionEnvelope::with_target` when minting
/// a named `policy.change` standing grant for an Admin or Delegate.
#[must_use]
pub fn policy_row_grant_target(scope: &crate::gate::PolicyRowScope, row_ref: &str) -> String {
    authority::row_target(scope, row_ref)
}

/// Result of one row verb: holders land, everyone else proposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyRowSubmission {
    Landed(PolicyRowReceipt),
    Proposed(PolicyRowProposal),
}

pub(super) fn holders_for_change_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    change: &PolicyRowChange,
    now: u64,
) -> Result<Vec<EntityId>> {
    authority::holders_for_in_txn(
        vault,
        txn,
        now,
        change.scope(),
        &policy_row_grant_target(change.scope(), change.row_ref()),
    )
}

fn propose_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    author: EntityId,
    change: PolicyRowChange,
    now: u64,
) -> Result<PolicyRowProposal> {
    if change.row_ref().trim().is_empty()
        || matches!(change.scope(), crate::gate::PolicyRowScope::World(s) | crate::gate::PolicyRowScope::Project(s) if s.trim().is_empty())
        || matches!(change.scope(), crate::gate::PolicyRowScope::WorldProject { world, project } if world.trim().is_empty() || project.trim().is_empty())
        || matches!(&change, PolicyRowChange::Add { text, .. } | PolicyRowChange::Edit { text, .. } | PolicyRowChange::AddWithWhy { text, .. } | PolicyRowChange::EditWithWhy { text, .. } if text.trim().is_empty())
        || matches!(&change, PolicyRowChange::AddWithWhy { why, .. } | PolicyRowChange::EditWithWhy { why, .. } | PolicyRowChange::DraftWhy { why, .. } if why.trim().is_empty())
    {
        return Err(Error::InvalidConfig(
            "invalid owner policy row proposal".to_owned(),
        ));
    }
    let holders = holders_for_change_in_txn(vault, txn, &change, now)?;
    if holders.is_empty() {
        return Err(denied());
    }
    let proposal = PolicyRowProposal {
        proposal_id: vault.store.clock.entity_id()?.to_hex(),
        author: author.to_hex(),
        change,
        holders: holders.into_iter().map(|id| id.to_hex()).collect(),
        status: PolicyProposalStatus::Pending,
        at: now,
    };
    ledger::put_proposal_in(vault, txn, &proposal)?;
    Ok(proposal)
}

fn land_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    holder: &AuthenticatedOwner,
    change: PolicyRowChange,
    now: u64,
) -> Result<PolicyRowReceipt> {
    holder.revalidate_in_txn(vault, txn)?;
    let holders = holders_for_change_in_txn(vault, txn, &change, now)?;
    if !holders.contains(&holder.actor()) {
        return Err(denied());
    }
    crate::gate::apply_owner_policy_row_change_in_txn(vault, holder, txn, &change, now)?;
    let receipt = ledger::append_change_in_txn(vault, txn, holder.actor(), change, now)?;
    notifications::enqueue_change_in_txn(vault, txn, &receipt, &holders, now)?;
    Ok(receipt)
}

impl Vault {
    /// One holder-aware verb for human callers. A human with no policy-power
    /// Grant submits an inert proposal; an authenticated holder lands at once.
    pub fn submit_policy_row_change(
        &self,
        actor: &AuthenticatedOwner,
        change: PolicyRowChange,
        now: u64,
    ) -> Result<PolicyRowSubmission> {
        let mut txn = self.store.env.write_txn()?;
        actor.revalidate_in_txn(self, &txn)?;
        let result =
            if holders_for_change_in_txn(self, &txn, &change, now)?.contains(&actor.actor()) {
                PolicyRowSubmission::Landed(land_in_txn(self, &mut txn, actor, change, now)?)
            } else {
                PolicyRowSubmission::Proposed(propose_in_txn(
                    self,
                    &mut txn,
                    actor.actor(),
                    change,
                    now,
                )?)
            };
        txn.commit()?;
        Ok(result)
    }

    /// Lands either tightening or loosening immediately under a live holder's power.
    /// Every edit writes its manifest bytes, receipt, event and notification intents
    /// atomically. Another holder may reverse it with a later change.
    pub fn change_policy_row(
        &self,
        holder: &AuthenticatedOwner,
        change: PolicyRowChange,
        now: u64,
    ) -> Result<PolicyRowReceipt> {
        let mut txn = self.store.env.write_txn()?;
        let receipt = land_in_txn(self, &mut txn, holder, change, now)?;
        txn.commit()?;
        Ok(receipt)
    }

    /// The first live holder to answer settles this proposal. The holder's
    /// approval is a new authenticated ruling; the proposal alone is inert.
    pub fn rule_policy_row_proposal(
        &self,
        holder: &AuthenticatedOwner,
        proposal_id: &str,
        approve: bool,
        now: u64,
    ) -> Result<Option<PolicyRowReceipt>> {
        let mut txn = self.store.env.write_txn()?;
        holder.revalidate_in_txn(self, &txn)?;
        let mut proposal =
            ledger::read_proposal_in(self, &txn, proposal_id)?.ok_or(Error::EntityNotFound)?;
        if !holders_for_change_in_txn(self, &txn, &proposal.change, now)?.contains(&holder.actor())
        {
            return Err(denied());
        }
        if !matches!(proposal.status, PolicyProposalStatus::Pending) {
            return Err(Error::InvalidConfig("proposal already answered".to_owned()));
        }
        if !proposal.holders.contains(&holder.actor().to_hex()) {
            return Err(denied());
        }
        let receipt = if approve {
            Some(land_in_txn(
                self,
                &mut txn,
                holder,
                proposal.change.clone(),
                now,
            )?)
        } else {
            None
        };
        proposal.status = match &receipt {
            Some(receipt) => PolicyProposalStatus::Approved {
                receipt_id: receipt.receipt_id.clone(),
                holder: holder.actor().to_hex(),
            },
            None => PolicyProposalStatus::Declined {
                holder: holder.actor().to_hex(),
            },
        };
        ledger::put_proposal_in(self, &mut txn, &proposal)?;
        txn.commit()?;
        Ok(receipt)
    }
}

impl Memory<'_> {
    /// Every non-holder, including an agent, submits a proposal in both
    /// directions. A facade actor cannot self-assert human holder authority.
    pub fn propose_policy_row_change(
        &self,
        change: PolicyRowChange,
        now: u64,
    ) -> MemoryResult<PolicyRowProposal> {
        self.with_verified_actor_write_txn(|txn| {
            propose_in_txn(self.vault(), txn, self.actor(), change, now).map_err(Into::into)
        })
    }
}

#[cfg(test)]
mod tests;
