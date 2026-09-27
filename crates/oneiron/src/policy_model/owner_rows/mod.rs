//! Holder-governed owner-policy row edits, proposals, events and change log.
mod authority;
mod ledger;
mod notifications;

pub use ledger::{PolicyChangedEvent, PolicyProposalStatus, PolicyRowProposal, PolicyRowReceipt};
pub use notifications::{PolicyNotificationMode, PolicyNotificationRule};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::gate::PolicyRowChange;
use crate::memory::{Memory, MemoryResult};

fn denied() -> Error {
    Error::InvalidConfig("a live policy-power holder is required".to_owned())
}

fn land_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    holder: &AuthenticatedOwner,
    change: PolicyRowChange,
    now: u64,
) -> Result<PolicyRowReceipt> {
    holder.revalidate_in_txn(vault, txn)?;
    let holders = authority::holders_in_txn(vault, txn, now)?;
    if !holders.contains(&holder.actor()) {
        return Err(denied());
    }
    crate::gate::apply_owner_policy_row_change_in_txn(vault, holder, txn, &change, now)?;
    let receipt = ledger::append_change_in_txn(vault, txn, holder.actor(), change, now)?;
    notifications::enqueue_change_in_txn(vault, txn, &receipt, &holders, now)?;
    Ok(receipt)
}

impl Vault {
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
        if !authority::holders_in_txn(self, &txn, now)?.contains(&holder.actor()) {
            return Err(denied());
        }
        let mut proposal =
            ledger::read_proposal_in(self, &txn, proposal_id)?.ok_or(Error::EntityNotFound)?;
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
            let holders = authority::holders_in_txn(self.vault(), txn, now)?;
            if holders.is_empty() {
                return Err(crate::memory::MemoryError::bad_request(
                    "policy change has no live holder",
                ));
            }
            let proposal = PolicyRowProposal {
                proposal_id: self.vault().store.clock.entity_id()?.to_hex(),
                author: self.actor().to_hex(),
                change,
                holders: holders.into_iter().map(|id| id.to_hex()).collect(),
                status: PolicyProposalStatus::Pending,
                at: now,
            };
            // Exact parser validation before persisting a question: a malformed
            // policy must never be able to become a holder-approved write.
            if proposal.change.row_ref().trim().is_empty() {
                return Err(crate::memory::MemoryError::bad_request(
                    "empty policy row ref",
                ));
            }
            ledger::put_proposal_in(self.vault(), txn, &proposal)?;
            Ok(proposal)
        })
    }
}

#[cfg(test)]
mod tests;
