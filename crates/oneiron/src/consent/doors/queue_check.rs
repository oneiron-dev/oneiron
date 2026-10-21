//! The owner's queued check approval (FIX 6868, L02 authority seam): the
//! durable record that the owner approved running one repository's frozen
//! check plan in the background. It is minted only from a live owner proof
//! in the writing transaction, and it is not that proof: it carries no
//! vault-open nonce, no credential bytes, and never rebuilds an
//! [`AuthenticatedOwner`]. It authorizes the deterministic requested checks
//! of that repository and plan alone, never a repository write, an export, a
//! ref move or anything an agent holds.
//!
//! It holds while its owner is a live person who still owns this vault and,
//! when a credential carried the approval, while that credential is live:
//! it follows the credential's own expiry and revocation and has no lifetime
//! of its own (CALL "queued-approval lifetime"). A lapse holds the work
//! until the owner asks again for the same plan.

use serde::{Deserialize, Serialize};

use super::{AuthenticatedOwner, person_is_live_in_txn};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::GateDecisionId;

/// An owner-approved frozen check execution on one repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct QueuedCheckApproval {
    actor: EntityId,
    /// The authentication the owner approved under, as provenance.
    decision_id: GateDecisionId,
    /// The slip that carried the approval, when a transport bound one.
    credential: Option<[u8; 32]>,
    /// Whether a host action authenticated the owner (a self-hosted root or
    /// the local dev mode).
    host_action: bool,
    repo: EntityId,
    plan_digest: String,
}

impl AuthenticatedOwner {
    /// The owner's approval of running `repo`'s frozen plan `plan_digest` in
    /// the background, minted after this proof revalidates as the vault's
    /// owner in the writing transaction.
    ///
    /// # Errors
    /// A proof that no longer holds as the owner's.
    pub(crate) fn queue_check_approval_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        repo: EntityId,
        plan_digest: &str,
    ) -> Result<QueuedCheckApproval> {
        let actor = self.revalidate_in_txn(vault, txn)?;
        Ok(QueuedCheckApproval {
            actor,
            decision_id: self.decision_id,
            credential: self
                .credential
                .as_ref()
                .map(|credential| credential.claims().slip_id),
            host_action: self.host_action.is_some(),
            repo,
            plan_digest: plan_digest.to_owned(),
        })
    }
}

impl QueuedCheckApproval {
    /// The live owner who gave this approval, as recorded: a value read for
    /// a checked baseline's canonical author (G2 PR3), never a new owner
    /// proof or any authority.
    #[must_use]
    pub(crate) fn recorded_actor(&self) -> EntityId {
        self.actor
    }

    /// Whether this approval still authorizes `repo`'s plan `plan_digest`
    /// in `txn`: the same repository and plan, a live owner and, when a
    /// credential carried it, that credential still live.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn holds_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        repo: EntityId,
        plan_digest: &str,
    ) -> Result<bool> {
        if self.repo != repo || self.plan_digest != plan_digest {
            return Ok(false);
        }
        if !person_is_live_in_txn(vault, txn, &self.actor)?
            || !crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &self.actor)?
        {
            return Ok(false);
        }
        if let Some(slip) = &self.credential
            && !vault.capability_slip_id_is_live_in_txn(txn, slip)?
        {
            return Ok(false);
        }
        Ok(true)
    }
}
