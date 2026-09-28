//! Owner-only vault-local drill-in to a custom-agent failure's tier-0 attempt
//! trace and terminal pack receipt. Classification and membership are never
//! accepted from a caller-held group snapshot.

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptRecord};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::receipt::{ReceiptKind, attempt_pack_receipt, attempt_pack_receipt_id};

use super::custom_review::{FailureSignalClass, member_in_txn};

/// The stored attempt is the tier-0 execution trace (including its events,
/// run id and result artifact reference). A terminal receipt is named only
/// when the vault still holds the actual receipt under that id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomFailureDrill {
    pub trace: AttemptRecord,
    pub receipt_refs: Vec<String>,
}

impl Vault {
    /// Reads one member of a vault-local failure group for its authenticated
    /// owner. No consent prompt or grant is minted: this is a read of the
    /// owner's own vault, not a disclosure to another audience.
    ///
    /// The class and attempt id are untrusted selectors, even when obtained
    /// from a prior `custom_agent_failure_groups` result. Membership, live
    /// custom-agent target and owner proof are checked on the same snapshot.
    /// No other actor can use this door; a host must use its separate scoped
    /// disclosure lane (and consent rules) for non-owner requests.
    pub fn drill_custom_agent_failure(
        &self,
        owner: &AuthenticatedOwner,
        class: FailureSignalClass,
        attempt_id: AttemptId,
    ) -> Result<CustomFailureDrill> {
        let trace = {
            let txn = self.store.env.read_txn()?;
            owner.revalidate_in_txn(self, &txn)?;
            if owner.actor() != crate::vault::embedded_owner_actor_id()? {
                // An unrooted vault has no authority-bound non-bootstrap owner.
                // Store-truth PERSON status alone is not a tier-0 read grant.
                let denied = || {
                    Error::Gate(crate::error::GateError::ConsentOwnerNotAuthenticated(
                        "failure drill requires a live owner binding",
                    ))
                };
                let fold = self
                    .authority_fold_readonly_in_txn(&txn)
                    .map_err(|_| denied())?;
                if fold.vault_id.is_none() || fold.vault_root_is_conflicted() {
                    return Err(denied());
                }
                crate::memory::verify_owner_actor_binding_in_txn(self, &txn, owner.actor())
                    .map_err(|_| denied())?;
            }
            member_in_txn(self, &txn, attempt_id, class)?
        };
        let id = attempt_pack_receipt_id(&trace.id);
        let mut receipt_refs = Vec::new();
        if let Some(receipt) = attempt_pack_receipt(self, &id)? {
            if receipt.receipt_id != id
                || receipt.receipt_kind != ReceiptKind::Outbound
                || receipt.outcome != trace.state.as_str()
            {
                return Err(Error::CorruptedIndex(
                    "custom-agent failure receipt mismatch",
                ));
            }
            receipt_refs.push(id);
        } else if !trace.manifest().is_empty()
            || crate::skill::resident::receipt_resident(self, &id)?.is_some()
        {
            // Every terminal door stamps a pack/resident receipt in the same
            // transaction as the attempt; absence here is lost evidence.
            return Err(Error::CorruptedIndex(
                "custom-agent failure receipt missing",
            ));
        }
        Ok(CustomFailureDrill {
            trace,
            receipt_refs,
        })
    }
}
