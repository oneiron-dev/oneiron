//! The live-owner check a managed vault's attested owner's queued work runs
//! under (FIX 11090). His supervisor attests him with no slip, so his
//! queued Continue and Retry, the turn programs he arms and the wakes his
//! landed turns owe them carry his person alone (`AttestedOwner { holder }`).
//! Whenever such an item's standing is judged, the host that attested him
//! checks he is the vault's live owner now; the fresh proof it answers with
//! is revalidated in the judging transaction and then dropped. Nothing is
//! minted or kept for him, so nothing of his expires or is revoked.
//!
//! A holder the vault no longer records as its live owner is
//! [`ManagedOwnerCheckError::OwnerNotLive`], the refusal of that one item.
//! A host that installed no check or has stopped, a vault no supervisor
//! manages now, and standing that does not read are
//! [`ManagedOwnerCheckError::Unavailable`]: an operational failure that
//! leaves the item to be judged again, never a refusal and never the host's
//! own native standing.

use std::sync::Arc;

use crate::consent::AuthenticatedOwner;
use crate::error::{Error, GateError};
use crate::memory::{MEMORY_CODE_OWNER_BINDING_REQUIRED, MemoryError};
use crate::{EntityId, Vault};

/// Why an attested owner's queued item runs no more: the reason its item
/// records.
pub(crate) const OWNER_NOT_LIVE: &str = "the attested owner is not this vault's live owner";

/// What the owner does about it.
const OWNER_NOT_LIVE_GUIDANCE: &str = "Sign in again as this vault's owner, then ask again.";

/// The upstream an unavailable check names, and its code.
const CHECK_TOOL: &str = "managed_owner_check";
const UNAVAILABLE_CODE: &str = "owner_standing_unavailable";

/// The host's check that a managed vault's attested owner is its live owner
/// now ([`Vault::install_managed_owner_check`]). It only reads: it never
/// opens a writer, so a judge may ask it inside its own transaction.
pub trait ManagedOwnerCheck: Send + Sync {
    /// `holder`'s owner proof, made afresh, while the vault records him as
    /// its live owner. The proof is checked again in the judging
    /// transaction and never kept.
    ///
    /// # Errors
    ///
    /// [`ManagedOwnerCheckError::OwnerNotLive`] when the vault reads and
    /// records someone else, or no one, as its live owner;
    /// [`ManagedOwnerCheckError::Unavailable`] for anything that did not
    /// read.
    fn require_live(&self, holder: EntityId) -> Result<AuthenticatedOwner, ManagedOwnerCheckError>;
}

/// Why an attested owner's item does not run as him now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedOwnerCheckError {
    /// The vault does not record him as its live owner: the ruled refusal
    /// of that one item.
    OwnerNotLive,
    /// His standing could not be judged: no host check, a stopped host, an
    /// unmanaged vault or a read that failed. Judged again later.
    Unavailable,
}

impl ManagedOwnerCheckError {
    /// The engine error a judge raises for it: the owner door's own refusal,
    /// or a retryable upstream failure.
    pub(crate) fn into_error(self) -> Error {
        match self {
            Self::OwnerNotLive => {
                Error::Gate(GateError::ConsentOwnerNotAuthenticated(OWNER_NOT_LIVE))
            }
            Self::Unavailable => Error::UpstreamToolFailure {
                tool: CHECK_TOOL,
                code: UNAVAILABLE_CODE.to_owned(),
            },
        }
    }

    /// Whether `error` is the owner refusal [`Self::into_error`] raised,
    /// carried as it was raised: an item that met it ends on it.
    pub(crate) fn is_owner_refusal(error: &Error) -> bool {
        matches!(
            error,
            Error::Gate(GateError::ConsentOwnerNotAuthenticated(reason)) if *reason == OWNER_NOT_LIVE
        )
    }

    /// The error a verb's caller or a queued item's record gets: an owner
    /// binding the vault no longer holds, or the unavailable check.
    pub(crate) fn into_memory_error(self) -> MemoryError {
        match self {
            Self::OwnerNotLive => MemoryError::new(
                MEMORY_CODE_OWNER_BINDING_REQUIRED,
                OWNER_NOT_LIVE,
                &[OWNER_NOT_LIVE_GUIDANCE],
            ),
            Self::Unavailable => self.into_error().into(),
        }
    }
}

impl Vault {
    /// Installs the host's managed-owner check on this vault handle, once
    /// per open vault and never process-global. A second install does
    /// nothing. Without one, every attested owner's item is unavailable.
    pub fn install_managed_owner_check(&self, check: Arc<dyn ManagedOwnerCheck>) {
        let _ = self.managed_owner_check.set(check);
    }

    /// `holder` as this vault's recorded, live owner now, read and typed
    /// before any door maps it to an answer: his fresh owner proof. A host's
    /// [`ManagedOwnerCheck`] answers with this verdict.
    ///
    /// # Errors
    ///
    /// [`ManagedOwnerCheckError::OwnerNotLive`] when the vault reads and
    /// records someone else, or no one, as its live owner, or records him
    /// while his PERSON is merged, split or deleted;
    /// [`ManagedOwnerCheckError::Unavailable`] when nothing definite reads.
    pub fn attested_owner_verdict(
        &self,
        holder: EntityId,
    ) -> Result<AuthenticatedOwner, ManagedOwnerCheckError> {
        let proof = match self.authenticate_recorded_owner(
            holder,
            &holder.to_hex(),
            crate::store::GateDecisionId::now(),
        ) {
            Ok(Some(proof)) => proof,
            Ok(None) => return Err(ManagedOwnerCheckError::OwnerNotLive),
            Err(_) => return Err(self.recorded_owner_refusal(holder)),
        };
        match self.is_live_vault_owner(&proof) {
            Ok(true) => Ok(proof),
            Ok(false) => Err(ManagedOwnerCheckError::OwnerNotLive),
            Err(_) => Err(self.recorded_owner_refusal(holder)),
        }
    }

    /// Why the recorded owner `holder` did not authenticate: not live when
    /// a read finds his PERSON merged, split or deleted, and unavailable
    /// when no read says so.
    fn recorded_owner_refusal(&self, holder: EntityId) -> ManagedOwnerCheckError {
        let gone = || -> crate::Result<bool> {
            if self.entity_lifecycle_state(&holder)?
                != crate::identity_topology::EntityLifecycleState::Active
            {
                return Ok(true);
            }
            let txn = self.store.env.read_txn()?;
            Ok(!crate::consent::person_is_live_in_txn(self, &txn, &holder)?)
        };
        match gone() {
            Ok(true) => ManagedOwnerCheckError::OwnerNotLive,
            Ok(false) | Err(_) => ManagedOwnerCheckError::Unavailable,
        }
    }
}

/// Whether `txn` holds positive evidence that `holder`'s PERSON is gone
/// for good: its lifecycle state is not Active (merged or split), or its
/// deletion state reads deleted. An absent row with neither, or any read
/// error, is not evidence.
fn attested_owner_gone_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, holder: EntityId) -> bool {
    let gone = || -> crate::Result<bool> {
        if vault.entity_lifecycle_state_in_txn(txn, &holder)?
            != crate::identity_topology::EntityLifecycleState::Active
        {
            return Ok(true);
        }
        Ok(
            crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, txn, &holder)?
                .deleted,
        )
    };
    gone().unwrap_or(false)
}

/// Whether `holder`, a managed vault's attested owner, is its live owner at
/// `txn`'s revision: the host's fresh proof for him, revalidated in `txn`
/// as every owner door revalidates its proof in its acting transaction,
/// then dropped.
///
/// # Errors
///
/// [`ManagedOwnerCheckError::OwnerNotLive`] when the host or `txn` finds
/// he is not the live owner, or `txn` holds him merged, split or deleted;
/// [`ManagedOwnerCheckError::Unavailable`] when either could not judge it.
pub(crate) fn require_live_managed_owner_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    holder: EntityId,
) -> Result<(), ManagedOwnerCheckError> {
    let judged = (|| -> Result<(), ManagedOwnerCheckError> {
        let check = vault
            .managed_owner_check
            .get()
            .ok_or(ManagedOwnerCheckError::Unavailable)?;
        let proof = check.require_live(holder)?;
        // A proof of another open vault judges nothing here.
        if !proof.belongs_to(vault) {
            return Err(ManagedOwnerCheckError::Unavailable);
        }
        match proof.revalidate_in_txn(vault, txn) {
            Ok(actor) if actor == holder => Ok(()),
            Ok(_) => Err(ManagedOwnerCheckError::Unavailable),
            Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_))) => {
                Err(ManagedOwnerCheckError::OwnerNotLive)
            }
            Err(_) => Err(ManagedOwnerCheckError::Unavailable),
        }
    })();
    match judged {
        Err(ManagedOwnerCheckError::Unavailable)
            if attested_owner_gone_in_txn(vault, txn, holder) =>
        {
            Err(ManagedOwnerCheckError::OwnerNotLive)
        }
        judged => judged,
    }
}
