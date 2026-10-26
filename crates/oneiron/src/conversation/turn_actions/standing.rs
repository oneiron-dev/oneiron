//! What a queued turn action stands on, judged again against the live vault
//! whenever its standing is: the in-process host's actor binding, the slip
//! its request was admitted on, or a managed vault's attested owner's live
//! ownership (FIX 11090).
use serde::{Deserialize, Serialize};

use super::TurnActionAttempt;
use crate::authority::{InvocationSlipBinding, ManagedOwnerCheckError, VerifiedSlip};
use crate::edge::EdgeActorClass;
use crate::memory::{MemoryError, MemoryResult};
use crate::{EntityId, Error, Vault};

/// What a queued action's requester stands on: never a secret, and judged
/// again against the live vault whenever the action's standing is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnActionAuthority {
    /// The in-process host asked, with no transport and no slip: the
    /// actor's binding alone is its standing.
    Native,
    /// The slip the request was admitted on, verified again whenever the
    /// action's standing is judged.
    Slip { binding: InvocationSlipBinding },
    /// The vault's owner `holder`, whom its supervisor attested with no slip
    /// (FIX 11090): the action stands only while the vault records him as
    /// its live owner. Nothing of his is kept.
    AttestedOwner { holder: EntityId },
}

impl TurnActionAttempt {
    /// Whether the action still stands, in `txn`: the requester's actor
    /// binding holds and, unless the attempt is native, the slip it was
    /// asked with does too, or its attested owner is still the vault's live
    /// owner. The action's standing, as a credential's liveness is a
    /// request's.
    #[must_use]
    pub fn requester_live_in(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> bool {
        self.requester_proof_in(vault, txn).is_ok()
    }

    /// The requester's standing in `txn`, and the slip's proof as it stands
    /// there: verified at this snapshot's fold and clock, every caveat
    /// included, still held by the requester at its class and granting a
    /// write. A native attempt stands on the actor binding, with no proof;
    /// an attested owner's on the host's check that the vault records him
    /// as its live owner, revalidated in `txn`, with no proof either. One
    /// that no longer is refuses with that typed reason, never a slip's.
    pub(super) fn requester_proof_in(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> MemoryResult<Option<VerifiedSlip>> {
        let (actor, class) = self.requester()?;
        crate::memory::verify_actor_binding_in_txn(vault, txn, actor, class)?;
        let binding = match &self.authority {
            TurnActionAuthority::Native => return Ok(None),
            TurnActionAuthority::Slip { binding } => binding,
            TurnActionAuthority::AttestedOwner { holder } => {
                // His person as a human is the requester, or the payload is
                // not his.
                if *holder != actor || class != EdgeActorClass::Human {
                    return Err(Error::CorruptedIndex("turn action owner").into());
                }
                crate::authority::require_live_managed_owner_in_txn(vault, txn, *holder)
                    .map_err(ManagedOwnerCheckError::into_memory_error)?;
                return Ok(None);
            }
        };
        let proof = vault
            .invocation_slip_in_txn(txn, binding)
            .map_err(|_| standing_lost())?;
        let claims = proof.claims();
        if claims.holder_ref != actor.to_hex()
            || claims.actor_class.as_deref() != Some(class.gate_actor_class())
            || !(proof.allows_verb("write") || proof.allows_verb("core:write"))
        {
            return Err(standing_lost());
        }
        Ok(Some(proof))
    }

    /// [`Self::requester_live_in`] in a snapshot of its own.
    #[must_use]
    pub fn requester_live(&self, vault: &Vault) -> bool {
        vault
            .store
            .env
            .read_txn()
            .is_ok_and(|txn| self.requester_live_in(vault, &txn))
    }

    /// Whether the action's attested owner is no longer the vault's live
    /// owner, judged now (FIX 11090): the typed reason his action stopped,
    /// never a revoked slip. `false` for every other requester, and while
    /// his standing cannot be judged.
    #[must_use]
    pub fn owner_not_live(&self, vault: &Vault) -> bool {
        let TurnActionAuthority::AttestedOwner { holder } = &self.authority else {
            return false;
        };
        vault.store.env.read_txn().is_ok_and(|txn| {
            crate::authority::require_live_managed_owner_in_txn(vault, &txn, *holder)
                == Err(ManagedOwnerCheckError::OwnerNotLive)
        })
    }
}

/// The slip a turn action was asked with no longer stands for its requester.
fn standing_lost() -> MemoryError {
    MemoryError::new(
        crate::memory::MEMORY_CODE_FORBIDDEN,
        "the slip this turn action was asked with no longer stands for its requester",
        &["Ask for the action again with a live credential."],
    )
}
