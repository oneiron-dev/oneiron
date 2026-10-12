//! The read key a verified credential reads under. The facade's read lane
//! and every server door that reads with a credential build it here, so no
//! two doors judge one credential apart.

use super::support::*;
use super::*;

use crate::Vault;
use crate::authority::VerifiedSlip;
use crate::claim::ScopedReadActorKey;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{ClaimError, Error, Result};

/// The holder the host's own credentials name: the host root and any slip
/// cut from it. It is no entity, so no grant can name it.
const HOST_HOLDER: &str = "host";

impl Vault {
    /// The read key `proof` reads under, judged in one snapshot. The holder's
    /// class is the credential's own; one that names none is judged as a
    /// person, so only the vault's bound owner passes as the owner.
    ///
    /// See [`Self::credential_read_key_in_txn`] for the rule. `None` is a
    /// credential that grants no read, or whose holder is no entity.
    pub fn credential_read_key(&self, proof: &VerifiedSlip) -> Result<Option<ScopedReadActorKey>> {
        let txn = self.store.env.read_txn()?;
        let class = match proof.claims().actor_class.as_deref() {
            None | Some("human") => Some(EdgeActorClass::Human),
            Some("agent") => Some(EdgeActorClass::Agent),
            Some("system") => Some(EdgeActorClass::System),
            Some(_) => None,
        };
        self.credential_read_key_in_txn(&txn, proof, class)
    }

    /// The one rule for a proof-backed read key. The vault owner's own live,
    /// unattenuated credential reads as the owner: a manifest never narrows
    /// the person on their own vault (ARCH-0057), and every read still checks
    /// that the credential is unexpired and unrevoked in its own snapshot. A
    /// narrower credential, the owner's too, reads only what it grants.
    ///
    /// Any other holder reads a relationship-scoped or private row only on a
    /// live grant for its relationship (ARCH-0006a rule 2), and an unscoped
    /// row as the credential's records allow. A grant is an extra condition:
    /// it never widens the records. The host's own credentials read what
    /// their Scope grants, as the owner's narrower credentials do.
    ///
    /// `holder_class` is the class the holder is judged as for the owner
    /// check; `None` is one no owner can hold.
    pub(crate) fn credential_read_key_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        proof: &VerifiedSlip,
        holder_class: Option<EdgeActorClass>,
    ) -> Result<Option<ScopedReadActorKey>> {
        let Some(key) = ScopedReadActorKey::from_verified_slip(proof) else {
            return Ok(None);
        };
        let claims = proof.claims();
        if claims.holder_ref == HOST_HOLDER {
            return Ok(Some(key));
        }
        let Ok(holder) = EntityId::from_hex(&claims.holder_ref) else {
            return Ok(None);
        };
        let owner = match holder_class {
            // A broken owner check (a conflicted authority root, a corrupt
            // row) carries its refusal, as the owner key's own reads do.
            Some(class) => actor_is_vault_owner_in_txn(self, txn, holder, class).map_err(
                |refusal| Error::Claim(ClaimError::ScopedReadOwnerNotLive(Box::new(refusal))),
            )?,
            None => false,
        };
        if !owner {
            return Ok(Some(key.require_relationship_grants(holder)));
        }
        if proof.is_full_vault_owner_grade()
            && claims.actor_class.as_deref() == Some(EdgeActorClass::Human.gate_actor_class())
            && self.capability_slip_is_live_in_txn(txn, proof)?
        {
            return Ok(Some(ScopedReadActorKey::vault_owner(holder).while_live(proof)));
        }
        Ok(Some(key))
    }
}

/// Whether `actor`, as `actor_class`, is the vault owner: the local embedded
/// owner, or a human whose owner binding verifies.
pub(crate) fn actor_is_vault_owner_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    actor_class: EdgeActorClass,
) -> MemoryResult<bool> {
    if actor_class == EdgeActorClass::Human && actor == crate::vault::embedded_owner_actor_id()? {
        // The local embedded-owner reader is the host's own-device read lane.
        // A separately paired authority root does not turn it into a peer.
        return Ok(true);
    }
    match verify_vault_owner_in_txn(vault, txn, actor, actor_class) {
        Ok(()) => Ok(true),
        // Not the owner: a human without the binding, or another class.
        Err(error)
            if error.code == MEMORY_CODE_OWNER_BINDING_REQUIRED
                || error.code == MEMORY_CODE_FORBIDDEN =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

/// The owner check: `actor` exists as `actor_class`, which is human, and its
/// owner binding verifies.
pub(crate) fn verify_vault_owner_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    actor_class: EdgeActorClass,
) -> MemoryResult<()> {
    verify_actor_binding_in_txn(vault, txn, actor, actor_class)?;
    if actor_class != EdgeActorClass::Human {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!(
                "actor class {} is not the vault owner",
                actor_class.gate_actor_class()
            ),
            &["Bind a human-class owner actor key."],
        ));
    }
    verify_owner_actor_binding_in_txn(vault, txn, actor)
}
