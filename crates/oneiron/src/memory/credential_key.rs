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

/// The holder the host root names, and every slip cut from it keeps. It is
/// no entity, so no grant can name it.
const HOST_HOLDER: &str = "host";

impl Vault {
    /// The read key `proof` reads under, judged in one snapshot: the owner
    /// check judges its holder, then `Self::credential_read_key_in_txn`
    /// builds the key. The holder is judged as the credential's own class;
    /// one that names none is judged as a person, so only the vault's bound
    /// owner passes. `None` is a credential that grants no read, or whose
    /// holder is no entity.
    ///
    /// A host credential reads as a person only on a self-hosted vault (FIX
    /// 2222): the host root itself reads as the owner it bound at install,
    /// with that owner's guarded floor key, and a slip cut from it keeps the
    /// key its Scope gives.
    ///
    /// # Errors
    ///
    /// [`Error::HostActionRequiresSupportGrant`] for any host credential on
    /// a vault that is not self-hosted (a hosted operator's root, a relay);
    /// the owner refusal for a self-hosted root that is not live or binds no
    /// live owner under its key.
    pub fn credential_read_key(&self, proof: &VerifiedSlip) -> Result<Option<ScopedReadActorKey>> {
        let txn = self.store.env.read_txn()?;
        self.credential_read_key_in(&txn, proof)
    }

    /// The key `proof`'s holder is judged under when it names a row it
    /// writes about rather than reads (FIX 8155): the rule
    /// [`Self::credential_read_key`] applies (the owner check, the
    /// relationship grants, the host root's action), built without asking
    /// the read verb, so a write-only credential is held to its bounds
    /// rather than refused for a verb it was not given. A door reads the
    /// named row under it only to judge whether the credential reaches it.
    pub fn credential_target_key(
        &self,
        proof: &VerifiedSlip,
    ) -> Result<Option<ScopedReadActorKey>> {
        let txn = self.store.env.read_txn()?;
        self.credential_key_in_with(
            &txn,
            proof,
            ScopedReadActorKey::from_verified_slip_as_target,
        )
    }

    /// Whether `proof`'s facet bounds leave its holder unbound (owner ruling
    /// FACET-READ = A), judged in one snapshot by the key
    /// [`Self::credential_read_key`] builds: the owner's own live credential,
    /// and a narrower one the owner still holds, read every facet; a
    /// delegate's or a transferred one never does. A door that refuses a
    /// facet narrowing asks this first, so it refuses the owner nothing the
    /// read lane gives. It lifts no world, record or channel bound.
    pub fn credential_facets_owner_exempt(&self, proof: &VerifiedSlip) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        match self.credential_read_key_in(&txn, proof)? {
            Some(key) => key.facets_owner_exempt_in(self, &txn),
            None => Ok(false),
        }
    }

    /// [`Self::credential_read_key`], judged in the caller's snapshot.
    pub(crate) fn credential_read_key_in(
        &self,
        txn: &heed::RoTxn<'_>,
        proof: &VerifiedSlip,
    ) -> Result<Option<ScopedReadActorKey>> {
        self.credential_key_in_with(txn, proof, ScopedReadActorKey::from_verified_slip)
    }

    /// [`Self::credential_read_key_in`], its proof-backed key built by `base`.
    fn credential_key_in_with(
        &self,
        txn: &heed::RoTxn<'_>,
        proof: &VerifiedSlip,
        base: fn(&VerifiedSlip) -> Option<ScopedReadActorKey>,
    ) -> Result<Option<ScopedReadActorKey>> {
        let claims = proof.claims();
        if claims.holder_ref == HOST_HOLDER {
            // FIX 2222 (owner ruling "A + support"): no host credential reads
            // as anyone where no host acts as a person. A hosted operator's
            // root, or a relay's, gets the typed refusal, never a key.
            if self.privacy_posture() != crate::HostingPrivacyPosture::SelfHostLocal {
                return Err(Error::HostActionRequiresSupportGrant);
            }
            // The self-hosted root itself acts as the owner it bound at
            // install and reads with that owner's floor key, held to the root
            // and its binding on every read.
            if claims.parent_id.is_none() && proof.is_full_vault_owner_grade() {
                let action = self.host_action_authority_in_txn(txn, proof)?;
                return Ok(Some(action.read_key()));
            }
            // A slip cut from it still names the host but may be held by
            // anyone (`attenuate_to`): it reads what its Scope grants, and a
            // relationship's rows only on a grant, which none can name.
            return Ok(base(proof).map(|key| {
                if proof.is_full_vault_owner_grade() {
                    key
                } else {
                    key.require_relationship_grants(None)
                }
            }));
        }
        let Ok(holder) = EntityId::from_hex(&claims.holder_ref) else {
            return Ok(None);
        };
        let class = match claims.actor_class.as_deref() {
            None | Some("human") => Some(EdgeActorClass::Human),
            Some("agent") => Some(EdgeActorClass::Agent),
            Some("system") => Some(EdgeActorClass::System),
            Some(_) => None,
        };
        let owner = match class {
            // A broken owner check (a conflicted authority root, a corrupt
            // row) carries its refusal, as the owner key's own reads do.
            Some(class) => {
                actor_is_vault_owner_in_txn(self, txn, holder, class).map_err(|refusal| {
                    Error::Claim(ClaimError::ScopedReadOwnerNotLive(Box::new(refusal)))
                })?
            }
            None => false,
        };
        self.credential_key_in_txn_with(txn, proof, holder, owner, base)
    }

    /// The one rule for a proof-backed read key, once the owner check
    /// ([`actor_is_vault_owner_in_txn`]) says whether `holder` is the vault
    /// owner. The owner check passes only a person, so only a person's
    /// credential (one naming no class, or `human`) counts as the owner's,
    /// whatever class the caller bound its handle as, and only while the key
    /// the slip was minted to proves it. The owner's own live, unattenuated
    /// credential reads as the owner: a manifest never narrows the person on
    /// their own vault (ARCH-0057), and every read still checks that the
    /// credential is unexpired and unrevoked in its own snapshot. A
    /// narrower credential, the owner's too, reads only what it grants; the
    /// owner's skips the relationship gate only while the owner binding holds
    /// in the read's own snapshot.
    ///
    /// Any other holder reads a relationship-scoped or private row only on a
    /// live grant for its relationship (ARCH-0006a rule 2), and an unscoped
    /// row as the credential's records allow. A grant is an extra condition:
    /// it never widens the records. `None` is a credential that grants no
    /// read, or one `holder` does not hold.
    pub(crate) fn credential_read_key_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        proof: &VerifiedSlip,
        holder: EntityId,
        owner: bool,
    ) -> Result<Option<ScopedReadActorKey>> {
        self.credential_key_in_txn_with(
            txn,
            proof,
            holder,
            owner,
            ScopedReadActorKey::from_verified_slip,
        )
    }

    /// [`Self::credential_read_key_in_txn`], its proof-backed key built by
    /// `base`.
    fn credential_key_in_txn_with(
        &self,
        txn: &heed::RoTxn<'_>,
        proof: &VerifiedSlip,
        holder: EntityId,
        owner: bool,
        base: fn(&VerifiedSlip) -> Option<ScopedReadActorKey>,
    ) -> Result<Option<ScopedReadActorKey>> {
        let claims = proof.claims();
        if claims.holder_ref != holder.to_hex() {
            return Ok(None);
        }
        let Some(key) = base(proof) else {
            return Ok(None);
        };
        // A handle bound as a person (the campaign surface binds every
        // caller so) may carry an agent's credential on the owner's PERSON:
        // that credential is not the owner's (CodeRabbit on #1413). Nor is
        // one the owner handed to another key: its holder is a delegate, so
        // every bound the owner set on it binds (Astra on #1432).
        if !owner
            || !matches!(claims.actor_class.as_deref(), None | Some("human"))
            || proof.is_transferred()
        {
            return Ok(Some(key.require_relationship_grants(Some(holder))));
        }
        if proof.is_full_vault_owner_grade()
            && claims.actor_class.as_deref() == Some(EdgeActorClass::Human.gate_actor_class())
            && self.capability_slip_is_live_in_txn(txn, proof)?
        {
            return Ok(Some(
                ScopedReadActorKey::vault_owner(holder).while_live(proof),
            ));
        }
        Ok(Some(key.exempt_while_owner(holder)))
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

/// Whether a narrower owner credential's relationship exemption holds in
/// `txn`: its holder is a live PERSON and is the vault owner. The embedded
/// owner needs no owner binding, but its PERSON must still be live, as the
/// owner key's own reads require (Sol R5-007). A soft delete keeps the
/// PERSON header as a shell, so the row's deletion state decides (Astra on
/// #1413).
pub(crate) fn owner_exemption_holds_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: EntityId,
) -> MemoryResult<bool> {
    let row = crate::vault::live_entity_row_in_txn(&vault.store, txn, &owner)?;
    if row.live_type() != Some(crate::registry::ENTITY_TYPE_PERSON) {
        // Gone, a deleted shell, or no longer a PERSON: the exemption has no
        // holder.
        return Ok(false);
    }
    actor_is_vault_owner_in_txn(vault, txn, owner, EdgeActorClass::Human)
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
