//! The embedded owner's door for the verb-table rows that are the vault
//! owner's (`vault.packs.put`, the `connector.*` key lifecycle). A server
//! takes the owner's proof from the request instead.

use super::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::GateError;
use crate::skill_hub::pack_catalog::PackInstallDisposition;
use crate::store::GateDecisionId;
use crate::write_envelope::skill_source::HubFile;

impl Memory<'_> {
    /// The vault owner's proof for this handle. Only the constructor-owned
    /// handle that holds the vault's writer lease has one, as
    /// [`Memory::export`]'s local door; binding a different PERSON never
    /// grants it.
    ///
    /// A handle a host bound to a credential ([`Memory::with_read_proof`])
    /// has it only while that credential is the owner's own live,
    /// unattenuated human slip, and the proof then carries it
    /// ([`crate::Vault::bind_owner_credential`]): every door that revalidates
    /// the proof refuses once it is revoked or expires. A narrower
    /// credential, the owner's too, takes no owner door, as it reads only
    /// what it grants (FIX EMBEDDED-OWNER-IGNORES-BOUND-PROOF).
    pub fn embedded_owner(&self, verb: &str) -> MemoryResult<AuthenticatedOwner> {
        let owner = self.embedded_owner_actor(verb)?;
        let proof =
            self.vault
                .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
        let Some(credential) = &self.read_proof else {
            return Ok(proof);
        };
        self.vault
            .bind_owner_credential(proof, credential.clone())
            .map_err(|error| match error {
                crate::Error::Gate(GateError::ConsentOwnerNotAuthenticated(reason)) => {
                    MemoryError::new(
                        MEMORY_CODE_FORBIDDEN,
                        format!("{verb} is the vault owner's: {reason}"),
                        &["Call it with the owner's own live, full credential."],
                    )
                }
                other => MemoryError::from(other),
            })
    }

    /// The embedded owner as the caller of the authority clock repair (FIX
    /// 11202), on the handle [`Self::embedded_owner`] admits: the one that
    /// holds the vault's writer lease and binds that owner as a human. No
    /// owner proof is minted here: the repair's writer judges the owner
    /// against the floor it stages. A handle bound to a credential calls
    /// with that credential, which the writer judges as it judges a
    /// transport's verified slip: only the owner's own live, unattenuated
    /// human slip acts as the owner.
    pub fn embedded_clock_repair_caller(
        &self,
        verb: &str,
    ) -> MemoryResult<crate::authority::ClockRepairCaller> {
        self.embedded_owner_actor(verb)?;
        Ok(match &self.read_proof {
            Some(credential) => crate::authority::ClockRepairCaller::verified(credential.clone()),
            None => crate::authority::ClockRepairCaller::embedded(),
        })
    }

    /// The embedded owner, when this handle binds that owner as a human in
    /// the process that holds the vault's writer lease.
    fn embedded_owner_actor(&self, verb: &str) -> MemoryResult<crate::EntityId> {
        let owner = crate::vault::embedded_owner_actor_id()?;
        if self.actor != owner
            || self.actor_class != EdgeActorClass::Human
            || !self
                .vault
                .writer_lease()
                .is_some_and(crate::store::VaultWriterLease::held_by_current_process)
        {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!("{verb} is the vault owner's"),
                &["Call it as the vault's owner."],
            ));
        }
        Ok(owner)
    }

    /// Installs a pack folder as the vault's embedded owner.
    pub fn put_pack_as_embedded_owner(
        &self,
        files: Vec<HubFile>,
    ) -> MemoryResult<PackInstallDisposition> {
        let proof = self.embedded_owner("vault.packs.put")?;
        Ok(self.vault.put_pack(&proof, files)?)
    }
}
