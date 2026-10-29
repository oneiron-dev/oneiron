//! The embedded owner's door for the verb-table rows that are the vault
//! owner's (`vault.packs.put`, the `connector.*` key lifecycle). A server
//! takes the owner's proof from the request instead.

use super::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::skill_hub::HubFile;
use crate::skill_hub::pack_catalog::PackInstallDisposition;
use crate::store::GateDecisionId;

impl Memory<'_> {
    /// The vault owner's proof for this handle. Only the constructor-owned
    /// handle that holds the vault's writer lease has one, as
    /// [`Memory::export`]'s local door; binding a different PERSON never
    /// grants it.
    pub fn embedded_owner(&self, verb: &str) -> MemoryResult<AuthenticatedOwner> {
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
        Ok(self
            .vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?)
    }

    /// The embedded owner as the caller of the authority clock repair (FIX
    /// 11202), on the handle [`Self::embedded_owner`] admits: the one that
    /// holds the vault's writer lease and binds that owner as a human. No
    /// owner proof is minted here: the repair's writer judges the owner
    /// against the floor it stages.
    pub fn embedded_clock_repair_caller(
        &self,
        verb: &str,
    ) -> MemoryResult<crate::authority::ClockRepairCaller> {
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
        Ok(crate::authority::ClockRepairCaller::embedded())
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
