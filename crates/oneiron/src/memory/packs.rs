//! `vault.packs.put` on an embedded handle: the vault's embedded owner's
//! put. A server takes the owner's proof from the request instead.

use super::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::edge::EdgeActorClass;
use crate::skill_hub::HubFile;
use crate::skill_hub::pack_catalog::PackInstallDisposition;
use crate::store::GateDecisionId;

impl Memory<'_> {
    /// Installs a pack folder as the vault's embedded owner. Only the
    /// constructor-owned handle that holds the vault's writer lease may use
    /// this door, as [`Memory::export`]'s local door; binding a different
    /// PERSON never grants it.
    pub fn put_pack_as_embedded_owner(
        &self,
        files: Vec<HubFile>,
    ) -> MemoryResult<PackInstallDisposition> {
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
                "vault.packs.put is the vault owner's",
                &["Install packs as the vault's owner."],
            ));
        }
        let proof =
            self.vault
                .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
        Ok(self.vault.put_pack(&proof, files)?)
    }
}
