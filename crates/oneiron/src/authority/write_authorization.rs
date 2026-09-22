//! Transaction-bound actor authorization for engine-owned write doors.

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::write_envelope::WriteActor;

use super::{AuthorityFold, CausalWriteDisposition};
use crate::error::ClaimError;

impl Vault {
    /// Captures this host's observed authority frontier for a new local write.
    /// Transport replay must retain its original frontier instead of calling this door.
    pub fn observed_write_actor(&self, writer: WriteActor) -> Result<WriteActor> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        for (key, binding) in &fold.actor_bindings {
            if binding.actor_ref == writer.entity_ref()
                && binding.actor_class == writer.actor_class().gate_actor_class()
                && binding.status == super::ActorBindingStatus::Active
                && let Some(hash) = fold
                    .actor_write_frontiers
                    .get(key)
                    .and_then(|frontiers| frontiers.iter().next_back())
            {
                let observed = writer.with_authority_frontier(*hash);
                self.verify_write_actor_in_txn(&txn, &observed)?;
                return Ok(observed);
            }
        }
        self.verify_write_actor_in_txn(&txn, &writer)?;
        Ok(writer)
    }

    /// Resolve the asserted class and current binding in the mutation snapshot.
    /// Unrooted vaults keep the canonical store-truth rule; conflicting or
    /// uncomputable roots never authorize. Callers still check the verb's role.
    pub(crate) fn verify_write_actor_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        writer: &WriteActor,
    ) -> Result<AuthorityFold> {
        let raw = self
            .store
            .port_entity_record(txn, &writer.entity_ref())?
            .map(|row| row.encode())
            .ok_or(Error::InvalidClaimBody(
                "writer must name a live authority-bearing entity",
            ))?;
        let entity_type = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("writer entity header"))?
            .entity_type;
        crate::provenance::validate_actor_class(entity_type, writer.actor_class())?;
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        if fold.vault_root_is_conflicted() {
            return Err(Error::InvalidClaimBody(
                "authority log folds to conflicting vault roots",
            ));
        }
        if fold.vault_id.is_some() {
            match fold.actor_write_disposition(
                &writer.entity_ref(),
                writer.actor_class().gate_actor_class(),
                writer.authority_frontier(),
            ) {
                CausalWriteDisposition::Admitted => {}
                CausalWriteDisposition::Unbound => {
                    return Err(Error::Claim(ClaimError::ActorLacksClaimAuthority {
                        reason: "writer has no active authority binding",
                    }));
                }
                CausalWriteDisposition::Quarantined => {
                    return Err(Error::Claim(ClaimError::WriteConcurrentWithRevocation));
                }
            }
        }
        Ok(fold)
    }

    /// The existing owner-verb rule: a live human actor and, once rooted,
    /// an active owner-capable binding. Agent/System labels confer no ownership.
    pub(crate) fn verify_owner_write_actor_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        writer: &WriteActor,
    ) -> Result<()> {
        self.verify_write_actor_in_txn(txn, writer)?;
        if writer.actor_class() != EdgeActorClass::Human {
            return Err(Error::Claim(ClaimError::ActorLacksClaimAuthority {
                reason: "an owner write requires a human actor",
            }));
        }
        Ok(())
    }
}
