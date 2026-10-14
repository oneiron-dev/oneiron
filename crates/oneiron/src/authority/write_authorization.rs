//! Transaction-bound actor authorization for engine-owned write doors.

use crate::batch::EntityMetadataHeader;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

use super::{AuthorityEntryHash, AuthorityFold, CausalWriteDisposition};
use crate::error::ClaimError;

impl Vault {
    /// Captures this host's observed authority frontier for a new local write.
    /// Transport replay must retain its original frontier instead of calling this door.
    pub fn observed_write_actor(&self, writer: WriteActor) -> Result<WriteActor> {
        let txn = self.store.env.read_txn()?;
        self.observed_write_actor_in_txn(&txn, writer)
    }

    /// [`Self::observed_write_actor`] in the caller's transaction, so a door
    /// checks the authority it commits under.
    pub(crate) fn observed_write_actor_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        writer: WriteActor,
    ) -> Result<WriteActor> {
        let fold = self.authority_fold_readonly_in_txn(txn)?;
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
                self.verify_write_actor_in_txn(txn, &observed)?;
                return Ok(observed);
            }
        }
        self.verify_write_actor_in_txn(txn, &writer)?;
        Ok(writer)
    }

    /// The binding generation `actor` holds now: a frontier at which one of
    /// its live bindings had observed every revocation of its key, or `None`
    /// when it holds no live binding (an unrooted vault included).
    pub(crate) fn actor_binding_generation_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: EntityId,
    ) -> Result<Option<AuthorityEntryHash>> {
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        Ok(fold.actor_bindings.iter().find_map(|(key, binding)| {
            (binding.actor_ref == actor && binding.status == super::ActorBindingStatus::Active)
                .then(|| {
                    fold.actor_write_frontiers
                        .get(key)?
                        .iter()
                        .next_back()
                        .copied()
                })
                .flatten()
        }))
    }

    /// [`Self::verify_write_actor_in_txn`] for a writer that must still hold
    /// the binding generation `generation` records. A writer revoked and
    /// regranted since holds a new binding, not that one: no frontier of its
    /// live bindings is the recorded one, and with none recorded it must have
    /// no revocation in its history.
    pub(crate) fn verify_write_actor_generation_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        writer: WriteActor,
        generation: Option<AuthorityEntryHash>,
    ) -> Result<()> {
        let writer = match generation {
            Some(hash) => writer.with_authority_frontier(hash),
            None => writer,
        };
        let fold = self.verify_write_actor_in_txn(txn, &writer)?;
        if fold.vault_id.is_none() {
            return Ok(());
        }
        let class = writer.actor_class().gate_actor_class();
        let held = match generation {
            Some(hash) => fold.actor_bindings.iter().any(|(key, binding)| {
                binding.actor_ref == writer.entity_ref()
                    && binding.actor_class == class
                    && binding.status == super::ActorBindingStatus::Active
                    && fold
                        .actor_write_frontiers
                        .get(key)
                        .is_some_and(|frontiers| frontiers.contains(&hash))
            }),
            None => !fold
                .actor_revocation_affected_writers
                .contains(&(writer.entity_ref(), class.to_owned())),
        };
        if held {
            Ok(())
        } else {
            Err(Error::Claim(ClaimError::ActorLacksClaimAuthority {
                reason: "writer's binding is newer than the one recorded",
            }))
        }
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
