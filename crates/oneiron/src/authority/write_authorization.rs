//! Transaction-bound actor authorization for engine-owned write doors.

use crate::batch::EntityMetadataHeader;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

use super::{AuthorityFold, AuthorityKey, CausalWriteDisposition, FoldedActorBinding};
use crate::error::ClaimError;
use crate::task_authority::{BindingGeneration, BindingId};

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

    /// The binding generation `actor` holds now: its live bindings, of any
    /// class, or `None` when it holds none (an unrooted vault included). At
    /// the cap the lowest binding of each class is kept first, so no class
    /// the actor holds is left out.
    pub(crate) fn actor_binding_generation_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: EntityId,
    ) -> Result<Option<BindingGeneration>> {
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        let held: Vec<_> = fold
            .actor_bindings
            .iter()
            .filter(|(_, binding)| {
                binding.actor_ref == actor && binding.status == super::ActorBindingStatus::Active
            })
            .map(|(key, binding)| (binding.actor_class.as_str(), actor_binding_id(key, binding)))
            .collect();
        Ok(BindingGeneration::from_classed_bindings(&held))
    }

    /// [`Self::verify_write_actor_in_txn`] at this host's observed frontier,
    /// for a writer that must still hold one of the bindings `generation`
    /// records. A writer rebound or revoked and regranted since holds a new
    /// binding, not one of those. With none recorded, it must hold its key's
    /// first binding (epoch 1; every rebind or regrant is a later epoch) and
    /// have no revocation in its history. A generation that names no binding
    /// (replicas that recorded none in common) admits nobody, rooted or not.
    pub(crate) fn verify_write_actor_generation_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        writer: WriteActor,
        generation: Option<BindingGeneration>,
    ) -> Result<()> {
        let refused = || {
            Err(Error::Claim(ClaimError::ActorLacksClaimAuthority {
                reason: "writer's binding is not one the consult recorded",
            }))
        };
        let writer = self.observed_write_actor_in_txn(txn, writer)?;
        if generation.is_some_and(|generation| generation.bindings().is_empty()) {
            return refused();
        }
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        if fold.vault_id.is_none() {
            return Ok(());
        }
        let class = writer.actor_class().gate_actor_class();
        let mut live = fold.actor_bindings.iter().filter(|(_, binding)| {
            binding.actor_ref == writer.entity_ref()
                && binding.actor_class == class
                && binding.status == super::ActorBindingStatus::Active
        });
        let held = match generation {
            Some(generation) => {
                live.any(|(key, binding)| generation.names(&actor_binding_id(key, binding)))
            }
            None => {
                !fold
                    .actor_revocation_affected_writers
                    .contains(&(writer.entity_ref(), class.to_owned()))
                    && live.any(|(_, binding)| binding.epoch == 1)
            }
        };
        if held { Ok(()) } else { refused() }
    }

    /// Resolve the asserted class and current binding in the mutation snapshot.
    /// Unrooted vaults keep the canonical store-truth rule; conflicting or
    /// uncomputable roots never authorize. Callers still check the verb's role.
    pub(crate) fn verify_write_actor_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        writer: &WriteActor,
    ) -> Result<AuthorityFold> {
        let fold = self.write_actor_store_truth_in_txn(txn, writer)?;
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

    /// [`Self::verify_write_actor_in_txn`] for the in-process host's own
    /// caller (`Memory::native_invocation`, OF-220): the same store truth,
    /// and on a rooted vault no binding asked of an actor the log never
    /// bound at this class, as the engine's runners and agents and the
    /// embedded SDK's actors are not. An actor the log bound is held to that
    /// binding: one revoked, or quarantined by a revocation, is refused, so
    /// native standing never outlives a revocation.
    pub(crate) fn verify_native_write_actor_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        writer: &WriteActor,
    ) -> Result<()> {
        let fold = self.write_actor_store_truth_in_txn(txn, writer)?;
        if fold.vault_id.is_some()
            && fold.actor_write_disposition(
                &writer.entity_ref(),
                writer.actor_class().gate_actor_class(),
                writer.authority_frontier(),
            ) == CausalWriteDisposition::Quarantined
        {
            return Err(Error::Claim(ClaimError::ActorLacksClaimAuthority {
                reason: "the actor's authority binding was revoked",
            }));
        }
        Ok(())
    }

    /// The store truth every writer check starts from: the writer names a
    /// live entity whose type admits its class, under an authority log that
    /// folds to at most one root. Answers that fold.
    fn write_actor_store_truth_in_txn(
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
        Ok(fold)
    }

    /// The owner-verb rule: a live human writer that is the vault's owner,
    /// as every owner verb asks it (H149): the embedded owner on an unrooted
    /// vault, the actor an active human binding names once rooted.
    /// Agent/System labels confer no ownership.
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
        crate::memory::verify_owner_actor_binding_in_txn(self, txn, writer.entity_ref()).map_err(
            |_| {
                Error::Claim(ClaimError::ActorLacksClaimAuthority {
                    reason: "an owner write requires the vault's owner",
                })
            },
        )
    }
}

/// One binding's identity: its key, epoch, actor and class. A rebind or a
/// regrant is a new epoch, so a new identity, and every replica holding the
/// binding names it alike.
fn actor_binding_id(key: &AuthorityKey, binding: &FoldedActorBinding) -> BindingId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron/consult-party/v1/binding");
    match key {
        AuthorityKey::Ed25519(bytes) => {
            hasher.update(b"ed25519");
            hasher.update(bytes);
        }
        AuthorityKey::P256(bytes) => {
            hasher.update(b"p256");
            hasher.update(&(bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        }
    }
    hasher.update(&binding.epoch.to_be_bytes());
    hasher.update(binding.actor_ref.as_bytes());
    hasher.update(binding.actor_class.as_bytes());
    *hasher.finalize().as_bytes()
}
