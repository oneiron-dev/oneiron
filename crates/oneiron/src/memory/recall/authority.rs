//! Actor-bound recall authority: store-truth identity, owner lane and scoped floor.
use super::*;

impl Memory<'_> {
    pub(super) fn bound_recall_authority(
        &self,
    ) -> MemoryResult<(
        crate::gate::ResolvedRetrievalFilter,
        Option<crate::claim::ScopedRead<'_>>,
    )> {
        // Resolve the actor before deciding whether this is a grant-bound read.
        // The trusted owner lane must not write a clock floor during recall:
        // anonymous off-record reads promise no base-store mutations.
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        verify_actor_binding_in_txn(self.vault, &txn, self.actor, self.actor_class)?;
        let owner = if self.actor_class == crate::EdgeActorClass::Human {
            // The seeded embedded owner is the trusted local host lane. Other
            // humans in a rooted vault require their live authority binding.
            if self.actor == crate::vault::embedded_owner_actor_id()? {
                true
            } else {
                match self.verify_owner_in_txn(&txn) {
                    Ok(()) => true,
                    Err(err) if err.code == crate::memory::MEMORY_CODE_OWNER_BINDING_REQUIRED => {
                        false
                    }
                    Err(err) => return Err(err),
                }
            }
        } else {
            false
        };
        let policy = crate::gate::resolve_policy_manifest(&self.vault.store, &txn)?;
        let actor_key = (!owner).then(|| {
            crate::claim::ScopedReadActorKey::with_actor_class(
                self.actor.to_hex(),
                self.actor_class.gate_actor_class(),
            )
            .expect("verified actor has a nonempty id and class")
            .require_access_grants(Some(self.actor))
        });
        let filter = crate::gate::narrow_retrieval_filter(
            &policy.retrieval_floor_for_actor(actor_key.as_ref()),
            None,
        )?;
        drop(txn);
        if actor_key.is_some() {
            // Persist grant time before the retrieval snapshot, never while a
            // read transaction is live. Owner recall needs no grant clock.
            self.vault.store.authorization_now()?;
        }
        Ok((filter, actor_key.map(|key| self.vault.scoped_read(key))))
    }
}
