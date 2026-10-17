//! A retire line for a world or a mask lands as a person's delete of it: a
//! user delete under the owner's gate, never an erase. The tombstone keeps a
//! world's keys, pads and sealed copies, so old bundles still restore it;
//! only an erase destroys them, and no seed line asks for one.
use crate::consent::AuthenticatedOwner;
use crate::deletion::{DeleteReason, DeletionGateContext, GatedDeletion};
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::{EntityId, Vault};

impl Vault {
    /// Deletes `id` as `owner`. The gate records the policy frontier the
    /// owner acts at, and every destructive writer re-proves the owner
    /// binding against its own view. Returns the delete's receipt, else the
    /// entity it deleted.
    pub(super) fn delete_shape_entity(
        &self,
        owner: &AuthenticatedOwner,
        id: EntityId,
    ) -> Result<String> {
        let actor = owner.revalidate(self)?;
        let context = {
            let txn = self.store.env.read_txn()?;
            let policy = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
            DeletionGateContext::new(
                actor,
                EdgeActorClass::Human,
                crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
                policy.read_frontier_hash()?,
            )
        };
        let reverify = |txn: &heed::RoTxn<'_>| owner.revalidate_in_txn(self, txn).map(|_| ());
        let outcome = self.delete_entity_with_reason_gated(
            &id,
            DeleteReason::UserDelete,
            GatedDeletion::new(context, &reverify),
        )?;
        Ok(outcome.receipt_id.unwrap_or(id).to_hex())
    }
}
