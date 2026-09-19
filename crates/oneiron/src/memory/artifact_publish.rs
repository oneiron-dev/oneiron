//! Owner-granted, per-artifact outbound publish authority.
use super::support::{verify_actor_binding_in_txn, verify_deletion_authority_in_txn};
use super::{Memory, MemoryError, MemoryResult};
use crate::outbound_grant::{
    StandingOutboundGrant, StandingOutboundGrantScope, StandingOutboundGrantStatus,
    encode_standing_outbound_grant_body,
};
use crate::{EntityId, edge::EdgeActorClass};

impl Memory<'_> {
    /// Grants an actor auto-publish on one artifact. This does not enable public hosting.
    pub fn grant_artifact_publish(
        &self,
        artifact: &str,
        grantee: EntityId,
        now: u64,
    ) -> MemoryResult<EntityId> {
        let id = EntityId::now();
        self.with_verified_actor_write_txn(|txn| {
            verify_deletion_authority_in_txn(self.vault, txn, self.actor, self.actor_class)?;
            verify_actor_binding_in_txn(self.vault, txn, grantee, EdgeActorClass::Agent)?;
            let policy = crate::gate::resolve_policy_manifest(&self.vault.store, txn)?;
            let grant = StandingOutboundGrant {
                principal_ref: grantee.to_hex(),
                origin_component_id: "artifact".into(),
                origin_action_id: "grant_publish".into(),
                origin_receipt_ref: None,
                scope: StandingOutboundGrantScope::ArtifactPublish {
                    artifact: artifact.to_owned(),
                },
                status: StandingOutboundGrantStatus::Active,
                created_at: now,
                revoked_at: None,
                last_used_at: None,
                binding_diff_handle: blake3::hash(
                    format!(
                        "artifact-publish:{}:{}:{}",
                        self.actor.to_hex(),
                        grantee.to_hex(),
                        artifact
                    )
                    .as_bytes(),
                )
                .as_bytes()
                .to_vec(),
                read_frontier_hash: policy.read_frontier_hash()?,
            };
            grant.validate().map_err(MemoryError::from)?;
            let bytes = encode_standing_outbound_grant_body(&grant)?;
            self.vault
                .apply_standing_outbound_grant_body(txn, &id, now, bytes)?;
            Ok(id)
        })
    }
}
