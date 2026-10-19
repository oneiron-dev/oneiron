//! Owner-bound artifact publication through the existing outbound Gate.

use super::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::artifact_hosting::door_types::*;
use crate::artifact_hosting::{ArtifactPointer, ArtifactPublishVerbRequest, ArtifactServeTier};
use crate::consent::AuthenticatedOwner;
use crate::write_envelope::WriteActor;

impl Memory<'_> {
    fn artifact_hosting_owner(&self, owner: &AuthenticatedOwner) -> MemoryResult<()> {
        if owner.revalidate(self.vault)? != self.actor
            || self.actor_class != crate::EdgeActorClass::Human
        {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "artifact hosting acts as the authenticated owner",
                &["Present the owner's own verified, unattenuated credential."],
            ));
        }
        Ok(())
    }

    fn artifact_publish_request_as(
        &self,
        owner: &AuthenticatedOwner,
        input: ArtifactPublishRequest,
    ) -> MemoryResult<ArtifactPublishVerbRequest> {
        self.artifact_hosting_owner(owner)?;
        let export_owner = self
            .vault
            .resolve_export_owner(&input.artifact, input.export)?
            .ok_or_else(|| MemoryError::not_found("artifact export is absent or withheld"))?;
        self.produced_from([export_owner]);
        if self.get_entity(&export_owner.to_hex())?.value.is_none() {
            return Err(MemoryError::not_found(
                "artifact export is absent or withheld",
            ));
        }
        Ok(ArtifactPublishVerbRequest {
            artifact: input.artifact,
            channel: input.channel,
            export: input.export,
            serve_tier: input.serve_tier,
            actor: WriteActor::new(self.actor, self.actor_class),
            publish_id: input.publish_id,
            occurred_at: input.occurred_at,
        })
    }

    pub fn artifact_publish_approval_as(
        &self,
        owner: &AuthenticatedOwner,
        input: ArtifactPublishRequest,
    ) -> MemoryResult<ArtifactPublishApproval> {
        let request = self.artifact_publish_request_as(owner, input)?;
        Ok(ArtifactPublishApproval {
            effect_digest: self
                .vault
                .artifact_publish_approval_digest(&request)?
                .to_hex(),
        })
    }

    pub fn artifact_publish_as(
        &self,
        owner: &AuthenticatedOwner,
        input: ArtifactPublishRequest,
    ) -> MemoryResult<ArtifactPublishView> {
        let request = self.artifact_publish_request_as(owner, input)?;
        let outcome = self.vault.request_artifact_publish(&request)?;
        Ok(ArtifactPublishView {
            status: outcome.status,
            pointer: outcome.pointer,
            receipt_ref: outcome.receipt.map(|receipt| receipt.receipt_id),
            gate_decision_ref: outcome.gate_decision_ref,
        })
    }

    pub fn artifact_pointer_as(
        &self,
        owner: &AuthenticatedOwner,
        input: ArtifactPointerRequest,
    ) -> MemoryResult<Option<ArtifactPointer>> {
        self.artifact_hosting_owner(owner)?;
        let Some(pointer) = self
            .vault
            .artifact_pointer(&input.artifact, input.channel)?
        else {
            return Ok(None);
        };
        let export_owner = self
            .vault
            .resolve_export_owner(&pointer.artifact, pointer.export)?
            .ok_or_else(|| MemoryError::not_found("artifact export is absent or withheld"))?;
        self.produced_from([export_owner]);
        Ok(self
            .collection_view(&export_owner)?
            .is_some()
            .then_some(pointer))
    }

    pub fn artifact_unpublish_as(
        &self,
        owner: &AuthenticatedOwner,
        input: ArtifactPointerRequest,
    ) -> MemoryResult<ArtifactUnpublished> {
        let visible = self.artifact_pointer_as(owner, input.clone())?.is_some();
        Ok(ArtifactUnpublished {
            removed: visible
                && self
                    .vault
                    .unpublish_artifact_pointer(&input.artifact, input.channel)?,
        })
    }

    pub fn artifact_link_token_as(
        &self,
        owner: &AuthenticatedOwner,
    ) -> MemoryResult<ArtifactLinkToken> {
        self.artifact_hosting_owner(owner)?;
        let (serve_tier, token) = ArtifactServeTier::mint_link_token();
        Ok(ArtifactLinkToken { serve_tier, token })
    }
}
