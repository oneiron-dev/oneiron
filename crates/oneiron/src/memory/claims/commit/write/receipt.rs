//! A landed claim commit's receipt: final approval, Gate decision, and the head it superseded.

use super::*;

impl Memory<'_> {
    pub(super) fn commit_receipt(
        &self,
        id: EntityId,
        prior: Option<EntityId>,
        approval: ClaimApprovalStatus,
    ) -> MemoryResult<CommitReceipt> {
        let superseded = match prior {
            Some(old_id)
                if self
                    .vault
                    .get_claim(&old_id)?
                    .is_some_and(|body| body.lifecycle == ClaimLifecycleStatus::Superseded) =>
            {
                Some((old_id, self.short_ref_of(&old_id)?))
            }
            Some(_) => None,
            None => None,
        };
        let final_approval = self.vault.get_claim(&id)?.map_or_else(
            || approval.as_str().to_owned(),
            |b| b.approval.as_str().to_owned(),
        );
        let receipt_ref = self
            .latest_decision_ref_for(&id)?
            .unwrap_or_else(|| format!("claim:{}", id.to_hex()));
        let short = self.short_ref_of(&id)?;
        let claim_ref = |id: &EntityId, short: Option<&str>| {
            crate::lens::RecordRef::from_id(crate::registry::ENTITY_TYPE_CLAIM, id, short)
        };
        Ok(CommitReceipt {
            claim: Some(claim_ref(&id, short.as_deref())),
            claim_short_id: short.unwrap_or_else(|| id.to_hex()),
            approval: final_approval,
            superseded: superseded
                .as_ref()
                .map(|(old_id, short)| claim_ref(old_id, short.as_deref())),
            superseded_short_id: superseded
                .map(|(old_id, short)| short.unwrap_or_else(|| old_id.to_hex())),
            receipt_ref,
        })
    }
}
