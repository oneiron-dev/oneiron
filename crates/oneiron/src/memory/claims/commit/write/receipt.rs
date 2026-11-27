//! A landed claim commit's receipt: final approval, Gate decision, and the head it superseded.

use super::*;

use oneiron_store::receipt_ref::ReceiptRef;

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
        let reason_codes = if final_approval == ClaimApprovalStatus::Proposed.as_str() {
            self.held_reason_codes(&id, &receipt_ref)?
        } else {
            Vec::new()
        };
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
            reason_codes,
            note: None,
        })
    }

    /// A held commit's reasons: the codes of the gate decision `receipt_ref`
    /// names, then the tray row's, each once, in that order.
    fn held_reason_codes(&self, id: &EntityId, receipt_ref: &str) -> MemoryResult<Vec<String>> {
        let store = &self.vault.store;
        let _custody = store.gate_custody_read_guard()?;
        let txn = store.env.read_txn().map_err(Error::from)?;
        let decision_id = receipt_ref
            .parse::<ReceiptRef>()
            .ok()
            .and_then(|r| r.gate_id());
        let decision = match decision_id {
            Some(decision_id) => store.gate_decision_in_txn(&txn, decision_id)?,
            None => None,
        };
        let tray = store.lenient_tray_in_txn(&txn, id)?;
        let mut codes = Vec::new();
        for code in decision
            .into_iter()
            .flat_map(|record| record.reason_codes)
            .chain(tray.into_iter().flat_map(|record| record.reason_codes))
        {
            if !codes.contains(&code) {
                codes.push(code);
            }
        }
        Ok(codes)
    }
}
