//! Consume the separate owner act for the same code-wait admission.

use super::*;
use crate::code_run::CodeConsentWaitRow;

impl Vault {
    /// The consumed marker of this exact admission, never a fresh authorization.
    pub(crate) fn code_wait_consumed_approval_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        row: &CodeConsentWaitRow,
        digest: &EffectDigest,
    ) -> Result<bool> {
        let Some((consumed, decision)) = row.consumed_approval() else {
            return Ok(false);
        };
        if consumed != *digest.as_bytes() {
            return Ok(false);
        }
        Ok(APPROVE_ONCE_MARKERS
            .get(&self.store, txn, digest.as_bytes())?
            .is_some_and(|marker| {
                marker.state == CONSENT_APPROVE_ONCE_SPENT && marker.decision_id == decision
            }))
    }

    /// Records a live owner's explicit rebind act. The wait's writer has proved
    /// the frozen target and actual holder succession; no other admission gets
    /// an available authorization from this act.
    pub(crate) fn record_code_wait_rebind_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        row: &CodeConsentWaitRow,
        previous: EffectDigest,
        successor: EffectDigest,
    ) -> Result<ConsentReceipt> {
        owner.revalidate_in_txn(self, txn)?;
        let proposal = row.rebind_proposal.as_ref().ok_or(Error::ConcurrentWrite(
            "the code consent rebind proposal changed",
        ))?;
        let (previous_digest, previous_decision) = row
            .consumed_approval()
            .ok_or(Error::ConcurrentWrite("the code consent approval changed"))?;
        let marker = APPROVE_ONCE_MARKERS
            .get(&self.store, &*txn, previous.as_bytes())?
            .ok_or(Error::ConcurrentWrite(
                "the consumed code consent marker is missing",
            ))?;
        if !row.approved_unsettled()
            || row.consumption.is_some()
            || row
                .admission
                .as_ref()
                .is_none_or(|admission| admission.intent_id != proposal.intent_id)
            || previous_digest != *previous.as_bytes()
            || marker.state != CONSENT_APPROVE_ONCE_SPENT
            || marker.decision_id != previous_decision
        {
            return Err(Error::ConcurrentWrite(
                "the consumed code consent authorization changed",
            ));
        }
        if previous == successor {
            if row.binding.pending.browser_action().is_none() {
                return Err(Error::ConcurrentWrite(
                    "the successor code binding did not change",
                ));
            }
            // Browser digests do not include the instrument-bearing binding.
            // Record the real act without a second marker or authorization.
            let receipt = ConsentReceipt::Approved {
                decision_id: GateDecisionId::from_bytes(self.store.clock.ulid()?),
                grant: ConsentGrant::ApproveOnce(successor),
            };
            self.append_consent_receipt_in_txn(txn, owner, &receipt)?;
            return Ok(receipt);
        }
        let receipt = self.approve_once_in_txn(txn, owner, successor)?;
        let authorization = approve_once_authorization_in_txn(&self.store, txn, &successor)?
            .ok_or(Error::InvariantViolation(
                "a code consent rebind minted no authorization",
            ))?;
        spend_approve_once_in_txn(&self.store, txn, &authorization)?;
        Ok(receipt)
    }
}
