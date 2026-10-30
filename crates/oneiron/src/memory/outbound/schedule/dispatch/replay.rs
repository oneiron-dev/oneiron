//! A client retry of a send already delivered: its receipt, read from the delivered-send index.

use super::*;

impl Memory<'_> {
    /// The delivered send this draft's idempotency key already names, as an
    /// `already_sent` receipt and its sender; `None` when none was delivered.
    pub(super) fn replay_delivered_send(
        &self,
        draft: &OutboundDraftInput,
    ) -> MemoryResult<Option<(OutboundIntentReceipt, Option<EntityId>)>> {
        if let Some(idempotency_key) = draft.idempotency_key.as_deref()
            && let Some(task_ref) = self
                .vault
                .store
                .get_delivered_send_task_by_idempotency(&self.actor, idempotency_key)?
        {
            let receipt =
                delivered_send_receipt_for_task(self.vault, task_ref)?.ok_or_else(|| {
                    MemoryError::from(Error::CorruptedIndex("send idempotency index"))
                })?;
            let actor_ref = self.actor.to_hex();
            if receipt.actor.as_deref() != Some(actor_ref.as_str())
                || receipt.fields.get("idempotency_key").map(String::as_str)
                    != Some(idempotency_key)
            {
                return Err(MemoryError::from(Error::CorruptedIndex(
                    "send idempotency index",
                )));
            }
            return Ok(Some((
                OutboundIntentReceipt {
                    intent_ref: receipt
                        .fields
                        .get("intent_ref")
                        .cloned()
                        .unwrap_or_else(|| format!("intent:task:{}", task_ref.to_hex())),
                    outcome: "already_sent".to_owned(),
                    gate_outcome: receipt.fields.get("gate_outcome").cloned(),
                    gate_decision_ref: receipt.fields.get("gate_decision_ref").cloned(),
                    gate_reason_codes: receipt
                        .fields
                        .get("gate_reason_codes")
                        .map(|codes| {
                            codes
                                .split(',')
                                .filter(|code| !code.is_empty())
                                .map(str::to_owned)
                                .collect()
                        })
                        .unwrap_or_default(),
                    approval_digest: receipt
                        .fields
                        .get(crate::outbound::APPROVAL_DIGEST_FIELD)
                        .cloned(),
                    deduped: true,
                },
                receipt
                    .fields
                    .get("channel_identity_ref")
                    .map(|value| EntityId::from_hex(value))
                    .transpose()?,
            )));
        }
        Ok(None)
    }
}
