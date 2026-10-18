//! Frozen context on text emits, retained on the existing outbound receipt spine.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{ContextReceiptFields, ReceiptKind, ReceiptRecord, append_context_receipt_fields};
use crate::memory::{
    Memory, MemoryError, MemoryResult, actor_is_vault_owner_in_txn, verify_actor_binding_in_txn,
};
use crate::EntityId;

/// A read of the context actually sent for an emit. No field is recompiled at read time.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextEmitReceipt {
    pub receipt_ref: String,
    pub occurred_at: u64,
    pub actor: String,
    pub conversation_id: String,
    pub request_digest: String,
    pub result_digest: String,
    pub context: ContextReceiptFields,
}

impl Memory<'_> {
    /// Records a completed reply, as this credential's actor. The host supplies the
    /// frozen assembly only after its admitted model has actually answered.
    pub fn record_context_reply(
        &self,
        conversation: EntityId,
        context: &ContextReceiptFields,
        request_digest: String,
        result_digest: String,
    ) -> MemoryResult<String> {
        let _reader = self.read_key()?;
        let mut receipt = ReceiptRecord {
            receipt_id: format!("emit:{}", EntityId::now().to_hex()),
            receipt_kind: ReceiptKind::Outbound,
            occurred_at: self.vault().store.clock.now_recorded_at(),
            actor: Some(self.actor().to_hex()),
            on_behalf_of: None,
            outcome: "replied".to_owned(),
            job_ref: None,
            trigger_ref: Some(conversation.to_hex()),
            policy_trace: Vec::new(),
            fields: BTreeMap::from([
                ("conversation_id".to_owned(), conversation.to_hex()),
                ("request_digest".to_owned(), request_digest),
                ("result_digest".to_owned(), result_digest),
                ("actor_class".to_owned(), self.actor_class().gate_actor_class().to_owned()),
            ]),
        };
        append_context_receipt_fields(&mut receipt, context)?;
        super::direct_dispatch::record_with_ref(self.vault(), receipt).map_err(MemoryError::from)
    }

    /// The caller's own emit, or any emit for the vault's live owner. A missing
    /// ref and another actor's ref both read as none, as call receipts do.
    pub fn context_emit_receipt(&self, receipt_ref: &str) -> MemoryResult<Option<ContextEmitReceipt>> {
        if !receipt_ref.starts_with("emit:") {
            return Ok(None);
        }
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        verify_actor_binding_in_txn(vault, &txn, self.actor(), self.actor_class())?;
        let owner = actor_is_vault_owner_in_txn(vault, &txn, self.actor(), self.actor_class())?;
        drop(txn);
        for record in super::direct_dispatch::receipts(vault)? {
            if record.receipt_id != receipt_ref || record.outcome != "replied" {
                continue;
            }
            let actor = record.actor.as_deref().unwrap_or_default();
            let own = actor == self.actor().to_hex()
                && record.fields.get("actor_class").map(String::as_str)
                    == Some(self.actor_class().gate_actor_class());
            if !own && !owner {
                return Ok(None);
            }
            let field = |name: &str| record.fields.get(name).cloned().ok_or_else(|| {
                MemoryError::from(crate::Error::CorruptedIndex("context emit receipt field"))
            });
            return Ok(Some(ContextEmitReceipt {
                receipt_ref: record.receipt_id.clone(),
                occurred_at: record.occurred_at,
                actor: actor.to_owned(),
                conversation_id: field("conversation_id")?,
                request_digest: field("request_digest")?,
                result_digest: field("result_digest")?,
                context: record.context_receipt_fields().ok_or_else(|| {
                    MemoryError::from(crate::Error::CorruptedIndex("context emit receipt stamp"))
                })?,
            }));
        }
        Ok(None)
    }
}
