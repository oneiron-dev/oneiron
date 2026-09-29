//! Fixed per-handle recovery metadata and terminal audit. No partial text is encoded.
use super::*;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::side_table::{self, Named, SideTable};
use serde::{Deserialize, Serialize};

/// In-flight streamed message recovery seed. Key: id16 (message id).
pub(super) const ACTIVE: SideTable<EntityId, Seed, Named> =
    SideTable::new(&side_table::MESSAGE_STREAM_ACTIVE);
/// Latest terminal stream receipt of a message. Key: id16 (message id).
const RECEIPT: SideTable<EntityId, MessageStreamReceipt, Named> =
    SideTable::new(&side_table::MESSAGE_STREAM_RECEIPT);
/// Per-generation stream receipt keyed by its receipt ref. Key: string
/// (hex32(message id) ":" hex32(generation)).
const RECEIPT_BY_REF: SideTable<String, MessageStreamReceipt, Named> =
    SideTable::new(&side_table::MESSAGE_STREAM_RECEIPT_BY_REF);
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Seed {
    pub message_id: EntityId,
    pub generation: EntityId,
    pub actor: EntityId,
    pub actor_class: u8,
    pub conversation: EntityId,
    pub turn: EntityId,
    pub author: WitnessAuthor,
    pub message_type: String,
    pub metadata: Option<serde_json::Value>,
    pub is_visible: bool,
    pub order: u32,
    pub occurred_at: u64,
    pub created_at_ms: u64,
    pub mode: MessageWriteMode,
    pub idle_timeout_ms: u64,
    pub continuation: bool,
}
impl Seed {
    pub(super) fn class(&self) -> Result<EdgeActorClass> {
        EdgeActorClass::try_from_u8(self.actor_class)
            .ok_or(Error::CorruptedIndex("stream actor class"))
    }
    pub(super) fn message(&self, content: String) -> WitnessMessage {
        WitnessMessage {
            id: Some(self.message_id.to_hex()),
            author: self.author,
            message_type: self.message_type.clone(),
            content,
            metadata: self.metadata.clone(),
            is_visible: self.is_visible,
            order: self.order,
        }
    }
    pub(super) fn turn(&self, content: String) -> WitnessTurn {
        WitnessTurn {
            conversation_ref: self.conversation.to_hex(),
            turn_ref: Some(self.turn.to_hex()),
            messages: vec![self.message(content)],
            occurred_at: self.occurred_at,
        }
    }
}
pub(super) fn receipt(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<MessageStreamReceipt>> {
    RECEIPT.get(&vault.store, txn, &id)
}
pub(super) fn finish(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    seed: &Seed,
    receipt: &MessageStreamReceipt,
) -> Result<()> {
    let stored = ACTIVE
        .get(&vault.store, txn, &seed.message_id)?
        .ok_or(Error::CorruptedIndex("stream recovery metadata missing"))?;
    if stored.generation != seed.generation {
        return Err(Error::ConcurrentWrite("message stream generation changed"));
    }
    // Per-generation receipt is immutable; the message key is the latest join.
    RECEIPT.put(&vault.store, txn, &seed.message_id, receipt)?;
    let by_ref = format!("{}:{}", seed.message_id.to_hex(), seed.generation.to_hex());
    RECEIPT_BY_REF.put(&vault.store, txn, &by_ref, receipt)?;
    ACTIVE.delete(&vault.store, txn, &seed.message_id)?;
    Ok(())
}
impl Vault {
    /// Joins the latest stream finality onto a MESSAGE. Atomic commits have none.
    pub fn message_stream_receipt(
        &self,
        message: &EntityId,
    ) -> MessageStreamResult<Option<MessageStreamReceipt>> {
        let txn = self.store.env.read_txn()?;
        Ok(receipt(self, &txn, *message)?)
    }
    /// Reads a specific immutable stream receipt, including earlier continuations.
    pub fn message_stream_receipt_by_ref(
        &self,
        reference: &str,
    ) -> MessageStreamResult<Option<MessageStreamReceipt>> {
        if !reference.starts_with("stream:v1:") || reference.len() != 10 + 32 + 1 + 32 {
            return Err(MessageStreamError::InvalidRequest(
                "invalid receipt reference",
            ));
        }
        let txn = self.store.env.read_txn()?;
        let suffix = reference[10..].to_owned();
        Ok(RECEIPT_BY_REF.get(&self.store, &txn, &suffix)?)
    }
}
