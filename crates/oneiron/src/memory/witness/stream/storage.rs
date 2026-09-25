//! Fixed per-handle recovery metadata and terminal audit. No partial text is encoded.
use super::*;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub(super) const ACTIVE: &[u8] = b"message_stream:v1:";
const RECEIPT: &[u8] = b"message_stream_receipt:v1:";
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
pub(super) fn key(prefix: &[u8], id: EntityId) -> Vec<u8> {
    [prefix, id.as_bytes()].concat()
}
pub(super) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value).map_err(|_| Error::CorruptedIndex("stream metadata encode"))
}
pub(super) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    rmp_serde::from_slice(bytes).map_err(|_| Error::CorruptedIndex("stream metadata decode"))
}
pub(super) fn receipt(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<MessageStreamReceipt>> {
    vault
        .store
        .vault_meta
        .get(txn, &key(RECEIPT, id))?
        .map(|bytes| decode(&bytes))
        .transpose()
}
pub(super) fn finish(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    seed: &Seed,
    receipt: &MessageStreamReceipt,
) -> Result<()> {
    let active_key = key(ACTIVE, seed.message_id);
    let stored: Seed = decode(
        &vault
            .store
            .vault_meta
            .get(txn, &active_key)?
            .ok_or(Error::CorruptedIndex("stream recovery metadata missing"))?,
    )?;
    if stored.generation != seed.generation {
        return Err(Error::ConcurrentWrite("message stream generation changed"));
    }
    // Per-generation receipt is immutable; the message key is the latest join.
    let bytes = encode(receipt)?;
    vault
        .store
        .vault_meta
        .put(txn, &key(RECEIPT, seed.message_id), &bytes)?;
    vault
        .store
        .vault_meta
        .put(txn, receipt.receipt_ref.as_bytes(), &bytes)?;
    vault.store.vault_meta.delete(txn, &active_key)?;
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
        Ok(self
            .store
            .vault_meta
            .get(&txn, reference.as_bytes())?
            .map(|b| decode(&b))
            .transpose()?)
    }
}
