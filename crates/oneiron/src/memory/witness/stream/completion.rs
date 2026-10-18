//! Whether a MESSAGE's reply is complete, derived from its latest stream
//! receipt. No writer states completeness: a reply is complete only when its
//! latest generation ended final and for a reason that finishes an answer.
use super::*;
use crate::FinishReason;
use crate::error::Result;
use crate::memory::MemoryResult;
use serde::Serialize;

/// A MESSAGE's completion, read from its latest stream receipt and its seed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct MessageCompletion {
    /// The latest generation ended without finishing its answer: cut off at a
    /// length, filtered, stopped for another reason, cancelled, failed, idle
    /// or recovered after a crash. Continue and Retry act on it.
    pub incomplete: bool,
    /// A stream is open on the MESSAGE now.
    pub generating: bool,
    /// Why the model that wrote the latest generation stopped, when one did.
    pub finish_reason: Option<FinishReason>,
}
impl MessageStreamReceipt {
    /// Final, and ended by its model's stop or tool call, or by a writer
    /// that is no model and finalized normally.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.finality == StreamFinality::Final
            && matches!(
                self.finish_reason,
                None | Some(FinishReason::Stop | FinishReason::ToolCalls)
            )
    }
}
/// [`Memory::message_completion`] in the caller's transaction, for a reader
/// that reads many MESSAGEs in one snapshot.
pub(crate) fn message_completion_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    message: &EntityId,
) -> Result<MessageCompletion> {
    let generating = storage::ACTIVE.contains(&vault.store, txn, message)?;
    // A MESSAGE no stream wrote is ordinary witnessed text: complete.
    Ok(match storage::receipt(vault, txn, *message)? {
        Some(receipt) => MessageCompletion {
            incomplete: !receipt.complete(),
            generating,
            finish_reason: receipt.finish_reason,
        },
        None => MessageCompletion {
            incomplete: false,
            generating,
            finish_reason: None,
        },
    })
}
impl Memory<'_> {
    /// Whether `message` holds a complete reply. It reveals no text.
    pub fn message_completion(&self, message: &EntityId) -> MemoryResult<MessageCompletion> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(|error| crate::memory::MemoryError::from(crate::Error::from(error)))?;
        Ok(message_completion_in_txn(self.vault, &txn, message)?)
    }
}
