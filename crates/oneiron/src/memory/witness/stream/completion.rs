//! Whether a MESSAGE's reply is complete, derived from its latest stream
//! receipt. No writer states completeness: a reply is complete only when its
//! latest generation ended final and for a reason that finishes an answer.
use super::*;
use crate::error::Result;
use crate::memory::MemoryResult;
use oneiron_model::llm::FinishReason;
use serde::Serialize;

#[doc(hidden)]
pub use oneiron_verb_wire::memory::witness::stream::completion::MessageCompletion;

/// [`Memory::message_completion`] in the caller's transaction, for a reader
/// that reads many MESSAGEs in one snapshot.
pub(crate) fn message_completion_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    message: &EntityId,
) -> Result<MessageCompletion> {
    message_completion_in(&vault.store, txn, message)
}

fn message_completion_in(
    dbs: &impl crate::side_table::SideTableDbs,
    txn: &heed::RoTxn<'_>,
    message: &EntityId,
) -> Result<MessageCompletion> {
    let generating = storage::ACTIVE.contains(dbs, txn, message)?;
    // A MESSAGE no stream wrote is ordinary witnessed text: complete.
    Ok(match storage::receipt_in(dbs, txn, *message)? {
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
        let lane = self.read_lane(crate::claim::ClaimReadStatus::Recorded)?;
        let result = lane.read_projected(
            &[crate::claim::PointRead::id(*message)],
            None,
            |txn, rows| {
                let Some(row) = rows
                    .into_iter()
                    .next()
                    .flatten()
                    .filter(|row| row.body.is_some())
                else {
                    return Ok::<_, crate::memory::MemoryError>(None);
                };
                if row.entity_type != crate::registry::ENTITY_TYPE_MESSAGE {
                    return Ok(None);
                }
                Ok(Some(message_completion_in(
                    &lane.store_read(),
                    txn,
                    message,
                )?))
            },
        )?;
        if let Some(completion) = result.value {
            self.produced_from([*message]);
            Ok(completion)
        } else {
            Ok(MessageCompletion {
                incomplete: false,
                generating: false,
                finish_reason: None,
            })
        }
    }
}
