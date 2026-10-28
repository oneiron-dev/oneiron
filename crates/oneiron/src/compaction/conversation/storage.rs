//! A conversation's landed self-written summaries (FIX 4465 D): one durable
//! receipt per SUMMARY, written in its mint's own transaction, naming the
//! epoch, the SESSION's turn range and the host's record of what wrote it,
//! the conversation evidence included. The Dreamer's check and the agent's
//! next log read it; it holds refs, hashes and usage, never words.

use serde::{Deserialize, Serialize};

use super::{ConversationEvidence, ConversationTurnSpan};
use crate::compaction::{CompactionEvidence, CompactionExecution, EpochMint};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::{EntityId, Result, Vault};

/// Landing receipts. Key: id16(summary).
const RECEIPTS: SideTable<EntityId, ConversationLandingReceipt, Named> =
    SideTable::new(&side_table::COMPACTION_CONVERSATION_RECEIPT);

/// One landed conversation summary's receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConversationLandingReceipt {
    pub(crate) summary: EntityId,
    pub(crate) epoch: u64,
    /// The SESSION's turn numbers the epoch covers.
    pub(crate) turn_start: u64,
    pub(crate) turn_end: u64,
    pub(crate) execution: CompactionExecution,
}

impl ConversationLandingReceipt {
    /// The conversation evidence the receipt names.
    pub(crate) fn evidence(&self) -> Option<&ConversationEvidence> {
        match self.execution.evidence.as_ref()? {
            CompactionEvidence::Conversation(evidence) => Some(evidence),
            CompactionEvidence::Executor { .. } => None,
        }
    }
}

/// Writes `mint`'s receipt in its own transaction.
pub(crate) fn put_conversation_receipt_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    mint: &EpochMint,
    execution: &CompactionExecution,
) -> Result<()> {
    let receipt = ConversationLandingReceipt {
        summary: mint.summary_id(),
        epoch: mint.epoch(),
        turn_start: mint.turn_start(),
        turn_end: mint.turn_end(),
        execution: execution.clone().without_calls(),
    };
    RECEIPTS.put(vault, txn, &receipt.summary, &receipt)
}

/// The receipt of `summary`, in the caller's snapshot.
pub(crate) fn conversation_receipt_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    summary: &EntityId,
) -> Result<Option<ConversationLandingReceipt>> {
    RECEIPTS.get(store, txn, summary)
}

impl Vault {
    /// The turns the conversation summary `summary` folded, each with the
    /// MESSAGEs its reader read, as its landing receipt names them, read on
    /// one snapshot; `None` when no receipt landed for it or the receipt
    /// names no conversation evidence.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn summary_folded_spans(
        &self,
        summary: &EntityId,
    ) -> Result<Option<Vec<ConversationTurnSpan>>> {
        let txn = self.store.env.read_txn()?;
        Ok(conversation_receipt_in(&self.store, &txn, summary)?
            .and_then(|receipt| receipt.evidence().map(|evidence| evidence.turns.clone())))
    }
}

/// Every landed receipt of `conversation`, in SUMMARY order.
pub(super) fn conversation_receipts_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    conversation: EntityId,
) -> Result<Vec<ConversationLandingReceipt>> {
    Ok(RECEIPTS
        .scan(store, txn)?
        .into_iter()
        .map(|(_, receipt)| receipt)
        .filter(|receipt| {
            receipt
                .evidence()
                .is_some_and(|evidence| evidence.conversation == conversation)
        })
        .collect())
}
