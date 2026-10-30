//! A terminal's receipts: the one a landed generation holds, and the one a write opens with.

use super::*;

/// This generation's receipt, if its terminal already landed.
pub(super) fn landed_receipt(
    vault: &Vault,
    seed: &Seed,
) -> MessageStreamResult<Option<MessageStreamReceipt>> {
    let txn = vault.store.env.read_txn()?;
    Ok(storage::receipt(vault, &txn, seed.message_id)?
        .filter(|done| done.generation == seed.generation))
}

/// The receipt a terminal write opens with, before its transaction sets its
/// final byte count and assertions.
pub(super) fn opening_receipt(
    state: &State,
    (finality, reason): (StreamFinality, StreamFinalityReason),
    finish_reason: Option<FinishReason>,
    recovered: bool,
) -> MessageStreamReceipt {
    let seed = &state.seed;
    MessageStreamReceipt {
        message_id: seed.message_id,
        actor: seed.actor,
        generation: seed.generation,
        finality,
        finality_reason: reason,
        finish_reason,
        bytes: state.text().len() as u64,
        recovered,
        // Every accepted delta was checkpointed before it was accepted, so a
        // recovered stream's text is all its process ever accepted.
        ephemeral_text_lost: false,
        receipt_ref: format!(
            "stream:v1:{}:{}",
            seed.message_id.to_hex(),
            seed.generation.to_hex()
        ),
        reply_assertions: crate::llm::ReplyAssertions::default(),
    }
}
