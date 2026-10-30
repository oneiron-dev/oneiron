//! A continuation's terminal: its prose links, read before its writer, and its one write.

use super::*;

/// OF-063 prose links (Engine ruling 10-17): a continuation's appended
/// text is read for the links its AI writer cannot resolve, receipt-only,
/// before the writer opens, and receipted only once the finalize has
/// landed (Engine ruling 10-18); a new message's final witness reads its
/// own through the witness program. A recovered stream is read the same
/// way. This close is the stream's one link receipt: its checkpoints and
/// presence frames leave none (Engine ruling 10-18).
pub(super) fn continuation_unlinked_prose(
    vault: &Vault,
    state: &State,
    memory: &Memory<'_>,
) -> Vec<crate::receipt::ReferenceRefusalFacts> {
    let seed = &state.seed;
    let mut unlinked_prose = Vec::new();
    if seed.continuation
        && seed.author == crate::memory::WitnessAuthor::Companion
        && !state.pending.is_empty()
        && let Ok(txn) = vault.store.env.read_txn()
        && let Ok(Some(base)) = admission::committed_text(vault, &txn, seed)
    {
        drop(txn);
        let text = format!("{base}{}", state.pending);
        unlinked_prose = crate::gate::record_references::prose_text_unlinked(
            memory,
            crate::gate::record_references::WITNESS_PROSE_ROW,
            "/messages/0/content",
            &text,
            base.len(),
        );
    }
    unlinked_prose
}

/// The continuation's write: its gate, its judged assertions, its appended
/// text and its finalize, in one transaction.
#[expect(
    clippy::too_many_arguments,
    reason = "the continuation's write joins its stream, its reply's assertions and its gates"
)]
pub(super) fn write_continuation_terminal(
    vault: &Vault,
    state: &State,
    assertions: &WitnessAssertions,
    gate: TerminalGate<'_>,
    callback: Callback,
    (lane, memory): (Option<&crate::claim::ScopedRead<'_>>, &crate::memory::Memory<'_>),
    (unread, unproven): (&std::cell::Cell<Option<String>>, &std::cell::Cell<Vec<String>>),
    receipt: &mut MessageStreamReceipt,
) -> MessageStreamResult<()> {
    let seed = &state.seed;
    vault.write_txn_door(callback, |txn| -> MessageStreamResult<()> {
        admit_terminal(gate, txn)?;
        reply_assertions::judge_in_txn(lane, txn, assertions, unread)?;
        unproven.set(reply_assertions::unproven_in_txn(memory, txn, assertions));
        // Judged: this generation keeps its seed's and its terminal's
        // set on its own receipt; the birth envelope stays (FIX 10258).
        receipt.reply_assertions =
            admitted_in_txn(&vault.store, txn, &[&seed.assertions, assertions])?;
        let base = admission::committed_text(vault, txn, seed)?.ok_or(Error::EntityNotFound)?;
        let text = format!("{base}{}", state.pending);
        admission::authorize(vault, txn, seed, &text, !state.pending.is_empty())?;
        let was_final =
            storage::receipt(vault, txn, seed.message_id)?.is_none_or(|prior| prior.complete());
        // A nonempty continuation edits the MESSAGE, and its first births
        // the document; an empty one edits nothing and births none (FIX
        // 4840).
        if !state.pending.is_empty() {
            crate::entity_doc::append_message_stream_in_txn(
                vault,
                txn,
                &seed.message_id,
                &state.pending,
                crate::write_envelope::WriteActor::new(seed.actor, seed.class()?),
                seed.occurred_at,
            )?;
        }
        receipt.bytes = text.len() as u64;
        storage::finish(vault, txn, seed, receipt)?;
        // Readers see only complete words: a finalize that adds some, or
        // makes an incomplete MESSAGE complete again, re-dirties its TURN.
        // One that ends a complete MESSAGE incomplete takes its words out
        // of the transcript: no new words for a branch, but the sieve and
        // the projector read what the turn says now.
        let now_final = receipt.complete();
        if now_final && (!state.pending.is_empty() || !was_final) {
            storage::redirty_turn(vault, txn, seed)?;
        } else if was_final && !now_final {
            crate::dreamer_wake::words_changed_in_txn(&vault.store, txn, &seed.turn)?;
        }
        Ok(())
    })
}
