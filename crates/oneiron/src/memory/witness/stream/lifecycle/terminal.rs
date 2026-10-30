//! A stream's terminal write, its host gate, and the retirement of a Retry its own proof refuses.
//! `commit_terminal` is its call surface.
//! `memory::witness::stream` defines the stream state; `lifecycle` defines `TerminalGate`.

use super::*;
use crate::memory::witness::reply_assertions::admitted_reply_assertions_in_txn as admitted_in_txn;

mod continuation;
mod new_message;
mod receipts;

use self::continuation::{continuation_unlinked_prose, write_continuation_terminal};
use self::new_message::write_new_message_terminal;
use self::receipts::{landed_receipt, opening_receipt};

fn admit_terminal(gate: TerminalGate<'_>, txn: &heed::RwTxn<'_>) -> MemoryResult<()> {
    if gate.is_some_and(|admit| !admit(txn)) {
        return Err(crate::memory::MemoryError::new(
            crate::memory::MEMORY_CODE_FORBIDDEN,
            "the stream's host refused its terminal write",
            &["Cancel the stream; nothing was committed."],
        ));
    }
    Ok(())
}

/// A stream's terminal write. A Retry's (FIX 3152, 3149) proves the Retry
/// again in that write, under the agent's and the requester's reads opened
/// before it, and lands its TURN, or its room regeneration permit, with its
/// MESSAGE; a Retry that no longer stands lands nothing and is retired
/// ([`retire_refused_retry`]), so `state` reads terminal.
pub(super) fn commit_terminal(
    vault: &Vault,
    state: &mut State,
    (finality, reason): (StreamFinality, StreamFinalityReason),
    finish_reason: Option<FinishReason>,
    assertions: &WitnessAssertions,
    recovered: bool,
    gate: TerminalGate<'_>,
) -> MessageStreamResult<MessageStreamReceipt> {
    // Set only when the Retry's own proof refuses it.
    let refused = std::cell::Cell::new(false);
    let written = terminal_write(
        vault,
        state,
        (finality, reason),
        finish_reason,
        assertions,
        recovered,
        gate,
        &refused,
    );
    if written.is_err() && refused.get() {
        retire_refused_retry(vault, state)?;
    }
    written
}

/// Retires a Retry its terminal's own proof refused (FIX 3152): its
/// requester's standing lapsed, or its source or room changed. No TURN,
/// MESSAGE, link or receipt lands, as for a Retry never admitted; its seed
/// goes, and the stream ends.
fn retire_refused_retry(vault: &Vault, state: &mut State) -> MessageStreamResult<()> {
    let seed = &state.seed;
    vault.try_with_write_txn_grouped(|txn| -> MessageStreamResult<()> {
        if storage::ACTIVE
            .get(&vault.store, txn, &seed.message_id)?
            .is_some_and(|row| row.generation == seed.generation)
        {
            storage::ACTIVE.delete(&vault.store, txn, &seed.message_id)?;
        }
        Ok(())
    })?;
    state.terminal = true;
    #[cfg(feature = "sync")]
    vault.message_streams.presence.clear(&state.seed);
    vault.message_streams.remove(state.handle())
}

#[expect(
    clippy::too_many_arguments,
    reason = "the terminal write joins its outcome, its reply's assertions and its gates"
)]
fn terminal_write(
    vault: &Vault,
    state: &State,
    (finality, reason): (StreamFinality, StreamFinalityReason),
    finish_reason: Option<FinishReason>,
    assertions: &WitnessAssertions,
    recovered: bool,
    gate: TerminalGate<'_>,
    refused: &std::cell::Cell<bool>,
) -> MessageStreamResult<MessageStreamReceipt> {
    let seed = &state.seed;
    // A postcommit index hook can return an error after a successful commit.
    // Recognize our immutable generation receipt before attempting another write.
    if let Some(done) = landed_receipt(vault, seed)? {
        return Ok(done);
    }
    let mut receipt = opening_receipt(state, (finality, reason), finish_reason, recovered);
    // The opener's own proof, restored, reads every link below (FIX 1667).
    let memory = super::super::reader::terminal_memory(vault, seed)?;
    let unlinked_prose = continuation_unlinked_prose(vault, state, &memory);
    // A host's gate is host code inside the transaction, so a gated write
    // takes the hosts' door: a group of its own.
    let callback = if gate.is_some() {
        Callback::Opaque
    } else {
        Callback::Audited
    };
    // OF-063 (FIX 3416): a continuation reads the records its terminal
    // asserts through the writer's own lane, opened before its writer; a
    // new MESSAGE's witness opens its own. `unread` carries the first
    // pointer the lane cannot read out of the aborted writer.
    let lane = if seed.continuation {
        reply_assertions::continuation_lane(&memory, assertions)?
    } else {
        None
    };
    let unread = std::cell::Cell::new(None);
    // The created records the judged set does not prove, receipted once
    // the terminal lands (FIX 11034).
    let unproven = std::cell::Cell::new(Vec::new());
    let written: MessageStreamResult<()> = if seed.continuation {
        write_continuation_terminal(
            vault,
            state,
            assertions,
            gate,
            callback,
            (lane.as_ref(), &memory),
            (&unread, &unproven),
            &mut receipt,
        )
    } else {
        // A recovered stream's `pending` is its seed's checkpoint.
        let text = state.text();
        receipt.bytes = text.len() as u64;
        // The reply's assertions ride the turn its terminal witnesses, and
        // its metadata keeps them; the seed stays as it was (FIX 3416).
        let turn = reply_assertions::terminal_turn(seed, text, assertions)?;
        write_new_message_terminal(
            vault,
            seed,
            &memory,
            &turn,
            gate,
            callback,
            refused,
            &mut receipt,
        )
    };
    let written = reply_assertions::settle(&memory, &unread, written);
    if let Err(error) = written {
        if let Some(done) = landed_receipt(vault, seed)? {
            crate::gate::record_references::receipt_landed_prose(&memory, &unlinked_prose);
            return Ok(done);
        }
        return Err(error);
    }
    crate::gate::record_references::receipt_landed_prose(&memory, &unlinked_prose);
    reply_assertions::receipt_unproven(&memory, &unproven);
    Ok(receipt)
}
