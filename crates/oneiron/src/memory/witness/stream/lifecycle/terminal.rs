//! A stream's terminal write, its host gate, and the retirement of a Retry its own proof refuses.
//! `commit_terminal` is its call surface.
//! `memory::witness::stream` defines the stream state; `lifecycle` defines `TerminalGate`.

use super::*;
use crate::memory::witness::reply_assertions::admitted_reply_assertions_in_txn as admitted_in_txn;

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
    {
        let txn = vault.store.env.read_txn()?;
        if let Some(done) = storage::receipt(vault, &txn, seed.message_id)?
            && done.generation == seed.generation
        {
            return Ok(done);
        }
    }
    let mut receipt = MessageStreamReceipt {
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
    };
    // The opener's own proof, restored, reads every link below (FIX 1667).
    let memory = super::super::reader::terminal_memory(vault, seed)?;
    // OF-063 prose links (Engine ruling 10-17): a continuation's appended
    // text is read for the links its AI writer cannot resolve, receipt-only,
    // before the writer opens, and receipted only once the finalize has
    // landed (Engine ruling 10-18); a new message's final witness reads its
    // own through the witness program. A recovered stream is read the same
    // way. This close is the stream's one link receipt: its checkpoints and
    // presence frames leave none (Engine ruling 10-18).
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
            &memory,
            crate::gate::record_references::WITNESS_PROSE_ROW,
            "/messages/0/content",
            &text,
            base.len(),
        );
    }
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
    let written: MessageStreamResult<()> = if seed.continuation {
        vault.write_txn_door(callback, |txn| -> MessageStreamResult<()> {
            admit_terminal(gate, txn)?;
            reply_assertions::judge_in_txn(lane.as_ref(), txn, assertions, &unread)?;
            // Judged: this generation keeps its seed's and its terminal's
            // set on its own receipt; the birth envelope stays (FIX 10258).
            receipt.reply_assertions =
                admitted_in_txn(&vault.store, txn, &[&seed.assertions, assertions])?;
            let base = admission::committed_text(vault, txn, seed)?.ok_or(Error::EntityNotFound)?;
            let text = format!("{base}{}", state.pending);
            admission::authorize(vault, txn, seed, &text)?;
            let was_final =
                storage::receipt(vault, txn, seed.message_id)?.is_none_or(|prior| prior.complete());
            #[cfg(feature = "sync")]
            crate::entity_doc::append_message_stream_in_txn(
                vault,
                txn,
                &seed.message_id,
                &state.pending,
                crate::write_envelope::WriteActor::new(seed.actor, seed.class()?),
                seed.occurred_at,
            )?;
            #[cfg(not(feature = "sync"))]
            if !state.pending.is_empty() {
                return Err(MessageStreamError::InvalidRequest(
                    "continuation requires entity documents (sync feature)",
                ));
            }
            receipt.bytes = text.len() as u64;
            storage::finish(vault, txn, seed, &receipt)?;
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
    } else {
        // A recovered stream's `pending` is its seed's checkpoint.
        let text = state.text();
        receipt.bytes = text.len() as u64;
        // The reply's assertions ride the turn its terminal witnesses, and
        // its metadata keeps them; the seed stays as it was (FIX 3416).
        let turn = reply_assertions::terminal_turn(seed, text, assertions)?;
        // A Retry's reads take their own snapshots, so they open before the
        // writer does.
        match seed
            .action
            .as_ref()
            .map(|action| memory.retry_lanes(action))
            .transpose()
        {
            Err(error) => {
                refused.set(true);
                Err(error.into())
            }
            Ok(lanes) => memory
                .witness_with_route_prepare_and_txn_effect(
                    &turn,
                    None,
                    callback,
                    || {},
                    |txn| {
                        admit_terminal(gate, txn)?;
                        // A Retry's reply names the reply it answers again,
                        // and the Retry is proven again, in the transaction
                        // that writes it: its TURN lands here, or its room
                        // regeneration permit admits its room row.
                        let retry = match admission::validate_regeneration(vault, txn, seed) {
                            Err(error) => {
                                Err(crate::memory::MemoryError::bad_request(error.to_string()))
                            }
                            Ok(()) => match (&seed.action, &lanes) {
                                (Some(action), Some((writer, requester))) => memory
                                    .prepare_action_retry_in_txn(
                                        txn,
                                        action,
                                        seed.turn,
                                        seed.occurred_at,
                                        writer,
                                        requester,
                                    ),
                                _ => Ok(None),
                            },
                        };
                        if retry.is_err() && seed.action.is_some() {
                            refused.set(true);
                        }
                        retry
                    },
                    |txn| -> MemoryResult<()> {
                        #[cfg(feature = "sync")]
                        crate::entity_doc::birth_message_stream_in_txn(
                            vault,
                            txn,
                            &seed.message_id,
                            crate::write_envelope::WriteActor::new(seed.actor, seed.class()?),
                            seed.occurred_at,
                        )?;
                        if let Some(source) = seed.regenerates {
                            // The kind's creation is this stream's alone (FIX
                            // 5972), its pair proven above in this transaction:
                            // the internal write lands it at the public put's
                            // weight, neutral VAD, no flags and clock.
                            let created_at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
                            vault
                                .batch_in()
                                .edge_with_value_fields(
                                    &seed.message_id,
                                    crate::edge::EdgeKind::Regenerates,
                                    &source,
                                    crate::batch::EdgeValueFields {
                                        weight: 1.0,
                                        created_at,
                                        vad: crate::affect::Vad::NEUTRAL,
                                        provenance: None,
                                    },
                                )
                                .apply(txn)?;
                        }
                        // The turn's set, seed and terminal, was admitted in
                        // this write: its receipt keeps it (FIX 10260).
                        receipt.reply_assertions =
                            admitted_in_txn(&vault.store, txn, &[&turn.assertions])?;
                        storage::finish(vault, txn, seed, &receipt)?;
                        Ok(())
                    },
                )
                .map(|_| ())
                .map_err(MessageStreamError::from),
        }
    };
    let written = reply_assertions::settle(&memory, &unread, written);
    if let Err(error) = written {
        let landed = {
            let txn = vault.store.env.read_txn()?;
            storage::receipt(vault, &txn, seed.message_id)?
                .filter(|done| done.generation == seed.generation)
        };
        if let Some(done) = landed {
            crate::gate::record_references::receipt_landed_prose(&memory, &unlinked_prose);
            return Ok(done);
        }
        return Err(error);
    }
    crate::gate::record_references::receipt_landed_prose(&memory, &unlinked_prose);
    Ok(receipt)
}
