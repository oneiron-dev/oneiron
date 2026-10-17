//! Terminal transitions and the host-driven quiet-stream pump.
use super::*;
use crate::FinishReason;
use crate::error::Error;
use crate::memory::MemoryResult;
use crate::store::Callback;

/// A pump attempts every due handle even if another actor has lost admission.
#[derive(Debug, Default)]
pub struct MessageStreamPump {
    pub finalized: Vec<MessageStreamReceipt>,
    pub refused: Vec<(EntityId, MessageStreamError)>,
}
/// A host's own condition on a terminal write, judged inside that write's
/// transaction (the credential a stream answers is still live, say).
type TerminalGate<'g> = Option<&'g dyn Fn(&heed::RwTxn<'_>) -> bool>;

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

impl Memory<'_> {
    pub fn finalize_stream(
        &self,
        handle: MessageStreamHandle,
    ) -> MessageStreamResult<MessageStreamReceipt> {
        let entry = self.stream_entry(handle)?;
        self.vault.finish_stream_entry(
            &entry,
            handle,
            (
                StreamFinality::Final,
                StreamFinalityReason::ExplicitFinalize,
            ),
            None,
            None,
        )
    }
    /// [`Self::finalize_stream`], committed only while `admit` holds inside
    /// the write transaction. A refusal commits nothing and leaves the stream
    /// open for the host to cancel.
    pub fn finalize_stream_if(
        &self,
        handle: MessageStreamHandle,
        admit: impl Fn(&heed::RwTxn<'_>) -> bool,
    ) -> MessageStreamResult<MessageStreamReceipt> {
        let entry = self.stream_entry(handle)?;
        self.vault.finish_stream_entry(
            &entry,
            handle,
            (
                StreamFinality::Final,
                StreamFinalityReason::ExplicitFinalize,
            ),
            None,
            Some(&admit),
        )
    }
    /// Ends a stream a model wrote, recording why the model stopped. A stop or
    /// a tool call finalizes it, committed only while `admit` holds inside the
    /// write transaction; a length cut, a filter or another stop leaves it
    /// partial under the same condition, so it reads incomplete; a cancelled
    /// terminal keeps its text and is recorded as cancelled.
    pub fn finalize_model_stream_if(
        &self,
        handle: MessageStreamHandle,
        finish_reason: FinishReason,
        admit: impl Fn(&heed::RwTxn<'_>) -> bool,
    ) -> MessageStreamResult<MessageStreamReceipt> {
        let entry = self.stream_entry(handle)?;
        let gated: TerminalGate<'_> = Some(&admit);
        let (outcome, gate) = match &finish_reason {
            FinishReason::Stop | FinishReason::ToolCalls => (
                (
                    StreamFinality::Final,
                    StreamFinalityReason::ExplicitFinalize,
                ),
                gated,
            ),
            FinishReason::Length | FinishReason::ContentFiltered | FinishReason::Other { .. } => (
                (
                    StreamFinality::Partial,
                    StreamFinalityReason::ExplicitFinalize,
                ),
                gated,
            ),
            FinishReason::Cancelled => (
                (
                    StreamFinality::Cancelled,
                    StreamFinalityReason::ExternalSignal,
                ),
                None,
            ),
        };
        self.vault
            .finish_stream_entry(&entry, handle, outcome, Some(finish_reason), gate)
    }
    pub fn cancel_stream(
        &self,
        handle: MessageStreamHandle,
        reason: StreamCancelReason,
    ) -> MessageStreamResult<MessageStreamReceipt> {
        let reason = match reason {
            StreamCancelReason::UserInterrupted => StreamFinalityReason::UserInterrupted,
            StreamCancelReason::AgentAborted => StreamFinalityReason::AgentAborted,
            StreamCancelReason::ExternalSignal => StreamFinalityReason::ExternalSignal,
            StreamCancelReason::Custom(text) if text.len() <= 1024 => {
                StreamFinalityReason::Custom(text)
            }
            StreamCancelReason::Custom(_) => {
                return Err(MessageStreamError::InvalidRequest(
                    "cancel reason exceeds 1024 bytes",
                ));
            }
        };
        let entry = self.stream_entry(handle)?;
        self.vault.finish_stream_entry(
            &entry,
            handle,
            (StreamFinality::Cancelled, reason),
            None,
            None,
        )
    }
    /// Drops a Retry's stream that never started (FIX 3152): one whose run
    /// its budget refused before any text. Its seed goes and nothing lands,
    /// no TURN, MESSAGE or receipt, as for a Retry never admitted. Any other
    /// stream ends by its terminal.
    pub fn abandon_unstarted_retry(&self, handle: MessageStreamHandle) -> MessageStreamResult<()> {
        let entry = self.stream_entry(handle)?;
        let mut state = lock(&entry)?;
        state.check(handle)?;
        if state.seed.action.is_none()
            || state.seed.continuation
            || !state.base.is_empty()
            || !state.pending.is_empty()
            || !state.raw.is_empty()
        {
            return Err(MessageStreamError::InvalidRequest(
                "only an unstarted Retry may be abandoned",
            ));
        }
        self.vault
            .try_with_write_txn_grouped(|txn| -> MessageStreamResult<()> {
                let row = storage::ACTIVE
                    .get(&self.vault.store, txn, &handle.message)?
                    .ok_or(MessageStreamError::StreamNotFound)?;
                if row.generation != handle.generation || !row.saved.is_empty() {
                    return Err(MessageStreamError::StreamNotFound);
                }
                storage::ACTIVE.delete(&self.vault.store, txn, &handle.message)?;
                Ok(())
            })?;
        state.terminal = true;
        self.vault.message_streams.remove(handle)
    }
}
impl Vault {
    fn finish_stream_entry(
        &self,
        entry: &Arc<Mutex<State>>,
        handle: MessageStreamHandle,
        outcome: (StreamFinality, StreamFinalityReason),
        finish_reason: Option<FinishReason>,
        gate: TerminalGate<'_>,
    ) -> MessageStreamResult<MessageStreamReceipt> {
        let mut state = lock(entry)?;
        state.check(handle)?;
        self.close_withheld(&mut state)?;
        let receipt = commit_terminal(self, &mut state, outcome, finish_reason, false, gate)?;
        // Storage success is authoritative. No output is removed on an error.
        state.terminal = true;
        #[cfg(feature = "sync")]
        self.message_streams.presence.clear(&state.seed);
        self.message_streams.remove(handle)?;
        Ok(receipt)
    }
    /// Host timer door. Call about once per second even while no tokens arrive.
    /// The sync connection calls this on its own independent housekeeping tick.
    pub fn pump_message_streams(&self) -> MessageStreamResult<MessageStreamPump> {
        self.pump_message_streams_at(now_ms())
    }
    /// Deterministic clock door for runtimes with their own wall-clock service.
    /// Passing an earlier time never expires a handle early.
    pub fn pump_message_streams_at(&self, now: u64) -> MessageStreamResult<MessageStreamPump> {
        let entries: Vec<_> = lock(&self.message_streams.entries)?
            .values()
            .cloned()
            .collect();
        let mut report = MessageStreamPump::default();
        for entry in entries {
            // Keep this entry locked from the deadline decision through commit:
            // an append cannot make the decision stale while we wait for LMDB.
            let mut state = lock(&entry)?;
            if state.terminal
                || now.saturating_sub(state.last_op_at_ms) < state.seed.idle_timeout_ms
            {
                continue;
            }
            let handle = state.handle();
            let reason = if state.seed.idle_timeout_ms == DEFAULT_MESSAGE_STREAM_IDLE_MS {
                StreamFinalityReason::IdleTimeout30s
            } else {
                StreamFinalityReason::IdleTimeout {
                    timeout_ms: state.seed.idle_timeout_ms,
                }
            };
            match self.close_withheld(&mut state).and_then(|()| {
                commit_terminal(
                    self,
                    &mut state,
                    (StreamFinality::Partial, reason),
                    None,
                    false,
                    None,
                )
            }) {
                Ok(receipt) => {
                    state.terminal = true;
                    #[cfg(feature = "sync")]
                    self.message_streams.presence.clear(&state.seed);
                    self.message_streams.remove(handle)?;
                    report.finalized.push(receipt);
                }
                Err(error) => report.refused.push((handle.message, error)),
            }
        }
        Ok(report)
    }
    /// A stream whose admitted text withholds a secret it may still have been
    /// writing takes it into custody whole as it ends (OF-067). Its seed
    /// checkpoints the closed text first, so the seed and the final MESSAGE
    /// hold the same handles. A stream whose seed the lift sweep stored again
    /// admits its text and axes again here too, in its own write.
    fn close_withheld(&self, state: &mut State) -> MessageStreamResult<()> {
        if !state.withheld && !state.relift {
            return Ok(());
        }
        let mut lifted = state.lifted.clone();
        let (pending, metadata) =
            self.try_with_write_txn_grouped(|txn| -> MessageStreamResult<_> {
                let (pending, _) = crate::batch::secret_scan::admit_stream_text_in_txn(
                    self,
                    txn,
                    state.seed.message_id,
                    admission::CONTENT,
                    &state.raw,
                    false,
                    &mut lifted,
                )?;
                let mut row = state.checkpoint(pending.clone());
                if state.relift {
                    admission::admit_axes_in_txn(self, txn, &mut row, &mut lifted)?;
                }
                admission::authorize(self, txn, &row, &format!("{}{}", state.base, pending))?;
                storage::checkpoint(self, txn, &row)?;
                Ok((pending, row.metadata))
            })?;
        state.pending = pending;
        state.lifted = lifted;
        state.withheld = false;
        if std::mem::take(&mut state.relift) {
            state.seed.metadata = metadata;
        }
        Ok(())
    }
    /// Open-time recovery after all read-only compatibility gates passed.
    /// Surviving seeds prove an interrupted process, even if it restarted inside
    /// the quiet interval. Each MESSAGE is born, or its continuation appended,
    /// with exactly the text its seed checkpointed, and left partial; nothing
    /// past the checkpoint is invented, and saved text is never dropped.
    /// A policy refusal aborts open and retains the seed for explicit repair.
    pub(crate) fn recover_message_streams(&self) -> MessageStreamResult<()> {
        // However many seeds survived, each is retired: none is refused for
        // the count. They are read a page at a time, so the decode holds one
        // page in memory, never the whole table.
        let mut after: Option<EntityId> = None;
        loop {
            let seeds = {
                let txn = self.store.env.read_txn()?;
                let start = after
                    .as_ref()
                    .map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
                let mut seeds = Vec::new();
                for row in storage::ACTIVE.iter_range(
                    &self.store,
                    &txn,
                    start,
                    std::ops::Bound::Unbounded,
                )? {
                    let (key, seed) = row?;
                    if key != seed.message_id {
                        return Err(Error::CorruptedIndex("stream seed key").into());
                    }
                    seed.mode.validate()?;
                    if seed.idle_timeout_ms == 0 {
                        return Err(Error::CorruptedIndex("stream idle threshold").into());
                    }
                    seeds.push(seed);
                    if seeds.len() == RECOVERY_PAGE {
                        break;
                    }
                }
                seeds
            };
            let Some(last) = seeds.last().map(|seed| seed.message_id) else {
                return Ok(());
            };
            for mut seed in seeds {
                // A seed holds its text as admitted; no raw copy outlives
                // the process that wrote it.
                let pending = std::mem::take(&mut seed.saved);
                let mut state = State {
                    last_op_at_ms: seed.created_at_ms,
                    raw: pending.clone(),
                    pending,
                    lifted: Lifted::default(),
                    withheld: false,
                    relift: false,
                    seed,
                    base: String::new(),
                    sequence: 0,
                    emitted_chars: 0,
                    dirty: false,
                    terminal: false,
                    _turn: None,
                };
                // A Retry that no longer stands is retired, landing
                // nothing (FIX 3152); any other refusal aborts open.
                if let Err(error) = commit_terminal(
                    self,
                    &mut state,
                    (
                        StreamFinality::Partial,
                        StreamFinalityReason::ProcessCrashRecovery,
                    ),
                    None,
                    true,
                    None,
                ) && !state.terminal
                {
                    return Err(error);
                }
            }
            after = Some(last);
        }
    }
}
/// Seeds open-time recovery reads and retires at a time.
const RECOVERY_PAGE: usize = 256;
/// A stream's terminal write. A Retry's (FIX 3152, 3149) proves the Retry
/// again in that write, under the agent's and the requester's reads opened
/// before it, and lands its TURN, or its room regeneration permit, with its
/// MESSAGE; a Retry that no longer stands lands nothing and is retired
/// ([`retire_refused_retry`]), so `state` reads terminal.
fn commit_terminal(
    vault: &Vault,
    state: &mut State,
    (finality, reason): (StreamFinality, StreamFinalityReason),
    finish_reason: Option<FinishReason>,
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
fn terminal_write(
    vault: &Vault,
    state: &State,
    (finality, reason): (StreamFinality, StreamFinalityReason),
    finish_reason: Option<FinishReason>,
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
    };
    let memory = vault.memory(seed.actor, seed.class()?);
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
    let written: MessageStreamResult<()> = if seed.continuation {
        vault.write_txn_door(callback, |txn| -> MessageStreamResult<()> {
            admit_terminal(gate, txn)?;
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
                    &seed.turn(text),
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
                            vault
                                .batch_in()
                                .edge(
                                    &seed.message_id,
                                    crate::edge::EdgeKind::Regenerates,
                                    &source,
                                    1.0,
                                )
                                .apply(txn)?;
                        }
                        storage::finish(vault, txn, seed, &receipt)?;
                        Ok(())
                    },
                )
                .map(|_| ())
                .map_err(MessageStreamError::from),
        }
    };
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
