//! Terminal transitions and the host-driven quiet-stream pump.
use super::*;
use crate::FinishReason;
use crate::error::Error;
use crate::memory::{MemoryResult, WitnessAssertions};
use crate::store::Callback;

mod terminal;

use self::terminal::*;

/// A pump attempts every due handle even if another actor has lost admission.
#[derive(Debug, Default)]
pub struct MessageStreamPump {
    pub finalized: Vec<MessageStreamReceipt>,
    pub refused: Vec<(EntityId, MessageStreamError)>,
}
/// A host's own condition on a terminal write, judged inside that write's
/// transaction (the credential a stream answers is still live, say).
type TerminalGate<'g> = Option<&'g dyn Fn(&heed::RwTxn<'_>) -> bool>;

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
            &WitnessAssertions::default(),
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
            &WitnessAssertions::default(),
            Some(&admit),
        )
    }
    /// Ends a stream a model wrote, recording why the model stopped. A stop or
    /// a tool call finalizes it, committed only while `admit` holds inside the
    /// write transaction; a length cut, a filter or another stop leaves it
    /// partial under the same condition, so it reads incomplete; a cancelled
    /// terminal keeps its text and is recorded as cancelled.
    ///
    /// `assertions` are the typed records the reply cited or created, from
    /// its host's own evidence (OF-063, FIX 3416). Each is read through the
    /// writer's own lane, opened before its writer, and judged in the
    /// terminal's write: one it cannot read refuses the terminal, which
    /// commits nothing and leaves the stream open. The generation's receipt
    /// keeps the set admitted, its seed's with it, in that write (FIX
    /// 10258); a new MESSAGE also copies it into its object metadata under
    /// `reply_assertions` unless its caller put that key there, and a
    /// continuation's MESSAGE keeps its birth envelope.
    pub fn finalize_model_stream_if(
        &self,
        handle: MessageStreamHandle,
        finish_reason: FinishReason,
        assertions: &WitnessAssertions,
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
            // A terminal that disagreed with what the stream showed keeps
            // the shown text, incomplete (FIX 8617).
            FinishReason::Length
            | FinishReason::ContentFiltered
            | FinishReason::Other { .. }
            | FinishReason::Incomplete { .. } => (
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
        self.vault.finish_stream_entry(
            &entry,
            handle,
            outcome,
            Some(finish_reason),
            assertions,
            gate,
        )
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
            &WitnessAssertions::default(),
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
        assertions: &WitnessAssertions,
        gate: TerminalGate<'_>,
    ) -> MessageStreamResult<MessageStreamReceipt> {
        let mut state = lock(entry)?;
        state.check(handle)?;
        self.close_withheld(&mut state)?;
        let receipt = commit_terminal(
            self,
            &mut state,
            outcome,
            finish_reason,
            assertions,
            false,
            gate,
        )?;
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
                    &WitnessAssertions::default(),
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
                admission::authorize(
                    self,
                    txn,
                    &row,
                    &format!("{}{}", state.base, pending),
                    !pending.is_empty(),
                )?;
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
    /// A refused replay (a revoked grant, an actor that no longer proves, a
    /// policy that moved) is that stream's alone (FIX 9974): its seed stays
    /// for explicit repair, its typed refusal is answered and logged, and the
    /// open goes on for every other stream. A storage failure fails the open.
    pub(crate) fn recover_message_streams(
        &self,
    ) -> MessageStreamResult<Vec<StreamRecoveryRefusal>> {
        let mut refused = Vec::new();
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
                return Ok(refused);
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
                // nothing (FIX 3152); any other refusal of the stream's own
                // is isolated to it (FIX 9974).
                if let Err(error) = commit_terminal(
                    self,
                    &mut state,
                    (
                        StreamFinality::Partial,
                        StreamFinalityReason::ProcessCrashRecovery,
                    ),
                    None,
                    &WitnessAssertions::default(),
                    true,
                    None,
                ) && !state.terminal
                {
                    if !stream_refusal(&error) {
                        return Err(error);
                    }
                    let refusal = StreamRecoveryRefusal {
                        message_id: state.seed.message_id,
                        conversation: state.seed.conversation,
                        actor: state.seed.actor,
                        error,
                    };
                    tracing::warn!(
                        stream_message = %refusal.message_id.to_hex(),
                        conversation = %refusal.conversation.to_hex(),
                        actor = %refusal.actor.to_hex(),
                        error = %refusal.error,
                        "a surviving stream seed's recovery was refused; its seed stays for repair"
                    );
                    refused.push(refusal);
                }
            }
            after = Some(last);
        }
    }
}

/// One surviving stream seed open-time recovery could not replay (FIX
/// 9974): the MESSAGE it names, where and by whom it was streamed, and the
/// refusal its write met. Its seed stays for explicit repair.
#[derive(Debug)]
pub(crate) struct StreamRecoveryRefusal {
    pub(crate) message_id: EntityId,
    pub(crate) conversation: EntityId,
    pub(crate) actor: EntityId,
    pub(crate) error: MessageStreamError,
}

/// Whether `error`, a seed's refused replay, is that stream's own refusal,
/// which recovery isolates (FIX 9974). A storage failure, a corrupt index or
/// a poisoned lock is the vault's, and fails the open as before.
fn stream_refusal(error: &MessageStreamError) -> bool {
    match error {
        MessageStreamError::Poisoned => false,
        MessageStreamError::Engine(error) => !matches!(
            error,
            Error::Storage(_) | Error::Io(_) | Error::MapFull | Error::CorruptedIndex(_)
        ),
        MessageStreamError::Memory(error) => error.code != crate::memory::MEMORY_CODE_INTERNAL,
        _ => true,
    }
}
/// Seeds open-time recovery reads and retires at a time.
const RECOVERY_PAGE: usize = 256;
