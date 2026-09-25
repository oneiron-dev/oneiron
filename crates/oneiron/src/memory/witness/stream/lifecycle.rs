//! Terminal transitions and the host-driven quiet-stream pump.
use super::*;
use crate::error::Error;
use crate::memory::MemoryResult;

/// A pump attempts every due handle even if another actor has lost admission.
#[derive(Debug, Default)]
pub struct MessageStreamPump {
    pub finalized: Vec<MessageStreamReceipt>,
    pub refused: Vec<(EntityId, MessageStreamError)>,
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
            StreamFinality::Final,
            StreamFinalityReason::ExplicitFinalize,
            false,
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
        self.vault
            .finish_stream_entry(&entry, handle, StreamFinality::Cancelled, reason, false)
    }
}
impl Vault {
    fn finish_stream_entry(
        &self,
        entry: &Arc<Mutex<State>>,
        handle: MessageStreamHandle,
        finality: StreamFinality,
        reason: StreamFinalityReason,
        recovered: bool,
    ) -> MessageStreamResult<MessageStreamReceipt> {
        let mut state = lock(entry)?;
        state.check(handle)?;
        let receipt = commit_terminal(self, &state, finality, reason, recovered)?;
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
            match commit_terminal(
                self,
                &state,
                StreamFinality::Partial,
                if state.seed.idle_timeout_ms == DEFAULT_MESSAGE_STREAM_IDLE_MS {
                    StreamFinalityReason::IdleTimeout30s
                } else {
                    StreamFinalityReason::IdleTimeout {
                        timeout_ms: state.seed.idle_timeout_ms,
                    }
                },
                false,
            ) {
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
    /// Open-time recovery after all read-only compatibility gates passed.
    /// Surviving seeds prove an interrupted process, even if it restarted inside
    /// the quiet interval. No durable token heartbeat or text copy is invented.
    /// A policy refusal aborts open and retains the seed for explicit repair.
    pub(crate) fn recover_message_streams(&self) -> MessageStreamResult<()> {
        let seeds = {
            let txn = self.store.env.read_txn()?;
            let mut seeds = Vec::new();
            for row in self.store.vault_meta.prefix_iter(&txn, storage::ACTIVE)? {
                if seeds.len() >= MAX_MESSAGE_STREAMS {
                    return Err(MessageStreamError::TooManyStreams);
                }
                let (key, bytes) = row?;
                let seed: Seed = storage::decode(&bytes)?;
                if key.as_ref() != storage::key(storage::ACTIVE, seed.message_id).as_slice() {
                    return Err(Error::CorruptedIndex("stream seed key").into());
                }
                seed.mode.validate()?;
                if seed.idle_timeout_ms == 0 {
                    return Err(Error::CorruptedIndex("stream idle threshold").into());
                }
                seeds.push(seed);
            }
            seeds
        };
        for seed in seeds {
            let state = State {
                last_op_at_ms: seed.created_at_ms,
                seed,
                base: String::new(),
                pending: String::new(),
                sequence: 0,
                emitted_chars: 0,
                dirty: false,
                terminal: false,
            };
            commit_terminal(
                self,
                &state,
                StreamFinality::Partial,
                StreamFinalityReason::ProcessCrashRecovery,
                true,
            )?;
        }
        Ok(())
    }
}
fn commit_terminal(
    vault: &Vault,
    state: &State,
    finality: StreamFinality,
    reason: StreamFinalityReason,
    recovered: bool,
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
        bytes: state.text().len() as u64,
        recovered,
        ephemeral_text_lost: recovered,
        receipt_ref: format!(
            "stream:v1:{}:{}",
            seed.message_id.to_hex(),
            seed.generation.to_hex()
        ),
    };
    let memory = vault.memory(seed.actor, seed.class()?);
    let written: MessageStreamResult<()> = if seed.continuation {
        vault.try_with_write_txn(|txn| -> MessageStreamResult<()> {
            let base = admission::committed_text(vault, txn, seed)?.ok_or(Error::EntityNotFound)?;
            let text = format!("{base}{}", state.pending);
            admission::authorize(vault, txn, seed, &text)?;
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
            Ok(())
        })
    } else {
        let text = if recovered {
            String::new()
        } else {
            state.text()
        };
        receipt.bytes = text.len() as u64;
        memory
            .witness_with_route_and_txn_effect(
                &seed.turn(text),
                None,
                || {},
                |txn| -> MemoryResult<()> {
                    #[cfg(feature = "sync")]
                    crate::entity_doc::birth_message_stream_in_txn(
                        vault,
                        txn,
                        &seed.message_id,
                        crate::write_envelope::WriteActor::new(seed.actor, seed.class()?),
                        seed.occurred_at,
                    )?;
                    storage::finish(vault, txn, seed, &receipt)?;
                    Ok(())
                },
            )
            .map(|_| ())
            .map_err(MessageStreamError::from)
    };
    if let Err(error) = written {
        let txn = vault.store.env.read_txn()?;
        if let Some(done) = storage::receipt(vault, &txn, seed.message_id)?
            && done.generation == seed.generation
        {
            return Ok(done);
        }
        return Err(error);
    }
    Ok(receipt)
}
