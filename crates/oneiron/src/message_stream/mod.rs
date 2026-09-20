//! Memory-only MESSAGE streaming with atomic witnessed finality receipts.
mod policy;
mod receipts;
mod types;
pub(crate) use receipts::write_in_txn as write_receipt_in_txn;
#[cfg(test)]
mod tests;
use crate::error::{Error, RecordError, Result};
use crate::memory::WitnessTurn;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
pub use types::*;

/// Preserves both typed engine refusals and actor-bound facade admission errors.
#[derive(Debug, thiserror::Error)]
pub enum MessageStreamError {
    #[error(transparent)]
    Engine(#[from] Error),
    #[error(transparent)]
    Admission(#[from] crate::memory::MemoryError),
}
pub type MessageStreamResult<T> = std::result::Result<T, MessageStreamError>;

const MAX_ACTIVE_STREAMS: usize = 128;
const MAX_STREAM_BYTES: usize = 8 * 1024 * 1024;
pub(crate) struct StreamState {
    handle: MessageStreamHandle,
    actor: WriteActor,
    turn: WitnessTurn,
    serialized_bytes: usize,
    last_op: Instant,
    last_flush: Instant,
    idle_timeout: Duration,
}
fn stream_limit() -> Error {
    Error::Record(RecordError::StreamLimit {
        resource: "buffered bytes",
        limit: MAX_STREAM_BYTES,
    })
}

/// Count the complete JSON representation without retaining a second copy.
/// Stop at the cap, including escaped strings and metadata keys/values.
fn serialized_size(value: &(impl serde::Serialize + ?Sized)) -> Result<usize> {
    struct Budget(usize);
    impl std::io::Write for Budget {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            if self.0 > MAX_STREAM_BYTES {
                return Err(std::io::Error::other("stream byte limit"));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut budget = Budget(0);
    serde_json::to_writer(&mut budget, value).map_err(|_| stream_limit())?;
    Ok(budget.0)
}

fn inactive(id: EntityId) -> Error {
    Error::Record(RecordError::StreamNotActive { message: id })
}
fn locked() -> Error {
    Error::InvariantViolation("message stream mutex poisoned")
}
fn frame(state: &mut StreamState) -> Option<MessageStreamFrame> {
    let MessageWriteMode::Streamed {
        sync_visibility, ..
    } = state.handle.mode
    else {
        return None;
    };
    state.last_flush = Instant::now();
    Some(MessageStreamFrame {
        message: state.handle.message,
        originator: state.actor.entity_ref(),
        text: state.turn.messages[0].content.clone(),
        visibility: sync_visibility,
    })
}
fn state<'a>(
    streams: &'a mut BTreeMap<EntityId, StreamState>,
    handle: &MessageStreamHandle,
) -> Result<&'a mut StreamState> {
    streams
        .get_mut(&handle.message)
        .filter(|s| s.handle.token == handle.token)
        .ok_or_else(|| inactive(handle.message))
}
impl Vault {
    /// Starts an empty one-message witness template. No MESSAGE or partial
    /// bytes are written until finalize/cancel. The regular witness gate runs
    /// at finalization against the then-current policy and actor authority.
    pub fn begin_message_stream(
        &self,
        message: EntityId,
        mut turn: WitnessTurn,
        actor: WriteActor,
        mode: Option<MessageWriteMode>,
    ) -> MessageStreamResult<MessageStreamHandle> {
        if turn.messages.len() != 1 || !turn.messages[0].content.is_empty() {
            return Err(
                Error::InvalidConfig("stream requires one empty witness message".into()).into(),
            );
        }
        if let Some(id) = &turn.messages[0].id
            && EntityId::from_hex(id)? != message
        {
            return Err(Error::InvalidConfig("stream message id mismatch".into()).into());
        }
        turn.messages[0].id = Some(message.to_hex());
        if turn.turn_ref.is_none() {
            turn.turn_ref = Some(self.new_entity_id()?.to_hex());
        }
        let serialized_bytes = serialized_size(&turn)?;
        let policy = self.message_stream_policy()?;
        let mode = mode
            .or_else(|| {
                policy
                    .agent_overrides
                    .get(&actor.entity_ref().to_hex())
                    .copied()
            })
            .unwrap_or(policy.default_mode);
        let validation = MessageStreamPolicy {
            default_mode: mode,
            ..Default::default()
        };
        policy::validate_policy(&validation)?;
        let mut streams = self.message_streams.lock().map_err(|_| locked())?;
        if streams.contains_key(&message) {
            return Err(Error::Record(RecordError::StreamAlreadyActive { message }).into());
        }
        if streams.len() >= MAX_ACTIVE_STREAMS {
            return Err(Error::Record(RecordError::StreamLimit {
                resource: "active streams",
                limit: MAX_ACTIVE_STREAMS,
            })
            .into());
        }
        self.memory(actor.entity_ref(), actor.actor_class())
            .with_verified_actor_write_txn(|txn| {
                if self.get_entity_type_in_txn(txn, &message)?.is_some()
                    || self.local_hard_delete_marker_exists_in_txn(txn, &message)?
                {
                    return Err(Error::InvalidConfig(
                        "stream id already exists or was deleted".into(),
                    )
                    .into());
                }
                Ok(())
            })?;
        let handle = MessageStreamHandle {
            message,
            token: self.new_entity_id()?,
            mode,
        };
        streams.insert(
            message,
            StreamState {
                handle: handle.clone(),
                actor,
                turn,
                serialized_bytes,
                last_op: Instant::now(),
                last_flush: Instant::now(),
                idle_timeout: Duration::from_millis(policy.idle_timeout_ms),
            },
        );
        Ok(handle)
    }
    /// Appends only in memory. A returned frame is handed to the host's
    /// ephemeral presence transport; it must never be logged as a sync op.
    pub fn append_to_stream(
        &self,
        handle: &MessageStreamHandle,
        delta: &str,
    ) -> Result<Option<MessageStreamFrame>> {
        let mut streams = self.message_streams.lock().map_err(|_| locked())?;
        let state = state(&mut streams, handle)?;
        // Each delta is a JSON string; its surrounding quotes already exist
        // in the empty template's content field.
        let bytes = serialized_size(delta)?.saturating_sub(2);
        let total = state.serialized_bytes.saturating_add(bytes);
        if total > MAX_STREAM_BYTES {
            return Err(stream_limit());
        }
        state.turn.messages[0].content.push_str(delta);
        state.serialized_bytes = total;
        state.last_op = Instant::now();
        let flush = match state.handle.mode {
            MessageWriteMode::Atomic => false,
            MessageWriteMode::Streamed { cadence, .. } => match cadence {
                StreamCadence::PerToken => true,
                StreamCadence::PerSentence => delta.ends_with(['.', '!', '?', '\n']),
                StreamCadence::PerWindow { milliseconds } => {
                    state.last_flush.elapsed() >= Duration::from_millis(u64::from(milliseconds))
                }
            },
        };
        Ok(if flush { frame(state) } else { None })
    }
    pub fn flush_stream(&self, handle: &MessageStreamHandle) -> Result<Option<MessageStreamFrame>> {
        let mut streams = self.message_streams.lock().map_err(|_| locked())?;
        Ok(frame(state(&mut streams, handle)?))
    }
    pub fn finalize_stream(
        &self,
        handle: &MessageStreamHandle,
    ) -> MessageStreamResult<MessageFinalityReceipt> {
        self.finish_stream(handle, MessageFinality::Final, None, None)
    }
    pub fn cancel_stream(
        &self,
        handle: &MessageStreamHandle,
        reason: StreamCancelReason,
    ) -> MessageStreamResult<MessageFinalityReceipt> {
        if matches!(&reason,StreamCancelReason::Custom(s) if s.trim().is_empty() || s.len()>4096) {
            return Err(Error::InvalidConfig("invalid stream cancellation reason".into()).into());
        }
        self.finish_stream(handle, MessageFinality::Cancelled, Some(reason), None)
    }
    fn finish_stream(
        &self,
        handle: &MessageStreamHandle,
        finality: MessageFinality,
        reason: Option<StreamCancelReason>,
        finality_reason: Option<String>,
    ) -> MessageStreamResult<MessageFinalityReceipt> {
        let mut streams = self.message_streams.lock().map_err(|_| locked())?;
        self.finish_locked(&mut streams, handle, finality, reason, finality_reason)
    }
    fn finish_locked(
        &self,
        streams: &mut BTreeMap<EntityId, StreamState>,
        handle: &MessageStreamHandle,
        finality: MessageFinality,
        reason: Option<StreamCancelReason>,
        finality_reason: Option<String>,
    ) -> MessageStreamResult<MessageFinalityReceipt> {
        let state = state(streams, handle)?;
        let mut receipt = MessageFinalityReceipt {
            receipt_id: handle.token.to_hex(),
            message_id: handle.message.to_hex(),
            actor_id: state.actor.entity_ref().to_hex(),
            finality,
            reason,
            finality_reason,
            recorded_at: 0,
            text_blake3: blake3::hash(state.turn.messages[0].content.as_bytes())
                .to_hex()
                .to_string(),
        };
        // The witness transaction writes both the complete row and this receipt.
        // On refusal the buffer remains intact, so the obligation can be retried.
        self.memory(state.actor.entity_ref(), state.actor.actor_class())
            .witness_stream_finality(&state.turn, &mut receipt)?;
        streams.remove(&handle.message);
        Ok(receipt)
    }
    /// Atomic convenience path uses exactly the same gate and receipt program.
    pub fn commit_message(
        &self,
        message: EntityId,
        content: &str,
        turn: WitnessTurn,
        actor: WriteActor,
    ) -> MessageStreamResult<MessageFinalityReceipt> {
        if content.len() > MAX_STREAM_BYTES {
            return Err(Error::Record(RecordError::StreamLimit {
                resource: "text bytes",
                limit: MAX_STREAM_BYTES,
            })
            .into());
        }
        let handle =
            self.begin_message_stream(message, turn, actor, Some(MessageWriteMode::Atomic))?;
        let result = self
            .append_to_stream(&handle, content)
            .map_err(MessageStreamError::from)
            .and_then(|_| self.finalize_stream(&handle));
        if result.is_err() {
            self.message_streams
                .lock()
                .map_err(|_| locked())?
                .remove(&handle.message);
        }
        result
    }
    /// Host-driven idle sweep. No process-global timer or background thread.
    /// Every due stream has an outcome, including refusals. Successful receipts
    /// remain visible when another stream fails; refused buffers stay retryable.
    pub fn finalize_idle_message_streams(
        &self,
    ) -> MessageStreamResult<Vec<IdleMessageStreamOutcome>> {
        let mut streams = self.message_streams.lock().map_err(|_| locked())?;
        let due: Vec<_> = streams
            .values()
            .filter(|s| s.last_op.elapsed() >= s.idle_timeout)
            .map(|s| s.handle.clone())
            .collect();
        let mut outcomes = Vec::with_capacity(due.len());
        for handle in due {
            let result = self.finish_locked(
                &mut streams,
                &handle,
                MessageFinality::Partial,
                None,
                Some("idle_timeout".into()),
            );
            outcomes.push(IdleMessageStreamOutcome { handle, result });
        }
        Ok(outcomes)
    }
}
