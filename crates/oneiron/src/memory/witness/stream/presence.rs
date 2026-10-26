//! Native EphemeralStore publication. Frames use the existing TAG_EPHEMERAL.
//! A host's relay takes each all-devices frame with its scope (FIX 9537).
use super::*;
use crate::sync::{
    EphemeralStore, LoroValue, MessagePresenceScope, ScopedPresenceFrame, transport,
};
use tokio::sync::broadcast;
const FRAME_BUDGET: usize = 64 * 1024;
/// Frames the lossy channel buffers for a socket that has not read them.
const PRESENCE_FRAMES: usize = 256;
/// One partial whose frame fits the budget, ready to publish.
pub(super) struct PresencePartial {
    key: String,
    value: LoroValue,
    visibility: StreamSyncVisibility,
    scope: MessagePresenceScope,
}
/// The socket consumes this lossy bounded channel directly, never SyncQueue.
pub(crate) struct StreamPresence {
    pub(crate) store: EphemeralStore,
    sender: broadcast::Sender<Vec<u8>>,
    /// The same frames with their scope, for a host's relay: lossy and
    /// bounded alike.
    scoped: broadcast::Sender<ScopedPresenceFrame>,
    emission: Mutex<()>,
}
impl Default for StreamPresence {
    fn default() -> Self {
        let (sender, _) = broadcast::channel(PRESENCE_FRAMES);
        let (scoped, _) = broadcast::channel(PRESENCE_FRAMES);
        Self {
            store: EphemeralStore::new(DEFAULT_MESSAGE_STREAM_IDLE_MS as i64),
            sender,
            scoped,
            emission: Mutex::new(()),
        }
    }
}
/// Whose message `seed`'s partials are: its conversation and generation.
fn scope(seed: &Seed, cleared: bool) -> MessagePresenceScope {
    MessagePresenceScope {
        message: seed.message_id,
        conversation: seed.conversation,
        generation: seed.generation,
        cleared,
    }
}
impl StreamPresence {
    pub(crate) fn subscribe_frames(&self) -> broadcast::Receiver<Vec<u8>> {
        self.sender.subscribe()
    }
    /// Builds `text`'s partial and preflights it on a scratch native store,
    /// so a refusal comes before the delta is checkpointed or accepted and
    /// leaves no local presence mutation. `None` in atomic mode. Manual
    /// buffering can exceed the cap; flush then refuses but finalize still
    /// commits every buffered byte.
    pub(super) fn prepare(
        seed: &Seed,
        text: &str,
        seq: u64,
    ) -> MessageStreamResult<Option<PresencePartial>> {
        let MessageWriteMode::Streamed { visibility, .. } = seed.mode else {
            return Ok(None);
        };
        let key = format!("msg:{}", seed.message_id.to_hex());
        let seq = i64::try_from(seq)
            .map_err(|_| MessageStreamError::InvalidRequest("presence sequence overflow"))?;
        let value = LoroValue::Map(
            vec![
                ("schema_version".to_owned(), LoroValue::I64(1)),
                (
                    "message_id".to_owned(),
                    LoroValue::String(seed.message_id.to_hex().into()),
                ),
                (
                    "generation".to_owned(),
                    LoroValue::String(seed.generation.to_hex().into()),
                ),
                ("seq".to_owned(), LoroValue::I64(seq)),
                ("text".to_owned(), LoroValue::String(text.into())),
            ]
            .into(),
        );
        let scratch = EphemeralStore::new(DEFAULT_MESSAGE_STREAM_IDLE_MS as i64);
        scratch.set(&key, value.clone());
        if scratch.encode(&key).len().saturating_add(1) > FRAME_BUDGET {
            return Err(MessageStreamError::PresenceFrameTooLarge);
        }
        Ok(Some(PresencePartial {
            key,
            value,
            visibility,
            scope: scope(seed, false),
        }))
    }
    /// Publishes a prepared partial: text its stream has already saved.
    pub(super) fn publish(&self, partial: PresencePartial) -> MessageStreamResult<()> {
        let PresencePartial {
            key,
            value,
            visibility,
            scope,
        } = partial;
        let _emission = lock(&self.emission)?;
        self.store.remove_outdated();
        self.store.set(&key, value);
        if visibility == StreamSyncVisibility::AllDevices {
            let frame = transport::encode_ephemeral(&self.store.encode(&key))
                .into_result()
                .map_err(|_| MessageStreamError::PresenceFrameTooLarge)?;
            // No receiver means disconnected. Presence is live-only; never persist
            // it for reconnect. The next append/flush publishes full text again.
            let _ = self.scoped.send(ScopedPresenceFrame {
                frame: frame.clone(),
                scope,
            });
            let _ = self.sender.send(frame);
        }
        Ok(())
    }
    pub(super) fn clear(&self, seed: &Seed) {
        let MessageWriteMode::Streamed { visibility, .. } = seed.mode else {
            return;
        };
        // Poison cannot make a committed durable transition report failure.
        let _emission = self
            .emission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = format!("msg:{}", seed.message_id.to_hex());
        self.store.delete(&key);
        if visibility == StreamSyncVisibility::AllDevices
            && let Ok(frame) = transport::encode_ephemeral(&self.store.encode(&key)).into_result()
        {
            let _ = self.scoped.send(ScopedPresenceFrame {
                frame: frame.clone(),
                scope: scope(seed, true),
            });
            let _ = self.sender.send(frame);
        }
        self.store.remove_outdated();
    }
}

impl Vault {
    /// Subscribes to local all-devices partials, each with the conversation
    /// and generation its stream's seed names (FIX 9537), so a host relays
    /// one only where that conversation may go. The bounded stream is
    /// live-only: lagged or disconnected frames are not replayed through the
    /// offline queue.
    pub fn subscribe_message_stream_presence(&self) -> broadcast::Receiver<ScopedPresenceFrame> {
        self.message_streams.presence.scoped.subscribe()
    }
}
