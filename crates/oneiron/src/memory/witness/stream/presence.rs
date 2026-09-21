//! Native EphemeralStore publication. Frames use the existing TAG_EPHEMERAL.
use super::*;
use crate::sync::{EphemeralStore, LoroValue, transport};
use tokio::sync::broadcast;
const FRAME_BUDGET: usize = 64 * 1024;
/// The socket consumes this lossy bounded channel directly, never SyncQueue.
pub(crate) struct StreamPresence {
    pub(crate) store: EphemeralStore,
    sender: broadcast::Sender<Vec<u8>>,
    emission: Mutex<()>,
}
impl Default for StreamPresence {
    fn default() -> Self {
        let (sender, _) = broadcast::channel(MAX_MESSAGE_STREAMS);
        Self {
            store: EphemeralStore::new(DEFAULT_MESSAGE_STREAM_IDLE_MS as i64),
            sender,
            emission: Mutex::new(()),
        }
    }
}
impl StreamPresence {
    pub(crate) fn subscribe_frames(&self) -> broadcast::Receiver<Vec<u8>> {
        self.sender.subscribe()
    }
    pub(super) fn publish(&self, seed: &Seed, text: &str, seq: u64) -> MessageStreamResult<()> {
        let MessageWriteMode::Streamed { visibility, .. } = seed.mode else {
            return Ok(());
        };
        let _emission = lock(&self.emission)?;
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
        // Preflight a scratch native store, so refusal accepts neither the delta
        // nor a local presence mutation. Manual buffering can exceed this cap;
        // flush then refuses but finalize still commits every buffered byte.
        let scratch = EphemeralStore::new(DEFAULT_MESSAGE_STREAM_IDLE_MS as i64);
        scratch.set(&key, value.clone());
        if scratch.encode(&key).len().saturating_add(1) > FRAME_BUDGET {
            return Err(MessageStreamError::PresenceFrameTooLarge);
        }
        self.store.remove_outdated();
        self.store.set(&key, value);
        if visibility == StreamSyncVisibility::AllDevices {
            let frame = transport::encode_ephemeral(&self.store.encode(&key))
                .into_result()
                .map_err(|_| MessageStreamError::PresenceFrameTooLarge)?;
            // No receiver means disconnected. Presence is live-only; never persist
            // it for reconnect. The next append/flush publishes full text again.
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
            let _ = self.sender.send(frame);
        }
        self.store.remove_outdated();
    }
}

impl Vault {
    /// Subscribes to local all-devices partials. The bounded stream is live-only:
    /// lagged or disconnected frames are not replayed through the offline queue.
    pub fn subscribe_message_stream_presence(&self) -> broadcast::Receiver<Vec<u8>> {
        self.message_streams.presence.subscribe_frames()
    }
}
