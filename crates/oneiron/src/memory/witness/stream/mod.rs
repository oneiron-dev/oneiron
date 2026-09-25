//! Ephemeral MESSAGE streams, bounded per vault, with transactional finality.
mod admission;
mod lifecycle;
mod policy;
#[cfg(feature = "sync")]
mod presence;
mod storage;
#[cfg(test)]
mod tests;
mod types;

use crate::memory::Memory;
use crate::{EntityId, Vault};
pub use lifecycle::MessageStreamPump;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use storage::Seed;
pub use types::*;

/// Registry lock never spans storage work. A per-handle lock serializes its
/// append/finalize transaction; no storage callback acquires that lock.
pub(crate) struct MessageStreamRuntime {
    entries: Mutex<BTreeMap<EntityId, Arc<Mutex<State>>>>,
    #[cfg(feature = "sync")]
    pub(crate) presence: presence::StreamPresence,
}
impl Default for MessageStreamRuntime {
    fn default() -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
            #[cfg(feature = "sync")]
            presence: presence::StreamPresence::default(),
        }
    }
}
struct State {
    seed: Seed,
    base: String,
    pending: String,
    last_op_at_ms: u64,
    sequence: u64,
    emitted_chars: usize,
    dirty: bool,
    terminal: bool,
}
impl State {
    fn text(&self) -> String {
        format!("{}{}", self.base, self.pending)
    }
    fn handle(&self) -> MessageStreamHandle {
        MessageStreamHandle {
            message: self.seed.message_id,
            generation: self.seed.generation,
        }
    }
    fn check(&self, handle: MessageStreamHandle) -> MessageStreamResult<()> {
        if self.terminal || self.handle() != handle {
            return Err(MessageStreamError::StreamNotFound);
        }
        Ok(())
    }
}
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}
fn lock<T>(mutex: &Mutex<T>) -> MessageStreamResult<std::sync::MutexGuard<'_, T>> {
    mutex.lock().map_err(|_| MessageStreamError::Poisoned)
}
impl MessageStreamRuntime {
    fn entry(&self, handle: MessageStreamHandle) -> MessageStreamResult<Arc<Mutex<State>>> {
        lock(&self.entries)?
            .get(&handle.message)
            .cloned()
            .ok_or(MessageStreamError::StreamNotFound)
    }
    fn remove(&self, handle: MessageStreamHandle) -> MessageStreamResult<()> {
        // This function is reached while the corresponding State remains locked.
        // A replacement cannot be admitted until this removes the map entry.
        lock(&self.entries)?.remove(&handle.message);
        Ok(())
    }
}
impl Memory<'_> {
    fn stream_entry(&self, handle: MessageStreamHandle) -> MessageStreamResult<Arc<Mutex<State>>> {
        let entry = self.vault.message_streams.entry(handle)?;
        {
            let state = lock(&entry)?;
            state.check(handle)?;
            if state.seed.actor != self.actor || state.seed.actor_class != self.actor_class as u8 {
                return Err(MessageStreamError::WrongActor);
            }
        }
        Ok(entry)
    }
    /// Reads the caller's accepted output even after a failed finalize.
    pub fn message_stream_partial(
        &self,
        handle: MessageStreamHandle,
    ) -> MessageStreamResult<MessageStreamPartial> {
        let entry = self.stream_entry(handle)?;
        let state = lock(&entry)?;
        state.check(handle)?;
        Ok(MessageStreamPartial {
            message_id: handle.message,
            text: state.text(),
            sequence: state.sequence,
            mode: state.seed.mode,
        })
    }
}
impl Vault {
    /// Number of resident handles. Bounded independently of token traffic.
    pub fn active_message_streams(&self) -> MessageStreamResult<usize> {
        Ok(lock(&self.message_streams.entries)?.len())
    }
}
