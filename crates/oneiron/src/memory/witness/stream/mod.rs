//! Ephemeral MESSAGE streams, waiting their turn past the vault's row, with
//! transactional finality.
mod admission;
mod api;
mod api_types;
mod completion;
mod lifecycle;
mod lift;
mod policy;
#[cfg(feature = "sync")]
mod presence;
mod reader;
mod refused;
mod reply_assertions;
mod session;
mod storage;
#[cfg(test)]
mod tests;
mod types;

use crate::batch::secret_scan::Lifted;
use crate::memory::Memory;
use crate::{EntityId, Vault};
pub use api_types::*;
pub use completion::MessageCompletion;
pub(crate) use completion::message_completion_in_txn;
pub use lifecycle::MessageStreamPump;
pub use refused::StreamRecoveryRefusal;
pub(in crate::memory::witness) use session::SessionStreamTerminal;
pub use session::{
    SessionMessageStream, SessionStreamEnd, SessionStreamOutcome, SessionStreamPartial,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use storage::Seed;
pub(crate) use storage::{
    erase_stream_seeds_in_txn, message_stream_finality_in_txn,
    message_stream_held_generations_in_txn, redact_receipt_assertions_in_txn,
    scrub_stream_seed_actor_in_txn,
};
pub(in crate::memory::witness) use storage::{
    generation_receipt_in, keep_session_terminal_in_txn, receipt_in,
};
pub use types::*;

/// Registry lock never spans storage work. A per-handle lock serializes its
/// append/finalize transaction; no storage callback acquires that lock.
pub(crate) struct MessageStreamRuntime {
    entries: Arc<Mutex<BTreeMap<EntityId, Resident>>>,
    /// The fair line past the vault's message-stream row.
    line: crate::live_rows::LiveLine,
    /// The refusals the vault's last open met replaying surviving seeds
    /// (FIX 11933), which the owner reads.
    refused: Mutex<Vec<StreamRecoveryRefusal>>,
    #[cfg(feature = "sync")]
    pub(crate) presence: presence::StreamPresence,
}
impl Default for MessageStreamRuntime {
    fn default() -> Self {
        Self {
            entries: Arc::new(Mutex::new(BTreeMap::new())),
            line: crate::live_rows::LiveLine::new(crate::live_rows::LiveRow::MessageStreams),
            refused: Mutex::new(Vec::new()),
            #[cfg(feature = "sync")]
            presence: presence::StreamPresence::default(),
        }
    }
}
#[derive(Clone)]
enum Resident {
    Recorded(Arc<Mutex<State>>),
    Session(Arc<Mutex<session::SessionState>>),
}

struct State {
    seed: Seed,
    base: String,
    /// The accepted text as admitted (OF-067): what the seed checkpoints, a
    /// partial publishes and the final MESSAGE commits.
    pending: String,
    /// The accepted text as its writer appended it. Only this process's
    /// memory holds it; each checkpoint admits it again whole.
    raw: String,
    /// The secrets this stream lifted into custody, with their handles.
    lifted: Lifted,
    /// Whether `pending` withholds a secret `raw` may still be writing.
    withheld: bool,
    /// The lift sweep stored this stream's seed again with its handles
    /// (OF-067): the stream's next checkpoint, or its end, admits its text
    /// and axes again in its own transaction and adopts them once that
    /// commits.
    relift: bool,
    last_op_at_ms: u64,
    sequence: u64,
    emitted_chars: usize,
    dirty: bool,
    terminal: bool,
    /// The stream's turn under the vault's row, held until the stream's
    /// state goes; none for a seed recovered at open.
    _turn: Option<crate::live_rows::LivePermit>,
}
impl State {
    fn text(&self) -> String {
        format!("{}{}", self.base, self.pending)
    }
    /// The ACTIVE row that checkpoints `saved` as this stream's accepted text.
    fn checkpoint(&self, saved: String) -> Seed {
        Seed {
            saved,
            ..self.seed.clone()
        }
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
            .and_then(|entry| match entry {
                Resident::Recorded(entry) => Some(Arc::clone(entry)),
                Resident::Session(_) => None,
            })
            .ok_or(MessageStreamError::StreamNotFound)
    }
    /// Streams waiting for a turn past the vault's row.
    #[cfg(test)]
    pub(crate) fn waiting(&self) -> usize {
        self.line.waiting()
    }
    fn remove(&self, handle: MessageStreamHandle) -> MessageStreamResult<()> {
        // This function is reached while the corresponding State remains locked.
        // A replacement cannot be admitted until this removes the map entry.
        lock(&self.entries)?.remove(&handle.message);
        Ok(())
    }
    /// Retires `entry`, whose `state` the caller holds, after an erase
    /// committed over it (FIX 9973): it ends, its text, raw copy and lifted
    /// handles go, its turn under the vault's row is released, and, while
    /// the registry still names this very entry, its presence clears and it
    /// leaves the registry. A State another stream of the message already
    /// replaced touches nothing of the replacement's.
    fn retire_erased(
        &self,
        entry: &Arc<Mutex<State>>,
        state: &mut State,
    ) -> MessageStreamResult<()> {
        state.terminal = true;
        state.base = String::new();
        state.pending = String::new();
        state.raw = String::new();
        state.seed.saved = String::new();
        state.lifted = Lifted::default();
        state.withheld = false;
        state.relift = false;
        state.dirty = false;
        state._turn = None;
        let handle = state.handle();
        // No replacement is admitted while this entry stays in the registry,
        // and only a holder of its State removes it.
        let current = matches!(
            lock(&self.entries)?.get(&handle.message),
            Some(Resident::Recorded(resident)) if Arc::ptr_eq(resident, entry)
        );
        if current {
            #[cfg(feature = "sync")]
            self.presence.clear(&state.seed);
            self.remove(handle)?;
        }
        Ok(())
    }
}
impl Memory<'_> {
    /// The caller's live stream `handle`. One an erase committed over is
    /// retired here and reads as not found (FIX 9973).
    fn stream_entry(&self, handle: MessageStreamHandle) -> MessageStreamResult<Arc<Mutex<State>>> {
        let entry = self.vault.message_streams.entry(handle)?;
        {
            let mut state = lock(&entry)?;
            state.check(handle)?;
            if self.vault.retire_stream_if_erased(&entry, &mut state)? {
                return Err(MessageStreamError::StreamNotFound);
            }
            if state.seed.actor != self.actor || state.seed.actor_class != self.actor_class as u8 {
                return Err(MessageStreamError::WrongActor);
            }
        }
        Ok(entry)
    }
    /// Reads the caller's accepted output even after a failed finalize. An
    /// erase committed before the read, judged under the guard the text is
    /// read under, leaves nothing to read (FIX 9973).
    pub fn message_stream_partial(
        &self,
        handle: MessageStreamHandle,
    ) -> MessageStreamResult<MessageStreamPartial> {
        let entry = self.stream_entry(handle)?;
        let mut state = lock(&entry)?;
        state.check(handle)?;
        if self.vault.retire_stream_if_erased(&entry, &mut state)? {
            return Err(MessageStreamError::StreamNotFound);
        }
        Ok(MessageStreamPartial {
            message_id: handle.message,
            text: state.text(),
            sequence: state.sequence,
            mode: state.seed.mode,
        })
    }
}
impl Vault {
    /// Retires `entry`, whose `state` the caller holds, when an erase has
    /// committed over its stream (FIX 9973), judged in a read of its own:
    /// `true` once it is retired. The caller holds no writer. A read that
    /// fails is an error, never taken for an erase.
    fn retire_stream_if_erased(
        &self,
        entry: &Arc<Mutex<State>>,
        state: &mut State,
    ) -> MessageStreamResult<bool> {
        if state.terminal {
            return Ok(false);
        }
        let erased = {
            let txn = self.store.env.read_txn()?;
            storage::stream_erased_in_txn(self, &txn, &state.seed)?
        };
        if erased {
            self.message_streams.retire_erased(entry, state)?;
        }
        Ok(erased)
    }
    /// Number of resident handles. Bounded independently of token traffic.
    pub fn active_message_streams(&self) -> MessageStreamResult<usize> {
        Ok(lock(&self.message_streams.entries)?.len())
    }
}
