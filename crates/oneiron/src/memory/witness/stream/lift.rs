//! The lift sweep's door for a stream's seed (OF-067). An old seed gets what
//! a checkpoint of it gets today: its text is admitted again whole, a new
//! MESSAGE's axes as its opening admitted them, and the seed is stored again
//! at its key with its handles. Its ids, topology, generation, timing and
//! mode stay, and no witness or stream receipt is written.
//!
//! A resident stream's state is coordinated explicitly, not through the
//! generation fence alone. The stream's lock comes before the writer, and
//! the sweep's transaction is already the writer, so the door only tries the
//! lock: a stream busy writing (it may be waiting for this very transaction)
//! refuses the lift as a concurrent write, and the sweep tries it again once
//! its walk ends. Holding the lock, the door admits the stream's own text as
//! an append would and stores the seed. The stream's memory then changes only
//! where a commit that failed could not mislead it: the masked text it shows,
//! and its `relift` mark. That mark has the stream's own next checkpoint, or
//! its end, admit its text and axes again in its own transaction and adopt
//! them once that commits, so a handle whose custody record this transaction
//! did not commit is never carried on. A value the lift did commit keeps its
//! handle there through the known-value index.

use super::*;
use crate::batch::secret_scan::admit_stream_text_in_txn;
use crate::error::{Error, Result};

impl Vault {
    /// The lift sweep's door for the seed of message `message`; see the
    /// module. `None` when no seed is stored for it; `Some(true)` when a
    /// handle replaced a secret.
    ///
    /// # Errors
    /// [`Error::ConcurrentWrite`] while the stream is writing, or once its
    /// generation is not the stored one; the door's refusal of a hit it
    /// cannot place, a secret in the message's type included.
    pub(crate) fn lift_stream_seed_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        message: &EntityId,
    ) -> Result<Option<bool>> {
        let Some(stored) = storage::ACTIVE.get(&self.store, txn, message)? else {
            return Ok(None);
        };
        let resident = self
            .message_streams
            .entries
            .lock()
            .map_err(|_| Error::InvariantViolation("the message stream registry is poisoned"))?
            .get(message)
            .cloned();
        let Some(entry) = resident else {
            return lift_saved_in_txn(self, txn, stored).map(Some);
        };
        let Ok(mut state) = entry.try_lock() else {
            return Err(Error::ConcurrentWrite(
                "a message stream is writing its seed",
            ));
        };
        if state.terminal || state.seed.generation != stored.generation {
            return Err(Error::ConcurrentWrite("message stream generation changed"));
        }
        let mut lifted = state.lifted.clone();
        let (saved, withheld) = admit_stream_text_in_txn(
            self,
            txn,
            *message,
            admission::CONTENT,
            &state.raw,
            true,
            &mut lifted,
        )?;
        let mut row = state.checkpoint(saved);
        admission::admit_axes_in_txn(self, txn, &mut row, &mut lifted)?;
        if row.saved == stored.saved && row.metadata == stored.metadata {
            return Ok(Some(false));
        }
        storage::checkpoint(self, txn, &row)?;
        state.pending = row.saved;
        state.withheld = withheld;
        state.relift = true;
        Ok(Some(true))
    }
}

/// A seed no process holds. What open-time recovery commits is its saved
/// text, finite, so that text is admitted closed.
fn lift_saved_in_txn(vault: &Vault, txn: &mut heed::RwTxn<'_>, stored: Seed) -> Result<bool> {
    let mut lifted = Lifted::default();
    let mut row = stored.clone();
    (row.saved, _) = admit_stream_text_in_txn(
        vault,
        txn,
        stored.message_id,
        admission::CONTENT,
        &stored.saved,
        false,
        &mut lifted,
    )?;
    admission::admit_axes_in_txn(vault, txn, &mut row, &mut lifted)?;
    if row.saved == stored.saved && row.metadata == stored.metadata {
        return Ok(false);
    }
    storage::checkpoint(vault, txn, &row)?;
    Ok(true)
}
