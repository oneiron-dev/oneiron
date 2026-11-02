//! A door's own refusals, logged in the writer the door already holds
//! (OF-470, FIX 2433, FIX 2435). A door opens an attempt before its checks:
//! each refusal its thread queues on this store while the attempt is open is
//! the attempt's, not the shared queue's. The door writes that batch in a
//! nested transaction of its own writer, so the refusals commit with it,
//! before the door answers, and never wait for another writer. A failed
//! audit write leaves the writer's other rows as they were. A batch that did
//! not reach its log, because its write or its writer's commit failed, goes
//! back to the shared queue for the next flush, its time and actor kept.

use std::cell::RefCell;

use heed::RwTxn;

use super::{RefusalNote, flush_refusals_in_txn, hosts_bytes};
#[cfg(feature = "sync")]
use crate::deletion::{LEGAL_HOLD_DEFERRAL, LEGAL_HOLD_REFUSAL};
use crate::error::Error;
#[cfg(feature = "sync")]
use crate::error::LegalHoldState;
use crate::store::Store;

thread_local! {
    /// The attempts open on this thread, innermost last: the store each one
    /// belongs to, by address, and the refusals it holds.
    static ATTEMPTS: RefCell<Vec<(usize, Vec<RefusalNote>)>> = const { RefCell::new(Vec::new()) };
}

fn store_key(store: &Store) -> usize {
    std::ptr::from_ref(store).addr()
}

/// Queues `note`: in this thread's innermost open attempt on `store`, else
/// in the store's shared queue.
pub(super) fn note(store: &Store, note: RefusalNote) {
    let key = store_key(store);
    let unowned = ATTEMPTS.with(|attempts| {
        let mut attempts = attempts.borrow_mut();
        let Some((_, batch)) = attempts.iter_mut().rev().find(|(of, _)| *of == key) else {
            return Some(note);
        };
        // One delete checks before publication and again in its writer.
        if !batch.iter().any(|held| held.same(&note)) {
            batch.push(note);
        }
        None
    });
    if let Some(note) = unowned {
        store.legal_hold_refusals.note(note);
    }
}

/// One door's attempt, open on this thread until it finishes. Dropped
/// unfinished, by a panic, it hands its refusals to the shared queue.
pub(crate) struct RefusalAttempt<'s> {
    store: &'s Store,
    /// Its place among this thread's open attempts.
    depth: usize,
    open: bool,
}

impl Store {
    /// Opens an attempt on this thread: the refusals it queues on this store
    /// until [`RefusalAttempt::finish`] are that attempt's batch.
    pub(crate) fn begin_refusal_attempt(&self) -> RefusalAttempt<'_> {
        let depth = ATTEMPTS.with(|attempts| {
            let mut attempts = attempts.borrow_mut();
            let depth = attempts.len();
            attempts.push((store_key(self), Vec::new()));
            depth
        });
        RefusalAttempt {
            store: self,
            depth,
            open: true,
        }
    }
}

impl<'s> RefusalAttempt<'s> {
    /// Closes the attempt: its batch, not yet in a hold log.
    pub(crate) fn finish(mut self) -> RefusalBatch<'s> {
        RefusalBatch {
            store: self.store,
            notes: self.close(),
            written: false,
        }
    }

    fn close(&mut self) -> Vec<RefusalNote> {
        if !std::mem::replace(&mut self.open, false) {
            return Vec::new();
        }
        ATTEMPTS.with(|attempts| {
            // An attempt opened inside this one closed before it.
            let mut attempts = attempts.borrow_mut();
            if attempts.len() <= self.depth {
                return Vec::new();
            }
            attempts
                .split_off(self.depth)
                .into_iter()
                .next()
                .map(|(_, notes)| notes)
                .unwrap_or_default()
        })
    }
}

impl Drop for RefusalAttempt<'_> {
    fn drop(&mut self) {
        let notes = self.close();
        self.store.legal_hold_refusals.restore(notes);
    }
}

/// One attempt's refusals, not yet in a hold log. Dropped before its
/// writer's commit [landed](Self::landed) it, it goes back to the shared
/// queue.
pub(crate) struct RefusalBatch<'s> {
    store: &'s Store,
    notes: Vec<RefusalNote>,
    /// Written in its door's writer, which has not committed yet.
    written: bool,
}

impl RefusalBatch<'_> {
    /// This batch with the refusals the shared queue holds: a door's that a
    /// failed write put back, or one no writer of its own logs. The group
    /// commit's leader carries them, as its flush did.
    #[must_use]
    pub(crate) fn with_queued(mut self) -> Self {
        for note in self.store.legal_hold_refusals.take() {
            if !self.notes.iter().any(|held| held.same(&note)) {
                self.notes.push(note);
            }
        }
        self
    }

    /// Writes the batch to its hold logs in a nested transaction of
    /// `parent`, the writer its door holds. Whether it wrote: a failed write
    /// leaves `parent` as it was.
    pub(crate) fn write_in(&mut self, parent: &mut RwTxn<'_>) -> bool {
        if self.notes.is_empty() {
            return false;
        }
        let hosted = hosts_bytes(self.store);
        let written = self
            .store
            .env
            .nested_write_txn(parent)
            .map_err(Error::from)
            .and_then(|mut audit| {
                flush_refusals_in_txn(self.store, &mut audit, &self.notes, hosted)?;
                audit.commit().map_err(Error::from)
            });
        if let Err(error) = &written {
            tracing::warn!(
                error = %error,
                "legal hold refusals kept for the next flush"
            );
        }
        self.written = written.is_ok();
        self.written
    }

    /// Settles the batch once its writer's commit is decided: in its logs
    /// when it was written and `committed`, back in the shared queue
    /// otherwise.
    pub(crate) fn landed(mut self, committed: bool) {
        if self.written && committed {
            self.notes.clear();
        }
    }

    /// Settles the batch in `parent`, a writer its door took and keeps for
    /// it alone: written and committed, or aborted with nothing to write. It
    /// never fails the door.
    #[cfg(feature = "sync")]
    pub(crate) fn settle_in(mut self, mut parent: RwTxn<'_>) {
        if !self.write_in(&mut parent) {
            return;
        }
        let committed = parent.commit();
        if let Err(error) = &committed {
            tracing::warn!(
                error = %error,
                "legal hold refusals kept for the next flush"
            );
        }
        self.landed(committed.is_ok());
    }

    /// Settles the batch in a writer of its own, taken now: for a door that
    /// held only a read snapshot, once it ended.
    #[cfg(feature = "sync")]
    pub(crate) fn settle_now(self) {
        if self.notes.is_empty() {
            return;
        }
        let store = self.store;
        match store.env.write_txn() {
            Ok(txn) => self.settle_in(txn),
            Err(error) => tracing::warn!(
                error = %error,
                "legal hold refusals kept for the next flush"
            ),
        }
    }
}

impl Drop for RefusalBatch<'_> {
    fn drop(&mut self) {
        self.store
            .legal_hold_refusals
            .restore(std::mem::take(&mut self.notes));
    }
}

/// Whether `error` is a legal hold's refusal of a destroying path
/// ([`Store::reject_legal_holds_in_txn`]) in any of its three forms, and not
/// another failure: a door defers on it and fails on the rest.
#[cfg(feature = "sync")]
pub(crate) fn is_hold_refusal(error: &Error) -> bool {
    match error {
        Error::LegalHold(notice) => notice.state == LegalHoldState::RetainedForLaw,
        Error::InvalidConfig(refusal) => {
            matches!(refusal.as_str(), LEGAL_HOLD_REFUSAL | LEGAL_HOLD_DEFERRAL)
        }
        _ => false,
    }
}
