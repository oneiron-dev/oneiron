//! The intent a keyed HTTP request's route writes under (FIX 10379).
//!
//! The host keeps a keyed request's intent row ([`IdempotencyEntry`] at
//! [`IdempotencyEntry::INTENT_STATUS`]) before its route runs, and settles it
//! with the outcome after (FIX 9527). While the route runs, the host opens the
//! row's key on each thread that runs it ([`with_idempotency_intent`]) and
//! carries it across each thread hop the route makes
//! ([`carry_idempotency_intent`]). Each write that commits through the
//! store's group commit on such a thread counts itself on that row, in its
//! own transaction, so the count commits or rolls back with the write: a
//! crash between the route's last commit and the settle leaves a row that
//! says how many writes the request committed, and no second store holds it. A write that commits any other way (its own
//! `env.write_txn()`, or on a hop the host did not carry) counts nothing, so
//! a row with no count still says only that the outcome is unknown.

use std::cell::RefCell;
use std::sync::Arc;

use heed::RwTxn;

use super::{IdempotencyEntry, ManifestDbs, Rows, Store};
use crate::error::{Error, Result};

thread_local! {
    static OPEN_INTENT: RefCell<Option<IdempotencyIntent>> = const { RefCell::new(None) };
}

impl IdempotencyEntry {
    /// The status an intent row holds: no HTTP status is 0 (FIX 9527).
    pub const INTENT_STATUS: u16 = 0;

    /// Whether this entry is an intent that no outcome settled and no erase
    /// took.
    #[must_use]
    pub fn is_open_intent(&self) -> bool {
        self.status == Self::INTENT_STATUS && !self.erased
    }
}

/// The key of a keyed request's intent row, under the HTTP idempotency
/// cache's rows.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyIntent(Arc<str>);

impl IdempotencyIntent {
    /// The intent the host keeps as `store_key`.
    ///
    /// # Errors
    ///
    /// A key outside the cache's declared rows.
    pub fn new(store_key: &str) -> Result<Self> {
        if !store_key
            .as_bytes()
            .starts_with(crate::side_table::HTTP_IDEMPOTENCY_REPLY.prefix)
        {
            return Err(Error::InvariantViolation(
                "an idempotency intent outside its rows",
            ));
        }
        Ok(Self(Arc::from(store_key)))
    }

    /// Counts one committed write on this intent's row in the write's own
    /// `txn`, while the row still stands as an open intent: a row that is
    /// settled, erased, released or does not decode is left as it is.
    ///
    /// # Errors
    ///
    /// Storage errors, which the write answers as its own.
    #[cfg(feature = "sync")]
    pub(super) fn count_commit_in_txn(
        &self,
        store: &impl ManifestDbs,
        txn: &mut RwTxn<'_>,
    ) -> Result<()> {
        let kept = match store.sync_state().get(txn, &self.0)? {
            Some(row) => IdempotencyEntry::decode(&row).ok(),
            None => None,
        };
        let Some(mut intent) = kept.filter(IdempotencyEntry::is_open_intent) else {
            return Ok(());
        };
        intent.committed_writes = intent.committed_writes.saturating_add(1);
        let raw = intent.encode()?;
        crate::side_table::host_sync_state_put(store, txn, &self.0, &raw)
    }

    /// A build without sync keeps no HTTP idempotency rows to count on.
    #[cfg(not(feature = "sync"))]
    pub(super) fn count_commit_in_txn(
        &self,
        _store: &impl ManifestDbs,
        _txn: &mut RwTxn<'_>,
    ) -> Result<()> {
        Ok(())
    }
}

/// Runs `work` with `intent` open on this thread: each write it commits
/// through the group commit counts itself on the intent's row. `None` opens
/// none. Whatever intent was open before is open again after.
#[doc(hidden)]
pub fn with_idempotency_intent<T>(
    intent: Option<&IdempotencyIntent>,
    work: impl FnOnce() -> T,
) -> T {
    let _scope = OpenIntentScope(OPEN_INTENT.with(|slot| slot.replace(intent.cloned())));
    work()
}

/// `work`, made to run under the intent open on this thread now, on
/// whichever thread it runs: what a host wraps around work it sends across a
/// thread hop. Outside any intent it runs as it is.
#[doc(hidden)]
pub fn carry_idempotency_intent<T>(work: impl FnOnce() -> T) -> impl FnOnce() -> T {
    let intent = open_intent();
    move || with_idempotency_intent(intent.as_ref(), work)
}

/// `write`, made to count itself on the intent open on the calling thread
/// when its rows stay ([`Rows::Commit`]), in its own transaction, so the
/// count commits or rolls back with them. The intent is read here, before
/// the write joins any group; with none open, that read is all it adds. A
/// count that fails drops the write's rows with its storage error.
pub(super) fn counting_commits<T, E>(
    store: &Store,
    write: impl FnOnce(&mut RwTxn<'_>) -> Rows<T, E>,
) -> impl FnOnce(&mut RwTxn<'_>) -> Rows<T, E>
where
    E: From<Error>,
{
    let intent = open_intent();
    move |txn: &mut RwTxn<'_>| match (intent, write(&mut *txn)) {
        (Some(intent), Rows::Commit(answer)) => match intent.count_commit_in_txn(store, txn) {
            Ok(()) => Rows::Commit(answer),
            Err(error) => Rows::Discard(Err(E::from(error))),
        },
        (_, rows) => rows,
    }
}

/// The intent open on this thread.
pub(super) fn open_intent() -> Option<IdempotencyIntent> {
    OPEN_INTENT.with(|slot| slot.borrow().clone())
}

/// The intent [`with_idempotency_intent`] replaced, open again when it drops.
struct OpenIntentScope(Option<IdempotencyIntent>);

impl Drop for OpenIntentScope {
    fn drop(&mut self) {
        let previous = self.0.take();
        OPEN_INTENT.with(|slot| *slot.borrow_mut() = previous);
    }
}
