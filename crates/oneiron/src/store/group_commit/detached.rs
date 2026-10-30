//! Detached writes (FIX 12023; Engine ruling 10-30 23:09, extended to the
//! light recall's own writes).
//!
//! A detached write's caller needs none of its rows to answer: a call
//! receipt's ref, a retrieval run's id and an authorization's judged time are
//! all minted before it queues. It takes its place in the group commit's one
//! arrival order, beside the writes whose threads wait for their turn, and
//! returns at once: no wait for the writer, its stage or its commit. The
//! group's leader runs its closure on the leader's own thread, in a
//! transaction nested in the shared one, when its turn comes: a writer
//! already leading, or the store's deferred-commit leader, which takes the
//! writer for it when no group is open. A closure that fails rolls back its
//! own rows only, is said in a warn with the write's name, and fails no
//! group.
//!
//! A crash before its group commits loses rows whose caller already answered.
//! A clean close keeps them: the vault's drop and the store's drop run every
//! detached write still queued before either closes, and a reader that must
//! see their rows waits until those queued so far are decided
//! ([`Store::wait_for_deferred_commits`]). Memory stays bounded without a
//! refusal: past [`DETACHED_WRITES_WAITING_MAX`] queued, an enqueuer waits for
//! the drain rather than drop its write.
//!
//! Most closures write over the store's core alone, which the store's own
//! leader holds ([`DetachedWrite::of_core`]). One that writes through the
//! vault's own doors (a call receipt, whose side-row wall mints custody
//! through the vault) holds the vault weakly, so a queued write never keeps a
//! vault open, and runs on a handle its leader takes while a holder keeps the
//! vault, or on the closing vault in its drop ([`DetachedWrite::of_vault`]).
//! When the handle a leader took turns out to be the last, because every
//! other holder let go while the write ran, the vault closes on a thread of
//! its own just after.
//!
//! A write may carry an after-commit callback ([`DetachedWrite::after_commit`]):
//! it runs once with whether the write's rows landed, after its group's
//! commit or that commit's failure, never at the stage. A write whose closure
//! failed is told `false` once its group's commit is decided, and a write lost
//! before any group ran it is told `false` as it is said lost.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};

use heed::RwTxn;

use crate::Vault;
use crate::error::{Error, Result};
use crate::store::idempotency_intent::{IdempotencyIntent, open_intent};
use crate::store::{ManifestDbs, Store, StoreCore, active_write_txn_depth, active_write_txn_guard};

use super::{Arrival, Callback, GroupCommit, Rows};

/// Past this many detached writes queued, an enqueuer waits for the drain
/// before it adds its own (FIX 12023): memory stays bounded, and no write is
/// refused or dropped.
pub(crate) const DETACHED_WRITES_WAITING_MAX: usize = 4096;

/// What runs once a detached write's group commit is decided, with whether
/// its rows landed: `true` only when its closure kept them and the group
/// committed. A lease is held from that commit, not from the queueing.
pub(crate) type AfterCommit = Box<dyn FnOnce(bool) + Send>;

/// A detached write's closure over the store's core.
type CoreWrite = Box<dyn FnOnce(&StoreCore, &mut RwTxn<'_>) -> Result<()> + Send>;

/// A detached write's closure through the vault's own doors.
type VaultWrite = Box<dyn FnOnce(&Vault, &mut RwTxn<'_>) -> Result<()> + Send>;

enum Closure {
    Core(CoreWrite),
    /// The vault, held weakly: a queued write keeps no vault open.
    Vault(Weak<Vault>, VaultWrite),
}

/// One detached write: its name, said in each warn about it, and its
/// closure, whose `Ok` keeps its rows and whose `Err` rolls them back.
pub(crate) struct DetachedWrite {
    name: &'static str,
    /// Its rows are only a clock floor's (FIX 11568).
    replay_only: bool,
    /// The keyed request's intent it counts itself on (FIX 10379), read on
    /// the thread it queued from.
    intent: Option<IdempotencyIntent>,
    closure: Closure,
    /// Told whether its rows landed, once that is decided.
    after: Option<AfterCommit>,
}

impl DetachedWrite {
    /// A write over the store's own rows, which the store's leader can run.
    /// Like a grouped write, it counts itself on the idempotency intent open
    /// on this thread, in its own transaction (FIX 10379).
    pub(crate) fn of_core<W>(name: &'static str, write: W) -> Self
    where
        W: FnOnce(&StoreCore, &mut RwTxn<'_>) -> Result<()> + Send + 'static,
    {
        Self {
            name,
            replay_only: false,
            intent: open_intent(),
            closure: Closure::Core(Box::new(write)),
            after: None,
        }
    }

    /// A write through the vault's own doors, run on a handle on `vault`
    /// taken for it, or on the vault itself as it closes. Like a grouped
    /// write, it counts itself on the idempotency intent open on this thread
    /// (FIX 10379).
    pub(crate) fn of_vault<W>(name: &'static str, vault: &Arc<Vault>, write: W) -> Self
    where
        W: FnOnce(&Vault, &mut RwTxn<'_>) -> Result<()> + Send + 'static,
    {
        Self {
            name,
            replay_only: false,
            intent: open_intent(),
            closure: Closure::Vault(Arc::downgrade(vault), Box::new(write)),
            after: None,
        }
    }

    /// This write's rows are only the clock floor (FIX 11568): a group that
    /// carries nothing else is noted as a replay-only commit, and the write
    /// counts on no intent, as the writer of its own it stands in for counted
    /// none.
    #[must_use]
    pub(crate) fn replay_only(mut self) -> Self {
        self.replay_only = true;
        self.intent = None;
        self
    }

    /// This write with `after`, run once with whether its rows landed: after
    /// its group's commit or that commit's failure, never at the stage, and
    /// with `false` when the write is lost before any group ran it (FIX
    /// 12023).
    #[must_use]
    pub(crate) fn after_commit(mut self, after: AfterCommit) -> Self {
        self.after = Some(after);
        self
    }

    /// Whether the store's leader, which holds no vault, can run it now: a
    /// write over the core, or one through a vault a holder still keeps.
    pub(super) fn runs_on_core(&self) -> bool {
        match &self.closure {
            Closure::Core(_) => true,
            Closure::Vault(vault, _) => vault.strong_count() > 0,
        }
    }
}

/// How many detached writes queued, and how many of them the commits since
/// decided, committed or lost (FIX 12023). They leave the queue in order and
/// each group settles its own before it passes the writer on, so the first
/// `settled` writes queued are the decided ones.
#[derive(Default)]
pub(super) struct DetachedWrites {
    counts: Mutex<DetachedCounts>,
    settled: Condvar,
    /// Wakes an enqueuer that waits past the bound; waited on with the
    /// queue's lock.
    pub(super) drained: Condvar,
}

#[derive(Default)]
struct DetachedCounts {
    queued: u64,
    settled: u64,
}

impl DetachedWrites {
    fn counts(&self) -> MutexGuard<'_, DetachedCounts> {
        self.counts.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Counts one write queued.
    fn queue_one(&self) {
        self.counts().queued += 1;
    }

    /// Counts `writes` more decided.
    fn settle(&self, writes: usize) {
        if writes == 0 {
            return;
        }
        self.counts().settled += writes as u64;
        self.settled.notify_all();
    }

    /// The writes decided so far.
    fn settled_count(&self) -> u64 {
        self.counts().settled
    }

    /// Blocks until every write queued so far is decided.
    pub(super) fn wait_settled(&self) {
        let counts = self.counts();
        let queued = counts.queued;
        drop(
            self.settled
                .wait_while(counts, |now| now.settled < queued)
                .unwrap_or_else(PoisonError::into_inner),
        );
    }
}

/// The detached writes one group ran, held until its commit is decided and
/// the writer is passed on.
pub(super) struct DetachedGroup<'v> {
    /// The vault whose drop leads this group, for the writes that need it.
    closing: Option<&'v Vault>,
    /// Taken from the queue and run here, kept or rolled back.
    ran: usize,
    kept: usize,
    /// Of `kept`, those whose rows are only a clock floor's.
    replay_only: usize,
    /// Each run write's after-commit callback, with whether its rows stayed.
    after: Vec<(AfterCommit, bool)>,
    /// The vault handles taken to run its writes.
    held: Vec<Arc<Vault>>,
}

impl<'v> DetachedGroup<'v> {
    /// A group's detached writes, none run yet; `closing` is the vault whose
    /// drop leads it.
    pub(super) fn new(closing: Option<&'v Vault>) -> Self {
        Self {
            closing,
            ran: 0,
            kept: 0,
            replay_only: 0,
            after: Vec::new(),
            held: Vec::new(),
        }
    }
}

impl DetachedGroup<'_> {
    /// The detached writes run in this group.
    pub(super) fn ran(&self) -> usize {
        self.ran
    }

    /// Of those, the ones whose rows stay.
    pub(super) fn kept(&self) -> usize {
        self.kept
    }

    /// Whether the group's rows are only a clock floor's, when
    /// `others_kept` writes besides these kept rows in it.
    pub(super) fn only_replay_rows(&self, others_kept: usize) -> bool {
        others_kept == 0 && self.kept > 0 && self.replay_only == self.kept
    }

    fn keep(&mut self, replay_only: bool) {
        self.kept += 1;
        self.replay_only += usize::from(replay_only);
    }

    /// Once the group's commit is decided: each run write's after-commit
    /// callback is told whether its rows landed, then the writes the group
    /// took count as decided. A failed commit loses rows whose callers
    /// answered already: said here, as no answer can say it.
    pub(super) fn settle(&mut self, writes: &DetachedWrites, committed: &heed::Result<()>) {
        if let Err(error) = committed
            && self.kept > 0
        {
            tracing::warn!(
                %error,
                lost = self.kept,
                "a group commit failed after its detached writes queued; their rows are lost"
            );
        }
        for (after, staged) in self.after.drain(..) {
            after(staged && committed.is_ok());
        }
        writes.settle(self.ran);
    }

    /// Lets go of the vault handles taken for this group, once the writer is
    /// passed on.
    pub(super) fn release(self) {
        for vault in self.held {
            if let Some(last) = Arc::into_inner(vault) {
                close_vault_elsewhere(last);
            }
        }
    }
}

impl GroupCommit {
    /// Whether a detached write the store's leader can run heads the queue.
    pub(super) fn detached_heads_for_leader(&self) -> bool {
        matches!(
            self.lock().queue.front(),
            Some(Arrival::Detached(write)) if write.runs_on_core()
        )
    }

    /// The detached write at the head of the queue, taken out of it.
    fn take_detached_front(&self) -> Option<DetachedWrite> {
        let mut waiting = self.lock();
        if !matches!(waiting.queue.front(), Some(Arrival::Detached(_))) {
            return None;
        }
        let Some(Arrival::Detached(write)) = waiting.take_front() else {
            return None;
        };
        self.detached.drained.notify_all();
        Some(write)
    }

    /// Puts a detached write its group could not run back at the head.
    pub(super) fn requeue_detached(&self, write: DetachedWrite) {
        let mut waiting = self.lock();
        waiting.queue.push_front(Arrival::Detached(write));
        waiting.detached += 1;
    }

    /// Drops every detached write still queued, each said lost in a warn by
    /// name with `reason`: no writer opened for it.
    pub(super) fn discard_detached(&self, reason: &'static str) {
        let lost = {
            let mut waiting = self.lock();
            let queue = std::mem::take(&mut waiting.queue);
            let mut lost = Vec::new();
            for arrival in queue {
                match arrival {
                    Arrival::Detached(write) => lost.push(write),
                    write @ Arrival::Write(_) => waiting.queue.push_back(write),
                }
            }
            waiting.detached = 0;
            lost
        };
        self.detached.drained.notify_all();
        let count = lost.len();
        for write in lost {
            tracing::warn!(write = write.name, reason, "a detached write is lost");
            if let Some(after) = write.after {
                after(false);
            }
        }
        self.detached.settle(count);
    }
}

impl Store {
    /// Queues `write` in this vault's group commit, in arrival order with
    /// every other write, and returns at once (FIX 12023): it waits for
    /// neither the writer nor its stage nor its commit. When no group is
    /// open, the store's deferred-commit leader takes the writer for it; when
    /// that leader cannot start, this thread leads the group itself and only
    /// then waits for the writer.
    ///
    /// Past [`DETACHED_WRITES_WAITING_MAX`] queued while a group is led, it
    /// first waits for the drain, never refusing the write. A thread inside a
    /// write may be the one that drains the queue, and never waits for it.
    pub(crate) fn group_write_detached(&self, write: DetachedWrite) {
        let group = &self.group_commit;
        let idle = {
            let mut waiting = group.lock();
            if active_write_txn_depth() == 0 {
                while waiting.leading && waiting.detached >= DETACHED_WRITES_WAITING_MAX {
                    waiting = group
                        .detached
                        .drained
                        .wait(waiting)
                        .unwrap_or_else(PoisonError::into_inner);
                }
            }
            waiting.queue.push_back(Arrival::Detached(write));
            waiting.detached += 1;
            group.detached.queue_one();
            group.arrival.notify_all();
            !std::mem::replace(&mut waiting.leading, true)
        };
        if idle {
            self.take_writer_for_detached();
        }
    }

    /// Takes the writer a detached write found idle: the store's leader
    /// leads its group; when it cannot start, this thread leads a group with
    /// no rows of its own, which runs the detached writes ahead of it.
    fn take_writer_for_detached(&self) {
        if self.request_deferred_commit_leader() {
            return;
        }
        let _ = self.lead(
            Callback::Audited,
            |_| Rows::<(), Error>::Discard(Ok(())),
            None,
        );
    }

    /// Takes the writer for detached writes left queued while no group
    /// leads, because no leader could take it for them, so a reader that
    /// waits for them is not left waiting.
    pub(super) fn take_writer_for_left_detached(&self) {
        let idle = {
            let mut waiting = self.group_commit.lock();
            waiting.detached > 0 && !std::mem::replace(&mut waiting.leading, true)
        };
        if idle {
            self.take_writer_for_detached();
        }
    }

    /// Runs every detached write still queued before this store, or the
    /// vault around it, closes (FIX 12023): on this thread, in groups it
    /// leads, with `closing` the vault whose drop this is, for the writes that
    /// need it. When no writer opens for them, they are said lost in a warn,
    /// by name.
    pub(crate) fn finish_detached_writes(&self, closing: Option<&Vault>) {
        let group = &self.group_commit;
        while group.lock().detached > 0 {
            let settled = group.detached.settled_count();
            let led = self.queue_write(
                Callback::Opaque,
                None,
                |_| Rows::<(), Error>::Discard(Ok(())),
                closing,
            );
            // Its writer did not open, or it ran none and no group leads to
            // run them: none of these can land.
            let stuck = group.detached.settled_count() == settled && !group.lock().leading;
            if led.is_err() || stuck {
                group.discard_detached("its store closed before a writer opened for it");
                return;
            }
        }
    }
}

impl StoreCore {
    /// Runs the detached writes at the head of the queue in `shared`, in
    /// order: those left ahead of a write that leads its own group because no
    /// leader could take the writer for them, or ahead of the vault's close.
    pub(super) fn run_queued_detached(
        &self,
        shared: &mut RwTxn<'_>,
        group: &mut DetachedGroup<'_>,
    ) {
        while let Some(write) = self.group_commit.take_detached_front() {
            if let Some(back) = self.run_detached(shared, write, group) {
                self.group_commit.requeue_detached(back);
                return;
            }
        }
    }

    /// Runs one detached write on this thread, in a transaction nested in
    /// `shared`: its rows stay when its closure returns `Ok`, and roll back,
    /// said in a warn by name, when it fails or panics; the group goes on.
    /// `Some` hands back a write whose vault no holder keeps while it closes
    /// on another thread: that close runs it.
    pub(super) fn run_detached(
        &self,
        shared: &mut RwTxn<'_>,
        write: DetachedWrite,
        group: &mut DetachedGroup<'_>,
    ) -> Option<DetachedWrite> {
        let DetachedWrite {
            name,
            replay_only,
            intent,
            closure,
            after,
        } = write;
        // A write through the vault runs on the closing vault, or on a handle
        // taken now; `None` while the vault closes on another thread.
        let held = match (&closure, group.closing) {
            (Closure::Vault(vault, _), None) => vault.upgrade().map(Some),
            (Closure::Core(_) | Closure::Vault(..), _) => Some(None),
        };
        let Some(held) = held else {
            return Some(DetachedWrite {
                name,
                replay_only,
                intent,
                closure,
                after,
            });
        };
        group.ran += 1;
        let _active_write_txn = active_write_txn_guard();
        let mut child = match self.env.nested_write_txn(shared) {
            Ok(child) => child,
            Err(error) => {
                tracing::warn!(
                    write = name,
                    %error,
                    "a detached write did not run: its transaction did not open"
                );
                group.held.extend(held);
                group.after.extend(after.map(|after| (after, false)));
                return None;
            }
        };
        let vault = held.as_deref().or(group.closing);
        let ran = catch_unwind(AssertUnwindSafe(|| -> Result<()> {
            match closure {
                Closure::Core(write) => {
                    write(self, &mut child)?;
                    count_on_intent(intent.as_ref(), &self.canonical_dbs(), &mut child)
                }
                Closure::Vault(_, write) => {
                    let vault = vault.ok_or(Error::InvariantViolation(
                        "a detached vault write ran with no vault",
                    ))?;
                    write(vault, &mut child)?;
                    count_on_intent(intent.as_ref(), &vault.store, &mut child)
                }
            }
        }));
        group.held.extend(held);
        let staged = match ran {
            Ok(Ok(())) => match child.commit() {
                Ok(()) => true,
                Err(error) => {
                    tracing::warn!(
                        write = name,
                        %error,
                        "a detached write's rows did not stage; they are rolled back"
                    );
                    false
                }
            },
            Ok(Err(error)) => {
                tracing::warn!(
                    write = name,
                    %error,
                    "a detached write failed; its rows are rolled back"
                );
                false
            }
            Err(_) => {
                tracing::warn!(
                    write = name,
                    "a detached write panicked; its rows are rolled back"
                );
                false
            }
        };
        if staged {
            group.keep(replay_only);
        }
        // Told only once the group's commit is decided, never here.
        group.after.extend(after.map(|after| (after, staged)));
        None
    }
}

/// Counts a detached write on the intent it queued under, in its own
/// transaction, as a grouped write counts itself (FIX 10379).
fn count_on_intent(
    intent: Option<&IdempotencyIntent>,
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
) -> Result<()> {
    intent.map_or(Ok(()), |intent| intent.count_commit_in_txn(dbs, txn))
}

/// Closes a vault whose last handle a group took to run a detached write, on
/// a thread of its own: this thread may be the store's leader, which that
/// close waits for. A vault no thread can start for stays open, said in a
/// warn, rather than close where its close would wait for itself.
fn close_vault_elsewhere(vault: Vault) {
    let slot = Arc::new(Mutex::new(Some(vault)));
    let held = Arc::clone(&slot);
    let started = std::thread::Builder::new()
        .name("oneiron-vault-close".into())
        .spawn(move || {
            let vault = held.lock().unwrap_or_else(PoisonError::into_inner).take();
            drop(vault);
        });
    if let Err(error) = started {
        tracing::warn!(
            %error,
            "a vault whose last handle a detached write held stays open: its close thread did not start"
        );
        std::mem::forget(slot.lock().unwrap_or_else(PoisonError::into_inner).take());
    }
}
