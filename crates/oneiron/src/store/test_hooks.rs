//! The test seams one open vault owns, plus the two path-keyed LMDB open
//! hooks that necessarily predate it.
//!
//! Engine state belongs to a vault or to a thread, never to the process, and a
//! test seam is no exception: a `#[cfg(test)]` static is the worst case of the
//! rule, because `cargo test --lib` runs the whole suite as parallel threads of
//! ONE process, so every sibling test shares the seam. That is what flaked
//! #923 — two raced-delete tests clobbered each other's rendezvous channels —
//! and the answer there was a process-wide serial lock that made the two tests
//! run one after the other. [`TestHooks`] is the ownership fix that retires it:
//! each test arms ITS OWN vault, so no test can reach another's seam and none
//! of them needs to queue.
//!
//! The two LMDB open hooks below stay process-level and path-keyed. They fire
//! between the vault root being bound and the environment being opened, i.e.
//! before any `Store` exists to own them; the armed path is what keeps one
//! test's hook out of another test's open.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::mpsc::SyncSender;
use std::sync::{LazyLock, Mutex};

use crate::deletion::{DeleteRendezvous, DeleteRendezvousChannels};
use crate::entity_id::EntityId;
use crate::store::GateDecisionId;

/// The test seams of ONE open vault: a field on [`super::StoreCore`], reached
/// as `vault.test_hooks()`, or as `store.test_hooks` through the `Store` deref
/// when only the store handle is in scope.
///
/// Every field is interior-mutable and armed through a shared reference, so the
/// store handle hands out `&TestHooks` and needs no lock of its own. A test arms
/// the vault it opened; a sibling test running in the same binary opened a
/// different vault and cannot see it.
#[derive(Default)]
pub(crate) struct TestHooks {
    /// The one-shot delete rendezvous: the step and target entity a delete must
    /// park at, and the two `sync_channel(0)` halves that park it.
    delete_rendezvous: Mutex<Option<DeleteRendezvousChannels>>,
    /// The one-shot sender fired once a headerful delete has proven its header
    /// `Some` and before it takes any write lock.
    after_header_read: Mutex<Option<SyncSender<()>>>,
}

impl TestHooks {
    /// Installs the one-shot rendezvous consumed when a delete of `target`
    /// reaches `step` on this vault. Any other step, or any other entity,
    /// passes straight through.
    pub(crate) fn install_delete_rendezvous(
        &self,
        step: DeleteRendezvous,
        target: EntityId,
        arrived: SyncSender<Option<GateDecisionId>>,
        resume: std::sync::mpsc::Receiver<()>,
    ) {
        *self
            .delete_rendezvous
            .lock()
            .expect("delete rendezvous slot poisoned") = Some((step, target, arrived, resume));
    }

    /// Parks the deleter once if a rendezvous is installed for THIS step and
    /// THIS entity, then clears it so a later delete on the same vault never
    /// blocks on a stale rendezvous. The mutex guard is released before the
    /// blocking `recv` — holding it across the park would deadlock every other
    /// delete on this vault that reaches a seam.
    pub(crate) fn signal_delete_rendezvous(
        &self,
        step: DeleteRendezvous,
        id: &EntityId,
        decision_id: Option<GateDecisionId>,
    ) {
        let mut installed = self
            .delete_rendezvous
            .lock()
            .expect("delete rendezvous slot poisoned");
        if installed
            .as_ref()
            .is_none_or(|(at_step, target, _, _)| *at_step != step || target != id)
        {
            return;
        }
        let (_, _, arrived, resume) = installed.take().expect("checked installed above");
        drop(installed);
        let _ = arrived.send(decision_id);
        let _ = resume.recv();
    }

    /// Installs the one-shot rendezvous sender consumed by
    /// [`Self::signal_after_header_read`]. The raced-delete harness arms the
    /// vault it is about to delete from; the matching receiver `recv()`s on the
    /// eraser side just before its commit.
    pub(crate) fn install_after_header_read_signal(&self, tx: SyncSender<()>) {
        *self
            .after_header_read
            .lock()
            .expect("after-header-read slot poisoned") = Some(tx);
    }

    /// Fires the rendezvous signal exactly once if this vault has a sender
    /// armed, then clears it so a later headerful delete never blocks on a
    /// stale rendezvous. A no-op on every vault that armed nothing.
    pub(crate) fn signal_after_header_read(&self) {
        let sender = self
            .after_header_read
            .lock()
            .expect("after-header-read slot poisoned")
            .take();
        if let Some(sender) = sender {
            // The rendezvous (`sync_channel(0)`) blocks here until the eraser
            // `recv()`s; that recv is positioned immediately before its commit,
            // so the deleter's header read is provably ordered before the erase.
            let _ = sender.send(());
        }
    }
}

struct TargetedLmdbOpenHook {
    path: PathBuf,
    hook: LmdbOpenHook,
}

type LmdbOpenHook = Box<dyn FnOnce(&Path) + Send>;

type LmdbOpenHookSlot = LazyLock<Mutex<Option<TargetedLmdbOpenHook>>>;

/// Fires between the vault root being bound as a descriptor capability and the
/// LMDB environment being opened through it, i.e. INSIDE the existing-only
/// open window. It is the deterministic seam for proving that a root replaced
/// in that window is refused and that the replacement receives no vault bytes.
///
/// On the existing-only door it runs at the TRUE final dereference: the
/// pinned local heed seam calls it after every path, option, and cache
/// preparation step, immediately before `mdb_env_open` itself, so a
/// replacement staged here sits in the window that used to be unreachable
/// inside the library. Production correctness never depends on it being armed
/// — the exact `/proc/self/fd/<dirfd>` path is what makes the open safe; this
/// hook only makes the schedule observable.
#[cfg(target_os = "linux")]
static BEFORE_LMDB_OPEN: LmdbOpenHookSlot = LazyLock::new(|| Mutex::new(None));

/// The mirror of [`BEFORE_LMDB_OPEN`] on the other side of the open: on the
/// existing-only door it runs the instant `mdb_env_open` returns, before any
/// post-open identity check, which is what lets an ABA schedule restore the
/// original before those checks look; on the create-capable door it runs once
/// `EnvOpenOptions::open` has returned.
static AFTER_LMDB_OPEN: LmdbOpenHookSlot = LazyLock::new(|| Mutex::new(None));
thread_local! {
    static FAIL_NEXT_RETRIEVAL_RUN_WRITE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    static FAIL_INITIAL_SEED_COMMIT: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

fn arm_lmdb_open_hook(
    slot: &LmdbOpenHookSlot,
    path: PathBuf,
    hook: impl FnOnce(&Path) + Send + 'static,
) {
    *slot.lock().expect("lmdb-open hook mutex poisoned") = Some(TargetedLmdbOpenHook {
        path,
        hook: Box::new(hook),
    });
}

/// Runs the armed hook only when it targets exactly `path`, so a hook armed by
/// one test can never fire inside another test's vault open.
fn run_lmdb_open_hook(slot: &LmdbOpenHookSlot, path: &Path) {
    let hook = {
        let mut armed = slot.lock().expect("lmdb-open hook mutex poisoned");
        if armed.as_ref().is_some_and(|hook| hook.path == path) {
            armed.take().map(|hook| hook.hook)
        } else {
            None
        }
    };
    if let Some(hook) = hook {
        hook(path);
    }
}

#[cfg(target_os = "linux")]
pub(super) fn arm_before_lmdb_open(path: PathBuf, hook: impl FnOnce(&Path) + Send + 'static) {
    arm_lmdb_open_hook(&BEFORE_LMDB_OPEN, path, hook);
}

#[cfg(target_os = "linux")]
pub(super) fn run_before_lmdb_open(path: &Path) {
    run_lmdb_open_hook(&BEFORE_LMDB_OPEN, path);
}

pub(crate) fn arm_after_lmdb_open(path: PathBuf, hook: impl FnOnce(&Path) + Send + 'static) {
    arm_lmdb_open_hook(&AFTER_LMDB_OPEN, path, hook);
}

pub(super) fn run_after_lmdb_open(path: &Path) {
    run_lmdb_open_hook(&AFTER_LMDB_OPEN, path);
}

pub(crate) fn fail_initial_seed_commit_for(path: PathBuf) {
    FAIL_INITIAL_SEED_COMMIT.with(|armed| *armed.borrow_mut() = Some(path));
}

pub(super) fn take_fail_initial_seed_commit_for(path: &Path) -> bool {
    FAIL_INITIAL_SEED_COMMIT.with(|armed| {
        let mut armed = armed.borrow_mut();
        if armed.as_ref().is_some_and(|armed_path| armed_path == path) {
            armed.take();
            true
        } else {
            false
        }
    })
}

pub(crate) fn fail_next_retrieval_run_write_for(path: PathBuf) {
    FAIL_NEXT_RETRIEVAL_RUN_WRITE.with(|armed| {
        *armed.borrow_mut() = Some(path);
    });
}

pub(super) fn take_fail_next_retrieval_run_write(path: &Path) -> bool {
    FAIL_NEXT_RETRIEVAL_RUN_WRITE.with(|armed| {
        let mut armed = armed.borrow_mut();
        if armed.as_ref().is_some_and(|armed_path| armed_path == path) {
            armed.take();
            true
        } else {
            false
        }
    })
}
