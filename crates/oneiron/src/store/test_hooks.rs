//! Test-only failure-injection hooks for the store open and retrieval
//! write paths.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

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
pub(crate) fn arm_before_lmdb_open(path: PathBuf, hook: impl FnOnce(&Path) + Send + 'static) {
    arm_lmdb_open_hook(&BEFORE_LMDB_OPEN, path, hook);
}

#[cfg(target_os = "linux")]
pub(crate) fn run_before_lmdb_open(path: &Path) {
    run_lmdb_open_hook(&BEFORE_LMDB_OPEN, path);
}

pub(crate) fn arm_after_lmdb_open(path: PathBuf, hook: impl FnOnce(&Path) + Send + 'static) {
    arm_lmdb_open_hook(&AFTER_LMDB_OPEN, path, hook);
}

pub(crate) fn run_after_lmdb_open(path: &Path) {
    run_lmdb_open_hook(&AFTER_LMDB_OPEN, path);
}

pub(crate) fn fail_initial_seed_commit_for(path: PathBuf) {
    FAIL_INITIAL_SEED_COMMIT.with(|armed| *armed.borrow_mut() = Some(path));
}

pub(crate) fn take_fail_initial_seed_commit_for(path: &Path) -> bool {
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

pub(crate) fn take_fail_next_retrieval_run_write(path: &Path) -> bool {
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
