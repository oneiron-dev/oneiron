//! Test-only failure-injection hooks for the store open and retrieval
//! write paths.

use std::cell::RefCell;

use super::*;

struct TargetedAfterLmdbOpenHook {
    path: PathBuf,
    hook: AfterLmdbOpenHook,
}

type AfterLmdbOpenHook = Box<dyn FnOnce(&Path) + Send>;

static AFTER_LMDB_OPEN: LazyLock<Mutex<Option<TargetedAfterLmdbOpenHook>>> =
    LazyLock::new(|| Mutex::new(None));
thread_local! {
    static FAIL_NEXT_RETRIEVAL_RUN_WRITE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    static FAIL_INITIAL_SEED_COMMIT: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

pub(crate) fn arm_after_lmdb_open(path: PathBuf, hook: impl FnOnce(&Path) + Send + 'static) {
    *AFTER_LMDB_OPEN
        .lock()
        .expect("after-lmdb-open hook mutex poisoned") = Some(TargetedAfterLmdbOpenHook {
        path,
        hook: Box::new(hook),
    });
}

pub(crate) fn run_after_lmdb_open(path: &Path) {
    let hook = {
        let mut armed = AFTER_LMDB_OPEN
            .lock()
            .expect("after-lmdb-open hook mutex poisoned");
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
