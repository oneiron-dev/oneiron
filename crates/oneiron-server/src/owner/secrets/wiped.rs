use std::cell::RefCell;
use std::sync::{Arc, Mutex, PoisonError};

/// A test thread's record: the hash of each buffer wiped on it or on a
/// worker of its engine-stack runtime.
pub(crate) type Record = Arc<Mutex<Vec<blake3::Hash>>>;

thread_local! {
    // Per thread, so sibling lib tests share no record. A lib test's
    // request runs on its engine-stack runtime's workers
    // (`crate::test_engine_stack`), not on the test's own thread: each
    // worker takes its test thread's record when it starts ([`share`]).
    static RECORD: RefCell<Record> = RefCell::default();
}

/// This thread's record, for the engine-stack workers it starts.
pub(crate) fn current() -> Record {
    RECORD.with(|record| Arc::clone(&record.borrow()))
}

/// Makes `record` this thread's: an engine-stack worker records what it
/// wipes into its test thread's record.
pub(crate) fn share(record: Record) {
    RECORD.with(|current| *current.borrow_mut() = record);
}

pub(super) fn saw(buffer: &[u8]) {
    let hash = blake3::hash(buffer);
    RECORD.with(|record| {
        record
            .borrow()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(hash);
    });
}

/// How many buffers were wiped that held exactly `bytes` just before the
/// wipe, on this thread or on a worker of its engine-stack runtime.
pub(crate) fn count(bytes: &[u8]) -> usize {
    let held = blake3::hash(bytes);
    RECORD.with(|record| {
        record
            .borrow()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|seen| **seen == held)
            .count()
    })
}
