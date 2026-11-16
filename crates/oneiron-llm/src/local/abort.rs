//! Abort handle shared between a generation and its event stream.
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Abort handle for one local generation.
///
/// The adapter checks this handle between local output parts and also flips it
/// when a stream is dropped before a terminal event.
#[derive(Debug, Clone, Default)]
pub struct LocalAbortHandle {
    aborted: Arc<AtomicBool>,
}

impl LocalAbortHandle {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn abort(&self) {
        self.aborted.store(true, Ordering::SeqCst);
    }

    #[must_use]
    pub fn is_aborted(&self) -> bool {
        self.aborted.load(Ordering::SeqCst)
    }
}
