//! One native allocation account and the durable outcome of its own write.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub use heed::PageAccount as NativeWriteAccount;

/// One attempt through the ordinary write door. Admission happens outside the
/// entire door; the account's native callbacks only consume preadmitted room.
/// Construct a fresh attempt for each replay, reusing the same allocation account.
pub struct NativeWriteAttempt {
    account: Arc<dyn NativeWriteAccount>,
    committed: AtomicBool,
}

impl NativeWriteAttempt {
    pub fn new(account: Arc<dyn NativeWriteAccount>) -> Self {
        Self {
            account,
            committed: AtomicBool::new(false),
        }
    }

    /// Whether this attempt's own rows reached a successful root commit. A
    /// later write-door error does not roll them back and must not replay them.
    pub fn own_rows_committed(&self) -> bool {
        self.committed.load(Ordering::Acquire)
    }

    pub(super) fn account(&self) -> Arc<dyn NativeWriteAccount> {
        Arc::clone(&self.account)
    }

    pub(super) fn mark_committed(&self) {
        self.committed.store(true, Ordering::Release);
    }
}
