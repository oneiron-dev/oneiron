//! The calling thread's open write-transaction depth: a guard raises it while
//! a vault write runs its closure, and a door that must not open a writer of
//! its own inside one reads it.

use std::cell::Cell;

thread_local! {
    static ACTIVE_WRITE_TXN_DEPTH: Cell<usize> = const { Cell::new(0) };
}

pub(crate) struct ActiveWriteTxnGuard;

impl Drop for ActiveWriteTxnGuard {
    fn drop(&mut self) {
        ACTIVE_WRITE_TXN_DEPTH.with(|depth| {
            depth.set(depth.get().saturating_sub(1));
        });
    }
}

pub(crate) fn active_write_txn_guard() -> ActiveWriteTxnGuard {
    ACTIVE_WRITE_TXN_DEPTH.with(|depth| {
        depth.set(depth.get().saturating_add(1));
    });
    ActiveWriteTxnGuard
}

pub(crate) fn active_write_txn_depth() -> usize {
    ACTIVE_WRITE_TXN_DEPTH.with(Cell::get)
}
