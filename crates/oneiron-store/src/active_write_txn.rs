//! The calling thread's open write transactions: a guard raises the depth
//! while a vault write runs its closure, and names the environment whose
//! writer that write holds. A door that must not open a writer of its own
//! inside any write reads the depth; a door that waits for one environment's
//! writer asks whether this thread holds that one.

use std::cell::{Cell, RefCell};

thread_local! {
    static ACTIVE_WRITE_TXN_DEPTH: Cell<usize> = const { Cell::new(0) };
    static ACTIVE_WRITE_TXN_ENVS: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
}

pub struct ActiveWriteTxnGuard {
    env: u64,
}

impl Drop for ActiveWriteTxnGuard {
    fn drop(&mut self) {
        ACTIVE_WRITE_TXN_DEPTH.with(|depth| {
            depth.set(depth.get().saturating_sub(1));
        });
        ACTIVE_WRITE_TXN_ENVS.with_borrow_mut(|envs| {
            if let Some(at) = envs.iter().rposition(|env| *env == self.env) {
                envs.remove(at);
            }
        });
    }
}

/// Raises the depth for a write that holds the writer of environment `env`,
/// a number no other environment open in this process shares.
pub fn active_write_txn_guard(env: u64) -> ActiveWriteTxnGuard {
    ACTIVE_WRITE_TXN_DEPTH.with(|depth| {
        depth.set(depth.get().saturating_add(1));
    });
    ACTIVE_WRITE_TXN_ENVS.with_borrow_mut(|envs| envs.push(env));
    ActiveWriteTxnGuard { env }
}

pub fn active_write_txn_depth() -> usize {
    ACTIVE_WRITE_TXN_DEPTH.with(Cell::get)
}

/// Whether a write on this thread holds the writer of environment `env`. A
/// write on another environment does not: that one's writer may be open on
/// another thread.
pub fn active_write_txn_holds(env: u64) -> bool {
    ACTIVE_WRITE_TXN_ENVS.with_borrow(|envs| envs.contains(&env))
}
