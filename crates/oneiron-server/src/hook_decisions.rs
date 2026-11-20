//! The hook `ai.verdict` decisions one thread collects while it runs its
//! row's hooks (FIX 8042): a browser batch's or library run's pre and post
//! hooks, which run on the calling thread, so the run's `model_free` reads
//! them. Record only: no ceiling is set and no verdict changes.
//!
//! Outside the verdict host's gate (`hook_verdict`): the facade and
//! code-mode doors collect around every row whether or not this build runs
//! a hook sandbox, so the mesh-only server build needs the collector
//! without the sandbox feature.

use std::cell::RefCell;

thread_local! {
    /// The hook decisions a browser call collects on this thread while it
    /// runs its row's hooks (FIX 8042).
    static COLLECTED: RefCell<Option<Vec<serde_json::Value>>> = const { RefCell::new(None) };
}

/// Runs `run`, collecting each hook `ai.verdict` decision this thread
/// answers meanwhile (FIX 8042): a browser batch's or library run's pre and
/// post hooks, which run on the calling thread, so the run's `model_free`
/// reads them. Record only: no ceiling is set and no verdict changes.
pub(crate) fn collect_hook_decisions<R>(run: impl FnOnce() -> R) -> (R, Vec<serde_json::Value>) {
    let outer = COLLECTED.with(|collected| collected.replace(Some(Vec::new())));
    let ran = run();
    let decisions = COLLECTED.with(|collected| collected.replace(outer));
    (ran, decisions.unwrap_or_default())
}

/// Keeps one hook `ai.verdict` decision in this thread's running collection
/// (FIX 8042). A decision answered outside any collection is dropped.
#[cfg_attr(not(feature = "code-sandbox-wasmtime"), allow(dead_code))]
pub(crate) fn record_hook_decision(decision: serde_json::Value) {
    COLLECTED.with(|collected| {
        if let Some(decisions) = collected.borrow_mut().as_mut() {
            decisions.push(decision);
        }
    });
}
