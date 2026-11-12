//! Moved from `crates/oneiron/src/code_run/activity.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::attempt_id::AttemptId;
use oneiron_store::store_clock::StoreClock;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;

/// What a scope holds open: a tool call or a model call.
#[derive(Debug, Clone, Copy)]
pub enum Scope {
    Tool,
    Generation,
}
