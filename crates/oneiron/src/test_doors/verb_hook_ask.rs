//! Doors for `oneiron-server`'s `tests/workflow_park_save_retry.rs`
//! ([WORKFLOW-PARK-FAIL-RETRYABLE]): a verb pre-hook's ask saved under a
//! call's invocation, the owner's proceed answer, and what a later try of
//! that invocation finds (`crate::runtime_hooks::verb::park_ask_door`).
//! Compiled only under `--cfg oneiron_test_support`; never API.

pub use crate::runtime_hooks::verb::park_ask_door::{HookAsk, SavedAsk};
