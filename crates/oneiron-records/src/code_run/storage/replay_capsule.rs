//! Moved from `crates/oneiron/src/code_run/storage/replay_capsule.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::code_run::contribution::ContributionReplayUnavailable;

/// What a fork writer kept, or why it kept nothing (FIX 6256). The writer
/// that meets the fence names the reason, and the runner keeps it as it is.
pub type ForkWrite<T> = std::result::Result<T, ContributionReplayUnavailable>;
pub mod fork_erase;
