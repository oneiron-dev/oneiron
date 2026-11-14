//! Moved from `crates/oneiron/src/dreamer_wake/sieve/rules.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_wake_contract::dreamer_wake::sieve::rules::RuleClass;
use regex::Regex;
use serde::Deserialize;
use serde::Serialize;

/// The date patterns, each its own scan.
pub const DATE_PATTERNS: usize = 9;
