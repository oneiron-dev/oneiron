//! Moved from `crates/oneiron/src/receipt/field_set.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub(crate) use oneiron_verb_wire::receipt::field_set::FIELD_ATTEMPT_CALLER;
pub use oneiron_verb_wire::receipt::field_set::FIELD_BUDGET_REFUSAL;
pub use oneiron_verb_wire::receipt::field_set::FIELD_EXECUTOR_ROLE;
pub use oneiron_verb_wire::receipt::field_set::FIELD_LEASE_GENERATION;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

pub const FIELD_MANIFEST_ATTRIBUTION: &str = "manifest.attribution";
