//! Moved from `crates/oneiron/src/code_run/types/request.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::code_run::types::*;

/// One SDK verb-table call from code mode, at the verb's SDK path.
#[derive(Debug, Clone, PartialEq)]
pub struct SelfAgentVerbCall {
    pub verb: verbs::AgentVerb,
    /// The verb's whole typed input, as its REST body and SDK bindings take it.
    pub input: serde_json::Value,
}
