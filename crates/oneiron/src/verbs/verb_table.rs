//! The runtime's one [`VerbTable`] (untangle slice 5.0a): core's hook boundary and room turns
//! reach the generated catalog and dispatch through it. Each method calls exactly what core
//! called before the slice.

use serde_json::Value;

use crate::memory::{Memory, MemoryResult};
use crate::verb_table::VerbTable;

/// The verb table generated from `scripts/sdk/verbs/`, as core reaches it.
#[derive(Debug, Clone, Copy)]
pub struct GeneratedVerbTable;

/// The one [`GeneratedVerbTable`] every door passes as `verbs: &dyn VerbTable`.
pub static VERB_TABLE: GeneratedVerbTable = GeneratedVerbTable;

impl VerbTable for GeneratedVerbTable {
    fn validate_input(&self, verb: &str, value: &Value) -> MemoryResult<()> {
        super::validate_input(verb, value)
    }

    fn validate_browser_input(&self, verb: &str, value: &Value) -> MemoryResult<()> {
        super::validate_browser_input(verb, value)
    }

    fn writes(&self, verb: &str) -> bool {
        super::AgentVerb::from_name(verb).is_some_and(super::AgentVerb::writes)
    }

    fn no_record(&self, verb: &str) -> bool {
        super::NO_RECORD_ROWS.contains(&verb)
    }

    fn invoke_with_notice(
        &self,
        memory: &Memory<'_>,
        verb: &str,
        value: Value,
    ) -> (MemoryResult<Value>, Option<bool>) {
        super::invoke_with_notice(memory, verb, value)
    }

    fn receipt_declared_refs(
        &self,
        memory: &Memory<'_>,
        verb: &str,
        value: Value,
    ) -> MemoryResult<()> {
        super::receipt_declared_refs(memory, verb, value)
    }
}
