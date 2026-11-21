//! Doors for tests/msgpack_lib_rows_a.rs (PLAN-UC-08 PR 5a). Compiled only under
//! --cfg oneiron_test_support; never API.

use rmpv::Value;

use crate::error::Result;

/// The value an anchored-annotation body holds under `key`.
pub fn annotation_map_get(value: &Value, key: &str) -> Option<Value> {
    crate::anchored_annotation::annotation_map_get_for_test(value, key)
}

/// The value a research-continuation artifact map holds under `key`.
pub fn continuation_field(value: &Value, key: &str) -> Option<Value> {
    crate::autoreason_campaign::research::continuation_field_for_test(value, key)
}

/// The value a code-run dispatch outcome map holds under `key`.
pub fn dispatch_outcome_map_get(entries: &[(Value, Value)], key: &str) -> Result<Value> {
    crate::code_run::dispatch_outcome_map_get_for_test(entries, key)
}

/// The value a plugin fit-install record map holds under `key`.
pub fn fit_map_entry(entries: &[(Value, Value)], key: &str) -> Option<Value> {
    crate::context_board::fit_map_entry_for_test(entries, key)
}

/// The value a conversation-DAG body holds under `name`.
pub fn quote_field(fields: &[(Value, Value)], name: &str) -> Option<Value> {
    crate::conversation_dag::quote_field_for_test(fields, name)
}

/// The value a retained conflict alternative holds under `key`.
pub fn retained_field(entry: &Value, key: &str) -> Result<Value> {
    crate::dreamer_consolidation::retained_field_for_test(entry, key)
}
