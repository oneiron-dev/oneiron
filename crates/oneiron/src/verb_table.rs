//! Core's view of the verb table (untangle slice 5.0a, S5-2 = A, S50A-3 = A): the per-verb
//! behaviour core's hook boundary and room turns call, and nothing else.
//!
//! The runtime implements it once, from its generated catalog and dispatch
//! (`crate::verbs::VERB_TABLE`). The functions that take it are the hook-boundary functions
//! (`task_verb::verb_hook_boundary`) and `RoomTurnHandle`'s dispatch methods. Their callers, the
//! runtime modules and the server's doors, pass it as `verbs: &dyn VerbTable`, as
//! `typed_row_validated` already takes its input check. No core caller passes it on, and
//! `Vault` holds none. The verb names core reads by name are in `crate::verb_names`.

use serde_json::Value;

use crate::memory::{Memory, MemoryResult};

/// The per-verb behaviour core calls through the runtime.
pub trait VerbTable: Sync {
    /// Checks `value` against row `verb`'s typed input.
    ///
    /// # Errors
    ///
    /// The row's input refusal; an unknown row's.
    fn validate_input(&self, verb: &str, value: &Value) -> MemoryResult<()>;

    /// Checks `value` against row `verb`'s run-bound browser projection input.
    ///
    /// # Errors
    ///
    /// As [`VerbTable::validate_input`].
    fn validate_browser_input(&self, verb: &str, value: &Value) -> MemoryResult<()>;

    /// Whether row `verb` writes; `false` for a name that is not a row.
    fn writes(&self, verb: &str) -> bool;

    /// Whether row `verb` keeps no call receipt on any transport (`no_record`
    /// on the row).
    fn no_record(&self, verb: &str) -> bool;

    /// Runs row `verb` on `memory` through its generated dispatch and the
    /// row boundary: its result, and the notice bit of its pre chain.
    fn invoke_with_notice(
        &self,
        memory: &Memory<'_>,
        verb: &str,
        value: Value,
    ) -> (MemoryResult<Value>, Option<bool>);

    /// Runs row `verb`'s record-reference check on `memory` alone.
    ///
    /// # Errors
    ///
    /// The row's refusal of a reference its input declares.
    fn receipt_declared_refs(
        &self,
        memory: &Memory<'_>,
        verb: &str,
        value: Value,
    ) -> MemoryResult<()>;
}
