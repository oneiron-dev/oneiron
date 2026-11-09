//! Port of generate.py:853-1417: the MCP dispatch (`agent_verb_dispatch.rs`), its argument projections and the
//! task-work rules the server's doors share (G4a).

use crate::py::value::Dict;

/// Port of generate.py:899-901 (takes_task_decisions): whether the served doors run this row on a worker with the
/// decision ladder bound (OF-533, FIX 2762). Absent is false.
pub(crate) fn takes_task_decisions(row: &Dict) -> bool {
    super::row_access::flag(row, "task_decisions")
}
