//! Schema mirror of the engine's refused second assignment: the task, the assignee it keeps,
//! and the one refused.

use serde_json::{Value, json};
use utoipa::ToSchema;

#[derive(ToSchema)]
#[expect(
    dead_code,
    reason = "OpenAPI mirror of the engine task-assignment conflict"
)]
pub(crate) struct TaskAssignmentConflictSchema {
    task_ref: String,
    held_assignee: String,
    offered_assignee: String,
}

/// The same conflict shape for the hand-written raw error schemas.
pub(crate) fn task_assignment_conflict_schema() -> Value {
    json!({
        "type": "object",
        "required": ["task_ref", "held_assignee", "offered_assignee"],
        "additionalProperties": false,
        "properties": {
            "task_ref": { "type": "string", "pattern": "^[0-9a-f]{32}$" },
            "held_assignee": { "type": "string", "pattern": "^[0-9a-f]{32}$" },
            "offered_assignee": { "type": "string", "pattern": "^[0-9a-f]{32}$" },
        },
    })
}
