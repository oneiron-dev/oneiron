//! Schema mirror of the engine's pending block: the check-in a pending refusal waits on.

use serde_json::{Value, json};
use utoipa::ToSchema;

#[derive(ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[expect(dead_code, reason = "OpenAPI mirror of the engine pending block")]
pub(crate) enum MemoryPendingSchema {
    CheckIn { check_in: String },
}

/// The same pending shape for the hand-written raw error schemas.
pub(crate) fn memory_pending_schema() -> Value {
    json!({
        "type": "object",
        "required": ["kind", "check_in"],
        "additionalProperties": false,
        "properties": {
            "kind": { "type": "string", "enum": ["check_in"] },
            "check_in": { "type": "string", "pattern": "^[0-9a-f]{32}$" },
        },
    })
}
