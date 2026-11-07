//! Dispatch payload kind carried by the background attempt queue.

pub use crate::store::dispatch_attempt_kind::AGENT_DISPATCH_ATTEMPT_TYPE;

/// The pinned dispatch-input body keys (dreamer-payload-side snake_case).
pub const AGENT_DISPATCH_INPUT_KEYS: [&str; 25] = [
    "schema_version",
    "target",
    "agent_def",
    "preset",
    "definition",
    "context_spec",
    "context_from",
    "depth_remaining",
    "project_ref",
    "spawn_intent",
    "scope",
    "healer_case",
    "task_type_ref",
    "budget",
    "launch",
    "origin_conversation",
    "room",
    "join",
    "team",
    "plan",
    "objectives",
    "comm",
    "direct_spawn",
    "requester",
    "task_type_parents",
];
