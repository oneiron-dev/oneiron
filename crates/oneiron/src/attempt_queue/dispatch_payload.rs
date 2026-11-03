//! Dispatch payload kind carried by the background attempt queue.

/// Payload-level attempt type carried inside the `"dreamer"` queue kind —
/// invisible to existing dreamer consumers, which match on their own types.
pub const AGENT_DISPATCH_ATTEMPT_TYPE: &str = "agent.dispatch";

