//! Durable queue kind discriminators for foreign-agent and surface-event dispatch.

/// Attempt `kind` every foreign-agent dispatch lands under.
pub const BYOA_ATTEMPT_KIND: &str = "agent.dispatch.byoa";

/// Attempt-queue kind owning inbound surface-event dispatch.
pub const SURFACE_EVENT_ATTEMPT_KIND: &str = "surface_event.dispatch.v1";

/// Payload-level attempt type carried inside the `"dreamer"` queue kind —
/// invisible to existing dreamer consumers, which match on their own types.
pub const AGENT_DISPATCH_ATTEMPT_TYPE: &str = "agent.dispatch";
