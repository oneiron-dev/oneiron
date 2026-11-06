//! Payload-aware scope vocabulary and pure evaluation live with consent.

pub use crate::consent::tool_scope::{
    DataClass, ScopedMcpBatchVerdict, ScopedMcpCall, ScopedMcpCallContext,
    ScopedMcpConsentDecision, ScopedMcpEscalationReason, ScopedMcpGrantRef,
    evaluate_scoped_mcp_call, evaluate_scoped_mcp_calls,
};
