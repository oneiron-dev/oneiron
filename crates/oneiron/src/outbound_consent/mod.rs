//! Payload-aware consent and transport boundary for scoped outbound tools.
//!
//! A real transport implementation is intentionally outside this module. Any
//! implementation plugged into [`OutboundResultSender`] must enforce
//! [`OutboundTransportPolicy`]: stdio children run with explicit environment,
//! inherited-FD, and filesystem allowlists; network transports verify TLS; and
//! the resolved endpoint checked here is the endpoint shown at grant time.

mod authority;
mod execution;
mod recovery;
mod result_scrub;
mod scope;

#[cfg(test)]
mod tests;

pub(crate) use self::authority::FrozenCallValidation;
#[cfg(test)]
pub(crate) use self::authority::observed_freeze_events_since;
pub use self::authority::{
    FrozenMcpPayload, OutboundBindingAuthority, OutboundBindingValidation, ScopedMcpAuthorization,
};
pub use self::execution::ScopedMcpDispatchResult;
// Test-only execution entry point: the durable lane is driven by recovery in
// production builds, so the re-export lives under the same cfg as its callers.
#[cfg(test)]
use self::execution::execute_scoped_mcp_outbound_call;
pub use self::recovery::{
    AuthorizedRecoveryError, AuthorizedRecoveryReport, recover_authorized_outbound_intents,
};
pub use self::result_scrub::{
    OutboundResultSender, OutboundTransportPolicy, OutboundTransportResult,
    QuarantinedOutboundResult, RawOutboundResult, ScrubbedOutboundResult, StdioSandboxPolicy,
    scrub_outbound_result,
};
pub use self::scope::{
    DataClass, ScopedMcpBatchVerdict, ScopedMcpCall, ScopedMcpCallContext,
    ScopedMcpConsentDecision, ScopedMcpEscalationReason, ScopedMcpGrantRef,
    evaluate_scoped_mcp_call, evaluate_scoped_mcp_calls,
};

// The flat outbound_consent.rs module used to provide these names to the
// sibling test module through `use super::*`: its own private crate import
// header, and every outbound-consent-internal item the tests name bare.
// After the directory split the seam re-imports both so `tests.rs` resolves
// exactly as it did before.
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::attempt_queue::AttemptId;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::outbound_intent_ledger::{
    FrozenOutboundCall, IntentState, OutboundAuthorizationBinding, OutboundCallClass,
    OutboundSendOutcome, OutboundToolDescriptor,
};
