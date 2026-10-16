//! Foreign-agent dispatch: the connector shapes, the egress seam, and the
//! terminal exhaust capture for agents this runtime does not host.
//!
//! This organ sits BESIDE [`crate::agent_dispatch`] rather than inside it.
//! Native in-process agents keep their spawn semantics untouched; a foreign
//! agent is not spawned at all, it is CONNECTED TO, and the two concerns share
//! nothing but the attempt row they both land on. Widening the native dispatch
//! input to carry connector configuration would have mixed "how do I start
//! this" with "how do I reach that".
//!
//! Exactly three v1 connector shapes exist, and the enum is closed on purpose:
//!
//! 1. [`ByoaConnectorSpec::Endpoint`] — a provider-neutral endpoint config that
//!    a host factory resolves into an existing [`LlmBackend`](crate::LlmBackend). The provider
//!    codecs stay host-owned; this module never speaks a wire protocol.
//! 2. [`ByoaConnectorSpec::ProtocolAttach`] — MCP, and only MCP. A2A gets no
//!    variant here, so an A2A attach is a compile error rather than a runtime
//!    refusal that a later change could soften into a permissive default.
//! 3. [`ByoaConnectorSpec::CliSandbox`] — an argv-only command run as a
//!    foreign sandbox guest against a real checkout. There is no shell string
//!    anywhere in this module, and no direct socket: network access exists
//!    only through an injected [`ByoaEgressPort`].
//!
//! Named runners (Claude Code, Codex, OpenCode) are [`DreamerProviderAdapter`]s
//! in a [`ProviderAdapterRegistry`]. An owner's [`RunnerSeatPolicy`] orders the
//! seats a Dreamer's work may run on, and [`ByoaDispatcher::route_runner_terminal`]
//! routes a spent seat's work under it: park, next seat, or back to the
//! Dreamer's own model roles. A vendor login never crosses this seam; it stays
//! with the official CLI on a runtime its vendor's terms allow
//! ([`login_placement`]).
//!
//! Credentials cross this seam as [`SandboxCredentialHandle`](crate::code_sandbox::SandboxCredentialHandle) references and
//! never as bytes. That is the whole redaction story: there is no secret in
//! any type here to leak into an attempt payload, a `Debug` rendering, or a
//! terminal receipt, because none of them ever holds one.
//!
//! A foreign agent owes this runtime no completion protocol. What it owes is
//! EXHAUST — transcript, stdout, stderr, diff bundle, checkpoint frontier —
//! and [`ByoaDispatcher::capture_terminal_exhaust`] folds that into exactly
//! one BLOB_ARTIFACT version whose `artifact@version` string becomes the
//! attempt row's result reference. An executor that stops without completing
//! is [`crate::attempt_queue::AttemptState::Abandoned`], not failed, and still
//! points at the last exhaust it produced.

mod provider;
pub use provider::{
    CLAUDE_CODE_PROGRAM, CODEX_PROGRAM, ClaudeCodeRunner, CodexRunner, DreamerProviderAdapter,
    DreamerProviderInput, OPENCODE_PROGRAM, OpenCodeRunner, ProviderAdapterRegistry,
};
mod seat;
pub use seat::{
    LoginPlacement, MAX_RUNNER_SEATS, OnSeatSpent, RUNNER_SEAT_DEDUPE_PREFIX, RunnerSeat,
    RunnerSeatPolicy, RunnerWork, SeatAuth, SeatRoute, SeatSpent, login_placement, spent_seat_in,
};
mod connector;
mod dispatcher;
mod error;
mod exhaust;
pub mod official_seats;
mod validate;

pub use self::official_seats::{
    ANTHROPIC_API_BASE_URL, ClaudeAgentSdkSeatAdapter, ClaudeCodeSeatAdapter, CodexSeatAdapter,
    DispatchOfficialSeat, DrySeatDecision, DrySeatFallback, GrokApiKeySeatAdapter,
    OfficialSeatAdapter, OfficialSeatDispatchOutcome, OfficialSeatInput, OfficialSeatRegistry,
    OfficialSeatRoute, OfficialSeatSpec, OfficialSeatStamp, OfficialSeatVendor,
    SIWC_AUTHORIZE_ENDPOINT, SIWC_RESPONSES_BASE_URL, SeatLoginPlan, SeatPlacementApproval,
    SeatPlanWindow, SignInWithChatGptAdapter, SiwcAuthorizeRequest, XAI_API_BASE_URL,
    check_seat_placement, decide_dry_seat, pkce_s256_challenge, seat_login_plan,
    siwc_authorize_url, validate_official_seat,
};

pub use self::connector::{
    BYOA_ATTEMPT_KIND, BYOA_CONNECTOR_SCHEMA_VERSION, BYOA_EXHAUST_MEDIA_TYPE,
    BYOA_MAX_EXHAUST_STREAM_BYTES, BYOA_MAX_EXHAUST_TOTAL_BYTES, BYOA_RESULT_REF_PREFIX,
    ByoEndpointProtocol, ByoEndpointSpec, ByoaAttemptPayload, ByoaConnectorKind, ByoaConnectorSpec,
    ByoaDispatchOutcome, ByoaDispatchStatus, CliSandboxSpec, DispatchByoa, ProtocolAttachKind,
    ProtocolAttachSpec, decode_byoa_attempt_payload, encode_byoa_attempt_payload,
};
pub use self::dispatcher::{
    ByoEndpointBackendFactory, ByoaCliExecutor, ByoaDispatcher, ByoaExecutionFence, ByoaMcpExecutor,
};
pub use self::error::{ByoaError, ByoaResult};
pub use self::exhaust::{
    BYOA_DEFAULT_ABANDON_REASON, BYOA_DEFAULT_FAILURE_REASON, ByoaEgressLease, ByoaEgressPort,
    ByoaExhaust, ByoaTerminalDisposition, ByoaTerminalReceipt, CaptureByoaExhaust,
    byoa_exhaust_artifact_id, byoa_result_ref, decode_byoa_exhaust, parse_byoa_result_ref,
    read_checkpoint_frontier,
};
pub use self::validate::validate_connector;

#[cfg(test)]
mod tests;

// The flat dispatch_byoa.rs module used to provide these names to the sibling
// test module through `use super::*`: every dispatch_byoa-internal item the
// tests name bare. After the directory split the seam re-imports them so
// `tests.rs` (and `tests/successor/`) resolve exactly as they did before.
#[cfg(test)]
use self::{connector::*, error::*, exhaust::*, validate::*};
#[cfg(test)]
use crate::attempt_queue::{
    AttemptId, AttemptRecord, AttemptResultRef, EnqueueAttempt, FailAttempt, SetAttemptResult,
};
#[cfg(test)]
use crate::blob_artifact::{
    BlobArtifactBody, BlobVersionProvenance, read_blob_artifact_head_in_txn,
};
#[cfg(test)]
use crate::checkout::{
    CheckoutFactSink, CheckoutId, CheckoutLeaseAct, CheckoutLeaseService, CheckoutLeaseState,
    CheckoutLiveness,
};
#[cfg(test)]
use crate::code_sandbox::microvm::ExecutionBudget;
#[cfg(test)]
use crate::code_sandbox::{SandboxBoundaryContract, SandboxCredentialHandle, SandboxGuestTier};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::Error;
#[cfg(test)]
use crate::temporal::TimeRange;
