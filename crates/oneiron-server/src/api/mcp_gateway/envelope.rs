//! JSON-RPC envelope types and request dispatch.

pub(crate) use self::http::*;
pub(crate) use self::request::*;
use super::booking_call::resolve_handshake_caller;
use super::call_meta::MCP_INVOCATION_META;
use super::tool_receipt::mcp_call_receipt;
use super::{
    admission, booking_call, clock_repair_call, device_release, ensure_mcp_actor_matches,
    execute_mcp_tool, mcp_actor_result, mcp_admit_scoped_call, mcp_error_response, mcp_params,
    mcp_validated_call_args, wakes, wire,
};
use crate::api::facade::{self, DoorClaim};
use crate::auth::Locality;
use crate::mcp::McpCacheHint;
use crate::mcp::McpPageBudget;
use crate::mcp::McpResolvedActor;
use crate::mcp::McpResultMetadata;
use crate::mcp::McpRetrievalHealth;
use crate::mcp::McpSurfaceMode;
use crate::server::SyncServer;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::{Extensions, HeaderMap, HeaderValue};
use axum::response::IntoResponse;
use axum::response::Json;
use axum::response::Response;
use oneiron::claim::CallerLocality;
use oneiron::runtime_hooks::InvocationId;
use oneiron::runtime_hooks::verb::InvocationOutcome;
use serde::Deserialize;
use serde_json::Value;
use serde_json::json;
use std::sync::Arc;

mod http;
mod request;

pub(crate) const MCP_CREDENTIAL_HEADER: &str = "x-oneiron-mcp-credential";

pub(crate) const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

#[derive(Debug, Deserialize)]
pub(crate) struct McpJsonRpcRequest {
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct McpToolCallParams {
    pub(super) name: String,
    #[serde(default)]
    pub(super) arguments: Value,
    /// The call's MCP metadata; `oneiron/invocation` names the logical verb
    /// its verb hooks fire once for (ARCH-0080 §3).
    #[serde(default, rename = "_meta")]
    pub(super) meta: Option<serde_json::Map<String, Value>>,
}

#[derive(Debug)]
pub(crate) struct McpGatewayError {
    pub(super) code: i64,
    pub(super) kind: &'static str,
    pub(super) message: String,
    pub(super) field: Option<String>,
    pub(super) vault_read: Option<Box<oneiron::code_run::vault_read::VaultReadError>>,
    /// Set only by the stale-write-verb-target refusal (ONE-1936); surfaces as
    /// `error.data.successor_short_id` so a client reads a FIELD instead of
    /// parsing the message.
    pub(super) successor_short_id: Option<String>,
    /// The effective scope the refusal was made under, present for every
    /// actor-derived error (ONE-1704). Absent only before a credential
    /// resolves, where there is no scope yet to state.
    // Boxed for SIZE only: inline, this one payload made the whole error 168
    // bytes, so every `Result<_, McpGatewayError>` in this module carried it.
    // The indirection is private — `mcp_error_response` moves the same `Value`
    // back out under the same key, so nothing on the wire moves.
    pub(super) effective_scope: Option<Box<Value>>,
    /// The bound a request field passed and the bytes it carried, surfaced
    /// as `error.data.max_bytes` and `error.data.received_bytes`. Boxed for
    /// size, as `effective_scope` is.
    pub(super) byte_bound: Option<Box<(usize, usize)>>,
    /// A `WRONG_ROOT` refusal's correction, surfaced as `error.data.attempted`,
    /// `error.data.replacement` and `error.data.schemaRef`.
    pub(super) wrong_root: Option<Box<oneiron::memory::MemoryWrongRoot>>,
    /// The refused `tools/call`'s lasting receipt (OF-538), surfaced as
    /// `error.data.receipt_ref` (and `error.data.no_record` for the anonymous
    /// exception). Boxed for size, as `effective_scope` is.
    pub(super) call_receipt: Option<Box<crate::api::call_receipt::CallStamp>>,
    /// The call receipt an `invoke_action` call's verb-table row's reply
    /// stated (FIX 5275), surfaced as `error.data.row_receipt`, apart from
    /// this call's own. Boxed for size, as `call_receipt` is.
    pub(super) row_receipt: Option<Box<crate::api::call_receipt::CallStamp>>,
    /// A verb hook's stop (ARCH-0080 §3), surfaced as `error.data.hook`; a
    /// code-mode door hands it back to the run as the typed stop.
    pub(super) hook: Option<Box<oneiron::runtime_hooks::VerbHookStop>>,
    /// When a model call no provider answered may be sent again, in seconds
    /// (FIX 3194), surfaced as `error.data.retry_after`; a code-mode door
    /// hands it back to the run as the typed outage.
    pub(super) retry_after: Option<u64>,
    /// A failed code run's kept type feedback, released apart from the
    /// refusal (FIX 10389, 10390), surfaced as `error.data.program_steps`.
    /// Never among the words its release reads. Boxed for size, as
    /// `effective_scope` is.
    pub(super) program_steps: Option<Box<super::type_feedback_release::ErrorProgramSteps>>,
    /// The refusal's stable reason codes, in its producer's order (FIX
    /// 7398), surfaced as `error.data.reason_codes` when it named any.
    pub(super) reason_codes: Vec<String>,
}

impl McpGatewayError {
    pub(super) fn new(code: i64, kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            kind,
            message: message.into(),
            field: None,
            vault_read: None,
            successor_short_id: None,
            effective_scope: None,
            byte_bound: None,
            wrong_root: None,
            call_receipt: None,
            row_receipt: None,
            hook: None,
            retry_after: None,
            program_steps: None,
            reason_codes: Vec::new(),
        }
    }

    /// A request field past a byte bound (`[limits]`): the typed tool error
    /// names the field, the bound and the bytes received.
    pub(super) fn payload_too_large(
        field: impl Into<String>,
        max_bytes: usize,
        received_bytes: usize,
    ) -> Self {
        let mut error = Self::new(
            -32602,
            "payload_too_large",
            "a request field exceeds its byte bound",
        )
        .with_field(field);
        error.byte_bound = Some(Box::new((max_bytes, received_bytes)));
        error
    }

    pub(super) fn with_field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }

    pub(super) fn with_successor_short_id(mut self, successor_short_id: impl Into<String>) -> Self {
        self.successor_short_id = Some(successor_short_id.into());
        self
    }

    fn with_effective_scope(mut self, actor: &McpResolvedActor) -> Self {
        self.effective_scope = Some(Box::new(crate::mcp::mcp_effective_scope_value(
            &actor.scope,
        )));
        self
    }
}

/// One request's actor plus the endpoint it arrived on.
///
/// The mode is REGISTRATION state carried down from the route, never something
/// the request could select. Everything that already spoke `McpResolvedActor`
/// still does, through `Deref`.
#[derive(Clone, Debug)]
pub(crate) struct McpCallContext {
    pub(crate) actor: McpResolvedActor,
    pub(crate) mode: McpSurfaceMode,
    pub(crate) request_id: String,
    /// Where this request's writes land (`write_facet::landing_facet`),
    /// judged once from the session it names.
    pub(crate) landing: Result<Option<oneiron::EntityId>, crate::api::write_facet::LandingRefused>,
    /// The logical verb this request runs, when it named one: its verb hooks
    /// fire once for it, however many wrappers it crosses (ARCH-0080 §3).
    pub(crate) invocation: Option<oneiron::runtime_hooks::InvocationId>,
    /// The hook pause the request resumes beside its invocation, by its ask
    /// handle (`_meta.hook_ask`, L13 PR-D): bound to its rows' memory, so a
    /// session-only call's pause that is gone refuses. Never inherited by a
    /// call of its own.
    pub(crate) hook_ask: Option<oneiron::EntityId>,
    /// The off-record session the request names, bound to its rows' memory
    /// surface: inside an anonymous one a reference refusal writes no
    /// receipt, as the call writes none (OF-063, OF-538).
    pub(crate) off_record_session: Option<String>,
    /// The room the request's room turn names (`x-oneiron-room-turn`), as
    /// the facade reads it: the room the caller's board renders as ROOM and
    /// reads its MEMORIES in, once the caller's own read admits it (FIX
    /// 1051). Never guessed from anything else.
    pub(crate) room_turn: Option<oneiron::EntityId>,
    /// The drain's permit, on a call settlement runs again (ARCH-0080 §3
    /// Ask): its row's pre chain enters as the drain's run of it. Never a
    /// request's.
    pub(crate) drain: Option<oneiron::runtime_hooks::verb::VerbAskDrainPermit>,
    /// A narrower caller's own holder proof, as the MCP HTTP ingress
    /// carried it, for the home an opened device asks (FIX 2905, FIX 2907).
    /// `None` for an owner-grade caller and off that ingress.
    pub(crate) forwarded: Option<oneiron::authority::ForwardedCallerProof>,
    /// The generated-UI surface profile the request's
    /// `_meta.clientCapabilities` declares (FIX 7969), read on every call
    /// because the MCP leg is stateless (ARCH-0048 G3). A lens the call
    /// renders is lowered for it unless its arguments name their own;
    /// `None` lowers for the whole atom kit. It selects a rendering and
    /// grants nothing.
    pub(crate) client_surface: Option<oneiron::lens::GeneratedUiSurfaceCapabilities>,
}

impl std::ops::Deref for McpCallContext {
    type Target = McpResolvedActor;

    fn deref(&self) -> &Self::Target {
        &self.actor
    }
}

impl McpCallContext {
    /// Who this request asks an opened device's home for (FIX 2905): an
    /// owner-grade credential is the device's owner; a narrower one is
    /// judged at the home on the holder proof its ingress carried, and with
    /// none asks nothing.
    pub(crate) fn home_caller(&self) -> oneiron::memory::HomeRecallCaller {
        let owner_grade = self
            .actor
            .auth
            .as_ref()
            .is_some_and(crate::auth::CoreAuth::is_owner_grade);
        oneiron::memory::HomeRecallCaller::admitted(owner_grade, self.forwarded.clone())
    }

    /// The closed metadata envelope for one result on this endpoint.
    pub(super) fn metadata(
        &self,
        health: McpRetrievalHealth,
        page: McpPageBudget,
        help: Vec<String>,
        cache: Option<McpCacheHint>,
    ) -> Value {
        // The facet a write lands in rides the result's scope.
        let mut scope = self.actor.scope.clone();
        if let Ok(Some(facet)) = self.landing {
            scope.facet_ref = Some(facet);
        }
        McpResultMetadata::new(
            self.request_id.clone(),
            self.mode,
            scope,
            health,
            page,
            help,
            cache,
        )
        .to_value()
    }
}
