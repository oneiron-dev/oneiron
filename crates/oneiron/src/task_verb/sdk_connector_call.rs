//! `connector.call` and `connector.schema` (ONE-2510): one tool of one
//! catalogued connector, called by name through the engine's governed path,
//! and that tool's approved input schema, read when a caller needs it.
//!
//! The reply is tagged by its outcome. A delivered tool's own reply is
//! foreign data: it stays nested under `result`, marked `foreign` with its
//! `source`, in every projection (an immediate answer, a settled wait, MCP
//! and HTTP). Nothing here writes it to memory, and nothing reads it as
//! instructions. Code mode spells a call `connector.<name>.<tool>(args)`;
//! the guest's proxy sends it as this one row.
//!
//! The calls (canon silent), each in one place:
//! - [`CONNECTOR_RESULT_NOT_RETAINED`]: a delivered reply with no body (a
//!   replay of a call already delivered, or a settled wait recovered after a
//!   crash in the delivery window) says so, and nothing is resent to rebuild
//!   it.
//! - [`connector_call_invocation`]: the ledger identity of a served call is
//!   its resolved invocation, bound to its caller, as a synthetic attempt at
//!   sequence 0.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::memory::{
    MEMORY_CODE_INTERNAL, MEMORY_CODE_MODEL_UNAVAILABLE, MEMORY_CODE_NOT_FOUND, Memory, MemoryError,
    MemoryResult,
};
use crate::outbound_consent::{
    ConnectorCallInvocation, ConnectorCallOutcome, ConnectorCallRequest, ConnectorToolSchema,
    UntrustedToolResult,
};
use crate::outbound_intent_ledger::IntentLedgerError;
use crate::runtime_hooks::InvocationId;

/// The reason a delivered reply carries when the tool's own reply is not in
/// it. The ledger never keeps a reply's bytes, and a call is never resent to
/// rebuild one.
pub const CONNECTOR_RESULT_NOT_RETAINED: &str = "result_not_retained";

/// The derive-key context of a served call's synthetic attempt id.
const CONNECTOR_ATTEMPT_CONTEXT: &str = "oneiron connector call attempt v1";

/// `connector.call`'s reply, tagged by `outcome`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ConnectorCallReply {
    /// The connector acknowledged the call. `result` is the tool's own
    /// reply, foreign data; null, with `result_not_retained` in `reasons`,
    /// when this answer has no reply to give.
    Delivered {
        result: Option<ConnectorToolResult>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        reasons: Vec<String>,
    },
    /// Held for consent or governance; nothing was sent. A code-mode run
    /// parks on `call_ref` until the hold settles.
    Held {
        call_ref: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decision_ref: Option<String>,
        reasons: Vec<String>,
    },
    /// Not sent, and never sent under this request.
    Refused {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decision_ref: Option<String>,
        reasons: Vec<String>,
    },
    /// The send's delivery is not settled. With `call_ref` the same send is
    /// retried; without one the connector may or may not have received it,
    /// and it is never sent again.
    PendingDelivery {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        call_ref: Option<String>,
        reasons: Vec<String>,
    },
}

/// A tool's own reply, as foreign data: who wrote it, marked foreign, and
/// the MCP fields exactly as the connector sent them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectorToolResult {
    /// `connector:<name>.<tool>`.
    pub source: String,
    /// Always true: the connector wrote every field below.
    pub foreign: bool,
    /// The MCP `content` blocks.
    pub content: Value,
    /// The MCP `structuredContent`, when the connector sent one.
    #[serde(default)]
    pub structured_content: Option<Value>,
    /// The connector's `isError`, or true for a JSON-RPC error answer.
    pub is_error: bool,
    /// The JSON-RPC error object, when the connector answered with one.
    #[serde(default)]
    pub rpc_error: Option<Value>,
}

/// `connector.schema`'s input: a catalogued connector and one of its tools.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorSchemaRequest {
    /// The connector's catalog name.
    pub name: String,
    /// The tool, as the connector's approved manifest names it.
    pub tool: String,
}

/// `connector.schema`'s reply: the tool's approved input schema on the
/// governing key the caller's own grant resolves, or why there is none. The
/// schema's text is the connector's, approved by the owner: it is marked
/// foreign too.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectorSchemaReply {
    /// `connector:<name>.<tool>`.
    pub source: String,
    /// Always true.
    pub foreign: bool,
    /// The approved input schema; absent when none is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Value>,
    /// Whether the tool's slate row marks it destructive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destructive: Option<bool>,
    /// The hold or refusal a call of the tool would meet first, when no
    /// schema is available.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

fn source(name: &str, tool: &str) -> String {
    format!("connector:{name}.{tool}")
}

impl ConnectorToolResult {
    fn foreign(name: &str, tool: &str, result: UntrustedToolResult) -> Self {
        Self {
            source: source(name, tool),
            foreign: true,
            content: result.content,
            structured_content: result.structured_content,
            is_error: result.is_error,
            rpc_error: result.rpc_error,
        }
    }
}

impl ConnectorCallReply {
    /// The wire reply of one engine outcome for a call of `tool` on `name`.
    #[must_use]
    pub fn project(name: &str, tool: &str, outcome: ConnectorCallOutcome) -> Self {
        match outcome {
            ConnectorCallOutcome::Delivered {
                result: Some(result),
                ..
            } => Self::Delivered {
                result: Some(ConnectorToolResult::foreign(name, tool, result)),
                reasons: Vec::new(),
            },
            ConnectorCallOutcome::Delivered { result: None, .. } => Self::Delivered {
                result: None,
                reasons: vec![CONNECTOR_RESULT_NOT_RETAINED.to_owned()],
            },
            ConnectorCallOutcome::Held {
                call_ref,
                decision_ref,
                reasons,
            } => Self::Held {
                call_ref: call_ref.to_hex(),
                decision_ref,
                reasons,
            },
            ConnectorCallOutcome::Refused {
                decision_ref,
                reasons,
            } => Self::Refused {
                decision_ref,
                reasons,
            },
            ConnectorCallOutcome::PendingDelivery {
                call_ref, reasons, ..
            } => Self::PendingDelivery {
                call_ref: call_ref.map(|call_ref| call_ref.to_hex()),
                reasons,
            },
        }
    }

    /// The call ref a code-mode run parks on: a hold, or a pending delivery
    /// the same send retries. `None` when this reply is the call's answer.
    #[must_use]
    pub fn wait_ref(&self) -> Option<EntityId> {
        match self {
            Self::Held { call_ref, .. }
            | Self::PendingDelivery {
                call_ref: Some(call_ref),
                ..
            } => EntityId::from_hex(call_ref).ok(),
            _ => None,
        }
    }
}

/// The ledger identity of one served call: the logical invocation its host
/// resolved (a code-mode step's, or the one HTTP or MCP carried or minted),
/// bound to the caller, as a synthetic attempt at sequence 0. No queued
/// attempt record is claimed. The same caller's same invocation replays the
/// ledger's intent and finds its held call again; another caller naming the
/// same invocation gets an identity of its own.
///
/// # Errors
///
/// Never in practice: the attempt id is always 16 bytes.
pub fn connector_call_invocation(
    actor: EntityId,
    invocation: InvocationId,
) -> crate::Result<ConnectorCallInvocation> {
    let mut hasher = blake3::Hasher::new_derive_key(CONNECTOR_ATTEMPT_CONTEXT);
    hasher.update(actor.as_bytes());
    hasher.update(&invocation.0);
    Ok(ConnectorCallInvocation {
        attempt_id: AttemptId::from_bytes(&hasher.finalize().as_bytes()[..16])?,
        call_seq: 0,
    })
}

/// A connector call's ledger failure as the verb's refusal.
#[must_use]
pub fn connector_call_error(error: IntentLedgerError) -> MemoryError {
    match error {
        IntentLedgerError::Engine(error) => MemoryError::from(error),
        IntentLedgerError::InvalidInput(message) => MemoryError::bad_request(message),
        other => MemoryError::new(
            MEMORY_CODE_INTERNAL,
            other.to_string(),
            &["Report this connector call failure."],
        ),
    }
}

/// `connector.call` on an embedded handle: refused, as no connector
/// transport is installed beneath an embedded vault. A server's host door
/// sends it.
pub fn connector_call_host_only(
    _memory: &Memory<'_>,
    _input: &ConnectorCallRequest,
) -> MemoryResult<ConnectorCallReply> {
    Err(MemoryError::new(
        MEMORY_CODE_MODEL_UNAVAILABLE,
        "connector.call sends through a server's installed connector transports; an embedded vault has none",
        &["Call it through a remote client of a server that serves it."],
    ))
}

/// `connector.schema`: one tool's approved input schema for the bound
/// caller, through the resolution a call of it takes. Reads only.
pub fn connector_schema_read(
    memory: &Memory<'_>,
    input: ConnectorSchemaRequest,
) -> MemoryResult<ConnectorSchemaReply> {
    let schema = memory
        .vault()
        .connector_tool_schema(memory, &input.name, &input.tool)
        .map_err(connector_call_error)?;
    let source = source(&input.name, &input.tool);
    Ok(match schema {
        ConnectorToolSchema::Approved {
            input_schema,
            destructive_hint,
        } => ConnectorSchemaReply {
            source,
            foreign: true,
            input_schema: Some(input_schema),
            destructive: Some(destructive_hint),
            reasons: Vec::new(),
        },
        ConnectorToolSchema::Unavailable { reasons } => ConnectorSchemaReply {
            source,
            foreign: true,
            input_schema: None,
            destructive: None,
            reasons,
        },
    })
}

/// `connector.call_status`'s input: the call ref a `held` or
/// `pending_delivery` reply named (FIX 2279).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorCallStatusRequest {
    /// The `call_ref` a `held` or `pending_delivery` `connector.call` reply
    /// named, 32 hex.
    pub call_ref: String,
}

/// `connector.call_status`'s answer: where one held call stands, for its
/// caller or the vault's owner. Its reply is `connector.call`'s own, so a
/// delivered tool's reply stays foreign data under `result`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ConnectorCallStatus {
    /// Held for consent or governance, or its send still retrying: nothing
    /// answered it yet. The settler resumes it on its own; read again later.
    Pending {
        call_ref: String,
        name: String,
        tool: String,
        /// When it was first held (unix ms); its expiry counts from here.
        held_at_ms: u64,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        reasons: Vec<String>,
    },
    /// Settled: the reply its wait settled with, as `connector.call` would
    /// have answered.
    Settled {
        call_ref: String,
        name: String,
        tool: String,
        reply: ConnectorCallReply,
    },
}

/// `connector.call_status` (ONE-2510, FIX 2279): a held connector call's
/// status by its ref, readable by the actor that called it and by the
/// vault's owner. Any other caller, and a ref this vault never held, read
/// the same not-found, so a ref discloses nothing to anyone else. It reads
/// the held row and the settled wait only: it sends nothing, resumes
/// nothing and claims no invocation.
///
/// # Errors
///
/// A malformed ref; not found; storage errors.
pub fn connector_call_status_read(
    memory: &Memory<'_>,
    input: ConnectorCallStatusRequest,
) -> MemoryResult<ConnectorCallStatus> {
    let not_found = || {
        MemoryError::new(
            MEMORY_CODE_NOT_FOUND,
            "no connector call with this ref is yours to read",
            &[
                "Pass the call_ref a held or pending_delivery connector.call reply named, as the caller that made the call or as the vault's owner.",
            ],
        )
    };
    let call_ref = EntityId::from_hex(&input.call_ref)
        .map_err(|_| MemoryError::bad_request("call_ref must be 32 hex"))?;
    let vault = memory.vault();
    let state = vault
        .connector_call_state(&call_ref)
        .map_err(connector_call_error)?
        .ok_or_else(not_found)?;
    if state.principal_ref != memory.actor().to_hex() && !memory.is_vault_owner()? {
        return Err(not_found());
    }
    let settled = crate::code_run::WaitDeliveries::canonical(vault).settled(call_ref)?;
    let call_ref = input.call_ref;
    let (name, tool) = (state.name, state.tool);
    if let Some(settled) = settled {
        let reply = serde_json::from_str::<ConnectorCallReply>(&settled.reply).map_err(|_| {
            MemoryError::new(
                MEMORY_CODE_INTERNAL,
                "a connector call's settled reply does not decode",
                &["Report this connector call failure."],
            )
        })?;
        return Ok(ConnectorCallStatus::Settled {
            call_ref,
            name,
            tool,
            reply,
        });
    }
    match (state.settled, state.held_at_ms) {
        (Some(outcome), _) => Ok(ConnectorCallStatus::Settled {
            reply: ConnectorCallReply::project(&name, &tool, outcome),
            call_ref,
            name,
            tool,
        }),
        (None, Some(held_at_ms)) => Ok(ConnectorCallStatus::Pending {
            call_ref,
            name,
            tool,
            held_at_ms,
            reasons: state.reasons,
        }),
        (None, None) => Err(MemoryError::new(
            MEMORY_CODE_INTERNAL,
            "an acknowledged connector call's settled reply is gone",
            &["Report this connector call failure."],
        )),
    }
}
