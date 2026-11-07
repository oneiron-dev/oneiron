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
//! - [`ConnectorCallReply::AwaitingInput`]: a connector that asks for input
//!   mid-call has received the call, so the reply is neither `delivered` nor
//!   `held`: its questions come back as foreign data with the handle
//!   `connector.answer` takes ([`ConnectorAnswerRequest`]), and a code-mode
//!   run gets them as the call's answer, never parked on them.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::memory::{
    MEMORY_CODE_INTERNAL, MEMORY_CODE_MODEL_UNAVAILABLE, MEMORY_CODE_NOT_FOUND, Memory,
    MemoryError, MemoryResult,
};
use crate::outbound_consent::{
    ConnectorAwaitingInput, ConnectorCallInvocation, ConnectorCallOutcome, ConnectorCallRequest,
    ConnectorSource, ConnectorToolSchema,
};
use crate::outbound_intent_ledger::IntentLedgerError;
use crate::runtime_hooks::InvocationId;

pub use crate::code_run::{
    CONNECTOR_QUESTIONS_NOT_RETAINED, CONNECTOR_RESULT_CREDENTIAL_CLEAR_FAILED,
    CONNECTOR_RESULT_NOT_RETAINED,
};

/// The derive-key context of a served call's synthetic attempt id.
const CONNECTOR_ATTEMPT_CONTEXT: &str = "oneiron connector call attempt v1";

pub use crate::code_run::{ConnectorCallReply, ConnectorToolResult};

pub use crate::code_run::{ConnectorAnswerAction, ConnectorAnswerRequest, ConnectorQuestionAnswer};

/// `connector.schema`'s input: a selected connector and one of its tools.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorSchemaRequest {
    /// The connector's name within the selected source.
    pub name: String,
    /// Explicit catalog or builtin selection. When absent, `web` selects
    /// the builtin and other names select their catalog entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<ConnectorSource>,
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

use crate::code_run::connector_result_source as source;

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
        &[super::host::SERVED_CLIENT_HINT],
    ))
}

/// `connector.schema`: one tool's approved input schema for the bound
/// caller, through the resolution a call of it takes. Reads only. The
/// built-in `google.sheets` answers its own declared schemas (FIX 4862).
/// It answers when the catalog source is selected (omitted or `catalog`);
/// an explicit `builtin` serves only `web` (FIX 11606).
pub fn connector_schema_read(
    memory: &Memory<'_>,
    input: ConnectorSchemaRequest,
) -> MemoryResult<ConnectorSchemaReply> {
    let selected = ConnectorSource::resolve(input.source, &input.name);
    let schema = if selected == ConnectorSource::Catalog
        && input.name == crate::channel_identity_provider::sheets::SHEETS_CATALOG_NAME
    {
        crate::channel_identity_provider::sheets::sheets_tool_schema(memory.vault(), &input.tool)?
    } else {
        memory
            .vault()
            .connector_tool_schema_from(memory, &input.name, &input.tool, input.source)
            .map_err(connector_call_error)?
    };
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
    /// The `call_ref` a `held`, `pending_delivery` or `awaiting_input`
    /// `connector.call` reply named, 32 hex.
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
        /// FIX 6424 part 3: the approve-once digest the call's approvable
        /// hold named, kept with it: the owner's press on it releases
        /// exactly the call as it was prepared.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        approval_digest: Option<String>,
    },
    /// Settled: the reply its wait settled with, as `connector.call` would
    /// have answered.
    Settled {
        call_ref: String,
        name: String,
        tool: String,
        reply: ConnectorCallReply,
    },
    /// Sent, and its connector asks for input (FIX 3837): round
    /// `generation`, `asked` questions, kept on the call's row; answer them
    /// with `connector.answer` and the reply's handle. The reply carries no
    /// questions' text, which the row never keeps: the call's own reply or
    /// its wait carried them. `uncertain` when the live exchange ended
    /// unanswered (a restart, a lost stream): the questions stand, and their
    /// delivery is not known.
    AwaitingInput {
        call_ref: String,
        name: String,
        tool: String,
        generation: u64,
        asked: usize,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        uncertain: bool,
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
    // A call whose connector asked for input reads from its row: its round
    // while it stands, its delivery once answered. A wait reply it settled
    // holds only its first questions (FIX 3837).
    if let Some(input) = state.input {
        memory.produced_from(state.source_rows.into_iter().flatten());
        let (name, tool) = (state.name, state.tool);
        return Ok(match state.settled {
            Some(outcome) => {
                // Read once settled, its row goes; its acknowledged caller
                // keeps this status (FIX 9158).
                if let Err(error) = vault.consume_settled_connector_input(&call_ref) {
                    tracing::warn!(%error, "connector call input row not consumed");
                }
                ConnectorCallStatus::Settled {
                    reply: ConnectorCallReply::project(&name, &tool, outcome),
                    call_ref: call_ref.to_hex(),
                    name,
                    tool,
                }
            }
            None => ConnectorCallStatus::AwaitingInput {
                call_ref: call_ref.to_hex(),
                generation: input.generation,
                asked: input.asked,
                uncertain: input.uncertain,
                reply: ConnectorCallReply::awaiting_input(
                    &name,
                    &tool,
                    call_ref,
                    ConnectorAwaitingInput {
                        handle: input.handle,
                        questions: Vec::new(),
                        live_until_ms: input.live_until_ms,
                    },
                ),
                name,
                tool,
            },
        });
    }
    // A call whose connector asked for input, its row read and gone: its
    // acknowledged caller keeps its outcome, never its wait's first
    // questions (FIX 9158).
    if state.acknowledged
        && let Some(outcome) = state.settled
    {
        memory.produced_from(state.source_rows.into_iter().flatten());
        return Ok(ConnectorCallStatus::Settled {
            reply: ConnectorCallReply::project(&state.name, &state.tool, outcome),
            call_ref: input.call_ref,
            name: state.name,
            tool: state.tool,
        });
    }
    let settled = crate::code_run::WaitDeliveries::canonical(vault).settled(call_ref)?;
    // The rows the call's passes picked (FIX 5455): kept beside its settled
    // reply once a settler answered its wait, else on its held row. A set
    // not known lists nothing more than before.
    let rows = settled
        .as_ref()
        .map_or(state.source_rows, |settled| settled.source_rows.clone());
    memory.produced_from(rows.into_iter().flatten());
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
            approval_digest: state.approval_digest,
        }),
        (None, None) => Err(MemoryError::new(
            MEMORY_CODE_INTERNAL,
            "an acknowledged connector call's settled reply is gone",
            &["Report this connector call failure."],
        )),
    }
}

/// `vault.connectors.calls.approve_once` (FIX 990): the owner's press on one
/// held connector call, by its ref and the exact digest he reviewed.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorCallApproveOnceRequest {
    /// The held call's ref, 32 hex.
    pub call_ref: String,
    /// The approve-once digest the call's current ask names (its status and
    /// its owner question), 64 lower-hex.
    pub approval_digest: String,
}

/// `vault.connectors.calls.approve_once`: the owner's approve-once press on
/// exactly the held call's current ask. It mints the consent door's own
/// exact-digest marker, grants nothing standing and sends nothing; the
/// call's next resume runs it.
///
/// # Errors
///
/// A malformed ref, a call that is not held or whose ask moved since it was
/// reviewed, the owner check's and the consent door's own refusals.
pub fn approve_connector_call_once(
    vault: &crate::Vault,
    owner: &crate::consent::AuthenticatedOwner,
    input: ConnectorCallApproveOnceRequest,
) -> MemoryResult<crate::consent::lifecycle::ConsentActReceipt> {
    let call_ref = EntityId::from_hex(&input.call_ref)
        .map_err(|_| MemoryError::bad_request("call_ref must be 32 hex"))?;
    vault
        .approve_connector_call_once(owner, &call_ref, &input.approval_digest)
        .map(Into::into)
        .map_err(connector_call_error)
}
