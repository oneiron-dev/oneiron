//! The connector-call shapes: the request, the host seam, its replies and
//! questions, and the caller's status view.
//! Entry: `ConnectorCallHost`. Defines its own items; the stored rows stay in `connector_call`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::attempt_queue::AttemptId;
use crate::connector_key::ConnectorCallRoute;
use crate::entity_id::EntityId;
use crate::secret_custody::SentPresentation;
use crate::secret_lease::SecretGrantRef;

use super::result_scrub::OutboundResultSender;
use super::tool_call::MutationIntent;

/// One guest call: a catalog name, one of its tools, and the arguments. It
/// carries no endpoint, credential, schema, grant or principal: the engine
/// and the host resolve those beneath the name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorCallRequest {
    /// The connector's catalog name.
    pub name: String,
    /// The tool, as the connector's approved manifest names it.
    pub tool: String,
    /// The tool's arguments, a JSON object.
    #[serde(default = "empty_arguments")]
    pub arguments: Value,
    /// Preview (the default) or an explicit mutation.
    #[serde(default)]
    pub mutation: MutationIntent,
}

fn empty_arguments() -> Value {
    Value::Object(serde_json::Map::new())
}

/// The host's own identity for one call (a code-mode step, a job attempt).
/// The ledger keys one logical send by it, so the same step run again
/// replays instead of sending twice. Never taken from the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectorCallInvocation {
    pub attempt_id: AttemptId,
    pub call_seq: u64,
}

/// A connector's own reply to `tools/call`. Foreign data: the connector
/// wrote it, so it is untrusted, never instructions, and never stored in the
/// vault.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UntrustedToolResult {
    /// The MCP `content` blocks, as the connector sent them.
    pub content: Value,
    /// The MCP `structuredContent`, when the connector sent one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured_content: Option<Value>,
    /// The connector's `isError`, or true when it answered with a JSON-RPC
    /// error instead of a result.
    pub is_error: bool,
    /// The JSON-RPC error object the connector answered with, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpc_error: Option<Value>,
}

/// One question a connector asked mid-call. Foreign data: the connector
/// wrote every field, so it is task input for the caller, never an
/// instruction and never an approval.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectorQuestion {
    /// The question's key in its round: `"0"` for a request on the reply
    /// stream, the connector's own key in a multi round-trip result.
    pub key: String,
    /// The connector's message.
    pub message: String,
    /// The JSON schema of the answer the connector asks for.
    pub requested_schema: Value,
}

/// The questions a connector answered a call with, as its host keeps them
/// for the caller: the live continuation's handle, the questions, and the
/// end of the round's live lease (unix ms): how long a synchronous answer
/// waits, never an expiry (FIX 3837).
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectorAwaitingInput {
    pub handle: String,
    pub questions: Vec<ConnectorQuestion>,
    pub live_until_ms: u64,
}

/// Who the next send runs for and under which standing grant, as the engine
/// resolved them: a host binds a question the connector asks to exactly
/// these, never to anything the guest named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorCallCaller {
    /// The calling actor, hex.
    pub principal_ref: String,
    pub grant_id: EntityId,
    /// The catalog name the caller called.
    pub name: String,
}

/// Why a delivered call's outcome carries no reply (FIX 2823).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorResultAbsence {
    /// The reply is not retained: a replay of an already delivered call, or
    /// a settled call read back. Nothing is sent again to fetch it.
    NotRetained,
    /// The send presented a custody record's value, and the value could not
    /// be read again to clear it from the reply, so the reply is withheld.
    CredentialClearFailed,
}

/// What one connector call came to.
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectorCallOutcome {
    /// The connector acknowledged the call. `result` is its reply when this
    /// send carried one; a replay of an already delivered call has none.
    /// `result_absence` says why when `result` is `None`.
    Delivered {
        intent: Option<[u8; 32]>,
        result: Option<UntrustedToolResult>,
        result_absence: Option<ConnectorResultAbsence>,
    },
    /// Held for consent or governance. Nothing was sent. Once the hold may
    /// have cleared, [`crate::Vault::resume_connector_call`] re-enters it.
    /// `approval_digest` (FIX 6424 part 3) is the approve-once digest, 64
    /// lower-hex, the Gate decision that held this prepared call names: the
    /// owner's press on it releases exactly this call. `None` for a hold no
    /// press clears here (before the call was prepared, or a code consent
    /// wait's own answer).
    Held {
        call_ref: EntityId,
        decision_ref: Option<String>,
        reasons: Vec<String>,
        approval_digest: Option<String>,
    },
    /// Not sent, and never will be under this request.
    Refused {
        decision_ref: Option<String>,
        reasons: Vec<String>,
    },
    /// The send's delivery is not settled. With a `call_ref`, resuming
    /// retries the same logical send; without one, the connector may or may
    /// not have received it and the ledger will not send it again.
    PendingDelivery {
        intent: [u8; 32],
        call_ref: Option<EntityId>,
        reasons: Vec<String>,
    },
    /// The connector received the call and asked for input before it would
    /// finish it. The send is delivered; the call's row `call_ref` keeps
    /// the round (never the questions' text) until the connector answers
    /// the call, and its caller polls it there (FIX 3837). A replay from the
    /// row carries no questions.
    AwaitingInput {
        call_ref: EntityId,
        intent: Option<[u8; 32]>,
        input: ConnectorAwaitingInput,
    },
}

/// The served side of the generic connector call: an
/// [`OutboundResultSender`] that also knows where each connector is
/// installed and keeps its own copy of the last reply.
pub trait ConnectorCallHost: OutboundResultSender {
    /// The endpoint this host installed for the routed connector, or `None`
    /// when it has none. The grant's endpoint allowlist still gates it.
    fn tool_endpoint(&self, route: &ConnectorCallRoute) -> Option<String>;

    /// Takes the reply the last `send` read, kept before the ledger's scrub
    /// destroyed the raw bytes. `None` when that send read no reply.
    fn take_result(&mut self) -> Option<UntrustedToolResult>;

    /// Presents the custody record `credential` as each send's credential
    /// from here on, in place of the route's own secret, through the
    /// credential door for the route's effector; `None` goes back to the
    /// route's. With a `grant`, each send redeems it at its door
    /// (`Vault::redeem_secret_grant_at_door`) instead. False when this host
    /// cannot present a record or a grant: a call that names one is then
    /// refused unsent.
    fn present_credential(
        &mut self,
        credential: Option<EntityId>,
        grant: Option<SecretGrantRef>,
    ) -> bool {
        credential.is_none() && grant.is_none()
    }

    /// Binds the caller and grant the next send runs for, or none. A host
    /// that keeps a connector's questions binds them to these; one that
    /// serves no questions ignores it.
    fn bind_caller(&mut self, _caller: Option<ConnectorCallCaller>) {}

    /// Takes the questions the last `send`'s connector answered with in
    /// place of a result, kept before the ledger's scrub. `None` when it
    /// asked none.
    fn take_awaiting_input(&mut self) -> Option<ConnectorAwaitingInput> {
        None
    }

    /// Ends the live questions `handle` names, which no caller will hold:
    /// the send's ledger step did not reach Done, or the call's row could
    /// not keep the questions (FIX 3844). Their worker cancels them now. A
    /// host that keeps no questions ignores it.
    fn abandon_awaiting_input(&mut self, _handle: &str) {}

    /// The live questions `handle` names are kept on the call `call_ref`'s
    /// row (FIX 3837): the host keeps that row current as the exchange goes
    /// on. A host that keeps no questions ignores it.
    fn bind_awaiting_call(&mut self, _handle: &str, _call_ref: EntityId) {}

    /// Takes the custody record the last `send` presented, as its door
    /// resolved it (FIX 5455): an empty list when it presented none, `None`
    /// when this host cannot say, which leaves the call's rows unknown.
    fn take_sent_custody(&mut self) -> Option<Vec<EntityId>> {
        None
    }

    /// Whether every send clears its reply, its questions and its raw copy
    /// of the custody value it presented, whatever selected it (a record, a
    /// grant or the route's own secret), INSIDE the door's callback with the
    /// bytes that door released (FIX 7646, FIX 7647), before any of it
    /// leaves. A host that does not has a named record's reply cleared by a
    /// reread instead, as before.
    fn clears_at_door(&self) -> bool {
        false
    }

    /// Takes the custody presentation the last `send` made, as its door
    /// released it: the record, the generation sent and its reply's release
    /// policy (FIX 7646). `None` when it presented none, or this host cannot
    /// say. Ids and generation only, never a value.
    fn take_sent_presentation(&mut self) -> Option<SentPresentation> {
        None
    }
}

/// One held or pending-delivery call, as a settler lists it: its ref, the
/// catalog name and tool it calls, and whether a resume already settled it
/// (then its row waits only for [`crate::Vault::ack_connector_call_delivery`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingConnectorCallRef {
    pub call_ref: EntityId,
    pub name: String,
    pub tool: String,
    pub settled: bool,
}

/// One tool's approved input schema, on the governing key the caller's own
/// grant resolves, or why there is none. Read-only and secret-free.
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectorToolSchema {
    Approved {
        input_schema: Value,
        destructive_hint: bool,
    },
    /// The hold or refusal a call of the tool would meet first.
    Unavailable { reasons: Vec<String> },
}

/// Where one connector call stands, for its caller-bound status read (FIX
/// 2279): who called it, what it calls, and how far it got. Secret-free and
/// reply-free: a settled reply is its wait's.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectorCallState {
    /// The calling actor, hex.
    pub principal_ref: String,
    pub name: String,
    pub tool: String,
    /// When it was first held; `None` once a settler acknowledged it.
    pub held_at_ms: Option<u64>,
    /// The hold reasons the owner's ask carried, once an ask was tried.
    pub reasons: Vec<String>,
    /// What a resume settled it to, receipt-only, while its wait reply is
    /// not yet acknowledged.
    pub settled: Option<ConnectorCallOutcome>,
    /// A settler answered its wait and acknowledged it: the reply is the
    /// wait's.
    pub acknowledged: bool,
    /// The rows the call's passes picked (FIX 5455) while its row stands;
    /// `None` when they are not known, and once acknowledged, when they ride
    /// the wait's reply instead.
    pub source_rows: Option<Vec<EntityId>>,
    /// FIX 6424 part 3: the approve-once digest the call's approvable hold
    /// named, kept on its row while it is held: the owner's press on it
    /// releases exactly the call as it was prepared. `None` once settled,
    /// and for a call no approvable hold asked about.
    pub approval_digest: Option<String>,
    /// The round of questions its connector asked once it was sent
    /// (FIX 3837), kept on its row: unanswered while `settled` is `None`.
    pub input: Option<super::connector_call_input::ConnectorCallInput>,
}
