//! The host door of `connector.call` (ONE-2510): one tool of one catalogued
//! connector, sent by this server's [`ServedConnectorCallHost`].
//! `host_doors` re-exports it, so the generated HTTP facade handler (the held
//! socket runs the same dispatch) and the MCP dispatcher (a tool call and an
//! MCP code-mode call) call it by the name every host door has; a pumped
//! agent run calls [`connector_call_listing_as`]. All of them meet one admission: the
//! caller's own principal, its own standing grant and the gate. The call is
//! never the owner's by default. The principal is the caller's: the facade
//! credential's own (`facade_actor`), the MCP connector's resolved actor, or
//! the pumped run's agent. `connector.answer` has the same door beside it
//! (FIX 3838), for a caller whose call answered `awaiting_input`.
//!
//! The door takes the logical invocation its call resolved and maps it, with
//! the caller, onto the ledger's call identity
//! ([`sdk::connector_call_invocation`]), so a replayed step neither sends
//! twice nor holds a second call. The served host and its blocking HTTP
//! client are built on a blocking worker, and the send happens there, never
//! inside a write transaction.
use std::sync::Arc;

use oneiron::memory::{Memory, MemoryError, MemoryResult};
use oneiron::outbound_consent::ConnectorCallRequest;
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::{self, ActAnswer, ConnectorAnswerRequest, ConnectorCallReply};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{Listed, credential_listing};
use crate::auth::CoreAuth;
use crate::connector_call_host::ServedConnectorCallHost;
use crate::server::SyncServer;

/// `connector.call`: `caller`'s call of one connector tool, under its own
/// grant, on the credential it presented, with its call's invocation as the
/// ledger identity. Beside it, the rows its reads listed and the rows its
/// passes picked (FIX 5455): the catalog route key, each standing grant
/// read, the governing key, each slate read and the custody record its send
/// presented; unknown when they are not known. The call runs as it asked
/// from any surface; for a caller off this device whose reply names or
/// lists a row that stays here, only the answer narrows, to the word that
/// it ran ([`crate::device_local::act_answer`]). Some answers are left
/// unjudged and answer as before ([`answers_as_before`]).
pub(crate) async fn connector_call(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: ConnectorCallRequest,
) -> (
    MemoryResult<ActAnswer<ConnectorCallReply>>,
    Option<Vec<EntityId>>,
) {
    const VERB: &str = "connector.call";
    let (answer, mut listed) =
        credential_listing(server, auth, caller, VERB, move |server, _, memory| {
            let memory = match invocation {
                Some(invocation) => memory.with_invocation(invocation),
                None => memory,
            };
            connector_call_listing_as(server, &memory, input)
        })
        .await;
    let answer = match answer {
        Ok((reply, Some(mut picked))) => {
            listed.append(&mut picked);
            (Ok(reply), Some(listed))
        }
        Ok((reply, None)) => (Ok(reply), None),
        Err(refusal) => (Err(refusal), Some(listed)),
    };
    match answer {
        (Ok(reply), rows) if answers_as_before(&reply) => (Ok(ActAnswer::Done(reply)), rows),
        answer => {
            crate::device_local::act_answer_maybe(server.vault(), &auth.destination(), answer)
        }
    }
}

/// Whether a connector's `awaiting_input` reply narrows like any other act
/// answer. Off (FIX-LIST line 5824): its caller keeps the questions, the
/// handle it answers them by through `connector.answer`, and their expiry,
/// as before, until an answer shape that keeps the handle and narrows only
/// the questions naming a kept row exists.
const AWAITING_INPUT_REPLY_NARROWS: bool = false;

/// Whether `reply` answers as before, unjudged. A held or pending call's
/// reply names the call ref its caller parks on and polls by, and no row
/// content; what the ref leads to narrows where it is read or delivered. A
/// connector's questions keep their answer path
/// ([`AWAITING_INPUT_REPLY_NARROWS`]).
pub(crate) fn answers_as_before(reply: &ConnectorCallReply) -> bool {
    reply.wait_ref().is_some()
        || (!AWAITING_INPUT_REPLY_NARROWS
            && matches!(reply, ConnectorCallReply::AwaitingInput { .. }))
}

/// One connector call for the caller `memory` is bound to, with the
/// invocation it carries, beside the rows the call's passes picked
/// (FIX 5455), `None` when they are not known. Blocking: it sends, so call
/// it on a blocking worker.
pub(crate) fn connector_call_listing_as(
    server: &SyncServer,
    memory: &Memory<'_>,
    input: ConnectorCallRequest,
) -> MemoryResult<(ConnectorCallReply, Option<Vec<EntityId>>)> {
    let invocation = memory
        .invocation()
        .map(|invocation| sdk::connector_call_invocation(memory.actor(), invocation))
        .transpose()
        .map_err(MemoryError::from)?;
    let mut host = ServedConnectorCallHost::new(server).map_err(MemoryError::from)?;
    let (name, tool) = (input.name.clone(), input.tool.clone());
    let (outcome, rows) = server
        .vault()
        .call_connector_listing(memory, input, invocation, &mut host)
        .map_err(sdk::connector_call_error)?;
    Ok((ConnectorCallReply::project(&name, &tool, outcome), rows))
}

/// `connector.answer`'s host door (FIX 3838): `caller`'s answer, on the
/// credential it presented, to the questions one of its own connector calls
/// waits on, so an HTTP or MCP `connector.call` that answered
/// `awaiting_input` has a door to answer through. The same registry and the
/// same check as a run's answer ([`connector_answer_as`]): only the call's
/// own caller answers, under that call's grant. Beside it, the rows its
/// reads listed; the connector's reply is foreign data and lists none.
pub(crate) async fn connector_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: ConnectorAnswerRequest,
) -> Listed<ConnectorCallReply> {
    const VERB: &str = "connector.answer";
    credential_listing(server, auth, caller, VERB, move |server, _, memory| {
        let memory = match invocation {
            Some(invocation) => memory.with_invocation(invocation),
            None => memory,
        };
        connector_answer_as(server, &memory, input)
    })
    .await
}

/// `connector.answer` (ONE-2510) for the caller `memory` is bound to: its
/// answer to the questions one of its connector calls waits on, by the
/// handle the `awaiting_input` reply named, checked under that call's grant
/// and principal and sent through this server's live question registry, the
/// one every connector host here keeps its questions in. Holding the handle
/// is not authority: only the call's own caller answers. Blocking: it waits
/// on the connector and on the owner, so call it on a blocking worker.
pub(crate) fn connector_answer_as(
    server: &SyncServer,
    memory: &Memory<'_>,
    input: ConnectorAnswerRequest,
) -> MemoryResult<ConnectorCallReply> {
    crate::connector_elicitation::answer_connector_question(server, memory, input)
}
