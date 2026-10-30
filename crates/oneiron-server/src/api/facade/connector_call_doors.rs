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

use oneiron::llm::run_admission::RunAdmission;
use oneiron::memory::{Memory, MemoryError, MemoryResult};
use oneiron::outbound_consent::ConnectorCallRequest;
use oneiron::runtime_hooks::InvocationId;
use oneiron::settings::ReadDestination;
use oneiron::task_verb::sdk::{
    self, ActAnswer, ConnectorAnswerRequest, ConnectorCallReply, NarrowedQuestion,
    NarrowedQuestions,
};
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
/// it ran ([`crate::device_local::act_answer`]); a connector's questions
/// narrow only their text and keep their answer path ([`narrowed_questions`],
/// FIX 5824). Some answers are left unjudged and answer as before
/// ([`answers_as_before`]).
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
    let line = super::host_doors::calling_line();
    let (answer, mut listed) =
        credential_listing(server, auth, caller, VERB, move |server, _, memory| {
            let memory = match invocation {
                Some(invocation) => memory.with_invocation(invocation),
                None => memory,
            };
            connector_call_listing_on(server, &memory, input, line.as_ref())
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
        (Ok(reply @ ConnectorCallReply::AwaitingInput { .. }), rows) => {
            narrowed_questions(server.vault(), &auth.destination(), reply, rows)
        }
        answer => {
            crate::device_local::act_answer_maybe(server.vault(), &auth.destination(), answer)
        }
    }
}

/// Whether a connector's `awaiting_input` reply narrows for a caller off
/// this device. On (FIX 5824): only the text of a question naming a row that
/// stays here is left behind, and the handle it is answered by through
/// `connector.answer`, the call's ref, its source and the round's live lease
/// leave whole ([`narrowed_questions`]).
const AWAITING_INPUT_REPLY_NARROWS: bool = true;

/// Whether `reply` answers as before, unjudged. A held or pending call's
/// reply names the call ref its caller parks on and polls by, and no row
/// content; what the ref leads to narrows where it is read or delivered. A
/// connector's questions narrow only their text
/// ([`AWAITING_INPUT_REPLY_NARROWS`]).
pub(crate) fn answers_as_before(reply: &ConnectorCallReply) -> bool {
    reply.wait_ref().is_some()
        || (!AWAITING_INPUT_REPLY_NARROWS
            && matches!(reply, ConnectorCallReply::AwaitingInput { .. }))
}

/// A connector's `awaiting_input` `reply` for a caller toward `destination`
/// (FIX 5824). A reply that may leave, or whose rows are not known, answers
/// whole beside its rows, as [`crate::device_local::act_answer_maybe`]
/// answers it. One that names or lists a row a world withheld from that
/// destination keeps (or whose check fails) keeps its answer path whole and
/// leaves the text of each question naming such a row here, beside no rows.
/// `ai.voice.tool` narrows its connector reply by it too (FIX 11725).
pub(super) fn narrowed_questions(
    vault: &oneiron::Vault,
    destination: &ReadDestination,
    reply: ConnectorCallReply,
    rows: Option<Vec<EntityId>>,
) -> (
    MemoryResult<ActAnswer<ConnectorCallReply>>,
    Option<Vec<EntityId>>,
) {
    let Some(rows) = rows else {
        return (Ok(ActAnswer::Done(reply)), None);
    };
    // Whether `payload`, derived from `named`, may leave: no row it names by
    // whole id or short ref, nor one of `named`, is withheld from there.
    let leaves = |mut named: Vec<EntityId>, payload: &serde_json::Value| {
        let Some(mut by_short_ref) = crate::device_local::short_refs_named(vault, payload) else {
            return false;
        };
        named.append(&mut by_short_ref);
        serde_json::to_vec(payload).is_ok_and(|bytes| {
            matches!(
                crate::device_local::retained_hold(vault, destination, &named, &bytes),
                Ok(None)
            )
        })
    };
    let whole = serde_json::to_value(&reply).unwrap_or(serde_json::Value::Null);
    if !destination.is_off_device() || leaves(rows.clone(), &whole) {
        return (Ok(ActAnswer::Done(reply)), Some(rows));
    }
    let ConnectorCallReply::AwaitingInput {
        handle,
        call_ref,
        source,
        foreign,
        questions,
        live_until_ms,
        reasons,
    } = reply
    else {
        return (Ok(ActAnswer::details_on_device()), Some(Vec::new()));
    };
    let questions = questions
        .into_iter()
        .map(|question| {
            let text = serde_json::Value::Array(vec![
                serde_json::Value::String(question.message.clone()),
                question.requested_schema.clone(),
            ]);
            if leaves(Vec::new(), &text) {
                NarrowedQuestion {
                    key: question.key,
                    message: Some(question.message),
                    requested_schema: Some(question.requested_schema),
                    on_device: false,
                }
            } else {
                NarrowedQuestion {
                    key: question.key,
                    message: None,
                    requested_schema: None,
                    on_device: true,
                }
            }
        })
        .collect();
    let narrowed = NarrowedQuestions {
        outcome: "awaiting_input".to_owned(),
        questions_narrowed: true,
        handle,
        call_ref,
        source,
        foreign,
        questions,
        live_until_ms,
        reasons,
    };
    (Ok(ActAnswer::QuestionsNarrowed(narrowed)), Some(Vec::new()))
}

/// [`connector_call_listing_as`] for a caller that spends on `line`, its
/// run's own: a web call on the deploy's key is charged there (FIX 11604).
/// Every other call runs as [`connector_call_listing_as`] runs it.
pub(crate) fn connector_call_listing_on(
    server: &SyncServer,
    memory: &Memory<'_>,
    input: ConnectorCallRequest,
    line: Option<&RunAdmission>,
) -> MemoryResult<(ConnectorCallReply, Option<Vec<EntityId>>)> {
    if input.name == oneiron::web_connector::WEB_CONNECTOR_NAME {
        return crate::web_connector::call_listing(server, memory, input, line);
    }
    connector_call_listing_as(server, memory, input)
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
    if input.name == oneiron::web_connector::WEB_CONNECTOR_NAME {
        return crate::web_connector::call_listing(server, memory, input, None);
    }
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
