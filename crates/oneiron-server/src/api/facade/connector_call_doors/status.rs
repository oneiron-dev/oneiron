//! Served status reads: the native row joined to this server's live questions.

use std::sync::Arc;

use oneiron::memory::MemoryResult;
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::{
    self, ActAnswer, ConnectorCallReply, ConnectorCallStatus, ConnectorCallStatusRequest,
};
use oneiron::{EdgeActorClass, EntityId};

use crate::auth::CoreAuth;
use crate::server::SyncServer;

use super::super::host_doors::support::credential_listing;
use super::narrowed_questions;

/// Reads as the credential's own caller, or the vault's owner, without
/// taking a question or sending an answer. Only matching live text is
/// joined; an absent copy leaves today's row-only status intact.
pub(crate) async fn connector_call_status(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: ConnectorCallStatusRequest,
) -> (MemoryResult<ConnectorCallStatus>, Option<Vec<EntityId>>) {
    let (answer, rows) = credential_listing(
        server,
        auth,
        caller,
        "connector.call_status",
        move |server, _, memory| {
            sdk::connector_call_status_read_with_questions(&memory, input, |call_ref, state| {
                server
                    .connector_elicitations
                    .questions_for_status(call_ref, state)
            })
        },
    )
    .await;
    match answer {
        Ok(ConnectorCallStatus::AwaitingInput {
            call_ref,
            name,
            tool,
            generation,
            asked,
            uncertain,
            reply: ActAnswer::Done(reply),
        }) if matches!(&reply, ConnectorCallReply::AwaitingInput { questions, .. } if !questions.is_empty()) =>
        {
            let (reply, rows) =
                narrowed_questions(server.vault(), &auth.destination(), reply, Some(rows));
            (
                reply.map(|reply| ConnectorCallStatus::AwaitingInput {
                    call_ref,
                    name,
                    tool,
                    generation,
                    asked,
                    uncertain,
                    reply,
                }),
                rows,
            )
        }
        other => (other, Some(rows)),
    }
}
