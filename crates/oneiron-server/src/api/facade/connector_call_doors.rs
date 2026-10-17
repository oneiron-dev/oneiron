//! The host door of `connector.call` (ONE-2510): one tool of one catalogued
//! connector, sent by this server's [`ServedConnectorCallHost`].
//! `host_doors` re-exports it, so the generated HTTP facade handler (the held
//! socket runs the same dispatch) and the MCP dispatcher (a tool call and an
//! MCP code-mode call) call it by the name every host door has; a pumped
//! agent run calls [`connector_call_as`]. All of them meet one admission: the
//! caller's own principal, its own standing grant and the gate. The call is
//! never the owner's by default. The principal is the caller's: the facade
//! credential's own (`facade_actor`), the MCP connector's resolved actor, or
//! the pumped run's agent.
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
use oneiron::task_verb::sdk::{self, ConnectorCallReply};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::internal;
use crate::auth::CoreAuth;
use crate::connector_call_host::ServedConnectorCallHost;
use crate::server::SyncServer;

/// `connector.call`: `caller`'s call of one connector tool, under its own
/// grant, on the credential it presented, with its call's invocation as the
/// ledger identity.
pub(crate) async fn connector_call(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: ConnectorCallRequest,
) -> MemoryResult<ConnectorCallReply> {
    const VERB: &str = "connector.call";
    let (actor, class) = caller;
    let server = Arc::clone(server);
    let auth = auth.clone();
    tokio::task::spawn_blocking(move || {
        let memory = crate::api::credential_memory(&server.vault, Some(&auth), actor, class)
            .at(auth.locality());
        let memory = match invocation {
            Some(invocation) => memory.with_invocation(invocation),
            None => memory,
        };
        connector_call_as(&server, &memory, input)
    })
    .await
    .map_err(|_| internal(VERB))?
}

/// One connector call for the caller `memory` is bound to, with the
/// invocation it carries. Blocking: it sends, so call it on a blocking
/// worker.
pub(crate) fn connector_call_as(
    server: &SyncServer,
    memory: &Memory<'_>,
    input: ConnectorCallRequest,
) -> MemoryResult<ConnectorCallReply> {
    let invocation = memory
        .invocation()
        .map(|invocation| sdk::connector_call_invocation(memory.actor(), invocation))
        .transpose()
        .map_err(MemoryError::from)?;
    let mut host = ServedConnectorCallHost::new(server).map_err(MemoryError::from)?;
    let (name, tool) = (input.name.clone(), input.tool.clone());
    let outcome = server
        .vault()
        .call_connector(memory, input, invocation, &mut host)
        .map_err(sdk::connector_call_error)?;
    Ok(ConnectorCallReply::project(&name, &tool, outcome))
}
