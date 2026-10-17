//! The host door of `self.use` (OF-560). The table's operations answer as
//! the engine's row does; `connector.call` sends one connector call with
//! the handle's secret as its credential, on this server's
//! [`ServedConnectorCallHost`]. `host_doors` re-exports it, so the generated
//! HTTP facade handler (the held socket runs the same dispatch) and the MCP
//! dispatcher call it by the name every host door has; a pumped agent run
//! calls [`self_use_as`].
//!
//! The call is the caller's: its own principal, its own standing grant and
//! the gate, as `connector.call`'s door admits it, with the invocation its
//! call resolved as the ledger identity. The record's binding for the
//! route's effector is the only grant of the secret. The host and its
//! blocking HTTP client are built on a blocking worker, and the send happens
//! there, never inside a write transaction.
use std::sync::Arc;

use oneiron::memory::{Memory, MemoryError, MemoryResult};
use oneiron::runtime_hooks::InvocationId;
use oneiron::secret_custody::SECRET_USE_CONNECTOR_CALL;
use oneiron::task_verb::sdk::{self, SecretUseAnswer, SecretUseRequest};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::{Listed, credential_listing};
use crate::auth::CoreAuth;
use crate::connector_call_host::ServedConnectorCallHost;
use crate::server::SyncServer;

/// `self.use`: `caller`'s use of one secret by its handle, on the credential
/// it presented, with its call's invocation as a connector call's ledger
/// identity. Beside it, the rows its reads listed.
pub(crate) async fn self_use(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: SecretUseRequest,
) -> Listed<SecretUseAnswer> {
    const VERB: &str = "self.use";
    credential_listing(server, auth, caller, VERB, move |server, _, memory| {
        let memory = match invocation {
            Some(invocation) => memory.with_invocation(invocation),
            None => memory,
        };
        self_use_as(server, &memory, input)
    })
    .await
}

/// One use for the caller `memory` is bound to, with the invocation it
/// carries. Blocking: an operation sends, so call it on a blocking worker.
pub(crate) fn self_use_as(
    server: &SyncServer,
    memory: &Memory<'_>,
    input: SecretUseRequest,
) -> MemoryResult<SecretUseAnswer> {
    if input.operation != SECRET_USE_CONNECTOR_CALL {
        return sdk::use_secret_as_caller(memory, input);
    }
    let invocation = memory
        .invocation()
        .map(|invocation| sdk::connector_call_invocation(memory.actor(), invocation))
        .transpose()
        .map_err(MemoryError::from)?;
    let mut host = ServedConnectorCallHost::new(server).map_err(MemoryError::from)?;
    sdk::use_secret_for_connector_call(memory, input, invocation, &mut host)
}
