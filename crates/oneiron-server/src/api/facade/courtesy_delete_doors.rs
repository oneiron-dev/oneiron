//! The host doors of the owner's courtesy delete rows (OF-273):
//! `vault.courtesy_delete.send`, `.sent`, `.incoming` and `.answer`.
//! `host_doors` re-exports them, so the generated HTTP facade handler and
//! the MCP dispatcher call them by the name every host door has. Each takes
//! the vault owner's proof as `/v1/owner/courtesy-delete/*` takes it
//! (`owner_routes::owner`) and runs the same call that route runs
//! (`owner::cooperative_deletion`): this host's own authority key signs, and
//! its courtesy outbox delivers. A former peer's signed ingress is peer HTTP,
//! with no row.
use std::sync::Arc;

use oneiron::memory::{MEMORY_CODE_INVALID_STATE, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{
    CourtesyDeleteAnswerRequest, CourtesyDeleteIncoming, CourtesyDeleteSendRequest,
    CourtesyDeleteSent, EmptyRequest,
};

use super::host_doors::internal;
use super::legal_hold_doors::as_owner;
use crate::auth::CoreAuth;
use crate::owner::OwnerError;
use crate::owner::cooperative_deletion;
use crate::server::SyncServer;

/// The owner route's refusal as the row's: the same statuses, in the
/// facade's error shape.
fn refusal(verb: &str, error: OwnerError) -> MemoryError {
    match error {
        OwnerError::Invalid(message) => MemoryError::bad_request(message),
        OwnerError::NotFound(what, which) => MemoryError::not_found(format!("no {what} {which}")),
        OwnerError::Changed(message) | OwnerError::Refused(message) => {
            MemoryError::new(MEMORY_CODE_INVALID_STATE, message, &[])
        }
        OwnerError::Engine(error) => MemoryError::from(*error),
        OwnerError::Host(_) => internal(verb),
    }
}

/// `vault.courtesy_delete.send`: asks a former peer to drop what an ended
/// pact delivered, and queues the ask for delivery.
pub(crate) async fn vault_courtesy_delete_send(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CourtesyDeleteSendRequest,
) -> MemoryResult<CourtesyDeleteSent> {
    const VERB: &str = "vault.courtesy_delete.send";
    as_owner(server, auth, VERB, move |server, owner| {
        cooperative_deletion::send(server, owner, &input).map_err(|error| refusal(VERB, error))
    })
    .await
}

/// `vault.courtesy_delete.sent`: every ask this vault sent, with its status.
pub(crate) async fn vault_courtesy_delete_sent(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> MemoryResult<Vec<CourtesyDeleteSent>> {
    const VERB: &str = "vault.courtesy_delete.sent";
    as_owner(server, auth, VERB, |server, _owner| {
        cooperative_deletion::sent(server).map_err(|error| refusal(VERB, error))
    })
    .await
}

/// `vault.courtesy_delete.incoming`: every ask a former peer sent.
pub(crate) async fn vault_courtesy_delete_incoming(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> MemoryResult<Vec<CourtesyDeleteIncoming>> {
    const VERB: &str = "vault.courtesy_delete.incoming";
    as_owner(server, auth, VERB, |server, _owner| {
        cooperative_deletion::incoming(server).map_err(|error| refusal(VERB, error))
    })
    .await
}

/// `vault.courtesy_delete.answer`: records the owner's choice on one
/// incoming ask, and sends the answer back when `reply_to` names where.
pub(crate) async fn vault_courtesy_delete_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CourtesyDeleteAnswerRequest,
) -> MemoryResult<CourtesyDeleteIncoming> {
    const VERB: &str = "vault.courtesy_delete.answer";
    as_owner(server, auth, VERB, move |server, owner| {
        cooperative_deletion::answer(server, owner, &input).map_err(|error| refusal(VERB, error))
    })
    .await
}
