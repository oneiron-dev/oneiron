//! Owner-authorized seal lifecycle, shared by generated HTTP, SDK and MCP calls.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::self_heal::audit::doors::{
    self, SealAttemptRequest, SealCompleteRequest, SealPendingRequest, SealReceiptView, SealRunReceipt,
    SealRunRequest,
};
use oneiron::self_heal::audit::{AttemptConfession, SealCheckRequest};

use super::host_doors::{Listed, internal, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

async fn as_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, &AuthenticatedOwner) -> oneiron::Result<T> + Send + 'static,
    rows: impl FnOnce(&T) -> Vec<EntityId>,
) -> Listed<T> {
    let owner = match owner_proof(auth, server, verb) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let server = Arc::clone(server);
    let answer: MemoryResult<T> =
        tokio::task::spawn_blocking(move || act(&server, &owner).map_err(MemoryError::from))
            .await
            .map_err(|_| internal(verb))
            .and_then(|answer| answer);
    let listed = answer.as_ref().map_or_else(|_| Vec::new(), rows);
    (answer, listed)
}

fn receipt_rows(view: &SealReceiptView) -> Vec<EntityId> {
    vec![view.receipt.confession.subject]
}

pub(crate) async fn vault_seal_confess(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AttemptConfession,
) -> Listed<SealReceiptView> {
    as_owner(
        server,
        auth,
        "vault.seal.confess",
        move |server, owner| doors::confess_as_owner(server.vault(), owner, &input),
        receipt_rows,
    )
    .await
}

pub(crate) async fn vault_seal_audit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SealAttemptRequest,
) -> Listed<SealReceiptView> {
    as_owner(
        server,
        auth,
        "vault.seal.audit",
        move |server, owner| doors::audit_as_owner(server.vault(), owner, &input),
        receipt_rows,
    )
    .await
}

pub(crate) async fn vault_seal_receipt(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SealAttemptRequest,
) -> Listed<Option<SealReceiptView>> {
    as_owner(
        server,
        auth,
        "vault.seal.receipt",
        move |server, owner| doors::receipt_as_owner(server.vault(), owner, &input),
        |view| view.as_ref().map_or_else(Vec::new, receipt_rows),
    )
    .await
}

pub(crate) async fn vault_seal_pending(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SealPendingRequest,
) -> Listed<Vec<SealCheckRequest>> {
    as_owner(
        server,
        auth,
        "vault.seal.pending",
        move |server, owner| doors::pending_as_owner(server.vault(), owner, &input),
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_seal_run(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SealRunRequest,
) -> Listed<SealRunReceipt> {
    as_owner(
        server,
        auth,
        "vault.seal.run",
        move |server, owner| doors::run_as_owner(server.vault(), owner, &input),
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_seal_complete(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SealCompleteRequest,
) -> Listed<SealReceiptView> {
    as_owner(
        server,
        auth,
        "vault.seal.complete",
        move |server, owner| doors::complete_as_owner(server.vault(), owner, &input),
        receipt_rows,
    )
    .await
}
