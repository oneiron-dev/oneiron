//! Owner-authorized seal lifecycle, shared by generated HTTP, SDK and MCP calls.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::self_heal::audit::doors::{
    self, SealAttemptRequest, SealCompleteRequest, SealPendingRequest, SealReceiptView,
    SealRunReceipt, SealRunRequest,
};
use oneiron::self_heal::audit::{AttemptConfession, SealCheckRequest};

use super::host_doors::support::{Listed, internal, owner_proof, refused};
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
        super::clock_ingress::run_blocking(move || act(&server, &owner).map_err(MemoryError::from))
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

/// `vault.seal.receipt`: the stored receipt, listing every row its content
/// was derived from (FIX 8164): its subject, the attempt's TASK and result,
/// and the rows its producers recorded its inputs read from. The facade's
/// release judges it by them right before it is sent.
pub(crate) async fn vault_seal_receipt(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SealAttemptRequest,
) -> Listed<Option<SealReceiptView>> {
    let (answer, rows) = as_owner(
        server,
        auth,
        "vault.seal.receipt",
        move |server, owner| doors::receipt_sourced_as_owner(server.vault(), owner, &input),
        |(_, rows)| rows.clone(),
    )
    .await;
    (answer.map(|(view, _)| view), rows)
}

/// `vault.seal.pending`: the pending checks whose attempts the caller's
/// destination admits (FIX 8164). A check whose attempt's content was
/// derived from a row a world withheld from there keeps is left out, and so
/// out of the count; one whose sources are unknown stays. On this device
/// every check stays. It lists the kept checks' rows, which the facade's
/// release judges again right before it is sent.
pub(crate) async fn vault_seal_pending(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SealPendingRequest,
) -> Listed<Vec<SealCheckRequest>> {
    let (answer, _) = as_owner(
        server,
        auth,
        "vault.seal.pending",
        move |server, owner| doors::pending_sourced_as_owner(server.vault(), owner, &input),
        |_| Vec::new(),
    )
    .await;
    let destination = auth.destination();
    let mut listed = Vec::new();
    let answer = answer.map(|sourced| {
        sourced
            .into_iter()
            .filter_map(|(request, rows)| {
                let value = serde_json::to_value(&request).unwrap_or_default();
                if super::known_denied_rows(server.vault(), &destination, &rows, &value) {
                    return None;
                }
                listed.extend(rows);
                Some(request)
            })
            .collect::<Vec<_>>()
    });
    listed.sort_unstable();
    listed.dedup();
    (answer, listed)
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
