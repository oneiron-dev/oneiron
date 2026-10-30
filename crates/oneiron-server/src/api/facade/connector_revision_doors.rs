//! FIX 988: the owner's doors onto proposed connector slate revisions, shared
//! by HTTP, SDK and MCP: his ruling on a scope exceed, the revisions waiting
//! on him, holding one back, his one stamp of one, and his observation of a
//! credential slot's issuer. Each runs on the owner's proof, revalidated in
//! the engine's own writer.
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::MemoryResult;
use oneiron::task_verb::sdk::{
    self, ConnectorCredentialBindingView, ConnectorIssuerReaskRequest, ConnectorRevisionSnoozeView,
    ConnectorScopeOutcomeRequest, ConnectorScopeOutcomeView, ConnectorSlateRevisionAcceptRequest,
    ConnectorSlateRevisionAcceptedView, ConnectorSlateRevisionCauseView,
    ConnectorSlateRevisionDeferRequest, ConnectorSlateRevisionOffersRequest,
    ConnectorSlateRevisionOffersView,
};
use oneiron::{EntityId, Vault};

use super::host_doors::support::{Listed, MaybeListed, internal, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// Runs `act` on the vault as the owner `auth` proves, off the async runtime.
async fn as_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&Vault, &AuthenticatedOwner) -> MemoryResult<T> + Send + 'static,
) -> MemoryResult<T> {
    let owner = owner_proof(auth, server, verb)?;
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || act(server.vault(), &owner))
        .await
        .unwrap_or_else(|_| Err(internal(verb)))
}

/// `vault.connectors.slates.scope_outcome`: it lists the key and grant the
/// signal's authority check read.
pub(crate) async fn vault_connectors_slates_scope_outcome(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConnectorScopeOutcomeRequest,
) -> Listed<ConnectorScopeOutcomeView> {
    let answer = as_owner(
        server,
        auth,
        "vault.connectors.slates.scope_outcome",
        move |vault, owner| sdk::record_connector_scope_outcome(vault, owner, input),
    )
    .await;
    let rows = answer.as_ref().map_or_else(
        |_| Vec::new(),
        |view| {
            [&view.signal.key_ref, &view.signal.grant_id]
                .into_iter()
                .filter_map(|reference| EntityId::from_hex(reference).ok())
                .collect()
        },
    );
    (answer, rows)
}

/// `vault.connectors.slates.revision_offers`: it reads keys, grants and
/// slates across every waiting revision, so its rows are not known.
pub(crate) async fn vault_connectors_slates_revision_offers(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConnectorSlateRevisionOffersRequest,
) -> MaybeListed<ConnectorSlateRevisionOffersView> {
    let answer = as_owner(
        server,
        auth,
        "vault.connectors.slates.revision_offers",
        move |vault, owner| sdk::connector_slate_revision_offers(vault, owner, input),
    )
    .await;
    (answer, None)
}

/// `vault.connectors.slates.defer_revision`: it reads the signal and its
/// ramp's side tables, which hold no row, so it lists none.
pub(crate) async fn vault_connectors_slates_defer_revision(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConnectorSlateRevisionDeferRequest,
) -> Listed<ConnectorRevisionSnoozeView> {
    let answer = as_owner(
        server,
        auth,
        "vault.connectors.slates.defer_revision",
        move |vault, owner| sdk::defer_connector_slate_revision(vault, owner, input),
    )
    .await;
    (answer, Vec::new())
}

/// `vault.connectors.slates.accept_revision`: its recheck reads keys and
/// grants by cause, so its rows are not known. An accepted issuer revision
/// with dependent rows starts the re-run of their discovery and
/// qualification on a blocking worker (FIX 9304); the answer, its shape and
/// the hold's lift do not wait on it.
pub(crate) async fn vault_connectors_slates_accept_revision(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConnectorSlateRevisionAcceptRequest,
) -> MaybeListed<ConnectorSlateRevisionAcceptedView> {
    let answer = as_owner(
        server,
        auth,
        "vault.connectors.slates.accept_revision",
        move |vault, owner| sdk::accept_connector_slate_revision(vault, owner, input),
    )
    .await;
    if let Ok(ConnectorSlateRevisionAcceptedView {
        cause:
            ConnectorSlateRevisionCauseView::CredentialIssuerChanged {
                binding_ref,
                dependent_rows,
                ..
            },
        ..
    }) = &answer
        && !dependent_rows.is_empty()
        && let Ok(binding_ref) = EntityId::from_hex(binding_ref)
    {
        let server = Arc::clone(server);
        drop(tokio::task::spawn_blocking(move || {
            crate::connector_admission_host::rerun_issuer_dependents(&server, binding_ref);
        }));
    }
    (answer, None)
}

/// `vault.connectors.slates.reask_issuer`: it lists the catalog key and
/// each dependent key it read.
pub(crate) async fn vault_connectors_slates_reask_issuer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConnectorIssuerReaskRequest,
) -> Listed<ConnectorCredentialBindingView> {
    let answer = as_owner(
        server,
        auth,
        "vault.connectors.slates.reask_issuer",
        move |vault, owner| sdk::reask_connector_issuer_as(vault, owner, input),
    )
    .await;
    match answer {
        Ok((view, rows)) => (Ok(view), rows),
        Err(error) => (Err(error), Vec::new()),
    }
}
