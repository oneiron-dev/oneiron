//! Consent lifecycle host doors, on the same owner proof as Gate policy.
use std::sync::Arc;

use oneiron::Vault;
use oneiron::consent::lifecycle::{
    self, ApproveOnceRequest, ConsentActReceipt, CreateStandingGrantRequest,
    DenyConsentRequest, RevokeGrantRequest,
};
use oneiron::consent::{AuthenticatedOwner, ConsentRegistry, ConsentRegistryQuery};
use oneiron::memory::MemoryResult;

use super::host_doors::{Listed, internal, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

async fn as_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&Vault, &AuthenticatedOwner) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let owner = match owner_proof(auth, server, verb) {
        Ok(owner) => owner,
        Err(error) => return (Err(error), Vec::new()),
    };
    let server = Arc::clone(server);
    let answer = tokio::task::spawn_blocking(move || act(server.vault(), &owner))
        .await
        .unwrap_or_else(|_| Err(internal(verb)));
    // Grants and their receipts live in side tables, not entity rows.
    (answer, Vec::new())
}

pub(crate) async fn vault_consent_approve_once(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ApproveOnceRequest,
) -> Listed<ConsentActReceipt> {
    as_owner(
        server,
        auth,
        "vault.consent.approve_once",
        move |vault, owner| lifecycle::approve_once(vault, owner, input),
    )
    .await
}

pub(crate) async fn vault_consent_deny(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DenyConsentRequest,
) -> Listed<ConsentActReceipt> {
    as_owner(server, auth, "vault.consent.deny", move |vault, owner| {
        lifecycle::deny(vault, owner, input)
    })
    .await
}

pub(crate) async fn vault_consent_create_standing_grant(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CreateStandingGrantRequest,
) -> Listed<ConsentActReceipt> {
    as_owner(
        server,
        auth,
        "vault.consent.create_standing_grant",
        move |vault, owner| lifecycle::create_standing_grant(vault, owner, input),
    )
    .await
}

pub(crate) async fn vault_consent_registry(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConsentRegistryQuery,
) -> Listed<ConsentRegistry> {
    as_owner(
        server,
        auth,
        "vault.consent.registry",
        move |vault, owner| lifecycle::registry(vault, owner, input),
    )
    .await
}

pub(crate) async fn vault_consent_revoke(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RevokeGrantRequest,
) -> Listed<ConsentActReceipt> {
    as_owner(server, auth, "vault.consent.revoke", move |vault, owner| {
        lifecycle::revoke(vault, owner, input)
    })
    .await
}
