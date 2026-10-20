//! Consent lifecycle host doors, on the same owner proof as Gate policy.
use std::sync::Arc;

use oneiron::Vault;
use oneiron::consent::bypass_lifecycle::{
    self as bypass, ActiveBypassGrantsRequest, BypassActiveState, BypassGrantWarningRequest,
    BypassGrantWarningView, BypassedEffectReceipt, BypassedEffectReceiptsRequest,
    CreateBypassGrantRequest,
};
use oneiron::consent::lifecycle::{
    self, ApproveOnceRequest, ConsentActReceipt, CreateStandingGrantRequest, DenyConsentRequest,
    RevokeGrantRequest,
};
use oneiron::consent::{AuthenticatedOwner, ConsentRegistry, ConsentRegistryQuery};
use oneiron::failure_signals::HeldFailureSignalBatchView;
use oneiron::memory::MemoryResult;
use oneiron::task_verb::sdk::EmptyRequest;

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

/// `vault.consent.failure_signals_held` (FIX 6740): the failure-signal batch
/// the vault carries, its exact content and the approve-once digest the
/// press beside it takes, under the owner's proof. Its answer lists the
/// worlds the batch's code-fix records touched, so every served door
/// releases it by them as it releases any owner read.
pub(crate) async fn vault_consent_failure_signals_held(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<Option<HeldFailureSignalBatchView>> {
    const VERB: &str = "vault.consent.failure_signals_held";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return (Err(error), Vec::new()),
    };
    let server = Arc::clone(server);
    let read =
        tokio::task::spawn_blocking(move || server.vault().held_failure_signal_batch(&owner)).await;
    match read {
        Ok(Ok((view, worlds))) => (Ok(view), worlds),
        Ok(Err(error)) => (Err(error), Vec::new()),
        Err(_) => (Err(internal(VERB)), Vec::new()),
    }
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

pub(crate) async fn vault_consent_bypass_grant_warning(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: BypassGrantWarningRequest,
) -> Listed<BypassGrantWarningView> {
    as_owner(
        server,
        auth,
        "vault.consent.bypass_grant_warning",
        move |vault, owner| bypass::bypass_grant_warning(vault, owner, input),
    )
    .await
}

pub(crate) async fn vault_consent_create_bypass_grant(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CreateBypassGrantRequest,
) -> Listed<Vec<ConsentActReceipt>> {
    as_owner(
        server,
        auth,
        "vault.consent.create_bypass_grant",
        move |vault, owner| bypass::create_bypass_grant(vault, owner, input),
    )
    .await
}

pub(crate) async fn vault_consent_active_bypass_grants(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ActiveBypassGrantsRequest,
) -> Listed<Vec<BypassActiveState>> {
    as_owner(
        server,
        auth,
        "vault.consent.active_bypass_grants",
        move |vault, owner| bypass::active_bypass_grants(vault, owner, input),
    )
    .await
}

pub(crate) async fn vault_consent_bypassed_effect_receipts(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: BypassedEffectReceiptsRequest,
) -> Listed<Vec<BypassedEffectReceipt>> {
    as_owner(
        server,
        auth,
        "vault.consent.bypassed_effect_receipts",
        move |vault, owner| bypass::bypassed_effect_receipts(vault, owner, input),
    )
    .await
}
