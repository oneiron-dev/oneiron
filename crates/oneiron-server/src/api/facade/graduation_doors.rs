//! Consent-graduation host doors, under the consent lifecycle's owner proof.
use std::sync::Arc;

use oneiron::Vault;
use oneiron::consent::AuthenticatedOwner;
use oneiron::consent_graduation::api::{self, *};
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
    // The ramp, policy, answers and grants live in side tables, not entity rows.
    (answer, Vec::new())
}

pub(crate) async fn vault_consent_graduation_policy(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GraduationPolicyRequest,
) -> Listed<GraduationPolicies> {
    as_owner(
        server,
        auth,
        "vault.consent.graduation.policy",
        move |vault, owner| api::policies(vault, owner, input),
    )
    .await
}

pub(crate) async fn vault_consent_graduation_policy_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GraduationPolicySetRequest,
) -> Listed<GraduationChanged> {
    as_owner(
        server,
        auth,
        "vault.consent.graduation.policy.set",
        move |vault, owner| api::set_policy(vault, owner, input),
    )
    .await
}

pub(crate) async fn vault_consent_graduation_policy_clear(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GraduationPolicyClearRequest,
) -> Listed<GraduationChanged> {
    as_owner(
        server,
        auth,
        "vault.consent.graduation.policy.clear",
        move |vault, owner| api::clear_policy(vault, owner, input),
    )
    .await
}

pub(crate) async fn vault_consent_graduation_stats(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GraduationScopeRequest,
) -> Listed<Option<GraduationStats>> {
    as_owner(
        server,
        auth,
        "vault.consent.graduation.stats",
        move |vault, owner| api::stats(vault, owner, input),
    )
    .await
}

pub(crate) async fn vault_consent_graduation_outcome(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GraduationOutcomeRequest,
) -> Listed<GraduationStats> {
    as_owner(
        server,
        auth,
        "vault.consent.graduation.outcome",
        move |vault, owner| api::record_outcome(vault, owner, input),
    )
    .await
}

pub(crate) async fn vault_consent_graduation_offers(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<Vec<GraduationOffer>> {
    as_owner(
        server,
        auth,
        "vault.consent.graduation.offers",
        move |vault, owner| api::offers(vault, owner),
    )
    .await
}

pub(crate) async fn vault_consent_graduation_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GraduationAnswerRequest,
) -> Listed<GraduationAnswerReceipt> {
    as_owner(
        server,
        auth,
        "vault.consent.graduation.answer",
        move |vault, owner| api::answer(vault, owner, input),
    )
    .await
}

pub(crate) async fn vault_consent_graduation_trust_table(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<Vec<GraduationTrustRow>> {
    as_owner(
        server,
        auth,
        "vault.consent.graduation.trust_table",
        move |vault, owner| api::trust_table(vault, owner),
    )
    .await
}

pub(crate) async fn vault_consent_graduation_settings_unpin(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GraduationScopeRequest,
) -> Listed<GraduationChanged> {
    as_owner(
        server,
        auth,
        "vault.consent.graduation.settings.unpin",
        move |vault, owner| api::unpin(vault, owner, input),
    )
    .await
}

pub(crate) async fn vault_consent_graduation_demote(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GraduationDemoteRequest,
) -> Listed<GraduationChanged> {
    as_owner(
        server,
        auth,
        "vault.consent.graduation.demote",
        move |vault, owner| api::demote(vault, owner, input),
    )
    .await
}
