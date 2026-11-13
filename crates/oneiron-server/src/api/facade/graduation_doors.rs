//! Consent-graduation host doors, under the consent lifecycle's owner proof.
use std::sync::Arc;

use oneiron::Vault;
use oneiron::consent::AuthenticatedOwner;
use oneiron::consent_graduation::api::{self, *};
use oneiron::memory::MemoryResult;
use oneiron::task_verb::sdk::EmptyRequest;

use super::clock_ingress;
use super::host_doors::support::{Listed, internal, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

async fn as_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&Vault, &AuthenticatedOwner) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    as_proven(server, verb, owner_proof(auth, server, verb), act).await
}

/// Runs `act` under `proof` on the engine's blocking pool, or answers the
/// proof's refusal.
async fn as_proven<T: Send + 'static>(
    server: &Arc<SyncServer>,
    verb: &'static str,
    proof: MemoryResult<AuthenticatedOwner>,
    act: impl FnOnce(&Vault, &AuthenticatedOwner) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let proof = match proof {
        Ok(proof) => proof,
        Err(error) => return (Err(error), Vec::new()),
    };
    let server = Arc::clone(server);
    let answer = clock_ingress::run_blocking(move || act(server.vault(), &proof))
        .await
        .unwrap_or_else(|_| Err(internal(verb)));
    // The ramp, policy, answers and grants live in side tables, not entity rows.
    (answer, Vec::new())
}

/// Who demotes a graduated scope over the host door (census L7-33; RULING
/// L7-33-HOLDER-ROUTE = A, as `gate_policy_doors::policy_putter` for FIX
/// 8177): the owner under its proof, as before, or a person on their own
/// verified slip who holds the ramp demotion policy power
/// ([`Vault::holds_ramp_demote_power`]). That check is read-only here, so a
/// powerless person's pre-hooks never fire, and the demotion writer makes it
/// again in its own transaction. Neither an Admin nor a Delegate label admits
/// anyone by itself; anyone else keeps the owner refusal it had.
pub(super) fn ramp_demoter(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<AuthenticatedOwner> {
    owner_proof(auth, server, verb).or_else(|refusal| {
        super::shared_act_doors::person(server, auth, verb)
            .ok()
            .filter(|person| {
                server
                    .vault()
                    .holds_ramp_demote_power(person)
                    .unwrap_or(false)
            })
            .ok_or(refusal)
    })
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
    const VERB: &str = "vault.consent.graduation.demote";
    // The owner's proof or a policy holder's own: the engine door admits
    // either and checks the power again in its writer.
    as_proven(
        server,
        VERB,
        ramp_demoter(server, auth, VERB),
        move |vault, proof| api::demote(vault, proof, input),
    )
    .await
}
