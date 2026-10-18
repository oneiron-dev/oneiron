//! Typed eval doors under the caller's own verified owner credential.
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::skill_optimize::eval_doors;

use super::host_doors::{Listed, internal, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

async fn owned<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&oneiron::Vault, &AuthenticatedOwner) -> oneiron::Result<T> + Send + 'static,
) -> Listed<T> {
    let owner = match owner_proof(auth, server, verb) {
        Ok(owner) => owner,
        Err(error) => return (Err(error), Vec::new()),
    };
    let server = Arc::clone(server);
    let answer: MemoryResult<T> = tokio::task::spawn_blocking(move || {
        act(server.vault(), &owner).map_err(MemoryError::from)
    })
    .await
    .map_err(|_| internal(verb))
    .and_then(|answer| answer);
    // These are local ledger rows and receipt refs, not core row content.
    (answer, Vec::new())
}

pub(crate) async fn vault_evals_author_now(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::skill_optimize::eval_doors::EvalAuthorNowRequest,
) -> Listed<oneiron::skill_optimize::eval_doors::EvalAuthoringRef> {
    owned(server, auth, "vault.evals.author_now", move |vault, owner| {
        eval_doors::author_now(vault, owner, input)
    })
    .await
}

pub(crate) async fn vault_evals_authoring_result(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::skill_optimize::eval_doors::EvalAuthoringRef,
) -> Listed<Option<oneiron::skill_optimize::eval_doors::EvalAuthoringResult>> {
    owned(server, auth, "vault.evals.authoring.result", move |vault, owner| {
        eval_doors::authoring_result(vault, owner, input)
    })
    .await
}

pub(crate) async fn vault_evals_families(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::skill_optimize::eval_doors::EvalSeatRequest,
) -> Listed<Vec<oneiron::skill_optimize::eval_doors::EvalFamilyView>> {
    owned(server, auth, "vault.evals.families", move |vault, owner| {
        eval_doors::families(vault, owner, input)
    })
    .await
}

pub(crate) async fn vault_evals_families_assign(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::skill_optimize::eval_doors::EvalFamilyAssignRequest,
) -> Listed<oneiron::skill_optimize::SourceFamily> {
    owned(server, auth, "vault.evals.families.assign", move |vault, owner| {
        eval_doors::assign_family(vault, owner, input)
    })
    .await
}

pub(crate) async fn vault_evals_cases(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::skill_optimize::eval_doors::EvalCasesRequest,
) -> Listed<Vec<oneiron::skill_optimize::EvalCase>> {
    owned(server, auth, "vault.evals.cases", move |vault, owner| {
        eval_doors::cases(vault, owner, input)
    })
    .await
}

pub(crate) async fn vault_evals_cases_record(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::skill_optimize::EvalCaseDraft,
) -> Listed<oneiron::skill_optimize::EvalCase> {
    owned(server, auth, "vault.evals.cases.record", move |vault, owner| {
        eval_doors::record_case(vault, owner, input)
    })
    .await
}

pub(crate) async fn vault_evals_cohorts(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::skill_optimize::eval_doors::EvalSeatRequest,
) -> Listed<Vec<oneiron::skill_optimize::eval_doors::EvalCohortView>> {
    owned(server, auth, "vault.evals.cohorts", move |vault, owner| {
        eval_doors::cohorts(vault, owner, input)
    })
    .await
}

pub(crate) async fn vault_evals_cohorts_open(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::skill_optimize::eval_doors::EvalCohortOpenRequest,
) -> Listed<oneiron::skill_optimize::EvalRelease> {
    owned(server, auth, "vault.evals.cohorts.open", move |vault, owner| {
        eval_doors::open_cohort(vault, owner, input)
    })
    .await
}

pub(crate) async fn vault_evals_exposure(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::skill_optimize::eval_doors::EvalCohortRef,
) -> Listed<oneiron::skill_optimize::eval_doors::EvalExposureLedger> {
    owned(server, auth, "vault.evals.exposure", move |vault, owner| {
        eval_doors::exposure(vault, owner, input)
    })
    .await
}

pub(crate) async fn vault_evals_sufficiency(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::skill_optimize::SufficiencyInput,
) -> Listed<oneiron::skill_optimize::SufficiencyCard> {
    owned(server, auth, "vault.evals.sufficiency", move |vault, owner| {
        eval_doors::sufficiency(vault, owner, input)
    })
    .await
}

pub(crate) async fn vault_evals_labels_blocked(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::skill_optimize::eval_doors::EvalBlockedLabelsRequest,
) -> Listed<Vec<oneiron::skill_optimize::EvalLabelAsk>> {
    owned(server, auth, "vault.evals.labels.blocked", move |vault, owner| {
        eval_doors::blocked_labels(vault, owner, input)
    })
    .await
}

pub(crate) async fn vault_evals_labels_pick(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::skill_optimize::eval_doors::EvalLabelPickRequest,
) -> Listed<oneiron::skill_optimize::EvalCase> {
    owned(server, auth, "vault.evals.labels.pick", move |vault, owner| {
        eval_doors::pick_label(vault, owner, input)
    })
    .await
}
