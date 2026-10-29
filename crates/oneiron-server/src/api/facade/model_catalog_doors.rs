//! The model catalog is evidence. Only an explicit owner acceptance can
//! change a role binding; refresh, nomination, trials and denial never do.
use std::sync::{Arc, Mutex};
use std::time::Instant;

use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::catalog_doors::*;
use oneiron::llm::decision::Reversibility;
use oneiron::llm::decision::questions::{GraphUnitContext, QuestionRecord};
use oneiron::llm::manifest::ModelBinding;
use oneiron::llm::model_trials::TrialReading;
use oneiron::llm::registry::PricedModelBackend;
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::{EntityId, LlmUsage};

use super::host_doors::support::{Listed, internal, naming, owner_proof};
use crate::auth::CoreAuth;
use crate::decision_host::MODEL_DIAL;
use crate::server::SyncServer;

async fn as_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, &AuthenticatedOwner) -> oneiron::Result<T> + Send + 'static,
) -> MemoryResult<T> {
    let owner = owner_proof(auth, server, verb)?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || act(&server, &owner).map_err(MemoryError::from))
        .await
        .map_err(|_| internal(verb))?
}

fn trial_rows(trial: &ModelTrialView) -> Vec<EntityId> {
    let mut rows = vec![trial.request.principal, trial.request.goal];
    for case in &trial.cases {
        rows.extend([case.selection.answer, case.selection.fact, case.unit]);
        rows.extend(case.derived_from.iter().copied());
    }
    rows.sort();
    rows.dedup();
    rows
}

fn proposal_rows(proposal: &ModelBindingProposal) -> Vec<EntityId> {
    trial_rows(&proposal.trial)
}

pub(crate) async fn vault_models_catalog_refresh(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelCatalogRefresh,
) -> Listed<ModelCatalogRevision> {
    naming(
        as_owner(
            server,
            auth,
            "vault.models.catalog.refresh",
            move |server, owner| server.vault().refresh_model_catalog_as_owner(owner, input),
        )
        .await,
        |_| Vec::new(),
    )
}

pub(crate) async fn vault_models_catalog_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelCatalogGet,
) -> Listed<ModelCatalogRevision> {
    naming(
        as_owner(
            server,
            auth,
            "vault.models.catalog.get",
            move |server, owner| server.vault().model_catalog_as_owner(owner, input),
        )
        .await,
        |_| Vec::new(),
    )
}

pub(crate) async fn vault_models_catalog_diff(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelCatalogDiffRequest,
) -> Listed<ModelCatalogDiff> {
    naming(
        as_owner(
            server,
            auth,
            "vault.models.catalog.diff",
            move |server, owner| server.vault().diff_model_catalog_as_owner(owner, input),
        )
        .await,
        |_| Vec::new(),
    )
}

pub(crate) async fn vault_models_trials_nominate(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelTrialNominate,
) -> Listed<ModelTrialView> {
    let locality = auth.locality();
    naming(
        as_owner(
            server,
            auth,
            "vault.models.trials.nominate",
            move |server, owner| {
                server
                    .vault()
                    .nominate_model_trial_as_owner(owner, input, locality)
            },
        )
        .await,
        trial_rows,
    )
}

pub(crate) async fn vault_models_trials_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelTrialRef,
) -> Listed<ModelTrialView> {
    let locality = auth.locality();
    naming(
        as_owner(
            server,
            auth,
            "vault.models.trials.get",
            move |server, owner| server.vault().model_trial_as_owner(owner, input, locality),
        )
        .await,
        trial_rows,
    )
}

pub(crate) async fn vault_models_trials_approve(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelTrialRef,
) -> Listed<ModelTrialView> {
    let locality = auth.locality();
    naming(
        as_owner(
            server,
            auth,
            "vault.models.trials.approve",
            move |server, owner| {
                server
                    .vault()
                    .approve_model_trial_as_owner(owner, input, locality)
            },
        )
        .await,
        trial_rows,
    )
}

pub(crate) async fn vault_models_trials_run(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelTrialRef,
) -> Listed<ModelTrialView> {
    let locality = auth.locality();
    naming(
        as_owner(
            server,
            auth,
            "vault.models.trials.run",
            move |server, owner| {
                server.vault().run_model_trial_as_owner(
                    owner,
                    input,
                    locality,
                    |record, backend, context| execute_trial(server, record, backend, context),
                )
            },
        )
        .await,
        trial_rows,
    )
}

/// `vault.models.trials.resend_arm`: the owner's resend of one arm of
/// unknown outcome (FIX 10464); the next run sends it.
pub(crate) async fn vault_models_trials_resend_arm(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelTrialArmRef,
) -> Listed<ModelTrialView> {
    let locality = auth.locality();
    naming(
        as_owner(
            server,
            auth,
            "vault.models.trials.resend_arm",
            move |server, owner| {
                server
                    .vault()
                    .resend_model_trial_arm_as_owner(owner, input, locality)
            },
        )
        .await,
        trial_rows,
    )
}

pub(crate) async fn vault_models_trials_complete(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelTrialComplete,
) -> Listed<ModelTrialView> {
    let locality = auth.locality();
    naming(
        as_owner(
            server,
            auth,
            "vault.models.trials.complete",
            move |server, owner| {
                server
                    .vault()
                    .complete_model_trial_as_owner(owner, input, locality)
            },
        )
        .await,
        trial_rows,
    )
}

pub(crate) async fn vault_models_bindings_propose(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelBindingPropose,
) -> Listed<ModelBindingProposal> {
    let locality = auth.locality();
    naming(
        as_owner(
            server,
            auth,
            "vault.models.bindings.propose",
            move |server, owner| {
                server
                    .vault()
                    .propose_model_binding_as_owner(owner, input, locality)
            },
        )
        .await,
        proposal_rows,
    )
}

pub(crate) async fn vault_models_bindings_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelBindingProposalRef,
) -> Listed<ModelBindingProposal> {
    let locality = auth.locality();
    naming(
        as_owner(
            server,
            auth,
            "vault.models.bindings.get",
            move |server, owner| {
                server
                    .vault()
                    .model_binding_proposal_as_owner(owner, input, locality)
            },
        )
        .await,
        proposal_rows,
    )
}

pub(crate) async fn vault_models_bindings_read(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelBindingRead,
) -> Listed<ModelBinding> {
    naming(
        as_owner(
            server,
            auth,
            "vault.models.bindings.read",
            move |server, owner| server.vault().model_binding_as_owner(owner, input),
        )
        .await,
        |_| Vec::new(),
    )
}

pub(crate) async fn vault_models_bindings_accept(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelBindingAccept,
) -> Listed<ModelBindingProposal> {
    let locality = auth.locality();
    naming(
        as_owner(
            server,
            auth,
            "vault.models.bindings.accept",
            move |server, owner| {
                server
                    .vault()
                    .accept_model_binding_as_owner(owner, input, locality)
            },
        )
        .await,
        proposal_rows,
    )
}

pub(crate) async fn vault_models_bindings_deny(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelBindingProposalRef,
) -> Listed<ModelBindingProposal> {
    let locality = auth.locality();
    naming(
        as_owner(
            server,
            auth,
            "vault.models.bindings.deny",
            move |server, owner| {
                server
                    .vault()
                    .deny_model_binding_as_owner(owner, input, locality)
            },
        )
        .await,
        proposal_rows,
    )
}

/// No held-out label enters this callback. It sees only the original
/// answer's still-readable source bodies, at their pinned hashes.
fn execute_trial(
    server: &SyncServer,
    record: &QuestionRecord,
    backend: &PricedModelBackend,
    context: &GraphUnitContext,
) -> oneiron::Result<TrialReading> {
    let usage = Arc::new(Mutex::new(Vec::new()));
    let held = server
        .decision_host()
        .ladder_for_trial(&backend.pin, Arc::clone(&usage))
        .map_err(|error| oneiron::Error::InvalidConfig(error.to_string()))?;
    let state = context.state_under(&[], &[], &record.definition.criteria);
    let evidence: Vec<_> = context.sources.iter().map(|source| source.id).collect();
    let deadline =
        RetrievalDeadline::hard(Instant::now(), record.definition.deadline(server.vault())?);
    let posture = crate::decision_graph::question_posture(server, record.definition.posture)
        .unwrap_or_else(|| server.vault().privacy_posture());
    let mut decision = held
        .ladder()
        .under_posture(posture, server.decision_host().remote_opt_in())
        .run(
            &record.definition.question,
            record.principal,
            &evidence,
            &state,
            MODEL_DIAL,
            &server.decision_host().bands(),
            Reversibility::ReversibleRead,
            &deadline,
        )?;
    decision.receipt.evidence_versions = context
        .sources
        .iter()
        .map(|source| oneiron::llm::decision::EvidenceVersion {
            id: source.id,
            body_hash: source.hash,
        })
        .collect();
    let reads = usage
        .lock()
        .map_err(|_| oneiron::Error::InvariantViolation("model trial usage lock"))?;
    if reads.is_empty() {
        return Err(oneiron::Error::InvalidConfig(
            "model trial produced no measured provider usage".into(),
        ));
    }
    let mut total = LlmUsage::zero();
    let add = |left: u64, right: u64| {
        left.checked_add(right)
            .ok_or(oneiron::Error::ArithmeticOverflow("model trial usage"))
    };
    for read in reads.iter() {
        total.input.total = add(total.input.total, read.input.total)?;
        total.input.cache_read = add(total.input.cache_read, read.input.cache_read)?;
        total.input.cache_write = add(total.input.cache_write, read.input.cache_write)?;
        total.output.total = add(total.output.total, read.output.total)?;
        total.output.text = add(total.output.text, read.output.text)?;
        total.output.reasoning = add(total.output.reasoning, read.output.reasoning)?;
    }
    total.raw_provider =
        serde_json::Value::Array(reads.iter().map(|read| read.raw_provider.clone()).collect());
    Ok(TrialReading {
        backend: backend.pin.clone(),
        decision: Some(decision),
        usage: total,
    })
}
