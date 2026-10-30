//! `vault.questions.outcome_windows`, `vault.questions.outcomes` and
//! `vault.questions.outcomes.project`: the caller's standing question's
//! closed outcome windows, its outcome labels and calibration pairs, and the
//! projection that binds its labels. Each replies through the caller's own
//! live lane (OF-506, FIX 11827): a narrowed caller gets each window, label
//! and pair whose rows that lane reads, and a projection's count of the
//! labels it reads; a full one, every one, as before. The projection binds
//! as it binds for anyone.

use std::sync::Arc;

use oneiron::llm::decision::questions::{
    OutcomeWindowClose, calibration_pairs_in_lane, closed_outcome_windows_in_lane,
    outcome_labels_in_lane, project_bound_outcomes_in_lane,
};
use oneiron::memory::MemoryResult;
use oneiron::receipt::{
    QuestionOutcomeWindowsRequest, QuestionOutcomes, QuestionOutcomesProjectRequest,
    QuestionOutcomesProjected, QuestionOutcomesRequest,
};

use super::super::host_doors::support::{Listed, internal, naming};
use super::{asker, asker_lane};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.questions.outcome_windows`: the caller's standing question's closed
/// outcome windows, across its versions; none when the question is not theirs.
/// Beside it, no row: the windows live in a side table.
pub(crate) async fn vault_questions_outcome_windows(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionOutcomeWindowsRequest,
) -> Listed<Vec<OutcomeWindowClose>> {
    naming(
        vault_questions_outcome_windows_answer(server, auth, input).await,
        |_| Vec::new(),
    )
}

async fn vault_questions_outcome_windows_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionOutcomeWindowsRequest,
) -> MemoryResult<Vec<OutcomeWindowClose>> {
    const VERB: &str = "vault.questions.outcome_windows";
    let principal = asker(auth, server, VERB)?.entity_ref();
    let server = Arc::clone(server);
    let auth = auth.clone();
    crate::api::facade::clock_ingress::run_blocking(
        move || -> MemoryResult<Vec<OutcomeWindowClose>> {
            let lane = asker_lane(server.vault(), &auth, principal, VERB)?;
            Ok(closed_outcome_windows_in_lane(
                server.vault(),
                &lane,
                principal,
                input.id,
            )?)
        },
    )
    .await
    .map_err(|_| internal(VERB))?
}

/// `vault.questions.outcomes`: the caller's standing question's stored
/// outcome labels and the calibration pairs the current facts still support,
/// each pairing an answer's prediction and probability with its label, read
/// at the caller's locality. Another principal's question is not found.
/// Beside it, the rows each label and pair names: a label's answer and fact,
/// and every row a pair was derived from.
pub(crate) async fn vault_questions_outcomes(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionOutcomesRequest,
) -> Listed<QuestionOutcomes> {
    naming(
        vault_questions_outcomes_answer(server, auth, input).await,
        |outcomes| {
            outcomes
                .labels
                .iter()
                .flat_map(|label| [label.answer, label.fact])
                .chain(
                    outcomes
                        .calibration
                        .iter()
                        .flat_map(|pair| pair.derived_from.iter().copied()),
                )
                .collect()
        },
    )
}

async fn vault_questions_outcomes_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionOutcomesRequest,
) -> MemoryResult<QuestionOutcomes> {
    const VERB: &str = "vault.questions.outcomes";
    let principal = asker(auth, server, VERB)?.entity_ref();
    // The feed goes to the requester's machine, as its connection proved it
    // (mesh PR2b).
    let destination = auth.destination();
    let server = Arc::clone(server);
    let auth = auth.clone();
    crate::api::facade::clock_ingress::run_blocking(move || -> MemoryResult<QuestionOutcomes> {
        let vault = server.vault();
        let lane = asker_lane(vault, &auth, principal, VERB)?;
        Ok(QuestionOutcomes {
            labels: outcome_labels_in_lane(vault, &lane, principal, input.id, &destination)?,
            calibration: calibration_pairs_in_lane(
                vault,
                &lane,
                principal,
                input.id,
                &destination,
            )?,
        })
    })
    .await
    .map_err(|_| internal(VERB))?
}

/// `vault.questions.outcomes.project`: projects the caller's standing
/// question's bound outcomes over the vault's current facts, binding each
/// admissible fact in an answer's horizon to that answer as a label. The
/// projection is idempotent over a fact's identity: replaying it binds none
/// again. Another principal's question binds none. Beside it, no row: the
/// labels live in a side table.
pub(crate) async fn vault_questions_outcomes_project(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionOutcomesProjectRequest,
) -> Listed<QuestionOutcomesProjected> {
    naming(
        vault_questions_outcomes_project_answer(server, auth, input).await,
        |_| Vec::new(),
    )
}

async fn vault_questions_outcomes_project_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionOutcomesProjectRequest,
) -> MemoryResult<QuestionOutcomesProjected> {
    const VERB: &str = "vault.questions.outcomes.project";
    let principal = asker(auth, server, VERB)?.entity_ref();
    let server = Arc::clone(server);
    let auth = auth.clone();
    crate::api::facade::clock_ingress::run_blocking(
        move || -> MemoryResult<QuestionOutcomesProjected> {
            let vault = server.vault();
            let lane = asker_lane(vault, &auth, principal, VERB)?;
            Ok(QuestionOutcomesProjected {
                id: input.id,
                projected: project_bound_outcomes_in_lane(vault, &lane, principal, input.id)?,
            })
        },
    )
    .await
    .map_err(|_| internal(VERB))?
}
