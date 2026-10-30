//! Witnessed goal intake and goal-vector optimizer doors under the caller's owner proof.
use std::sync::Arc;

use oneiron::memory::{MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{self, *};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::Listed;
use super::hub_doors::owner_call;
use crate::api::scoped_auth::lane_reads_each;
use crate::auth::CoreAuth;
use crate::replay_judge::{self, ServeAxisBandit};
use crate::server::SyncServer;

pub(crate) async fn vault_projects_goal_intake_complete(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ProjectGoalIntakeCompleteRequest,
) -> Listed<oneiron::task_verb::sdk::ProjectGoalIntakeReceipt> {
    owner_call(
        server,
        auth,
        "vault.projects.goal.intake.complete",
        move |server, owner| {
            let answer = sdk::project_goal_intake_complete_as_owner(server.vault(), owner, &input)?;
            let rows = vec![
                input.project_ref,
                answer.goal_claim,
                input.turns.question,
                input.turns.answer,
                input.turns.draft,
                input.turns.confirmation,
            ];
            Ok((answer, rows))
        },
    )
    .await
}

pub(crate) async fn vault_projects_goal_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ProjectRefRequest,
) -> Listed<oneiron::task_verb::sdk::ProjectGoalView> {
    owner_call(
        server,
        auth,
        "vault.projects.goal.get",
        move |server, owner| {
            let project = EntityId::from_hex(&input.project_ref)?;
            let answer = sdk::project_goal_get_as_owner(server.vault(), owner, project)?;
            let rows = std::iter::once(project).chain(answer.goal_claim).collect();
            Ok((answer, rows))
        },
    )
    .await
}

pub(crate) async fn vault_skills_optimize_propose(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillOptimizeProposeRequest,
) -> Listed<oneiron::task_verb::sdk::SkillOptimizeProposalReceipt> {
    owner_call(
        server,
        auth,
        "vault.skills.optimize.propose",
        move |server, owner| {
            let answer = sdk::skill_optimize_propose_as_owner(server.vault(), owner, &input)?;
            let rows = vec![answer.skill, answer.proposal];
            Ok((answer, rows))
        },
    )
    .await
}

pub(crate) async fn vault_skills_optimize_measure(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillOptimizeMeasureRequest,
) -> Listed<oneiron::task_verb::sdk::SkillOptimizeMeasurement> {
    owner_call(
        server,
        auth,
        "vault.skills.optimize.measure",
        move |server, owner| {
            let judge = replay_judge::registered().ok_or_else(|| {
                MemoryError::new(
                    MEMORY_CODE_MODEL_UNAVAILABLE,
                    "no skill judge is registered",
                    &[],
                )
            })?;
            let pulls = input
                .pulls_per_axis
                .or(judge.live_pulls_per_axis())
                .ok_or_else(|| {
                    MemoryError::bad_request(
                        "name pulls_per_axis or set skills.live_pulls_per_axis",
                    )
                })?;
            let bandit = ServeAxisBandit::for_proposal(judge, &input.proposal)?;
            let answer = sdk::skill_optimize_measure_as_owner(
                server.vault(),
                owner,
                &input,
                judge,
                &bandit,
                pulls,
            )?;
            Ok((answer, vec![input.proposal]))
        },
    )
    .await
}

pub(crate) async fn vault_skills_optimize_score(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillOptimizeProposalRequest,
) -> Listed<oneiron::task_verb::sdk::SkillOptimizeResultView> {
    owner_call(
        server,
        auth,
        "vault.skills.optimize.score",
        move |server, owner| {
            let judge = replay_judge::registered().ok_or_else(|| {
                MemoryError::new(
                    MEMORY_CODE_MODEL_UNAVAILABLE,
                    "no skill judge is registered",
                    &[],
                )
            })?;
            let answer = sdk::skill_optimize_score_as_owner(server.vault(), owner, &input, judge)?;
            let rows = answer.rows();
            Ok((answer, rows))
        },
    )
    .await
}

pub(crate) async fn vault_skills_optimize_admit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillOptimizeProposalRequest,
) -> Listed<oneiron::task_verb::sdk::SkillOptimizeResultView> {
    owner_call(
        server,
        auth,
        "vault.skills.optimize.admit",
        move |server, owner| {
            let answer = sdk::skill_optimize_admit_as_owner(server.vault(), owner, &input)?;
            let rows = answer.rows();
            Ok((answer, rows))
        },
    )
    .await
}

pub(crate) async fn vault_skills_optimize_goal_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillOptimizeGoalRequest,
) -> Listed<oneiron::task_verb::sdk::SkillOptimizeGoalView> {
    owner_call(
        server,
        auth,
        "vault.skills.optimize.goal.get",
        move |server, owner| {
            let answer = sdk::skill_optimize_goal_as_owner(server.vault(), owner, &input)?;
            let rows = std::iter::once(input.skill)
                .chain(answer.project)
                .chain(answer.goal_claim)
                .collect();
            Ok((answer, rows))
        },
    )
    .await
}

pub(crate) async fn vault_skills_optimize_goal_bind(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillOptimizeGoalBindRequest,
) -> Listed<oneiron::task_verb::sdk::SkillOptimizeGoalRevision> {
    owner_call(
        server,
        auth,
        "vault.skills.optimize.goal.bind",
        move |server, owner| {
            let answer = sdk::skill_optimize_goal_bind_as_owner(server.vault(), owner, &input)?;
            let rows = std::iter::once(input.skill).chain(input.project).collect();
            Ok((answer, rows))
        },
    )
    .await
}

pub(crate) async fn vault_skills_optimize_preferences_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillOptimizeGoalRequest,
) -> Listed<Option<oneiron::skill_optimize::SkillTradeoffPreferences>> {
    owner_call(
        server,
        auth,
        "vault.skills.optimize.preferences.get",
        move |server, owner| {
            let answer = sdk::skill_optimize_preferences_as_owner(server.vault(), owner, &input)?;
            Ok((answer, vec![input.skill]))
        },
    )
    .await
}

pub(crate) async fn vault_skills_optimize_preferences_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillOptimizePreferencesSetRequest,
) -> Listed<oneiron::task_verb::sdk::SkillOptimizeGoalRevision> {
    owner_call(
        server,
        auth,
        "vault.skills.optimize.preferences.set",
        move |server, owner| {
            let answer =
                sdk::skill_optimize_preferences_set_as_owner(server.vault(), owner, &input)?;
            Ok((answer, vec![input.skill]))
        },
    )
    .await
}

/// Who lists and picks tradeoff asks on the typed doors (FIX 8178): the
/// owner, under its proof, as before; else the person or agent the
/// credential binds, as `/v1/core/skills/tradeoff-asks` admits it, whose
/// reached responsible role the engine checks as its authorization. A
/// caller that is neither keeps the owner refusal it had.
pub(super) enum Picker {
    Owner(oneiron::consent::AuthenticatedOwner),
    Holder(oneiron::WriteActor),
}

pub(super) fn picker(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<Picker> {
    super::owner_binding::facade_owner(server, auth, verb)
        .map(Picker::Owner)
        .or_else(|refusal| match super::facade_actor(server, auth) {
            Ok((actor, class @ (EdgeActorClass::Human | EdgeActorClass::Agent))) => {
                Ok(Picker::Holder(oneiron::WriteActor::new(actor, class)))
            }
            _ => Err(refusal),
        })
}

/// `act` off the runtime as [`picker`] admits the caller.
async fn picked<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, &Picker) -> MemoryResult<(T, Vec<EntityId>)> + Send + 'static,
) -> Listed<T> {
    let picker = match picker(server, auth, verb) {
        Ok(picker) => picker,
        Err(refusal) => return (Err(refusal), Vec::new()),
    };
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || match act(&server, &picker) {
        Ok((answer, rows)) => (Ok(answer), rows),
        Err(error) => (Err(error), Vec::new()),
    })
    .await
    .unwrap_or_else(|_| (Err(super::host_doors::support::internal(verb)), Vec::new()))
}

pub(crate) async fn vault_skills_optimize_tradeoff_asks(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EmptyRequest,
) -> Listed<Vec<SkillOptimizeTradeoffAskView>> {
    let lane = auth.clone();
    picked(
        server,
        auth,
        "vault.skills.optimize.tradeoff_asks",
        move |server, picker| {
            let _ = input;
            let answer = match picker {
                Picker::Owner(owner) => {
                    sdk::skill_optimize_tradeoff_asks_as_owner(server.vault(), owner)?
                }
                Picker::Holder(by) => {
                    sdk::skill_optimize_tradeoff_asks_for(server.vault(), &by.entity_ref())?
                }
            };
            // FIX 8162: the asks the caller's own lane reads whole, as
            // `GET /v1/core/skills/tradeoff-asks` lists them.
            let answer = lane_reads_each(server.vault(), &lane, answer, tradeoff_view_refs)
                .map_err(|error| super::FacadeApiError::from(error).into_memory_error())?;
            let rows = answer
                .iter()
                .map(|view| view.ask.question.proposal)
                .collect();
            Ok((answer, rows))
        },
    )
    .await
}

/// The rows a listed tradeoff ask names (FIX 8162).
fn tradeoff_view_refs(view: &SkillOptimizeTradeoffAskView) -> Vec<EntityId> {
    super::role_picks::tradeoff_ask_refs(&view.ask)
}

pub(crate) async fn vault_skills_optimize_tradeoff_asks_pick(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillOptimizeTradeoffPickRequest,
) -> Listed<oneiron::task_verb::sdk::SkillOptimizeResultView> {
    picked(
        server,
        auth,
        "vault.skills.optimize.tradeoff_asks.pick",
        move |server, picker| {
            let answer = match picker {
                Picker::Owner(owner) => {
                    sdk::skill_optimize_tradeoff_pick_as_owner(server.vault(), owner, &input)?
                }
                Picker::Holder(by) => {
                    sdk::skill_optimize_tradeoff_pick_by(server.vault(), by, &input)?
                }
            };
            let rows = answer.rows();
            Ok((answer, rows))
        },
    )
    .await
}

/// `vault.skills.optimize.tradeoff_asks.resolve` (FIX 9125): the owner's own
/// tradeoff decision, under its proof only. Agents keep `tradeoff_asks` and
/// its pick.
pub(crate) async fn vault_skills_optimize_tradeoff_asks_resolve(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillOptimizeTradeoffResolveRequest,
) -> Listed<oneiron::task_verb::sdk::SkillOptimizeResultView> {
    owner_call(
        server,
        auth,
        "vault.skills.optimize.tradeoff_asks.resolve",
        move |server, owner| {
            let answer =
                sdk::skill_optimize_tradeoff_resolve_as_owner(server.vault(), owner, &input)?;
            let rows = answer.rows();
            Ok((answer, rows))
        },
    )
    .await
}
