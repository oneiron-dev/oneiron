//! Description routing for an agent run's typed seat (FIX 11307). When the vault's owner set
//! a description policy, a run stamped with its task type is routed once
//! ([`Vault::route_seat`]): its candidates are the models its agent lists, graded on the
//! host's decision ladder, and its seat is born on the routed model and effort. A run with
//! no policy and no route of its own, one whose launch plan already picked its model, and
//! one whose route or routed birth fails are each born as before.

use std::time::Instant;

use oneiron::llm::routing::{DescriptionDecisions, SeatBirth, SeatSettings};
use oneiron::llm::seat::{ModelSeat, SeatDecisions, SeatTask};
use oneiron::task_type::TaskTypeRef;
use oneiron::{EntityId, ModelTierRef, TierPrecedence, Vault};

/// What the route's fitness grades ask of each candidate's description line.
const DESCRIPTION_FIT_WORDING: &str = "How well does this model, at this effort, fit the task? \
    Read its description line against the task and its type: 1 is a full fit, 0 none.";

/// The role a routed agent-run seat is recorded under.
const TASK_RUN_SEAT_ROLE: &str = "task_run";

/// `run_id`'s seat for `task`, stamped with `type_ref`: born on its description route when
/// one applies, else as [`Vault::birth_task_model_seat`] births it.
pub(super) fn task_seat(
    vault: &Vault,
    run_id: EntityId,
    type_ref: &TaskTypeRef,
    task: &SeatTask,
    decisions: &SeatDecisions,
    parent_at: Option<Instant>,
) -> oneiron::Result<ModelSeat> {
    if let Some(routed) = routed_task(vault, run_id, type_ref, task, decisions) {
        match vault.birth_task_model_seat(run_id, type_ref, &routed, decisions, parent_at) {
            Ok(seat) => return Ok(seat),
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                run = %run_id.to_hex(),
                "the routed seat was not born; the run's seat is born as before"
            ),
        }
    }
    vault.birth_task_model_seat(run_id, type_ref, task, decisions, parent_at)
}

/// `task` pinned to the model and effort its description route picked, or `None` when no
/// route applies or the route fails.
fn routed_task(
    vault: &Vault,
    run_id: EntityId,
    type_ref: &TaskTypeRef,
    task: &SeatTask,
    decisions: &SeatDecisions,
) -> Option<SeatTask> {
    if task.override_model.is_some() {
        return None;
    }
    let id = run_id.to_hex();
    // A run routed once keeps its route on resume, whatever the policy is now.
    let policy = vault.description_policy().ok().flatten();
    if policy.is_none() && vault.routed_seat(&id).ok().flatten().is_none() {
        return None;
    }
    let settings = SeatSettings {
        allowed_models: (!task.listed.is_empty()).then(|| {
            task.listed
                .iter()
                .map(|listed| listed.model_ref.clone())
                .collect()
        }),
        effort: task.override_effort,
        ..SeatSettings::default()
    };
    // The run's calls bind its model seat; the profile names the routed seat's tier.
    let tier = TierPrecedence::for_purpose(&task.purpose, ModelTierRef(task.facet.clone()));
    let grades = DescriptionDecisions {
        ladder: decisions.ladder.ladder(),
        principal: decisions.principal,
        dial: decisions.dial,
        bands: decisions.bands.clone(),
        wording: DESCRIPTION_FIT_WORDING.to_owned(),
        budget: decisions.budget,
    };
    let birth = SeatBirth {
        id: &id,
        role: TASK_RUN_SEAT_ROLE,
        task: &task.task,
        type_ref: Some(type_ref),
        purpose: &task.purpose,
        settings: &settings,
        tier: &tier,
    };
    let routed = vault
        .route_seat(birth, &grades, crate::decision_host::description_notes())
        .inspect_err(|error| {
            tracing::warn!(
                kind = ?error.kind(),
                run = %id,
                "the description route failed; the run's seat is born as before"
            );
        })
        .ok()?;
    Some(SeatTask {
        override_model: Some(routed.model),
        override_effort: Some(routed.effort),
        ..task.clone()
    })
}
