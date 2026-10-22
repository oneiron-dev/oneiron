//! The workers a started host runs on its seats: the Dreamer and the
//! workflow pump, and the MACRO declaration of a host whose Dreamer does
//! not run. `AiHost::start_with` starts them.

use super::*;

/// A served host whose Dreamer does not run declares that it cannot take
/// MACRO work now (FIX 4898), so no other machine elects it for MACRO; its
/// own election still claims a vault no node has claimed, for its standing
/// questions. A device of another home (`device`) declares through its
/// `[device_sync]` section instead.
pub(super) fn served_without_dreamer(vault: &Vault, device: bool) {
    if !device {
        crate::home_candidacy::declare(vault, true, false, false);
    }
}

pub(super) async fn start_dreamer(
    vault: &Arc<Vault>,
    runtime: &Arc<ModelRuntime>,
    models: &ModelsConfig,
    host_root: bool,
    device: bool,
    status: &Arc<StatusCell>,
    idle: IdleSample,
    decisions: Arc<OnceLock<DecisionHost>>,
    question_timer: dreamer::QuestionTimer,
    admission: dreamer::PassAdmission,
) -> Result<DreamerHost, IdleReason> {
    if !models.dreamer.enabled {
        return Err(IdleReason::Disabled);
    }
    if models.dreamer.runner_seats.is_some() {
        // The policy is validated and registered at config load (OF-137),
        // but this host has no BYOA endpoint factory, egress port, or
        // checkout service to execute runner seats with yet. Say so rather
        // than silently pretend the BYO runner took the work.
        tracing::warn!(
            "models.dreamer.runner_seats is configured; this host cannot execute BYO runner seats yet, so Dreamer work stays on the internal model roles"
        );
    }
    let seat = runtime
        .seat(DREAMER_ROLE)
        .ok_or(IdleReason::NoModelConfigured)?
        .clone();
    if !host_root {
        return Err(IdleReason::NoHostAuthority);
    }
    // A pass the policy cannot serve would park its attempts for good; leave
    // them queued until the policy carries the Dreamer's rows again.
    match vault.dreamer_weave_reach() {
        Ok(reach) if reach.ready() => {}
        Ok(_) => return Err(IdleReason::NeedsOwnerGrant),
        Err(error) => {
            tracing::error!(%error, "dreamer policy reach could not be read");
            return Err(IdleReason::StartFailed);
        }
    }
    // Each pass calls every role on the model the vault's live manifest pins
    // for it (else the role's seat, else the Dreamer's), so the routes the
    // owner's defaults must allow are those models', not the seat's.
    let routes = match dreamer::role_routes(runtime, vault, &seat) {
        Ok(routes) => routes,
        Err((role, RoleRefusal::RouteNotServed { .. })) => {
            return Err(if role == DREAMER_EXTRACTION_ROLE {
                IdleReason::ExtractionModelNotServed
            } else {
                IdleReason::RoleModelNotServed
            });
        }
        Err((role, refusal)) => {
            // An engine refusal logs by kind: its text can quote the vault.
            let kind = match &refusal {
                RoleRefusal::Refused(error) => Some(error.kind()),
                RoleRefusal::NoSeat | RoleRefusal::RouteNotServed { .. } => None,
            };
            tracing::error!(?kind, role = ?role, "a dreamer role's route could not be resolved");
            return Err(IdleReason::StartFailed);
        }
    };
    let localities = routes
        .iter()
        .map(|(role, route)| (dreamer_role_purpose(*role), route.locality))
        .collect::<Vec<_>>();
    let egress = match policy::dreamer_route(vault, &localities, models.extraction_egress) {
        Ok(DreamerRoute::Ready { egress }) => egress,
        Ok(DreamerRoute::Blocked(reason)) => return Err(reason),
        Err(error) => {
            tracing::error!(%error, "dreamer route policy could not be read");
            return Err(IdleReason::StartFailed);
        }
    };
    DreamerHost::spawn(DreamerStart {
        vault: Arc::clone(vault),
        runtime: Arc::clone(runtime),
        seat,
        settings: models.dreamer.clone(),
        egress,
        status: Arc::clone(status),
        idle,
        windows: dreamer::dream_windows(models),
        decisions,
        question_timer,
        admission,
        device,
    })
    .await
    .map_err(|error| {
        tracing::error!(%error, "dreamer failed to start");
        IdleReason::StartFailed
    })
}

pub(super) fn start_workflows(
    vault: &Arc<Vault>,
    runtime: &Arc<ModelRuntime>,
    models: &ModelsConfig,
    status: &Arc<StatusCell>,
    decisions: Arc<OnceLock<DecisionHost>>,
    host: step::StepHost,
) -> Result<WorkflowPump, IdleReason> {
    if !models.workflows.enabled {
        return Err(IdleReason::Disabled);
    }
    if runtime.seat(CHAT_ROLE).is_none() {
        return Err(IdleReason::NoModelConfigured);
    }
    WorkflowPump::spawn(
        Arc::clone(vault),
        StepRunner {
            models: Arc::clone(runtime),
            budget_units: models.workflows.step_budget_units,
            retry_backoff_secs: models.workflows.retry_backoff_secs,
            spent: Default::default(),
            host,
            confession: confession_wording::of(Some(models)),
        },
        Arc::clone(status),
        decisions,
    )
    .map_err(|error| {
        tracing::error!(%error, "workflow pump failed to start");
        IdleReason::StartFailed
    })
}
