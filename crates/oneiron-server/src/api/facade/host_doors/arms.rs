//! The experiment arm doors of the lane economy (design pass 32 section 5):
//! `vault.arms.admit`, `vault.arms.forecast`, `vault.arms.get`,
//! `vault.arms.list`, `vault.arms.units.reserve` and
//! `vault.arms.units.cancel`. Each proves
//! `verb_grant_caller`: the owner under their own proof, or an agent whose
//! own live owner Grant lists the verb; an agent admits into and reads only
//! the lines its Grant reaches, as the engine's act judges it again. Arms
//! live in a side table, which holds no entity row: the doors list none. So
//! no invocation claim keeps the reads' reply
//! (`invocations::UNKEPT_REPLY_VERBS`): a same-id retry of a get or a list
//! runs the read again, with the line cover, and is never answered a saved
//! arm.

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::experiment_arm::{
    ARMS_ADMIT_VERB, ARMS_FORECAST_VERB, ARMS_GET_VERB, ARMS_LIST_VERB, ARMS_UNITS_CANCEL_VERB,
    ARMS_UNITS_RESERVE_VERB, ArmAdmitRequest, ArmForecastRequest, ArmList, ArmListRequest, ArmRef,
    ArmView, UnitCancel, UnitCancelRequest, UnitReserveAnswer, UnitReserveRequest, UnitView,
    arm_admit_as, arm_forecast_as, arm_get_as, arm_list_as, unit_cancel_as, unit_order_as,
    unit_ordered_view_as, unit_reserve_as,
};
use oneiron::gpu_job::{GpuJobActor, GpuJobConnector, GpuJobError, UnitJobStart};
use oneiron::gpu_line::ClaimKey;
use oneiron::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use oneiron::work_order::{OrderState, WaitRule};

use super::support::Listed;
use super::verb_grant::verb_grant_door;
use crate::auth::CoreAuth;
use crate::config::gpu_jobs::GpuOfferSettings;
use crate::gpu_execution_node::issuer::not_the_issuer;
use crate::gpu_host::{NoProvider, job_backend, now_ms, offer_with_backend};
use crate::server::SyncServer;
use crate::work_order_host::locked_order_pass;

use super::work_orders::refusal_of_end;

/// `vault.arms.admit`: admits one arm into a seated family of a GPU line,
/// with its first allowance held from now until rung 1 leaves `Open`, the
/// arm is withdrawn, the period ends or the hold lies dormant. A repeat
/// under the same intent key, or of the same ask on the same contract,
/// answers the same arm. The period record names the period's allocation;
/// the claims are its hold (HOLD-IS-CLAIM-FOLD = A), so the door installs
/// nothing in the host account.
pub(crate) async fn vault_arms_admit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ArmAdmitRequest,
) -> Listed<ArmView> {
    verb_grant_door(server, auth, ARMS_ADMIT_VERB, move |_, memory, owner| {
        arm_admit_as(memory, owner, &input, now_ms())
    })
    .await
}

/// `vault.arms.forecast`: writes the rung's one forecast for the arm's own
/// runner, before the rung's first claim. A repeat of the same forecast,
/// under the same intent key or another, answers the same arm.
pub(crate) async fn vault_arms_forecast(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ArmForecastRequest,
) -> Listed<ArmView> {
    verb_grant_door(server, auth, ARMS_FORECAST_VERB, move |_, memory, owner| {
        arm_forecast_as(memory, owner, &input, now_ms())
    })
    .await
}

/// `vault.arms.get`: one arm, with whether it is open and the rung it
/// stands at.
pub(crate) async fn vault_arms_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ArmRef,
) -> Listed<ArmView> {
    verb_grant_door(server, auth, ARMS_GET_VERB, move |_, memory, owner| {
        arm_get_as(memory, owner, &input)
    })
    .await
}

/// `vault.arms.list`: the arms the caller may read, newest first.
pub(crate) async fn vault_arms_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ArmListRequest,
) -> Listed<ArmList> {
    verb_grant_door(server, auth, ARMS_LIST_VERB, move |_, memory, owner| {
        arm_list_as(memory, owner, &input)
    })
    .await
}

/// `vault.arms.units.reserve`: claims one unit of an arm's current rung on
/// one of the line's offers, with its seconds drawn from the line's pools,
/// in one write (design 5.2). The offer must have a backend on this host;
/// the engine's act judges every other check. A repeat under the same intent
/// key, or of the same ask under the same logical attempt, answers the same
/// claim. After the reserve commits, the door starts the claim's one job
/// through the one start gate (design 5.3): quoted on the claim's id, its
/// workload and its reserved seconds, under the claim and not a
/// `vault.gpu.jobs.start` Grant. A start the gate refuses releases the claim
/// and answers the refusal; a provider's refusal holds the job and answers
/// the released unit. A repeat of a unit that started or ended answers it as
/// it stands.
///
/// With a wait other than `no` (row H3) the door makes a work order instead,
/// holding nothing (pass 34, 1.1), runs one pass of the loop at once, and
/// answers the order as the caller reads it, judged on this verb over the line
/// and not under a `vault.jobs.order` Grant; the loop reserves the unit and
/// starts its job when it can run. An order no wait can clear answers its
/// refusal, as `vault.jobs.order` does.
pub(crate) async fn vault_arms_units_reserve(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: UnitReserveRequest,
) -> Listed<UnitReserveAnswer> {
    let shared = Arc::clone(server);
    verb_grant_door(
        server,
        auth,
        ARMS_UNITS_RESERVE_VERB,
        move |server, memory, owner| {
            // R5's one-issuer check, the start gate's first call (pass 33, 8.7): a replica
            // that is not the vault's issuer refuses a vault machine offer before reserving.
            if let Some(settings) = server.config.gpu_jobs.offer(&input.offer)
                && let Err(refused) = not_the_issuer(server, &settings.backend)
            {
                let issuer = refused
                    .issuer
                    .map_or_else(|| "none".to_owned(), |issuer| issuer.to_hex());
                return Err(MemoryError::new(
                    MEMORY_CODE_INVALID_STATE,
                    format!(
                        "{ARMS_UNITS_RESERVE_VERB}: {}: {refused} (issuer: {issuer})",
                        refused.code()
                    ),
                    &["Reserve on the vault's issuer of vault machine jobs."],
                ));
            }
            let (offer, connector) = offer_with_backend(server, &input.offer).map_err(|error| {
                MemoryError::new(
                    MEMORY_CODE_INVALID_STATE,
                    format!("{ARMS_UNITS_RESERVE_VERB}: offer_not_managed: {error}"),
                    &["Reserve on an offer of the line that this host can start."],
                )
            })?;
            if input.wait != WaitRule::No {
                let now = now_ms();
                let view = unit_order_as(memory, owner, &input, now)?;
                if view.replayed {
                    return Ok(UnitReserveAnswer::Order(Box::new(view)));
                }
                locked_order_pass(&shared, now)?;
                let view = unit_ordered_view_as(memory, owner, input.line, &view.order.id)?
                    .unwrap_or(view);
                if let OrderState::GivenUp { why } = &view.order.state
                    && let Some(refusal) = refusal_of_end(why)
                {
                    return Err(refusal);
                }
                return Ok(UnitReserveAnswer::Order(Box::new(view)));
            }
            let reserved = unit_reserve_as(memory, owner, &input, now_ms())?;
            start_reserved_unit(server, memory, owner, offer, connector.as_ref(), reserved)
                .map(UnitReserveAnswer::Unit)
        },
    )
    .await
}

/// Starts the one job of the unit `reserved` names while its claim stands
/// `Claimed`, and answers the unit as it stands after the start.
fn start_reserved_unit(
    server: &SyncServer,
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    offer: &GpuOfferSettings,
    connector: &dyn GpuJobConnector,
    reserved: UnitView,
) -> MemoryResult<UnitView> {
    let key = ClaimKey::of(
        reserved.arm,
        reserved.rung,
        &reserved.unit_key,
        reserved.attempt,
    );
    let now = now_ms();
    let Some(request) = server.vault.unit_job_request(&key, now)? else {
        return Ok(reserved.current(&server.vault)?);
    };
    let quote = offer.offer.quote_for(
        reserved.job,
        &request,
        server.config.gpu_jobs.default_maximum_secs,
        now,
    )?;
    let agent;
    let actor = match owner {
        Some(owner) => GpuJobActor::Owner(owner),
        None => {
            agent = memory.gpu_job_agent();
            GpuJobActor::Agent(&agent)
        }
    };
    server.vault.start_claimed_gpu_job(
        UnitJobStart {
            actor,
            offer: &offer.offer,
            quote: &quote,
        },
        &key,
        server.gpu_jobs.permits(),
        connector,
        now,
    )?;
    Ok(reserved.current(&server.vault)?)
}

/// `vault.arms.units.cancel`: withdraws a unit whose job has not started,
/// ending its claim released and returning its seconds to the pools it
/// drew, or cancels its started job through the scoped path (design 5.3):
/// the act judged the line, the lead role and "the reserver, or the owner",
/// and the caller needs no `vault.gpu.jobs.cancel` Grant. A cancelled job's
/// claim ends at its terminal. The owner cancels any unit; an agent only one
/// it reserved.
pub(crate) async fn vault_arms_units_cancel(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: UnitCancelRequest,
) -> Listed<UnitView> {
    verb_grant_door(
        server,
        auth,
        ARMS_UNITS_CANCEL_VERB,
        move |server, memory, owner| match unit_cancel_as(memory, owner, &input, now_ms())? {
            UnitCancel::Withdrawn(view) => Ok(view),
            UnitCancel::JobStarted(started) => {
                let job = server
                    .vault
                    .gpu_job(&started.job())?
                    .ok_or(GpuJobError::NotFound)?;
                let connector: Arc<dyn GpuJobConnector> = if job.state.is_live() {
                    job_backend(server, &job)?
                } else {
                    Arc::new(NoProvider)
                };
                let view = started.view().clone();
                match server.vault.cancel_unit_gpu_job(
                    started,
                    server.gpu_jobs.permits(),
                    connector.as_ref(),
                    now_ms(),
                ) {
                    // A provider that does not answer leaves the cancel standing; the
                    // worker terminates the chunk on its next steps.
                    Ok(_) | Err(GpuJobError::Connector(_)) => Ok(view.current(&server.vault)?),
                    Err(error) => Err(error.into()),
                }
            }
        },
    )
    .await
}

/// `vault.arms.units.reserve`'s no-wait act for a caller already bound to
/// its own handle (`memory`), with its owner proof when it has one: the
/// one-issuer check, an offer of the line this host can start, the engine's
/// reserve (which judges the caller, its Grant and the line again), then
/// the claim's one job through the one start gate. A turn program's run
/// door calls it for the program's own agent, with no owner proof
/// ([RSI-PROJECT-WORKFLOW]).
pub(crate) fn reserve_and_start_unit(
    server: &SyncServer,
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    input: &UnitReserveRequest,
) -> MemoryResult<UnitView> {
    if let Some(settings) = server.config.gpu_jobs.offer(&input.offer)
        && let Err(refused) = not_the_issuer(server, &settings.backend)
    {
        let issuer = refused
            .issuer
            .map_or_else(|| "none".to_owned(), |issuer| issuer.to_hex());
        return Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            format!(
                "{ARMS_UNITS_RESERVE_VERB}: {}: {refused} (issuer: {issuer})",
                refused.code()
            ),
            &["Reserve on the vault's issuer of vault machine jobs."],
        ));
    }
    let (offer, connector) = offer_with_backend(server, &input.offer).map_err(|error| {
        MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            format!("{ARMS_UNITS_RESERVE_VERB}: offer_not_managed: {error}"),
            &["Reserve on an offer of the line that this host can start."],
        )
    })?;
    let reserved = unit_reserve_as(memory, owner, input, now_ms())?;
    start_reserved_unit(server, memory, owner, offer, connector.as_ref(), reserved)
}
