//! The owner's runner seat doors (FIX 7451, FIX 11067):
//! `vault.runners.seats.quotas`, `vault.runners.seats.top_up` and
//! `vault.runners.seats.resume`, beside the budget doors. No seat, quota or
//! resume logic lives here: the engine reads and clears the seats' quota
//! records and resumes their parked work, rechecking the owner's proof in
//! its own transaction.
use std::sync::Arc;

use oneiron::authority::OwnerOrDelegate;
use oneiron::dispatch_byoa::{
    RUNNER_SEAT_QUOTAS_VERB, RUNNER_SEAT_TOP_UP_VERB, RUNNER_WORK_RESUME_VERB,
    RunnerSeatCreditTopUpRequest, RunnerSeatQuotasRequest, RunnerSeatQuotasView,
    RunnerSeatTopUpReceipt, RunnerWorkResumeRequest, RunnerWorkResumeView,
};

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_or_delegate_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_runners_seats_quotas(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RunnerSeatQuotasRequest,
) -> Listed<RunnerSeatQuotasView> {
    as_owner_or_delegate_naming(
        server,
        auth,
        RUNNER_SEAT_QUOTAS_VERB,
        move |server, who| match who {
            OwnerOrDelegate::Owner(owner) => {
                server.vault().runner_seat_quotas_as_owner(owner, &input)
            }
            OwnerOrDelegate::Delegate(agent) => {
                server.vault().runner_seat_quotas_as_delegate(agent, &input)
            }
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_runners_seats_top_up(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RunnerSeatCreditTopUpRequest,
) -> Listed<RunnerSeatTopUpReceipt> {
    as_owner_or_delegate_naming(
        server,
        auth,
        RUNNER_SEAT_TOP_UP_VERB,
        move |server, who| match who {
            OwnerOrDelegate::Owner(owner) => {
                server.vault().top_up_runner_seat_as_owner(owner, &input)
            }
            OwnerOrDelegate::Delegate(agent) => {
                server.vault().top_up_runner_seat_as_delegate(agent, &input)
            }
        },
        |_| Vec::new(),
    )
    .await
}

/// This node's own runner seat registry, as the seat host routes a bound
/// work's end under it (`runtime/seat_host/terminal.rs`): each official seat
/// under its adapter, its login machine attached, then the plain CLI
/// runners. A node whose config names no runner seats has only the plain CLI
/// runners. The caller never names it.
fn node_runner_seat_registry(
    server: &SyncServer,
) -> oneiron::memory::MemoryResult<oneiron::dispatch_byoa::ProviderAdapterRegistry> {
    let Some(settings) = server.ai.runner_seats() else {
        return Ok(oneiron::dispatch_byoa::ProviderAdapterRegistry::standard());
    };
    settings.registry().map_err(|text| {
        oneiron::memory::MemoryError::new(
            oneiron::memory::MEMORY_CODE_INVALID_STATE,
            text,
            &["Fix [models.dreamer] runner_seats in this node's config."],
        )
    })
}

/// `vault.runners.seats.resume`: the owner's or a delegate's resume of a
/// parked bound runner work, on this node's own runner seats (FIX RUNNER-
/// RESUME-DROPS-NODE-REGISTRY), so a work bound on an official seat resumes
/// on that seat and its login machine, not on the plain runner of the same
/// name.
pub(crate) async fn vault_runners_seats_resume(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RunnerWorkResumeRequest,
) -> Listed<RunnerWorkResumeView> {
    as_owner_or_delegate_naming(
        server,
        auth,
        RUNNER_WORK_RESUME_VERB,
        move |server, who| {
            let registry = node_runner_seat_registry(server)?;
            match who {
                OwnerOrDelegate::Owner(owner) => server
                    .vault()
                    .resume_runner_work_as_owner(owner, &registry, &input),
                OwnerOrDelegate::Delegate(agent) => server
                    .vault()
                    .resume_runner_work_as_delegate(agent, &registry, &input),
            }
        },
        |_| Vec::new(),
    )
    .await
}
