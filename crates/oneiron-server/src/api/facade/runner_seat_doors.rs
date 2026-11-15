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

pub(crate) async fn vault_runners_seats_resume(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RunnerWorkResumeRequest,
) -> Listed<RunnerWorkResumeView> {
    as_owner_or_delegate_naming(
        server,
        auth,
        RUNNER_WORK_RESUME_VERB,
        move |server, who| match who {
            OwnerOrDelegate::Owner(owner) => {
                server.vault().resume_runner_work_as_owner(owner, &input)
            }
            OwnerOrDelegate::Delegate(agent) => {
                server.vault().resume_runner_work_as_delegate(agent, &input)
            }
        },
        |_| Vec::new(),
    )
    .await
}
