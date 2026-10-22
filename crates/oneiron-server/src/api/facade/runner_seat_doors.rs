//! The owner's runner seat quota doors (FIX 7451):
//! `vault.runners.seats.quotas` and `vault.runners.seats.top_up`, beside the
//! budget doors. No seat or quota logic lives here: the engine reads and
//! clears the seats' quota records, rechecking the owner's proof in its own
//! transaction.
use std::sync::Arc;

use oneiron::dispatch_byoa::{
    RunnerSeatCreditTopUpRequest, RunnerSeatQuotasRequest, RunnerSeatQuotasView,
    RunnerSeatTopUpReceipt,
};

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_runners_seats_quotas(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RunnerSeatQuotasRequest,
) -> Listed<RunnerSeatQuotasView> {
    as_owner_naming(
        server,
        auth,
        "vault.runners.seats.quotas",
        move |server, owner| server.vault().runner_seat_quotas_as_owner(owner, &input),
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_runners_seats_top_up(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RunnerSeatCreditTopUpRequest,
) -> Listed<RunnerSeatTopUpReceipt> {
    as_owner_naming(
        server,
        auth,
        "vault.runners.seats.top_up",
        move |server, owner| server.vault().top_up_runner_seat_as_owner(owner, &input),
        |_| Vec::new(),
    )
    .await
}
