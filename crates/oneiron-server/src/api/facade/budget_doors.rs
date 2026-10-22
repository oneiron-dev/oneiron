//! Credential-backed budget controls, beside the owner's held-run routes.
//! No model or accounting logic lives here: the engine owns leases and
//! holds, and the usage ledger owns settled physical-call receipts.
use std::sync::Arc;

use oneiron::agent_dispatch::PartialResultHold;
use oneiron::agent_dispatch::budget_doors::{self, *};
use oneiron::llm::rsi_doors::{self, RsiLineRequest, RsiLineView};
use oneiron::llm::{RsiBudgetConfig, RsiTopUp};
use oneiron::memory::MemoryError;

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_budgets_lease_open(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OpenSpendLeaseRequest,
) -> Listed<SpendLeaseView> {
    as_owner_naming(
        server,
        auth,
        "vault.budgets.lease.open",
        move |server, owner| {
            budget_doors::open_spend_lease_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_budgets_lease(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SpendScopeRequest,
) -> Listed<SpendLeaseView> {
    as_owner_naming(
        server,
        auth,
        "vault.budgets.lease",
        move |server, owner| {
            budget_doors::spend_lease_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_budgets_lease_top_up(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: TopUpSpendLeaseRequest,
) -> Listed<SpendLeaseView> {
    as_owner_naming(
        server,
        auth,
        "vault.budgets.lease.top_up",
        move |server, owner| {
            budget_doors::top_up_spend_lease_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_budgets_hold(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: BudgetHoldRequest,
) -> Listed<Option<PartialResultHold>> {
    as_owner_naming(
        server,
        auth,
        "vault.budgets.hold",
        move |server, owner| {
            budget_doors::budget_hold_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_budgets_hold_resume(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: BudgetHoldRequest,
) -> Listed<PartialResultHold> {
    as_owner_naming(
        server,
        auth,
        "vault.budgets.hold.resume",
        move |server, owner| {
            budget_doors::resume_budget_hold_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_budgets_local(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LocalRunnerBudgetRequest,
) -> Listed<LocalRunnerBudgetView> {
    as_owner_naming(
        server,
        auth,
        "vault.budgets.local",
        move |server, owner| {
            budget_doors::local_runner_budget_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_budgets_reservations(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RunnerBudgetReservationsRequest,
) -> Listed<RunnerBudgetReservationsView> {
    as_owner_naming(
        server,
        auth,
        "vault.budgets.reservations",
        move |server, owner| {
            budget_doors::runner_budget_reservations_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_budgets_settlements(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RunSettlementsRequest,
) -> Listed<RunSettlementsView> {
    as_owner_naming(
        server,
        auth,
        "vault.budgets.settlements",
        move |server, owner| {
            owner.revalidate(server.vault())?;
            let usage = server.vault_usage();
            let settlements = usage
                .as_ref()
                .map(|usage| {
                    server
                        .usage_ledger
                        .run_settlements(usage.owner(), usage.vault_id(), &input.run)
                        .map_err(|error| MemoryError::bad_request(error.to_string()))
                })
                .transpose()?
                .unwrap_or_default();
            Ok(RunSettlementsView {
                run: input.run,
                metering_enabled: usage.is_some(),
                settlements,
            })
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_budgets_rsi_configure(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RsiBudgetConfig,
) -> Listed<RsiLineView> {
    as_owner_naming(
        server,
        auth,
        "vault.budgets.rsi.configure",
        move |server, owner| {
            rsi_doors::configure_rsi_budget_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_budgets_rsi(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RsiLineRequest,
) -> Listed<RsiLineView> {
    as_owner_naming(
        server,
        auth,
        "vault.budgets.rsi",
        move |server, owner| {
            rsi_doors::rsi_line_as_owner(server.vault(), owner, &input).map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_budgets_rsi_top_up(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RsiTopUp,
) -> Listed<RsiLineView> {
    as_owner_naming(
        server,
        auth,
        "vault.budgets.rsi.top_up",
        move |server, owner| {
            rsi_doors::top_up_rsi_budget_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_budgets_rsi_hold(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RsiLineRequest,
) -> Listed<RsiLineView> {
    as_owner_naming(
        server,
        auth,
        "vault.budgets.rsi.hold",
        move |server, owner| {
            rsi_doors::hold_rsi_budget_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_budgets_rsi_hold_resume(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RsiLineRequest,
) -> Listed<RsiLineView> {
    as_owner_naming(
        server,
        auth,
        "vault.budgets.rsi.hold.resume",
        move |server, owner| {
            rsi_doors::resume_rsi_budget_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}
