//! Credential-backed budget controls, beside the owner's held-run routes.
//! No model or accounting logic lives here: the engine owns leases and
//! holds, and the usage ledger owns settled physical-call receipts. The
//! owner's lease, hold, local-budget, reservation and RSI doors are
//! generated from their rows (UC-01 PR 2.2).
use std::sync::Arc;

use oneiron::agent_dispatch::budget_doors::{self, *};
use oneiron::llm::run_admission::resident_doors::{
    self, ResidentSharesRequest, ResidentSharesView, SetResidentShareRequest,
};
use oneiron::memory::MemoryError;

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The owner reads any lease on its proof; a person or agent on a verified
/// slip of its own reads a lease its own run spends under or reserved
/// (slice 6.5a, S65-BUDGET = A). Spend rows are read by no read lane, so the
/// row refuses a slip narrowed to records, worlds or facets
/// (`unrestricted_record_scope`, FACET-READ).
pub(crate) async fn vault_budgets_lease(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (oneiron::EntityId, oneiron::EdgeActorClass),
    _invocation: Option<oneiron::runtime_hooks::InvocationId>,
    input: SpendScopeRequest,
) -> Listed<SpendLeaseView> {
    const VERB: &str = "vault.budgets.lease";
    match super::run_read_doors::run_reader(server, auth, VERB) {
        Ok(Some(_)) => {
            as_owner_naming(
                server,
                auth,
                VERB,
                move |server, owner| {
                    budget_doors::spend_lease_as_owner(server.vault(), owner, &input)
                        .map_err(MemoryError::from)
                },
                |_| Vec::new(),
            )
            .await
        }
        Ok(None) => {
            super::host_doors::support::credential_listing(
                server,
                auth,
                caller,
                VERB,
                move |_, _, memory| budget_doors::spend_lease_as_reader(&memory, &input),
            )
            .await
        }
        Err(refusal) => (Err(refusal), Vec::new()),
    }
}

/// The owner reads every settlement of a served run on its proof; a person or
/// agent on a verified slip of its own reads the run's settlements stamped
/// with its own agent id (FIX RUN-SETTLEMENTS-OWN-AGENT-READ), which the
/// engine reader keeps once it has proved the slip's read
/// (`budget_doors::own_run_settlements_as_reader`). Spend rows are read by no
/// read lane, so the row refuses a slip narrowed to records, worlds or facets
/// (`unrestricted_record_scope`), as `vault.budgets.lease` does.
pub(crate) async fn vault_budgets_settlements(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (oneiron::EntityId, oneiron::EdgeActorClass),
    _invocation: Option<oneiron::runtime_hooks::InvocationId>,
    input: RunSettlementsRequest,
) -> Listed<RunSettlementsView> {
    const VERB: &str = "vault.budgets.settlements";
    match super::run_read_doors::run_reader(server, auth, VERB) {
        Ok(Some(_)) => {
            as_owner_naming(
                server,
                auth,
                VERB,
                move |server, owner| {
                    owner.revalidate(server.vault())?;
                    let (metering_enabled, settlements) = ledger_settlements(server, &input.run)?;
                    Ok(RunSettlementsView {
                        run: input.run,
                        metering_enabled,
                        settlements,
                    })
                },
                |_| Vec::new(),
            )
            .await
        }
        Ok(None) => {
            super::host_doors::support::credential_listing(
                server,
                auth,
                caller,
                VERB,
                move |server, _, memory| {
                    let (metering_enabled, rows) = ledger_settlements(server, &input.run)?;
                    let settlements = budget_doors::own_run_settlements_as_reader(&memory, rows)?;
                    Ok(RunSettlementsView {
                        run: input.run,
                        metering_enabled,
                        settlements,
                    })
                },
            )
            .await
        }
        Err(refusal) => (Err(refusal), Vec::new()),
    }
}

/// Whether this host meters its vault's usage, and the settlements of `run`
/// its usage ledger keeps: none while it meters nothing.
fn ledger_settlements(
    server: &SyncServer,
    run: &str,
) -> oneiron::memory::MemoryResult<(bool, Vec<RunRungSettlement>)> {
    let usage = server.vault_usage();
    let settlements = usage
        .as_ref()
        .map(|usage| {
            server
                .usage_ledger
                .run_settlements(usage.owner(), usage.vault_id(), run)
                .map_err(|error| MemoryError::bad_request(error.to_string()))
        })
        .transpose()?
        .unwrap_or_default();
    Ok((usage.is_some(), settlements))
}

/// The residents a share view names.
fn residents(view: &ResidentSharesView) -> Vec<oneiron::EntityId> {
    view.residents
        .iter()
        .filter_map(|share| oneiron::EntityId::from_hex(&share.resident).ok())
        .collect()
}

/// `vault.budgets.resident_shares`: every resident's share and depletion
/// (FIX 11310). It lists the residents it names.
pub(crate) async fn vault_budgets_resident_shares(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ResidentSharesRequest,
) -> Listed<ResidentSharesView> {
    as_owner_naming(
        server,
        auth,
        "vault.budgets.resident_shares",
        move |server, owner| {
            resident_doors::resident_shares_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        residents,
    )
    .await
}

/// `vault.budgets.resident_shares.set`: the owner sets one resident's share
/// (FIX 11310). It lists the residents the view it answers names.
pub(crate) async fn vault_budgets_resident_shares_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SetResidentShareRequest,
) -> Listed<ResidentSharesView> {
    as_owner_naming(
        server,
        auth,
        "vault.budgets.resident_shares.set",
        move |server, owner| {
            resident_doors::set_resident_share_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        residents,
    )
    .await
}
