//! Owner-authenticated child admission and sealed-cohort setup.
//! The verb-table admission checks the owner before hooks; these handlers
//! revalidate that same proof before entering the existing engine doors.
use std::sync::Arc;

use oneiron::skill_optimize::{EvalAuthoringInventory, EvalAuthoringReport, EvalCohortSetup};
use oneiron::task_verb::sdk::{EvalInventoryWire, ResearchChildReceipt, ResearchChildWire};

use super::host_doors::{Listed, internal, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.research.create_child` (`host_door_lists`): the receipt carries
/// the root, parent and child attempt refs only, side-table attempts the
/// answer names by ref. The agent definition dispatch reads is admission,
/// never served content, so the list is complete and empty.
pub(crate) async fn vault_research_create_child(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ResearchChildWire,
) -> Listed<ResearchChildReceipt> {
    const VERB: &str = "vault.research.create_child";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return (Err(error), Vec::new()),
    };
    let server = Arc::clone(server);
    let answer = tokio::task::spawn_blocking(move || {
        oneiron::task_verb::sdk::research_create_child_as_owner(server.vault(), &owner, input)
    })
    .await
    .map_err(|_| internal(VERB))
    .and_then(|answer| answer);
    (answer, Vec::new())
}

pub(crate) async fn vault_evals_inventory(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EvalInventoryWire,
) -> Listed<EvalAuthoringInventory> {
    const VERB: &str = "vault.evals.inventory";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return (Err(error), Vec::new()),
    };
    let server = Arc::clone(server);
    // The inventory contains metadata only. Its receipt and ledger rows are
    // not core entity rows; no case content or sealed membership is served.
    let answer = tokio::task::spawn_blocking(move || {
        oneiron::task_verb::sdk::eval_inventory_as_owner(server.vault(), &owner, input)
    })
    .await
    .map_err(|_| internal(VERB))
    .and_then(|answer| answer);
    (answer, Vec::new())
}

/// `vault.evals.cohorts.setup` (`host_door_lists`): unlike the inventory,
/// each cut's near-copy audit reads case text before the report counts its
/// coverage, so the door lists every TURN, MESSAGE and proposal artifact
/// those audits read, from the same reads
/// ([`oneiron::Vault::setup_eval_cohorts_listing`]). A setup that cuts
/// nothing audits no text and lists none.
pub(crate) async fn vault_evals_cohorts_setup(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EvalCohortSetup,
) -> Listed<EvalAuthoringReport> {
    const VERB: &str = "vault.evals.cohorts.setup";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return (Err(error), Vec::new()),
    };
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        oneiron::task_verb::sdk::eval_cohorts_setup_as_owner_listing(server.vault(), &owner, input)
    })
    .await
    .unwrap_or_else(|_| (Err(internal(VERB)), Vec::new()))
}
