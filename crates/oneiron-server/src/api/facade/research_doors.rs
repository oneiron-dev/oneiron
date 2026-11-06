//! Research and eval host doors, using the caller's original source reader.
//! Owner writes revalidate the same proof checked before hooks; Repair recipe
//! preparation uses the caller's ordinary scoped read without an owner grant.
use std::sync::Arc;

use oneiron::skill_optimize::{EvalAuthoringInventory, EvalAuthoringReport, EvalCohortSetup};
use oneiron::task_verb::sdk::{EvalInventoryWire, ResearchChildReceipt, ResearchChildWire};

use super::host_doors::support::{Listed, internal, owner_listing, owner_proof};
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
    let answer = super::clock_ingress::run_blocking(move || {
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
    let answer = super::clock_ingress::run_blocking(move || {
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
/// those audits read, and every admitted Repair source, from the same reads
/// ([`oneiron::Memory::setup_eval_cohorts_listing`]). A setup that cuts
/// nothing audits no text and lists none. Source receipts ride in the report.
pub(crate) async fn vault_evals_cohorts_setup(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EvalCohortSetup,
) -> Listed<EvalAuthoringReport> {
    const VERB: &str = "vault.evals.cohorts.setup";
    let clock_server = Arc::clone(server);
    let (answer, mut rows) = owner_listing::as_owner(server, auth, VERB, move |memory, owner| {
        // Keep the inner result and row list together even on a refusal.
        Ok(memory.setup_eval_cohorts_listing(owner, input, clock_server.vault().now_recorded_at()))
    })
    .await;
    match answer {
        Ok((answer, audited)) => {
            rows.extend(audited);
            rows.sort_unstable();
            rows.dedup();
            (answer, rows)
        }
        Err(error) => (Err(error), rows),
    }
}

/// Queue a paired measurement under the authenticated caller's original
/// source reader. Asking reads metadata only, never the sealed source.
pub(crate) async fn vault_evals_measurements_request(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::skill_optimize::EvalMeasurementRequest,
) -> Listed<oneiron::skill_optimize::EvalMeasurementRef> {
    const VERB: &str = "vault.evals.measurements.request";
    let clock_server = Arc::clone(server);
    owner_listing::as_owner(server, auth, VERB, move |memory, owner| {
        let digest = memory.request_eval_measurement(
            owner,
            &input,
            clock_server.vault().now_recorded_at(),
        )?;
        Ok(oneiron::skill_optimize::EvalMeasurementRef {
            digest: blake3::Hash::from(digest).to_hex().as_str().to_owned(),
        })
    })
    .await
}

/// Record or reuse the exact recipe through the existing owner-validated
/// writer, without widening this credential's source-reading rights.
pub(crate) async fn vault_evals_repair_record(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::skill_optimize::EvalRepairCaseRequest,
) -> Listed<oneiron::skill_optimize::EvalRepairCaseReference> {
    const VERB: &str = "vault.evals.repair.record";
    let source_rows = super::host_doors::support::hex_rows([&input.recipe.source.claim_ref]);
    let (answer, mut rows) = owner_listing::as_owner(server, auth, VERB, move |memory, owner| {
        memory
            .record_eval_repair_case(owner, &input)
            .map(oneiron::skill_optimize::EvalRepairCaseReference::from)
    })
    .await;
    rows.extend(source_rows);
    (answer, rows)
}
