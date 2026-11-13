//! The owner's verdict on an agent's plan-doc (plan mode), with the owner's
//! own proof.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::note::{PlanDocSettlementView, PlanDocVerdictRequest};

use super::host_doors::support::{MaybeListed, owner_proof};
use super::shared_act_doors::as_person_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// An answered plan-doc names its NOTE.
fn settled_plan_rows(settled: &PlanDocSettlementView) -> Option<Vec<EntityId>> {
    Some(vec![settled.plan_ref])
}

pub(crate) async fn vault_plans_approve(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PlanDocVerdictRequest,
) -> MaybeListed<PlanDocSettlementView> {
    const VERB: &str = "vault.plans.approve";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| oneiron::note::approve_plan_doc_as(server.vault(), &owner, input),
        settled_plan_rows,
    )
    .await
}

pub(crate) async fn vault_plans_reject(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PlanDocVerdictRequest,
) -> MaybeListed<PlanDocSettlementView> {
    const VERB: &str = "vault.plans.reject";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| oneiron::note::reject_plan_doc_as(server.vault(), &owner, input),
        settled_plan_rows,
    )
    .await
}
