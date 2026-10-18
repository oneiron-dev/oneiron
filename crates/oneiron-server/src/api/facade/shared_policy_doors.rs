//! The host doors of the shared-act policy rows (DOOR-129), beside
//! `shared_act_doors`: a live Owner reads every policy row and one proposed
//! change under the owner's proof; a live editor proposes a row change and
//! answers one under their own person proof
//! (`shared_act_doors::person`), so each Owner's approval or veto is their
//! own act and no request carries another's. The engine's live editor set,
//! digest binding and narrowing checks decide. `host_doors` re-exports them.
//!
//! Each row lists its rows (`host_door_lists`): the policy rows live in the
//! policy manifest and the vault kind's shipped table, and a change in the
//! shared-act tables, none of which holds a listed row, so each lists none.
use std::sync::Arc;

use oneiron::federation::{SharedActPoliciesView, SharedActPolicyChange};
use oneiron::task_verb::sdk::{
    self, SharedActPolicyAnswerRequest, SharedActPolicyChangeRequest,
    SharedActPolicyProposeRequest, SharedVaultRequest,
};

use super::host_doors::{MaybeListed, owner_proof};
use super::shared_act_doors::{as_person_naming, person};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.shared.policy.get`: every shared-act policy row, for a live Owner.
pub(crate) async fn vault_shared_policy_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedVaultRequest,
) -> MaybeListed<SharedActPoliciesView> {
    const VERB: &str = "vault.shared.policy.get";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::read_shared_act_policies(server.vault(), &owner, input),
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.shared.policy.propose`: a live editor proposes one row change.
pub(crate) async fn vault_shared_policy_propose(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedActPolicyProposeRequest,
) -> MaybeListed<SharedActPolicyChange> {
    const VERB: &str = "vault.shared.policy.propose";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, proposer| {
            sdk::propose_shared_act_policy_change(server.vault(), &proposer, input)
        },
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.shared.policy.answer`: a live editor approves or vetoes a change.
pub(crate) async fn vault_shared_policy_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedActPolicyAnswerRequest,
) -> MaybeListed<SharedActPolicyChange> {
    const VERB: &str = "vault.shared.policy.answer";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, holder| sdk::answer_shared_act_policy_change(server.vault(), &holder, input),
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.shared.policy.change`: one change and its answers, for a live Owner.
pub(crate) async fn vault_shared_policy_change(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedActPolicyChangeRequest,
) -> MaybeListed<SharedActPolicyChange> {
    const VERB: &str = "vault.shared.policy.change";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::read_shared_act_policy_change(server.vault(), &owner, input),
        |_| Some(Vec::new()),
    )
    .await
}
