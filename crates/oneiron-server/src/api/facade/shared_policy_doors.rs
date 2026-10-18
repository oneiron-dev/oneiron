//! The host doors of the shared-act policy rows (DOOR-129), beside
//! `shared_act_doors`: a live Owner reads every policy row under the owner's
//! proof. `host_doors` re-exports them.
//!
//! Each row lists its rows (`host_door_lists`): the policy rows live in the
//! policy manifest and the vault kind's shipped table, none of which holds a
//! listed row, so each lists none.
use std::sync::Arc;

use oneiron::federation::SharedActPoliciesView;
use oneiron::task_verb::sdk::{self, SharedVaultRequest};

use super::host_doors::{MaybeListed, owner_proof};
use super::shared_act_doors::as_person_naming;
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
