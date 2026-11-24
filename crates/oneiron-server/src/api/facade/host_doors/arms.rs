//! The experiment arm doors of the lane economy (design pass 32 section 5):
//! `vault.arms.get` and `vault.arms.list`. Each proves `verb_grant_caller`:
//! the owner under their own proof, or an agent whose own live owner Grant
//! lists the verb; an agent reads only the arms of lines its Grant reaches,
//! as the engine's read judges it again. Arms live in a side table, which
//! holds no entity row: the doors list none.

use std::sync::Arc;

use oneiron::experiment_arm::{
    ARMS_GET_VERB, ARMS_LIST_VERB, ArmList, ArmListRequest, ArmRef, ArmView, arm_get_as,
    arm_list_as,
};

use super::support::Listed;
use super::verb_grant::verb_grant_door;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.arms.get`: one arm, with whether it is open and the rung it
/// stands at.
pub(crate) async fn vault_arms_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ArmRef,
) -> Listed<ArmView> {
    verb_grant_door(server, auth, ARMS_GET_VERB, move |_, memory, owner| {
        arm_get_as(memory, owner, &input)
    })
    .await
}

/// `vault.arms.list`: the arms the caller may read, newest first.
pub(crate) async fn vault_arms_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ArmListRequest,
) -> Listed<ArmList> {
    verb_grant_door(server, auth, ARMS_LIST_VERB, move |_, memory, owner| {
        arm_list_as(memory, owner, &input)
    })
    .await
}
