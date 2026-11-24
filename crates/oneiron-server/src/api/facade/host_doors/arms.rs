//! The experiment arm doors of the lane economy (design pass 32 section 5):
//! `vault.arms.admit`, `vault.arms.get` and `vault.arms.list`. Each proves
//! `verb_grant_caller`: the owner under their own proof, or an agent whose
//! own live owner Grant lists the verb; an agent admits into and reads only
//! the lines its Grant reaches, as the engine's act judges it again. Arms
//! live in a side table, which holds no entity row: the doors list none.

use std::sync::Arc;

use oneiron::experiment_arm::{
    ARMS_ADMIT_VERB, ARMS_GET_VERB, ARMS_LIST_VERB, ArmAdmitRequest, ArmList, ArmListRequest,
    ArmRef, ArmView, arm_admit_as, arm_get_as, arm_list_as,
};

use super::install_line_allocation;
use super::support::Listed;
use super::verb_grant::verb_grant_door;
use crate::auth::CoreAuth;
use crate::gpu_host::now_ms;
use crate::server::SyncServer;

/// `vault.arms.admit`: admits one arm into a seated family of a GPU line,
/// with its first allowance held from now until it closes or its period
/// ends. A repeat under the same intent key answers the same arm. An admit
/// can be the first write of a period, so the door then installs that
/// period's allocation, as the line doors do (LM-1).
pub(crate) async fn vault_arms_admit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ArmAdmitRequest,
) -> Listed<ArmView> {
    verb_grant_door(
        server,
        auth,
        ARMS_ADMIT_VERB,
        move |server, memory, owner| {
            let now = now_ms();
            let view = arm_admit_as(memory, owner, &input, now)?;
            if let Some(line) = server.vault().gpu_line(&input.line)? {
                install_line_allocation(server, &line, now);
            }
            Ok(view)
        },
    )
    .await
}

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
