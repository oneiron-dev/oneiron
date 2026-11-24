//! The experiment arm doors of the lane economy (design pass 32 section 5):
//! `vault.arms.admit`, `vault.arms.forecast`, `vault.arms.get` and
//! `vault.arms.list`. Each proves
//! `verb_grant_caller`: the owner under their own proof, or an agent whose
//! own live owner Grant lists the verb; an agent admits into and reads only
//! the lines its Grant reaches, as the engine's act judges it again. Arms
//! live in a side table, which holds no entity row: the doors list none. So
//! no invocation claim keeps the reads' reply
//! (`invocations::UNKEPT_REPLY_VERBS`): a same-id retry of a get or a list
//! runs the read again, with the line cover, and is never answered a saved
//! arm.

use std::sync::Arc;

use oneiron::experiment_arm::{
    ARMS_ADMIT_VERB, ARMS_FORECAST_VERB, ARMS_GET_VERB, ARMS_LIST_VERB, ArmAdmitRequest,
    ArmForecastRequest, ArmList, ArmListRequest, ArmRef, ArmView, arm_admit_as, arm_forecast_as,
    arm_get_as, arm_list_as,
};

use super::support::Listed;
use super::verb_grant::verb_grant_door;
use crate::auth::CoreAuth;
use crate::gpu_host::now_ms;
use crate::server::SyncServer;

/// `vault.arms.admit`: admits one arm into a seated family of a GPU line,
/// with its first allowance held from now until rung 1 leaves `Open`, the
/// arm is withdrawn, the period ends or the hold lies dormant. A repeat
/// under the same intent key, or of the same ask on the same contract,
/// answers the same arm. The period record names the period's allocation;
/// the claims are its hold (HOLD-IS-CLAIM-FOLD = A), so the door installs
/// nothing in the host account.
pub(crate) async fn vault_arms_admit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ArmAdmitRequest,
) -> Listed<ArmView> {
    verb_grant_door(server, auth, ARMS_ADMIT_VERB, move |_, memory, owner| {
        arm_admit_as(memory, owner, &input, now_ms())
    })
    .await
}

/// `vault.arms.forecast`: writes the rung's one forecast for the arm's own
/// runner, before the rung's first claim. A repeat of the same forecast,
/// under the same intent key or another, answers the same arm.
pub(crate) async fn vault_arms_forecast(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ArmForecastRequest,
) -> Listed<ArmView> {
    verb_grant_door(server, auth, ARMS_FORECAST_VERB, move |_, memory, owner| {
        arm_forecast_as(memory, owner, &input, now_ms())
    })
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
