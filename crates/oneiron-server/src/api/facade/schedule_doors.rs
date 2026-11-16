//! The host doors of the Schedule primitive's verbs (DESIGN 15-setting-primitive, stage 0.2):
//! `vault.schedules.list`, `.arm`, `.disarm` and `.run`, each on the calling actor's own
//! credential (`facade_actor`). The engine door judges the caller itself: the vault owner on the
//! owner's own live slip, or an agent on its verified binding.
use std::sync::Arc;

use oneiron::runtime_hooks::InvocationId;
use oneiron::schedule::ScheduleView;
use oneiron::task_verb::sdk::{
    self, ScheduleArmRequest, ScheduleDisarmed, ScheduleList, ScheduleListRequest, ScheduleRef,
};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{Listed, credential_listing};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.schedules.list`: the armed jobs the caller may see.
pub(crate) async fn vault_schedules_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: ScheduleListRequest,
) -> Listed<ScheduleList> {
    credential_listing(
        server,
        auth,
        caller,
        "vault.schedules.list",
        move |_, _, memory| sdk::schedule_list_embedded(&memory, input),
    )
    .await
}

/// `vault.schedules.arm`: one job armed under the caller's own power.
pub(crate) async fn vault_schedules_arm(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: ScheduleArmRequest,
) -> Listed<ScheduleView> {
    credential_listing(
        server,
        auth,
        caller,
        "vault.schedules.arm",
        move |_, _, memory| sdk::schedule_arm_embedded(&memory, input),
    )
    .await
}

/// `vault.schedules.disarm`: one armed job disarmed.
pub(crate) async fn vault_schedules_disarm(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: ScheduleRef,
) -> Listed<ScheduleDisarmed> {
    credential_listing(
        server,
        auth,
        caller,
        "vault.schedules.disarm",
        move |_, _, memory| sdk::schedule_disarm_embedded(&memory, input),
    )
    .await
}

/// `vault.schedules.run`: one armed job due from now.
pub(crate) async fn vault_schedules_run(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: ScheduleRef,
) -> Listed<ScheduleView> {
    credential_listing(
        server,
        auth,
        caller,
        "vault.schedules.run",
        move |_, _, memory| sdk::schedule_run_embedded(&memory, input),
    )
    .await
}
