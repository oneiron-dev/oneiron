//! Credential-bound owner projection of the native device-succession door.

use std::sync::Arc;

use oneiron::memory::device_succession::DevicePredecessor;

use super::host_doors::support::Listed;
use super::host_doors::support::owner_action::as_owner;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_devices_predecessor_name(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DevicePredecessor,
) -> Listed<DevicePredecessor> {
    as_owner(
        server,
        auth,
        "vault.devices.predecessor.name",
        move |memory, owner| memory.device_predecessor_name_as(owner, input),
    )
    .await
}
