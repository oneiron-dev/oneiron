//! Typed owner doors over the snapshot handles' bounds (primitive A, slice 6.4b).
use std::sync::Arc;

use oneiron::settings::snapshot_read::SnapshotReadSettings;
use oneiron::task_verb::sdk::EmptyRequest;

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_settings_snapshot_read(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<SnapshotReadSettings> {
    as_owner_naming(
        server,
        auth,
        "vault.settings.snapshot_read",
        |server, owner| Ok(server.vault().snapshot_read_settings_as_owner(owner)?),
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_settings_snapshot_read_replace(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SnapshotReadSettings,
) -> Listed<SnapshotReadSettings> {
    as_owner_naming(
        server,
        auth,
        "vault.settings.snapshot_read.replace",
        move |server, owner| {
            Ok(server
                .vault()
                .replace_snapshot_read_settings_as_owner(owner, input)?)
        },
        |_| Vec::new(),
    )
    .await
}
