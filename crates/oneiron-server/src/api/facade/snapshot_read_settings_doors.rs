//! Typed doors over the snapshot handles' bounds (primitive A, slice 6.4b). The replace is the
//! owner's. The read answers the owner under its proof, or a person or agent on a verified slip
//! of its own that holds any `engine.controls` class, which the engine checks at the read
//! (untangle 6.6f; Engine 10 Nov 14:36, S66F-READ = C).
use std::sync::Arc;

use oneiron::settings::snapshot_read::SnapshotReadSettings;
use oneiron::task_verb::sdk::EmptyRequest;

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use super::substrate_read_doors::{as_reader, substrate_reader};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_settings_snapshot_read(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<SnapshotReadSettings> {
    const VERB: &str = "vault.settings.snapshot_read";
    match substrate_reader(server, auth, VERB) {
        Ok(Some(_)) => {
            as_owner_naming(
                server,
                auth,
                VERB,
                |server, owner| Ok(server.vault().snapshot_read_settings_as_owner(owner)?),
                |_| Vec::new(),
            )
            .await
        }
        Ok(None) => {
            let answer = as_reader(server, auth, VERB, |server, reader| {
                oneiron::snapshot_read::snapshot_read_settings_as_holder(server.vault(), reader)
            })
            .await;
            (answer, Vec::new())
        }
        Err(refusal) => (Err(refusal), Vec::new()),
    }
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
