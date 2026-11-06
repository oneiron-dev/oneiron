//! The owner's retained sync held-edit evidence, with no settlement act.

use std::sync::Arc;

use oneiron::task_verb::sdk::{self, EmptyRequest, SyncHeldEditEvidence};

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_sync_quarantine_held_edits(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EmptyRequest,
) -> Listed<Vec<(u64, SyncHeldEditEvidence)>> {
    as_owner_naming(
        server,
        auth,
        "vault.sync.quarantine.held_edits",
        move |server, owner| sdk::sync_quarantine_held_edits_as_owner(server.vault(), owner, input),
        |_| Vec::new(),
    )
    .await
}
