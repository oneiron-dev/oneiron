//! Owner-selected AG-UI file capture; shared by served facade transports.

use std::sync::Arc;

use oneiron::ingest::{AgUiFileImport, AgUiFileReceipt};

use super::host_doors::support::Listed;
use super::host_doors::support::owner_listing::as_owner;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_ingest_ag_ui_import(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AgUiFileImport,
) -> Listed<AgUiFileReceipt> {
    as_owner(
        server,
        auth,
        "vault.ingest.ag_ui.import",
        move |memory, owner| memory.ingest_ag_ui_file(owner, &input),
    )
    .await
}
