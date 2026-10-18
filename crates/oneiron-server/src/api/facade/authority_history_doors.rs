//! Owner-authenticated signed authority history transfer. The HTTP, held
//! socket and MCP projections all reach these same verb-table host doors.
use std::sync::Arc;

use oneiron::task_verb::sdk::{self, AuthorityHistoryImported, EmptyRequest, SignedAuthorityHistory};

use super::host_doors::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The original signed authority bytes, under the audit door's owner proof.
pub(crate) async fn vault_authority_history_export(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<SignedAuthorityHistory> {
    as_owner_naming(
        server,
        auth,
        "vault.authority.history.export",
        move |server, owner| sdk::export_authority_history_as_owner(server.vault(), owner),
        |_| Vec::new(),
    )
    .await
}

/// Atomic signed-envelope submission. The authority log holds no user row.
pub(crate) async fn vault_authority_history_import(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SignedAuthorityHistory,
) -> Listed<AuthorityHistoryImported> {
    as_owner_naming(
        server,
        auth,
        "vault.authority.history.import",
        move |server, owner| sdk::import_authority_history_as_owner(server.vault(), owner, input),
        |_| Vec::new(),
    )
    .await
}
