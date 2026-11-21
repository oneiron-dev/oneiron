//! Owner-authenticated signed authority history transfer. The HTTP, held
//! socket and MCP projections all reach these same verb-table host doors.
use std::sync::Arc;

use oneiron::task_verb::sdk::{
    self, AuthorityHistoryImported, EmptyRequest, SignedAuthorityHistory,
};

use super::host_doors::support::{Listed, internal, refused};
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The original signed authority bytes, for the owner or a live audit_read
/// holder (RULING AUDIT-READ-POWER-LIST = B).
pub(crate) async fn vault_authority_history_export(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<SignedAuthorityHistory> {
    let reader = match crate::api::facade::audit_read_doors::audit_reader(
        server,
        auth,
        "vault.authority.history.export",
    ) {
        Ok(reader) => reader,
        Err(refusal) => return refused(refusal),
    };
    let server = Arc::clone(server);
    let answer = crate::api::facade::clock_ingress::run_blocking(move || {
        sdk::export_authority_history_as_reader(server.vault(), &reader)
    })
    .await
    .map_err(|_| internal("vault.authority.history.export"))
    .and_then(|answer| answer);
    (answer, Vec::new())
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
