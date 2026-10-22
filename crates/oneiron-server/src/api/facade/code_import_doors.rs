//! Credential-bound host projections of the outside import doors (FIX 6871,
//! G7 PR1): `vault.code.imports.create` and `vault.code.imports.get`.
//!
//! HTTP, SDK, MCP and code mode all bind the caller here, as the exact
//! publish doors bind theirs: the credential's own principal, with the
//! owner's proof when the credential carries it. The request's verified
//! credential then lends its handle the one call's Git transport. The
//! engine door admits the owner, or that principal by the same receive
//! decision any push meets, and the door's own receive admission decides
//! each send again. A credential that binds no principal is nobody.
use std::sync::Arc;

use oneiron::EdgeActorClass;
use oneiron::EntityId;
use oneiron::memory::origin_doors::{
    ExternalImportLookup, ExternalImportProof, ExternalImportReceipt, ExternalImportRequest,
    ExternalImportStatus,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::repo_mutation::external_import::ExternalGitSourceHost;

use super::host_doors::support::{Listed, credential_listing};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

fn not_an_importer(verb: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("{verb} is the vault owner's, or a principal's whose standing admits the push"),
        &[
            "Present the owner's credential, or your own credential with a git_push Grant on \
           this repository.",
        ],
    )
}

/// The check an import row's door runs before its pre chain
/// (`door_admits`): a credential that binds a principal.
pub(super) fn imports_admit(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<()> {
    super::owner_binding::facade_caller_or(server, auth, || not_an_importer(verb)).map(drop)
}

/// The bound caller, its proof and the transport its credential lends.
type Importer = (
    (EntityId, EdgeActorClass),
    ExternalImportProof,
    Arc<dyn ExternalGitSourceHost>,
);

fn importer(server: &Arc<SyncServer>, auth: &CoreAuth, verb: &str) -> MemoryResult<Importer> {
    let caller = super::owner_binding::facade_caller_or(server, auth, || not_an_importer(verb))?;
    let proof = match super::owner_binding::facade_owner(server, auth, verb) {
        Ok(owner) => ExternalImportProof::Owner(owner),
        Err(_) => ExternalImportProof::Member,
    };
    let host = crate::api::git_http::external_import_host(server, auth)?;
    Ok((caller, proof, host))
}

pub(crate) async fn vault_code_imports_create(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ExternalImportRequest,
) -> Listed<ExternalImportReceipt> {
    const VERB: &str = "vault.code.imports.create";
    let (caller, proof, host) = match importer(server, auth, VERB) {
        Ok(bound) => bound,
        Err(refusal) => return (Err(refusal), Vec::new()),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory
            .with_external_git_source_host(host)
            .code_external_import_create_as(&proof, input)
    })
    .await
}

pub(crate) async fn vault_code_imports_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ExternalImportLookup,
) -> Listed<Option<ExternalImportStatus>> {
    const VERB: &str = "vault.code.imports.get";
    let (caller, proof, host) = match importer(server, auth, VERB) {
        Ok(bound) => bound,
        Err(refusal) => return (Err(refusal), Vec::new()),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory
            .with_external_git_source_host(host)
            .code_external_import_get_as(&proof, input)
    })
    .await
}
