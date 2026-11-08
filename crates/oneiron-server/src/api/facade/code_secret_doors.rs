//! Host doors for a repository's marked secrets (FIX 7608 slice 8): the
//! owner reads the marks and remediations, and stages the remediation of
//! the current code. Both act as the authenticated owner, as every code
//! door does; the engine reads and stages, and returns no value.

use std::sync::Arc;

use oneiron::memory::code_doors::{
    CodeRepoRequest, CodeRepoSecretProposeRequest, CodeRepoSecretRemediation, CodeRepoSecretsView,
};

use super::host_doors::support::Listed;
use super::host_doors::support::owner_action::as_owner;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_code_secrets_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeRepoRequest,
) -> Listed<CodeRepoSecretsView> {
    as_owner(
        server,
        auth,
        "vault.code.secrets.get",
        move |memory, owner| memory.code_repo_secrets_get_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_secrets_propose(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeRepoSecretProposeRequest,
) -> Listed<CodeRepoSecretRemediation> {
    as_owner(
        server,
        auth,
        "vault.code.secrets.propose",
        move |memory, owner| memory.code_repo_secrets_propose_as(owner, input),
    )
    .await
}
