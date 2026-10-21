//! The host doors of the owner's `git_push` Grant rows (FIX 6867, G1-PUSH):
//! `vault.repo.git_push.mint` and `.revoke`, and the served-repo anchor they
//! name repos by (`vault.repo.anchor.bind`, G1 PR3b). `host_doors` re-exports them, so
//! the generated HTTP facade handler and the MCP dispatcher call them by the
//! name every host door has, and a tool call, a code-mode call and an SDK
//! call meet one admission: the vault owner's proof (`facade_owner`, a
//! managed vault's attested owner among them), never a person's or an
//! agent's. Each engine door rechecks that proof in its own writer and
//! records the owner's act with `surface`, where his say-so reached this
//! install (`host_door_surface`). Each lists the grant row it wrote.
use std::sync::Arc;

use oneiron::authority::ActSurface;
use oneiron::task_verb::sdk::{
    self, GitPushGrantMintInput, GitPushGrantMintOutput, GitPushGrantRevokeInput,
    GitPushGrantRevokeOutput, RepoAnchorBindInput, RepoAnchorBindOutput,
};

use super::host_doors::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.repo.git_push.mint`: the owner grants a named person or agent raw
/// git push on named repos, listing the grant row it wrote.
pub(crate) async fn vault_repo_git_push_mint(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: GitPushGrantMintInput,
) -> Listed<GitPushGrantMintOutput> {
    as_owner_naming(
        server,
        auth,
        "vault.repo.git_push.mint",
        move |server, owner| sdk::mint_git_push_grant_as(server.vault(), owner, surface, input),
        |minted| vec![minted.grant.grant_ref],
    )
    .await
}

/// `vault.repo.git_push.revoke`: the owner revokes one git_push Grant,
/// listing the grant row it names.
pub(crate) async fn vault_repo_git_push_revoke(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: GitPushGrantRevokeInput,
) -> Listed<GitPushGrantRevokeOutput> {
    as_owner_naming(
        server,
        auth,
        "vault.repo.git_push.revoke",
        move |server, owner| sdk::revoke_git_push_grant_as(server.vault(), owner, surface, input),
        |revoked| vec![revoked.grant_ref],
    )
    .await
}

/// `vault.repo.anchor.bind`: the owner binds a served repo to its CODE
/// anchor in a PROJECT, listing the anchor and the PROJECT.
pub(crate) async fn vault_repo_anchor_bind(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RepoAnchorBindInput,
) -> Listed<RepoAnchorBindOutput> {
    as_owner_naming(
        server,
        auth,
        "vault.repo.anchor.bind",
        move |server, owner| sdk::bind_repo_anchor_as(server.vault(), owner, input),
        |bound| vec![bound.anchor.repo, bound.anchor.project],
    )
    .await
}
