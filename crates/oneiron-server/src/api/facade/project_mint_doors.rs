//! The host doors of the owner's project mint (FIX [OWNER-PROJECT-MINT-DOOR]):
//! `vault.projects.mint` and its read `vault.projects.minted`. `host_doors`
//! re-exports them, so the generated HTTP facade handler and the MCP
//! dispatcher call them by the name every host door has. Both admit the
//! vault owner's proof, as `/v1/owner` takes it, through one check
//! ([`project_mint_owner`]); owner proof only was chosen by the Engine
//! (28 Nov), not ruled by the owner. The mint signs the new project's state
//! with the owner's project signer under the host's slip issuer, as
//! `vault.projects.confirm` does; the embedded handle's `projects_mint` keeps
//! refusing.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::workspace_roster::{
    OwnerMintedProjectsPage, OwnerMintedProjectsRequest, OwnerProjectMintAnswer,
    OwnerProjectMintRequest,
};

use super::host_doors::support::internal;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The one caller check of both doors: the vault owner's own verified,
/// unattenuated credential.
fn project_mint_owner(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<AuthenticatedOwner> {
    super::owner_binding::facade_owner(server, auth, verb)
}

/// `vault.projects.mint`: the owner mints one project under a parent of
/// their own, or the root. Beside the answer, the project and its parent.
pub(crate) async fn vault_projects_mint(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OwnerProjectMintRequest,
) -> (MemoryResult<OwnerProjectMintAnswer>, Vec<EntityId>) {
    const VERB: &str = "vault.projects.mint";
    let owner = match project_mint_owner(server, auth, VERB) {
        Ok(owner) => owner,
        Err(refusal) => return (Err(refusal), Vec::new()),
    };
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || {
        let vault = server.vault();
        let minted = crate::api::pairing::with_issuer(&server, |issuer| {
            Ok(vault
                .owner_project_signer(issuer)
                .map_err(MemoryError::from)
                .and_then(|signer| vault.mint_owner_project(&owner, &signer, &input)))
        })
        .map_err(|_| internal(VERB))
        .and_then(|minted| minted);
        let listed = minted
            .as_ref()
            .map(|answer| vec![answer.project.project, answer.project.parent])
            .unwrap_or_default();
        (minted, listed)
    })
    .await
    .unwrap_or_else(|_| (Err(internal(VERB)), Vec::new()))
}

/// `vault.projects.minted`: one page of the projects the owner minted.
/// Beside the answer, the projects it names.
pub(crate) async fn vault_projects_minted(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OwnerMintedProjectsRequest,
) -> (MemoryResult<OwnerMintedProjectsPage>, Vec<EntityId>) {
    const VERB: &str = "vault.projects.minted";
    let owner = match project_mint_owner(server, auth, VERB) {
        Ok(owner) => owner,
        Err(refusal) => return (Err(refusal), Vec::new()),
    };
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || {
        let page = server.vault().owner_minted_projects(&owner, &input);
        let listed = page
            .as_ref()
            .map(|page| page.projects.iter().map(|row| row.project).collect())
            .unwrap_or_default();
        (page, listed)
    })
    .await
    .unwrap_or_else(|_| (Err(internal(VERB)), Vec::new()))
}
