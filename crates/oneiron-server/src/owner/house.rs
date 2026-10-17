//! The house mind leads the root project (ARCH-0067: the vault is the root
//! project, its house mind leads it and the Owners sit as its board; FIX
//! 700/911). The owner finishes a stored workspace and its house takes the
//! lead at once; a start binds the one stored workspace's house while the
//! root still follows its seeded leader, and never replaces a leader the
//! board chose.

use oneiron::Vault;
use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;

use super::OwnerResult;
use super::cooperative_deletion::with_issuer;
use crate::server::SyncServer;

/// `POST /v1/owner/workspace/finish`: the house `workspace_ref`'s stored
/// preset names leads the root, signed by this host for the owner. A root
/// that already follows that house keeps it; an unknown workspace is not
/// found.
pub(crate) fn finish_workspace(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    workspace_ref: &str,
) -> OwnerResult<()> {
    let vault = server.vault();
    with_issuer(server, |issuer| {
        let signer = vault.owner_project_signer(issuer)?;
        vault.bind_workspace_house_leader(workspace_ref, owner, &signer)
    })
}

/// At start, after the root takes its first signature: the stored
/// workspace's house leads the root while the root follows its seeded
/// leader. A host with no secret has no issuer and a relay signs nothing;
/// either binds nothing. A failure is logged and the start goes on.
pub(crate) fn bind_house_leader_at_start(vault: &Vault, secret: Option<&str>) {
    if let Err(error) = bind_at_start(vault, secret) {
        tracing::warn!(%error, "the house mind was not bound as the root project's leader; the next start tries again");
    }
}

fn bind_at_start(vault: &Vault, secret: Option<&str>) -> anyhow::Result<()> {
    let Some(secret) = secret.filter(|secret| !secret.is_empty()) else {
        return Ok(());
    };
    if vault.privacy_posture() == oneiron::HostingPrivacyPosture::Relay {
        return Ok(());
    }
    let issuer = HostSlipIssuer::from_secret(secret.as_bytes())?;
    if vault.bind_default_house_leader(&super::local_owner(vault)?, &issuer)? {
        tracing::info!("the workspace's house mind now leads the root project");
    }
    Ok(())
}
