//! The house mind leads the root project (ARCH-0067: the vault is the root
//! project, its house mind leads it and the Owners sit as its board; FIX
//! 700/911). The owner finishes a stored workspace and its house takes the
//! lead at once; a start binds the one stored workspace's house while the
//! root still follows its seeded leader, and never replaces a leader the
//! board chose.
//!
//! The house runs its org in a role (HOUSE-BIND = A): the owner's finish
//! names it, else the config's `house_role` does, else the finish runs it
//! as deputy, [`oneiron::workspace_roster::DEFAULT_HOUSE_ROLE`] (DEPUTY = A;
//! HOUSE-ROLE-DEPUTY-AFTER-7071 = A). The start binds only when the config
//! names one (HOUSE-BIND-ROLE-SOURCE): no owner act, no default.

use oneiron::Vault;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::FederationGrantRole;

use super::courtesy_delete::with_issuer;
use super::{OwnerError, OwnerResult};
use crate::server::SyncServer;

/// `POST /v1/owner/workspace/finish`: the house `workspace_ref`'s stored
/// preset names leads the root, signed by this host for the owner, and runs
/// its org in `role`, else in the config's `house_role`, else as deputy
/// ([`oneiron::workspace_roster::DEFAULT_HOUSE_ROLE`]). A root that already
/// follows that house keeps it; an unknown workspace is not found.
pub(crate) fn finish_workspace(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    workspace_ref: &str,
    role: Option<&str>,
) -> OwnerResult<()> {
    let role = match role {
        Some(value) => oneiron::workspace_roster::parse_house_role(value).ok_or_else(|| {
            OwnerError::Invalid("role must be member, steward, admin, deputy or owner".to_owned())
        })?,
        None => server
            .config
            .house_role
            .unwrap_or(oneiron::workspace_roster::DEFAULT_HOUSE_ROLE),
    };
    let vault = server.vault();
    with_issuer(server, |issuer| {
        let signer = vault.owner_project_signer(issuer)?;
        vault.bind_workspace_house_leader(workspace_ref, role, owner, &signer)
    })
}

/// At start, after the root takes its first signature: the stored
/// workspace's house leads the root while the root follows its seeded
/// leader, in the config's `house_role`. A host with no secret has no issuer
/// and a relay signs nothing; either binds nothing, and so does a config
/// that names no `house_role`. A failure is logged and the start goes on.
pub(crate) fn bind_house_leader_at_start(
    vault: &Vault,
    secret: Option<&str>,
    role: Option<FederationGrantRole>,
) {
    if let Err(error) = bind_at_start(vault, secret, role) {
        tracing::warn!(%error, "the house mind was not bound as the root project's leader; the next start tries again");
    }
}

fn bind_at_start(
    vault: &Vault,
    secret: Option<&str>,
    role: Option<FederationGrantRole>,
) -> anyhow::Result<()> {
    if secret.is_none_or(str::is_empty) {
        return Ok(());
    }
    let Some(role) = role else {
        tracing::info!("no house_role is set; the start binds no house mind");
        return Ok(());
    };
    if vault.privacy_posture() == oneiron::HostingPrivacyPosture::Relay {
        return Ok(());
    }
    // The root signs with this install's own issuer seed (FIX-LIST 3018);
    // the configured secret only admits it.
    let issuer = vault.load_host_slip_issuer()?;
    if vault.bind_default_house_leader(role, &super::local_owner(vault)?, &issuer)? {
        tracing::info!("the workspace's house mind now leads the root project");
    }
    Ok(())
}
