//! Who a host credential acts as at a server door (FIX 2222 = A, slice B;
//! owner ruling "A + support", 2026-10-18).
//!
//! On a self-hosted vault the host's own root, and the explicit local dev
//! mode, act as the vault's owner: the embedded owner Human the root bound at
//! install, reading with that owner's guarded key
//! (`Vault::host_action_authority`, `Vault::dev_action_authority`). On a
//! hosted vault the operator's root acts as nobody: every owner act answers
//! the typed support-grant refusal, and only its admin commands run. Every
//! door resolves a host credential here, through one resolver, so no door
//! picks its own actor for one, and a refusal never falls through to
//! another actor.
//!
//! Admission is not authentication: `check_api_auth` still judges a legacy
//! caller's grade, and a ROOT ADMIN door (static schema, skills, usage,
//! lease repair, operator recovery, `/v1/owner` status and backups) takes no
//! actor and no read key, so it keeps working on a hosted vault.

use oneiron::authority::HostActionAuthority;

use super::facade::FacadeApiError;
use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::server::SyncServer;

/// The host action `auth` takes on `vault`. `None`: no host credential (a
/// bound slip, a managed vault's attested owner, an account key), which
/// keeps its own path. `Some(Err)`: the typed refusal on a vault where no
/// host acts as a person, or the owner refusal on a self-hosted one whose
/// root binds no live owner.
pub(crate) fn host_action_of(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
) -> Option<oneiron::Result<HostActionAuthority>> {
    if let Some(root) = auth.host_root() {
        return Some(vault.host_action_authority(root));
    }
    if auth.is_local_dev_hatch() {
        return Some(vault.dev_action_authority());
    }
    // A slip cut from the root still names the host: where no host acts as a
    // person, it acts as nobody either. On a self-hosted vault it keeps the
    // key its Scope gives, and acts as no person.
    if auth.is_host_holder()
        && vault.privacy_posture() != oneiron::HostingPrivacyPosture::SelfHostLocal
    {
        return Some(Err(oneiron::Error::HostActionRequiresSupportGrant));
    }
    None
}

/// The one resolver every facade, action and MCP door asks (FIX 2222).
/// `None` keeps today's path for an ordinary bound credential; `Some` is a
/// self-hosted root or the dev mode acting as the owner. A hosted operator's
/// root is refused, typed, before the door picks any actor.
pub(crate) fn facade_host_action(
    server: &SyncServer,
    auth: &CoreAuth,
) -> Result<Option<HostActionAuthority>, FacadeApiError> {
    host_action_of(server.vault(), auth)
        .transpose()
        .map_err(|error| FacadeApiError::from(oneiron::MemoryError::from(error)))
}

/// The owner-act admission of a legacy door (FIX 2222), after its grade was
/// authenticated: a host root or the dev mode acts as the owner on a
/// self-hosted vault, and gets the typed refusal anywhere else; a managed
/// vault's attested owner and an ordinary verified slip keep their own key.
/// An owner-grade caller that verified no slip and is neither of those names
/// no one to act as, so it is refused. It runs before any read, body actor,
/// cached replay or socket upgrade.
pub(crate) fn require_host_owner_act(
    server: &SyncServer,
    auth: &CoreAuth,
) -> Result<Option<HostActionAuthority>, ApiError> {
    match host_action_of(server.vault(), auth) {
        Some(action) => action.map(Some).map_err(host_action_refusal),
        None if auth.is_owner_grade()
            && auth.verified_slip().is_none()
            && auth.managed_owner().is_none() =>
        {
            Err(ApiError::forbidden_scope("owner"))
        }
        None => Ok(None),
    }
}

/// A host action's refusal on the legacy plane: 403 with
/// `required_scope: support_grant` for the typed refusal, and the owner
/// refusal's own status for a self-hosted root that binds no live owner.
pub(crate) fn host_action_refusal(error: oneiron::Error) -> ApiError {
    super::core_engine_error("host action failed", error)
}
