//! Doors for changing the policy in force between the owner's check and write.

use crate::authority::ActSurface;
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::{FreeTimePolicy, FreeTimePolicyInput};
use crate::error::Result;
use crate::settings::RoomThreadAdminSettings;
use crate::settings::agent_world_access::{AgentWorldAccessChange, AgentWorldAccessSetRequest};
use crate::settings::default_facet::DefaultFacet;
use crate::settings::undo_send::UndoSendSetting;
use crate::{EntityId, Vault};

/// [`Vault::set_room_thread_admin_settings`] with `between` run after the door asked and before its
/// write opens.
///
/// # Errors
/// As [`Vault::set_room_thread_admin_settings`].
pub fn set_room_thread_admin_settings_between(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: Option<ActSurface>,
    admin_walk_in: Option<bool>,
    admin_delete: Option<bool>,
    between: impl FnOnce(),
) -> Result<RoomThreadAdminSettings> {
    vault.set_room_thread_admin_settings_between(
        owner,
        surface,
        admin_walk_in,
        admin_delete,
        between,
    )
}

/// [`Vault::set_default_facet_as_owner`] with `between` run after the door asked and before its
/// write opens.
///
/// # Errors
/// As [`Vault::set_default_facet_as_owner`].
pub fn set_default_facet_as_owner_between(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: Option<ActSurface>,
    setting: DefaultFacet,
    between: impl FnOnce(),
) -> Result<DefaultFacet> {
    vault.set_default_facet_as_owner_between(owner, surface, setting, between)
}

/// [`Vault::set_undo_send`] with `between` run after the door asked and before its
/// write opens.
///
/// # Errors
/// As [`Vault::set_undo_send`].
pub fn set_undo_send_between(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: Option<ActSurface>,
    setting: &UndoSendSetting,
    between: impl FnOnce(),
) -> Result<UndoSendSetting> {
    vault.set_undo_send_between(owner, surface, setting, between)
}

/// [`Vault::set_agent_world_access_as_owner`] with `between` run after the door asked and before
/// its write opens.
///
/// # Errors
/// As [`Vault::set_agent_world_access_as_owner`].
pub fn set_agent_world_access_as_owner_between(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: Option<ActSurface>,
    request: AgentWorldAccessSetRequest,
    between: impl FnOnce(),
) -> Result<AgentWorldAccessChange> {
    vault.set_agent_world_access_as_owner_between(owner, surface, request, between)
}

/// [`Vault::set_free_time_policy`] with `between` run after the door asked and before its
/// write opens.
///
/// # Errors
/// As [`Vault::set_free_time_policy`].
pub fn set_free_time_policy_between(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: Option<ActSurface>,
    agent: EntityId,
    expected_revision: u64,
    input: FreeTimePolicyInput,
    between: impl FnOnce(),
) -> Result<FreeTimePolicy> {
    vault.set_free_time_policy_between(owner, surface, agent, expected_revision, input, between)
}
