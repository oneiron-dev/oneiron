//! Doors for changing the value in force between the owner's check and write.

use crate::Vault;
use crate::authority::{
    ActSurface, ConversationLearningView, ConversationTrainingView, LastDeviceKeyConfirmation,
    MachineAnswerLanding, MachineRemoval, MachineRole, OwnerKeyRemoval,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::world_keys::PolicyRevision;

/// [`Vault::set_machine_role`] runs `between` after the door asks and before its write opens.
///
/// # Errors
/// As [`Vault::set_machine_role`].
pub fn set_machine_role_between(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    machine: EntityId,
    role: MachineRole,
    seen: Option<[u8; 32]>,
    between: impl FnOnce(),
) -> Result<MachineAnswerLanding> {
    vault.set_machine_role_between(owner, surface, machine, role, seen, between)
}

/// [`Vault::set_conversation_training`] runs `between` after the door asks and before its write opens.
///
/// # Errors
/// As [`Vault::set_conversation_training`].
pub fn set_conversation_training_between(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    leave_out: bool,
    seen: Option<PolicyRevision>,
    between: impl FnOnce(),
) -> Result<ConversationTrainingView> {
    vault.set_conversation_training_between(owner, surface, leave_out, seen, between)
}

/// [`Vault::set_conversation_learning`] runs `between` after the door asks and before its write opens.
///
/// # Errors
/// As [`Vault::set_conversation_learning`].
pub fn set_conversation_learning_between(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    on: bool,
    allow_opt_out: bool,
    seen: Option<PolicyRevision>,
    between: impl FnOnce(),
) -> Result<ConversationLearningView> {
    vault.set_conversation_learning_between(owner, surface, on, allow_opt_out, seen, between)
}

/// [`Vault::remove_owner_key`] runs `between` after the door asks and before its write opens.
///
/// # Errors
/// As [`Vault::remove_owner_key`].
pub fn remove_owner_key_between(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    key: [u8; 32],
    confirmation: LastDeviceKeyConfirmation,
    between: impl FnOnce(),
) -> Result<OwnerKeyRemoval> {
    vault.remove_owner_key_between(owner, key, confirmation, between)
}

/// [`Vault::remove_machine`] runs `between` after the door asks and before its write opens.
///
/// # Errors
/// As [`Vault::remove_machine`].
pub fn remove_machine_between(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    machine: EntityId,
    seen: Option<[u8; 32]>,
    confirmation: LastDeviceKeyConfirmation,
    between: impl FnOnce(),
) -> Result<MachineRemoval> {
    vault.remove_machine_between(owner, surface, machine, seen, confirmation, between)
}
