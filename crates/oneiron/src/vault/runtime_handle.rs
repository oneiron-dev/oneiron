//! The agent runtime's one read path to the vault state it needs that is
//! not public (slice 5.0b, S5-4 = A).
//!
//! The runtime modules (`verbs`, `code_run`, `engine_executor`,
//! `runtime_hooks`, `code_sandbox`, `off_record`, `outbound_consent`) read
//! seven `Vault` fields that are not public. They read them through
//! [`Vault::runtime`], never by field syntax, so a crate above core can read
//! the same state with no field widened. `Vault::store` is public and is read
//! directly. Core modules keep their direct field reads.

use std::sync::Arc;

use super::Vault;
use crate::code_run::activity::AttemptActivityRuntime;
use crate::code_sandbox::egress::VaultHostFloor;
use crate::config::VaultConfig;
use crate::engine_executor::AttemptCancels;
use crate::runtime_hooks::verb::VerbHookState;
use crate::skill::SkillInvocations;
use crate::store::result_body_pins::ResultBodyPins;

/// Borrowed references to the seven non-public `Vault` fields the agent
/// runtime reads ([`Vault::runtime`]). Each accessor returns the field as the
/// vault holds it, borrowed for the vault's lifetime.
#[derive(Clone, Copy)]
pub struct RuntimeHandle<'v> {
    verb_hook_state: &'v VerbHookState,
    config: &'v VaultConfig,
    host_net_floor: &'v Arc<VaultHostFloor>,
    attempt_cancels: &'v AttemptCancels,
    attempt_activity: &'v AttemptActivityRuntime,
    result_body_pins: &'v ResultBodyPins,
    skill_invocations: &'v SkillInvocations,
}

impl Vault {
    /// The vault state the agent runtime reads that is not public.
    #[inline]
    pub fn runtime(&self) -> RuntimeHandle<'_> {
        RuntimeHandle {
            verb_hook_state: &self.verb_hook_state,
            config: &self.config,
            host_net_floor: &self.host_net_floor,
            attempt_cancels: &self.attempt_cancels,
            attempt_activity: &self.attempt_activity,
            result_body_pins: &self.result_body_pins,
            skill_invocations: &self.skill_invocations,
        }
    }
}

impl<'v> RuntimeHandle<'v> {
    /// Verb hooks' in-memory state (`Vault::verb_hook_state`).
    #[inline]
    pub(crate) const fn verb_hook_state(self) -> &'v VerbHookState {
        self.verb_hook_state
    }

    /// Whether this vault opens off-record sessions
    /// (`VaultConfig::off_record_enabled`).
    #[inline]
    pub const fn off_record_enabled(self) -> bool {
        self.config.off_record_enabled
    }

    /// The byte budget of one off-record session's overlay
    /// (`VaultConfig::off_record_overlay_budget_bytes`).
    #[inline]
    pub const fn off_record_overlay_budget_bytes(self) -> usize {
        self.config.off_record_overlay_budget_bytes
    }

    /// The prefix width a vector query may also have
    /// (`VaultConfig::fast_dims`); the full width is
    /// [`Vault::embedding_dimensions`].
    #[inline]
    pub const fn fast_dims(self) -> Option<u16> {
        self.config.fast_dims
    }

    /// The floor this vault's guests' network work charges
    /// (`Vault::host_net_floor`).
    #[inline]
    pub const fn host_net_floor(self) -> &'v Arc<VaultHostFloor> {
        self.host_net_floor
    }

    /// The step loops leased attempts run on this vault
    /// (`Vault::attempt_cancels`).
    #[inline]
    pub(crate) const fn attempt_cancels(self) -> &'v AttemptCancels {
        self.attempt_cancels
    }

    /// What the runtime witnesses of each leased attempt it runs now
    /// (`Vault::attempt_activity`).
    #[inline]
    pub(crate) const fn attempt_activity(self) -> &'v AttemptActivityRuntime {
        self.attempt_activity
    }

    /// The result bodies this vault's readers hold
    /// (`Vault::result_body_pins`).
    #[inline]
    pub const fn result_body_pins(self) -> &'v ResultBodyPins {
        self.result_body_pins
    }

    /// The callable skill invocations running on this vault
    /// (`Vault::skill_invocations`).
    #[inline]
    pub const fn skill_invocations(self) -> &'v SkillInvocations {
        self.skill_invocations
    }
}
