//! The attempt queue's owner Setting keys (DESIGN 15-setting-primitive): rows the setting
//! catalogue reads from this file.

use crate::check_in::ActClass;
use crate::setting::{Kind, ScopeKind, lower_is_tighter};

/// Off: only the owner, or a runtime ground, takes the hard rung.
fn owner_forces() -> bool {
    false
}

crate::setting::setting_keys! {
    /// Let this agent force-cancel. Off by default: the hard rung (`vault.tasks.cancel.force`
    /// and the turn-program hold release) takes the owner or a runtime ground, as before, and an
    /// agent keeps the soft rung and the proposal. On for an agent, it stops a TASK's live
    /// branches as the owner's delegate: the one cancel receipt names the agent and the ground
    /// `owner_delegate`, never the owner. An agent's row names one agent; the vault row opens
    /// every agent, and an agent's own row wins over it. On is the looser value, so only the
    /// owner turns it on; an agent's change waits on the owner's answer (restriction wave 11,
    /// census C49).
    pub(crate) ATTEMPT_QUEUE_AGENT_MAY_FORCE_CANCEL: bool = "attempt_queue.agent_may_force_cancel" {
        kind: Kind::new(owner_forces)
            .strictest(owner_forces)
            .tighter(lower_is_tighter::<bool>),
        scopes: &[ScopeKind::Vault, ScopeKind::Agent],
        act: ActClass::GrantWiden,
    };
}
