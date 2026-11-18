//! The owner's auto-apply of an action-mode patch as a Setting key (restriction wave 14, C22;
//! Engine RULING RESTRICTION-WAVE-14-ROWS, 16 Nov 03:37). Off by default: a finding freezes its
//! band's agent-ceiling patch and only the owner's `Vault::apply_action_mode` puts it on the
//! agent's definition, as before. On, the night applies the frozen patch of a fresh finding
//! itself, through the same fenced ceiling writer, and records the inverse with its receipt, so
//! the owner's revert of that finding puts the ceiling back.

use crate::check_in::ActClass;
use crate::setting::{Kind, lower_is_tighter};

/// Off: only the owner's apply puts a frozen patch on an agent's definition.
fn owner_applies() -> bool {
    false
}

crate::setting::setting_keys! {
    /// Apply each fresh action-mode finding's frozen agent-ceiling patch at once (C22). The night
    /// applies it only while the policy in force is the owner's own row, so every patch it
    /// applies is one the owner wrote. On is the looser value, so only the owner turns it on; an
    /// agent's change waits on the owner's answer. While it stays on, a later night whose band
    /// names the patch again applies it again; turning it off stops that.
    pub(crate) AUTO_APPLY_PATCH: bool = "dreamer.action_mode.auto_apply_patch" {
        kind: Kind::new(owner_applies)
            .strictest(owner_applies)
            .tighter(lower_is_tighter::<bool>),
        act: ActClass::GrantWiden,
    };
}
