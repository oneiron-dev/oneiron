//! The lens system's owner Setting keys (DESIGN 15-setting-primitive): rows the setting catalogue
//! reads from this file.

use crate::check_in::ActClass;
use crate::setting::{Kind, ScopeKind, lower_is_tighter};

/// Off: the owner alone selects a proposed lens for its slot.
fn owner_alone() -> bool {
    false
}

crate::setting::setting_keys! {
    /// Let this agent select a proposed lens revision for its slot, or clear the slot
    /// (restriction census C33; Engine RULING RESTRICTION-WAVE-9-CANON C33 = A). Off by default:
    /// the owner alone selects, as before. On for an agent, that agent selects a revision, never
    /// one its own lineage proposed, which the engine refuses whatever this key says. An agent's
    /// row decides before the vault row. On is the looser value, so only the owner turns it on;
    /// an agent's change waits on the owner's answer.
    pub(crate) LENS_SLOT_AGENT_SELECT: bool = "lens.slot.agent_select" {
        kind: Kind::new(owner_alone)
            .strictest(owner_alone)
            .tighter(lower_is_tighter::<bool>),
        scopes: &[ScopeKind::Agent],
        act: ActClass::GrantWiden,
    };
}
