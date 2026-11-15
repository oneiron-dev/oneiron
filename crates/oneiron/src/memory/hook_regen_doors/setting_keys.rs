//! Hook regen's owner Setting keys (DESIGN 15-setting-primitive): rows the setting catalogue
//! reads from this file.

use crate::setting::{Kind, lower_is_tighter};

/// Off: the regen doors take the owner's proof alone.
fn read_by_owner_alone() -> bool {
    false
}

crate::setting::setting_keys! {
    /// Let agents read hook regen and adopt identical candidates. Off by default: the regen
    /// doors take the owner's proof alone. On, an agent whose live grant names the verb reads
    /// due and get and adopts a candidate whose golden replay is identical; a differing
    /// candidate still needs the owner's stamp (DOOR-077). On is the looser value, so only the
    /// owner turns it on; an agent's change waits on the owner's answer.
    pub(crate) HOOK_REGEN_AGENT_MAY_ADOPT: bool = "memory.hook_regen.agent_may_adopt" {
        kind: Kind::new(read_by_owner_alone)
            .strictest(read_by_owner_alone)
            .tighter(lower_is_tighter::<bool>),
    };
}
