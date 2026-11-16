//! Structural puts' owner Setting keys (DESIGN 15-setting-primitive): rows the setting catalogue
//! reads from this file.

use crate::setting::{Kind, lower_is_tighter};

/// Off: only a verified human-class owner mints a PERSON.
fn mint_by_owner_alone() -> bool {
    false
}

crate::setting::setting_keys! {
    /// Let agents mint PERSON entities. Off by default: only a verified human-class owner mints
    /// a PERSON. On, an agent whose live grant names the structural put's verb mints one;
    /// binding any actor to that PERSON stays an authority op the owner signs (BindActor), and
    /// every owner verb still reads that binding (support/actors.rs:138). On is the looser
    /// value, so only the owner turns it on; an agent's change waits on the owner's answer.
    pub(crate) PERSON_AGENT_MAY_MINT: bool = "memory.person.agent_may_mint" {
        kind: Kind::new(mint_by_owner_alone)
            .strictest(mint_by_owner_alone)
            .tighter(lower_is_tighter::<bool>),
    };
}
