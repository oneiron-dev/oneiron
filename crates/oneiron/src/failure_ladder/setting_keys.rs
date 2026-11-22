//! The failure ladder's owner Setting keys (DESIGN 15-setting-primitive): rows the setting
//! catalogue reads from this file.

use crate::check_in::ActClass;
use crate::setting::{Kind, ScopeKind, lower_is_tighter};

/// Off: the owner alone drills into a custom agent's failure.
fn owner_alone() -> bool {
    false
}

crate::setting::setting_keys! {
    /// Let this agent drill into a custom agent's failure: the tier-0 attempt trace and the
    /// terminal receipt behind it (restriction census C53). Off by default: the owner alone
    /// drills, as before. On for an agent, that agent drills through its own door, and the
    /// answer holds only what the agent's own read admits. An agent's row decides before the
    /// vault row. On is the looser value, so only the owner turns it on; an agent's change waits
    /// on the owner's answer.
    pub(crate) FAILURE_DRILL_DELEGATE: bool = "failure_ladder.drill.delegate" {
        kind: Kind::new(owner_alone)
            .strictest(owner_alone)
            .tighter(lower_is_tighter::<bool>),
        scopes: &[ScopeKind::Agent],
        act: ActClass::GrantWiden,
    };
}
