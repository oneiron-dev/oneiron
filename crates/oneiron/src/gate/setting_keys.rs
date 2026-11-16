//! The gate's owner Setting keys (DESIGN 15-setting-primitive): rows the setting catalogue reads
//! from this file.

use crate::check_in::ActClass;
use crate::setting::{Kind, ScopeKind, lower_is_tighter};

/// Off: the owner alone settles a Dreamer consent bundle.
fn owner_alone() -> bool {
    false
}

crate::setting::setting_keys! {
    /// Let this agent approve or decline a Dreamer consent bundle (restriction census C29; Engine
    /// RULING RESTRICTION-WAVE-9-CANON C29 = A, canon's settlement policy row of DEC-0006). Off
    /// by default: the owner alone settles one, as before. On for an agent, that agent settles a
    /// bundle, never one its own lineage or forks opened, which the engine refuses whatever this
    /// key says; a member whose obligation needs an owner-tier answer keeps waiting for the
    /// owner. An agent's row decides before the vault row. On is the looser value, so only the
    /// owner turns it on; an agent's change waits on the owner's answer.
    pub(crate) CONSENT_BUNDLE_DELEGATE_RESOLVE: bool = "gate.consent_bundle.delegate_resolution" {
        kind: Kind::new(owner_alone)
            .strictest(owner_alone)
            .tighter(lower_is_tighter::<bool>),
        scopes: &[ScopeKind::Agent],
        act: ActClass::GrantWiden,
    };
}
