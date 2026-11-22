//! The seal audit's owner Setting keys (DESIGN 15-setting-primitive): rows the setting catalogue
//! reads from this file.

use crate::check_in::ActClass;
use crate::setting::{Kind, ScopeKind, lower_is_tighter};

/// Off: the owner alone reads seal audits.
fn owner_alone() -> bool {
    false
}

crate::setting::setting_keys! {
    /// Let this agent read seal audits: a sealed attempt's audit, its receipt and its pending
    /// checks (restriction census C54). Off by default: the owner alone reads them, as before.
    /// On for an agent, that agent reads them through its own doors, and each answer holds only
    /// what the agent's own read admits. An agent's row decides before the vault row. On is the
    /// looser value, so only the owner turns it on; an agent's change waits on the owner's
    /// answer.
    pub(crate) SEAL_AUDIT_DELEGATE_READ: bool = "self_heal.audit.delegate_read" {
        kind: Kind::new(owner_alone)
            .strictest(owner_alone)
            .tighter(lower_is_tighter::<bool>),
        scopes: &[ScopeKind::Agent],
        act: ActClass::GrantWiden,
    };
}
