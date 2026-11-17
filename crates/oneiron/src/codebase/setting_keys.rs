//! The codebase's owner Setting keys (DESIGN 15-setting-primitive): rows the setting catalogue
//! reads from this file.

use crate::check_in::ActClass;
use crate::setting::{Kind, ScopeKind, lower_is_tighter};

/// Off: only the owner registers a local repository.
fn owner_registers() -> bool {
    false
}

crate::setting::setting_keys! {
    /// Let this agent register a local Git repository in a project. Off by default:
    /// `vault.repo.anchor.bind` with a `local_folder` takes the owner, as before. On for an agent,
    /// it registers (or updates) a local repository's CODE anchor in a PROJECT it can read,
    /// with every check the owner's registration has. The registration record names no
    /// registrant, the owner's or an agent's. An agent's row names one agent; the vault row
    /// opens every agent, and an agent's own row wins over it. On is the looser value, so only
    /// the owner turns it on; an agent's change waits on the owner's answer (restriction wave
    /// 11, census C55).
    pub(crate) CODEBASE_REGISTRATION_AGENT_MAY_REGISTER: bool = "codebase.registration.agent_may_register" {
        kind: Kind::new(owner_registers)
            .strictest(owner_registers)
            .tighter(lower_is_tighter::<bool>),
        scopes: &[ScopeKind::Vault, ScopeKind::Agent],
        act: ActClass::GrantWiden,
    };
}
