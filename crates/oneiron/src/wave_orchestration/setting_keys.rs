//! Wave planning's owner Setting keys (DESIGN 15-setting-primitive): rows the setting catalogue
//! reads from this file.

use crate::check_in::ActClass;
use crate::setting::{Kind, ScopeKind, lower_is_tighter};

/// Off: only the owner plans a wave or reads its status.
fn owner_plans() -> bool {
    false
}

crate::setting::setting_keys! {
    /// Let this agent plan waves and read their status. Off by default: `POST /v1/ai/waves` and
    /// `GET /v1/ai/waves/{attempt}` take the owner, as before. On for an agent, its credential
    /// (Read and Write) enqueues a wave whose epic and planner it can read, and reads the status
    /// of a wave whose epic it can read; the attempt names the agent as its actor. An agent's row
    /// names one agent; the vault row opens every agent of the vault, and an agent's own row
    /// wins over it. A member is never let in by this key. On is the looser value, so only the
    /// owner turns it on; an agent's change waits on the owner's answer (restriction wave 11,
    /// census C57).
    pub AI_WAVES_AGENT_MAY_PLAN: bool = "ai.waves.agent_may_plan" {
        kind: Kind::new(owner_plans)
            .strictest(owner_plans)
            .tighter(lower_is_tighter::<bool>),
        scopes: &[ScopeKind::Vault, ScopeKind::Agent],
        act: ActClass::GrantWiden,
    };
}
