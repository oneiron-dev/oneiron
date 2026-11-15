//! The agent definitions' catalogue keys (DESIGN 15-setting-primitive, stage 4): an agent's plan
//! mode.

use super::AgentPlanMode;
use crate::check_in::ActClass;
use crate::setting::{Kind, ScopeKind};

crate::setting::setting_keys! {
    /// Whether an agent works from a plan the owner approved: `required` (a run a non-owner
    /// starts needs an approved plan), `optional` (the default) or `off` (it may not propose
    /// one). An agent's row is that agent's mode; the vault's row is every other agent's. The
    /// owner sets both; a change that loosens an agent's mode widens what it may do.
    pub(crate) PLAN_MODE: AgentPlanMode = "agents.plan_mode" {
        kind: Kind::new(AgentPlanMode::default),
        scopes: &[ScopeKind::Vault, ScopeKind::Agent],
        act: ActClass::GrantWiden,
    };
}
