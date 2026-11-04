use serde::{Deserialize, Serialize};

pub(crate) use crate::gate::fanout_mode::FanoutApprovalMode as ConsultFanOutMode;

/// Vault-owned approval knobs. There is no per-peer budget by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsultFanOutPolicy {
    /// The exceptional-width check threshold. It only marks the check, which
    /// never holds; `mode` gates every fan-out at any width.
    pub approval_threshold: u32,
    pub mode: ConsultFanOutMode,
    /// Optional anomaly detector, not a spend cap. Crossings pause visibly.
    pub peer_rate: Option<ConsultFanOutRate>,
    /// The owner-authored actor request rate. Past it a fan-out still lands,
    /// and the first request past it in a window leaves an OF-520 check.
    /// Every fan-out of an actor counts against the vault's row; a scoped
    /// row's rate composes into its policy but does not move the check.
    pub create_rate: TaskCreateRateLimit,
}

impl Default for ConsultFanOutPolicy {
    fn default() -> Self {
        crate::gate::default_consult_fanout_policy()
    }
}

/// Optional per-peer rate evidence window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsultFanOutRate {
    pub window_secs: u64,
    pub spike_at: u32,
}

/// Per-actor create quota within one node-local time window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskCreateRateLimit {
    pub limit: usize,
    pub window_seconds: u64,
}

impl Default for TaskCreateRateLimit {
    fn default() -> Self {
        Self {
            limit: 10,
            window_seconds: 60,
        }
    }
}

/// Policy path supplied by an authenticated host for a frozen consult plan.
/// The vault level is implicit; each additional level names its parent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsultFanOutScope {
    pub project_ref: Option<String>,
    pub subproject_ref: Option<String>,
    pub thread_ref: Option<String>,
}
