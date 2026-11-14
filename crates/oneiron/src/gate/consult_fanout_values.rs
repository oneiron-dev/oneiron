use serde::{Deserialize, Serialize};

use crate::check_in::CheckInMode;

/// Vault-owned approval knobs. There is no per-peer budget by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsultFanOutPolicy {
    /// The exceptional-width check threshold. It only marks the check, which
    /// never holds; `mode` gates every fan-out at any width.
    pub approval_threshold: u32,
    pub mode: CheckInMode,
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

#[doc(hidden)]
pub use oneiron_records::gate::consult_fanout_values::{
    ConsultFanOutRate, ConsultFanOutScope, TaskCreateRateLimit,
};
